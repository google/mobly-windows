# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""SSH client for the Windows controller module."""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import errno
import logging
import os
import pathlib
import re
import socket
import stat
import threading
from typing import Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree

from mobly import logger as mobly_logger
import paramiko
from paramiko import channel
from paramiko import sftp_attr
from paramiko import ssh_exception
from zmq.ssh import forward

from mobly_windows import device_config
from mobly_windows.lib import errors


# Windows Console uses character sets based on system languages.
# The default multilingual encoding is windows-1252 (cp1252).
# There will be some "mojibake" if the system language is non-Latin.
# https://docs.microsoft.com/en-us/windows/win32/intl/code-pages
# https://docs.microsoft.com/en-us/windows/win32/intl/code-page-identifiers
_DEFAULT_ENCODING = 'cp1252'
# The default encoding used in Powershell.
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding?view=powershell-7.3#character-encoding-in-windows-powershell
_DEFAULT_ENCODING_POWERSHELL = 'UTF-16LE'
# The tag indicating that the string is in Powershell CLIXML format.
_POWERSHELL_XML_TAG = '#< CLIXML'
_CRLF_TAG = '_x000D__x000A_'
# The width of the pseudo-terminal.
_PTY_WIDTH = 2000


@dataclasses.dataclass
class CommandResults:
  """A container to collect full command results."""

  exit_code: int = 0
  stdout: str = ''
  stderr: str = ''


# TODO(b/210804977): Consolidate SSH interface of CrOS and Windows controller.
class SSHProxy:
  """SSH client to interact with the test Windows device.

  Attributes:
    log: A logger adapted from root logger with an added prefix specific to a
      remote test machine. The prefix is "[SSHProxy| hostname:ssh_port] ".
    ssh_client: The underlying Paramiko SSHClient object.
  """

  def __init__(self,
               config: device_config.DeviceConfig,
               allow_agent: bool = False) -> None:
    """Initializes the SSH client instance.

    Args:
      config: The configurations for the test Windows device.
      allow_agent: Allow use of ssh-agent for underlying ssh_client object.
    """
    self._hostname = config.hostname
    self._ssh_port = config.ssh_port
    self._username = config.username
    self._password = config.password
    self._allow_agent = allow_agent
    self._port_forward_servers: Dict[int, forward.ForwardServer] = {}

    self._sftp: Optional[paramiko.SFTPClient] = None

    self.log = mobly_logger.PrefixLoggerAdapter(
        logging.getLogger(),
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX:
                f'[SSHProxy|{self._hostname}:{self._ssh_port}]'
        },
    )
    self.ssh_client = paramiko.SSHClient()
    self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    logging.getLogger('paramiko').setLevel(logging.WARNING)

  def __repr__(self) -> str:
    return f'<SSHProxy|{self._hostname}:{self._ssh_port}>'

  def connect(
      self,
      timeout: Optional[float] = None,
      banner_timeout: Optional[float] = None,
  ) -> None:
    """Connects to the test machine.

    Arguments:
      timeout: Optional connection timeout in seconds.
      banner_timeout: Optional timeout for the SSH banner to be presented.
    """
    self.ssh_client.connect(
        self._hostname,
        port=self._ssh_port,
        username=self._username,
        password=self._password,
        allow_agent=self._allow_agent,
        timeout=timeout,
        banner_timeout=banner_timeout)
    self._sftp = self.ssh_client.open_sftp()
    self.log.debug('Connected to %s:%d', self._hostname, self._ssh_port)

  def disconnect(self) -> None:
    """Disconnects from the test machine and cleans up."""
    for server in self._port_forward_servers.values():
      server.shutdown()
      server.server_close()
    self._port_forward_servers.clear()

    if self._sftp:
      self._sftp.close()
      self._sftp = None
    self.ssh_client.close()
    self.log.debug('Disconnected from %s', self._hostname)

  def forward_port(self,
                   remote_port: int,
                   local_port: int = 0) -> int:
    """Sets up an SSH tunnel to forward a port from local to remote machine.

    The tunnel will run in a separate thread.

    Args:
      remote_port: The port on the remote host to forward all data to.
      local_port: The port on the local machine from which to forward all data.
        If 0, an unused port is picked.

    Returns:
      The local port number used to open the SSH tunnel.

    Raises:
      errors.PortForwardingError: Raised if the remote port has been forwarded
        to a different local port.
    """

    if remote_port in self._port_forward_servers:
      _, real_port = self._port_forward_servers[remote_port].server_address
      if not local_port or local_port == real_port:
        return real_port
      else:
        error_string = (f'Remote port {remote_port} has been forwarded to '
                        f'local port {real_port}')
        raise errors.PortForwardingError(self, error_string)

    # Construction of the port forwarding server and subhandler.
    class SubHandler(forward.Handler):
      """Configures the local forward server."""
      chain_host = self._hostname
      chain_port = remote_port
      ssh_transport = self.ssh_client.get_transport()

    port_forward_server = (
        forward.ForwardServer(('127.0.0.1', local_port), SubHandler))

    # Start the server loop on a separate thread.
    thread = threading.Thread(target=port_forward_server.serve_forever,
                              daemon=True)
    thread.start()

    self._port_forward_servers[remote_port] = port_forward_server
    _, real_port = port_forward_server.server_address

    self.log.debug('Forwarded address %s to local port %d',
                   f'{self._hostname}:{remote_port}', real_port)
    return real_port

  def execute_command_impl(
      self,
      command: str,
      timeout: float | None = None,
      get_pty: bool = False,
      combine_stderr: bool = False,
  ) -> Tuple[
      channel.Channel,
      channel.ChannelStdinFile,
      channel.ChannelFile,
      channel.ChannelStderrFile,
  ]:
    """Executes the command in the remote machine."""
    channel_ = self.ssh_client.get_transport().open_session()
    if timeout is not None:
      channel_.settimeout(timeout)
    if get_pty:
      channel_.get_pty(width=_PTY_WIDTH)
    channel_.set_combine_stderr(combine_stderr)

    channel_.exec_command(command)

    stdin_file = channel_.makefile_stdin('wb')
    stdout_file = channel_.makefile('rb')
    stderr_file = channel_.makefile_stderr('rb')
    return (channel_, stdin_file, stdout_file, stderr_file)

  def execute_command(
      self,
      command: str,
      timeout: Optional[float] = None,
      ignore_error: bool = False,
      command_results_collector: Optional[CommandResults] = None) -> str:
    """Executes the command in the remote machine.

    The command waits for the remote process to complete and returns the
    result. If the command you run produces large amount of output (either to
    stdout or to stderr), please use execute_command_async().

    Args:
      command: The command to be executed in the remote machine.
      timeout: Optional timeout in seconds. If a non-negative float is given,
        subsequent channel read/write operations will raise a timeout exception
        if the timeout period value has elapsed before the operation has
        completed. Setting a timeout of None disables timeouts.
      ignore_error: Whether to raise an exception if the command fails remotely.
      command_results_collector: the container to collect full command results.

    Returns:
      A string representing stripped stdout of the command.

    Raises:
      errors.ExecuteCommandError: Raised if not ignoring error and status code
        of command is greater than 0.
      errors.SshRemoteError: Raised if failed to get the command result.
    """
    (channel_, _, stdout_file, stderr_file) = self.execute_command_impl(
        command, timeout=timeout, get_pty=False
    )

    # Blocking wait until the command completes.
    exit_code = channel_.recv_exit_status()

    with contextlib.closing(channel_):
      try:
        with contextlib.closing(stdout_file):
          stdout_str = decode_bytes(stdout_file.read())
        with contextlib.closing(stderr_file):
          stderr_str = decode_bytes(stderr_file.read())
      except errors.DecodeError as e:
        raise errors.SshRemoteError(
            self, f'Failed to decode output of command: {command}'
        ) from e

    command_result = CommandResults(exit_code, stdout_str, stderr_str)
    if command_results_collector:
      for key, value in dataclasses.asdict(command_result).items():
        setattr(command_results_collector, key, value)

    self.log.debug('cmd: %s, stdout: %s, stderr: %s, ret: %s', command,
                   stdout_str, stderr_str, exit_code)
    if not ignore_error and exit_code:
      raise errors.ExecuteCommandError(self, command, command_result)
    return stdout_str

  def execute_command_async(
      self,
      command: str,
      timeout: Optional[int] = None,
      get_pty: bool = False
  ) -> Tuple[channel.ChannelStdinFile, channel.ChannelFile,
             channel.ChannelStderrFile]:
    """Executes the command in the remote machine.

    This method returns immediately. It doesn't wait for the remote process to
    complete. The command will run on Windows device as a subprocess of ssh, and
    will be killed when the ssh connection is closed.

    NOTE: Users of this method must hold at least one of the three files
    returned by this method, or the channel `channelFile.channel`, until the
    remote process completes. Because this method only keeps a weak reference of
    the channel, if there are no other references, the channel object might be
    reclaimed by garbage collection, causing the remote task to be killed
    silently. All channel file objects hold the reference of the channel, so
    it's safe if users hold at least one of the file objects.

    Args:
      command: The command to be executed in the remote machine.
      timeout: Optional timeout in seconds.
      get_pty: Whether to request a pseudo-terminal from the server. This is
        usually used right after creating a client channel, to ask the server to
        provide some basic terminal semantics for a shell invoked with
        invoke_shell. It is not necessary (or desirable) to enable it if you are
        going to execute a single command. But you need to enable it if you
        would like to get output stream continuously when the command is running
        even for a single command.

    Returns:
      The stdin, stdout, and stderr of the executing command which can be used
      for Python file I/O.
    """
    self.log.debug('Executing async command on remote machine: %s', command)
    (_, stdin_file, stdout_file, stderr_file) = self.execute_command_impl(
        command, timeout=timeout, get_pty=get_pty
    )
    return (stdin_file, stdout_file, stderr_file)

  def execute_ps_command(
      self,
      command: str,
      timeout: Optional[float] = None,
      ignore_error: bool = False,
      command_results_collector: Optional[CommandResults] = None) -> str:
    """Executes the command in the Powershell on remote machine.

    Args:
      command: The Powershell command to be executed.
      timeout: Optional timeout in seconds.
      ignore_error: Whether to raise an exception if the command fails remotely.
      command_results_collector: the container to collect full command results.

    Returns:
      A CommandResult object that collects status code, stdout and stderr.
    """
    self.log.debug(
        'Executing Powershell command on remote machine: %s', command
    )
    # Encodes Powershell command to wrap up complex strings that may otherwise
    # cause issues for the command-line.
    encoded_cmd = base64.b64encode(
        command.encode(_DEFAULT_ENCODING_POWERSHELL)
    ).decode('ascii')
    ps_cmd = f'powershell -encodedcommand {encoded_cmd}'
    command_results_collector = (
        CommandResults()
        if command_results_collector is None
        else command_results_collector
    )
    self.execute_command(
        ps_cmd,
        timeout=timeout,
        ignore_error=True,
        command_results_collector=command_results_collector,
    )
    command_results_collector.stderr = _get_error_message_from_clixml(
        command_results_collector.stderr
    )
    if not ignore_error and command_results_collector.exit_code:
      raise errors.ExecuteCommandError(
          self, f'[Powershell command] {command}', command_results_collector
      )
    return command_results_collector.stdout

  def execute_ps_command_async(
      self, command: str, timeout: Optional[int] = None, get_pty: bool = False
  ) -> Tuple[
      channel.ChannelStdinFile, channel.ChannelFile, channel.ChannelStderrFile
  ]:
    """Executes the Powershell command and returns immediately.

    NOTE: Users of this method must hold at least one of the three files
    returned by this method, or the channel `channelFile.channel`, until the
    remote process completes. Because this method only keeps a weak reference of
    the channel, if there are no other references, the channel object might be
    reclaimed by garbage collection, causing the remote task to be killed
    silently. All channel file objects hold the reference of the channel, so
    it's safe if users hold at least one of the file objects.

    Args:
      command: The Powershell command to be executed.
      timeout: Optional timeout in seconds.
      get_pty: Whether to request a pseudo-terminal from the server.

    Returns:
      The stdin, stdout, and stderr of the executing command which can be used
      for Python file I/O.
    """
    self.log.debug(
        'Executing async Powershell command on remote machine: %s', command
    )
    encoded_cmd = base64.b64encode(
        command.encode(_DEFAULT_ENCODING_POWERSHELL)
    ).decode('ascii')
    ps_cmd = f'powershell -encodedcommand {encoded_cmd}'
    return self.execute_command_async(ps_cmd, timeout=timeout, get_pty=get_pty)

  def stat(self, remote_path: str) -> Optional[sftp_attr.SFTPAttributes]:
    """Obtains stat info of a remote SFTP path on the client.

    The path can be either to a file or to a folder.

    Args:
      remote_path: The path on the remote machine.

    Returns:
      The SFTP attributes of the remote path, or None if the remote path does
      not exist.

    Raises:
      IOError: Raised if obtaining stat info failed with an error status other
        than errno.ENOENT. For example, this may be caused by a
        permission-denied error on the remote machine.
    """
    self.log.debug('Obtaining stat info of remote path: %s', remote_path)
    try:
      return self._sftp.stat(remote_path.rstrip('\\'))
    except IOError as e:
      # ENOENT means "no such file or directory".
      if e.errno == errno.ENOENT:
        return None
      raise

  def exists(self, remote_path: str) -> bool:
    """Checks whether the path exists on the remote machine.

    The path can be either to a file or to a folder.

    Args:
      remote_path: The path on the remote machine.

    Returns:
      True if the path exists, False otherwise.

    Raises:
      IOError: Raised if obtaining stat info failed with an error status other
        than errno.ENOENT. For example, this may be caused by a
        permission-denied error on the remote machine.
    """
    return self.stat(remote_path) is not None

  def is_root_dir(self, dir_path: str) -> bool:
    r"""Checks whether the dir_path is a root directory on the remote machine.

    On Windows, the root directory is "drive:\" where drive is an uppercase
    letter, for example, the root directory is usually "C:\". The directory
    separator is usually a "\".

    Args:
      dir_path: The remote directory path.

    Returns:
      True if dir_path is a valid root directory, False otherwise.

    Raises:
      IOError: Raised if obtaining stat info failed with an error status other
        than errno.ENOENT. For example, this may be caused by a
        permission-denied error on the remote machine.
    """
    if not self.exists(dir_path):
      return False
    return dir_path.rstrip('\\') == pathlib.PureWindowsPath(dir_path).drive

  def is_dir(self, dir_path: str) -> bool:
    """Checks whether the dir_path is a directory.

    Args:
      dir_path: The path on the remote machine.

    Returns:
      True if dir_path is a valid path to a directory, False otherwise.

    Raises:
      IOError: Raised if obtaining stat info failed with an error status other
        than errno.ENOENT. For example, this may be caused by a
        permission-denied error on the remote machine.
    """
    dir_stat_info = self.stat(dir_path)
    return dir_stat_info and stat.S_ISDIR(dir_stat_info.st_mode)

  def is_file(self, file_path: str) -> bool:
    """Checks whether the file_path is a file.

    Args:
      file_path: The path on the remote machine.

    Returns:
      True if file_path is a valid path to a file, False otherwise.

    Raises:
      IOError: Raised if obtaining stat info failed with an error status other
        than errno.ENOENT. For example, this may be caused by a
        permission-denied error on the remote machine.
    """
    file_stat_info = self.stat(file_path)
    return file_stat_info and stat.S_ISREG(file_stat_info.st_mode)

  def list_dir(self, remote_dir: str) -> List[str]:
    """Lists the names of the entries in the given path.

    The returned list is in arbitrary order. It does not include the special
    entries '.' and '..' even if they are present in the folder. This method is
    meant to mirror os.listdir as closely as possible.

    Args:
      remote_dir: The remote directory path.

    Returns:
      A list of strings containing the names of the entries.
    """
    self.log.debug('Listing the entries in remote dir %s', remote_dir)
    return self._sftp.listdir(remote_dir)

  def rm_file(self, remote_file: str) -> None:
    """Removes a remote file from the remote machine.

    Args:
      remote_file: The remote file path.
    """
    if self.exists(remote_file):
      self._sftp.remove(remote_file)
      self.log.debug('Removed remote file %s', remote_file)
    else:
      self.log.debug('Remote file to remove %s does not exist', remote_file)

  def rm_dir(self, remote_dir: str) -> CommandResults:
    """Recursively removes a remote directory from the remote machine.

    Args:
      remote_dir: The remote directory path.

    Returns:
      A CommandResults container with full command results.
    """
    if self.exists(remote_dir):
      command_results = CommandResults()
      # The Windows command `rd /s /q` deletes a directory tree in quiet mode.
      # https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rd
      self.execute_command(
          f'rd /s /q "{remote_dir}"',
          ignore_error=True,
          command_results_collector=command_results)
      if not command_results.exit_code:
        self.log.debug('Removed remote folder %s', remote_dir)
      else:
        error_string = (
            f'exit code: {command_results.exit_code}, '
            f'stdout {command_results.stdout}, '
            f'stderr: {command_results.stderr}')
        self.log.debug('Removing remote folder %s failed with %s',
                       remote_dir, error_string)
      return command_results

    self.log.debug('Remote folder to remove %s does not exist', remote_dir)
    return CommandResults(exit_code=-1)

  def rm_dir_or_error(self, remote_dir: str) -> None:
    """Recursively removes a remote directory or else raises an error.

    On Windows, busy files cannot be deleted. This function makes it easy to
    notice that problem. Usually the solution is to reboot the machine.
    Note that if the directory doesn't exist then no error will be thrown.

    Args:
      remote_dir: The remote directory path.

    Raises:
      IOError: If the command failed with an error message showing that the
        device is busy. This matches RmFile's IOError.
      errors.SshRemoteError: If the command failed (exit code other than 0), but
        reason for the failure wasn't clear.
    """
    command_results = self.rm_dir(remote_dir)
    if command_results.exit_code:
      error_string = (
          f'exit code: {command_results.exit_code}, '
          f'stdout {command_results.stdout}, stderr: {command_results.stderr}')
      if 'being used by another process' in command_results.stderr:
        raise IOError('Likely a process is still using the file that '
                      f'you are trying to delete: {error_string}')
      else:
        raise errors.SshRemoteError(self, error_string)

  def _make_dirs_impl(self, remote_dir: pathlib.PureWindowsPath) -> None:
    """Recursively makes directories on the remote machine.

    Args:
      remote_dir: The absolute path of the remote directory.

    Raises:
      RuntimeError: A component in remote_dir is not a directory.
    """
    remote_dir_str = str(remote_dir)
    remote_stat_info = self.stat(remote_dir_str)
    if remote_stat_info:  # path exists
      if stat.S_ISDIR(remote_stat_info.st_mode):
        return  # already a directory; nothing to do.
      raise RuntimeError(f'{remote_dir_str} is not a directory.')

    self._make_dirs_impl(remote_dir.parent)
    self._sftp.mkdir(remote_dir_str)

  def make_dirs(self, remote_dir: str) -> None:
    """Makes a directory on the remote machine.

    Args:
      remote_dir: The absolute path of the target remote directory.

    Raises:
      ValueError: The remote_dir is not a valid absolute path.
    """
    windows_dir_path = pathlib.PureWindowsPath(remote_dir)
    if not windows_dir_path.is_absolute():
      raise ValueError(f'{remote_dir} is not an absolute path.')

    if not self.is_root_dir(windows_dir_path.drive):
      raise ValueError(f'{remote_dir} does not have a valid root directory.')

    self._make_dirs_impl(windows_dir_path)
    self.log.debug('Created new remote folder %s', remote_dir)

  def move_path(self, remote_old_path: str, remote_new_path: str) -> None:
    """Moves a file or folder from remote_old_path to remote_new_path.

    Args:
      remote_old_path: The existing old path on the remote machine.
      remote_new_path: The non-existing new path on the remote machine.

    Raises:
      IOError: Raised if renaming the path goes wrong on the remote machine.
        This may be caused: if remote_old_path does not exist;
        if remote_new_path exists; if remote_old_path is a directory and
        remote_old_path a file, or the opposite; if the dirname of
        remote_new_path does not exist; if the path would be moved to another
        filesystem (e.g. mount point); if something else goes wrong.
    """
    self._sftp.rename(remote_old_path, remote_new_path)
    self.log.debug('Moved remote path from %s to %s',
                   remote_old_path, remote_new_path)

  def push_dir(self,
               local_src_dir: str,
               remote_dest_dir: str,
               change_permission: bool = False) -> None:
    """Pushes local directory recursively to the remote machine.

    Args:
      local_src_dir: The local directory to be copied to the remote machine.
      remote_dest_dir: The destination directory in the remote machine.
      change_permission: Whether to change the specified user access rights to
        full control on the remote destination.
    """
    self.make_dirs(remote_dest_dir)
    for (dir_path, _, file_names_list) in os.walk(local_src_dir):
      for file_name in file_names_list:
        local_file = os.path.join(dir_path, file_name)
        self.push(
            local_file,
            local_file.replace(local_src_dir, remote_dest_dir, 1),
            change_permission=change_permission)
    self.log.debug('Pushed local dir %s to test machine as remote dir %s',
                   local_src_dir, remote_dest_dir)

  def push(self,
           local_src_file: str,
           remote_dest_file: str,
           change_permission: bool = False) -> None:
    """Pushes local file to the remote machine.

    Args:
      local_src_file: The local file to be copied to the remote machine.
      remote_dest_file: The destination file location in the remote machine.
      change_permission: Whether to change the specified user access rights to
        full control on the remote destination.
    """
    self.make_dirs(str(pathlib.PureWindowsPath(remote_dest_file).parent))
    self._sftp.put(local_src_file, remote_dest_file)
    if change_permission:
      self.execute_command(
          f'icacls {remote_dest_file} /grant {self._username}:f')
    self.log.debug('Pushed local file %s to test machine as remote file %s',
                   local_src_file, remote_dest_file)

  def push_files(self,
                 local_src_file_list: List[str],
                 remote_dest_dir: str,
                 change_permission: bool = False) -> None:
    """Pushes local files to the specified remote directory.

    Args:
      local_src_file_list: The path list of local files to be copied to the
        remote machine.
      remote_dest_dir: The destination directory location in the remote
        machine.
      change_permission: Whether to change the specified user access rights to
        full control on the remote destination.
    """

    for local_src_file in local_src_file_list:
      file_basename = os.path.basename(local_src_file)
      remote_dest_file_path = str(pathlib.PureWindowsPath(
          remote_dest_dir, file_basename))
      self.push(local_src_file, remote_dest_file_path, change_permission)

  def pull(self, remote_src_file: str, local_dest_file: str) -> None:
    """Pulls a file from the remote machine as a local file.

    Args:
      remote_src_file: The remote source file name.
      local_dest_file: The local destination file name.

    Raises:
      RuntimeError: The source file does not exist on the remote machine, or the
        destination file already exists on the local machine.
    """
    if not self.exists(remote_src_file):
      raise RuntimeError(
          f'The remote source file ({remote_src_file}) does not exist.')
    if os.path.exists(local_dest_file):
      raise RuntimeError(
          f'The local destination file ({local_dest_file}) already exists.')

    local_dir_path = os.path.dirname(local_dest_file)
    if not os.path.exists(local_dir_path):
      os.makedirs(local_dir_path)
    self._sftp.get(remote_src_file, local_dest_file)
    self.log.debug('Pulled file %s from test machine to local file %s',
                   remote_src_file, local_dest_file)

  def pull_to_directory(self, remote_src_file: str,
                        local_dest_dir: str) -> None:
    """Pulls a remote file into a local directory.

    Args:
      remote_src_file: The remote source file path.
      local_dest_dir: The path to the local destination directory.
    """
    filename = pathlib.PureWindowsPath(remote_src_file).name
    self.pull(remote_src_file, os.path.join(local_dest_dir, filename))
    self.log.debug('Pulled file %s from test machine to local dir %s',
                   remote_src_file, local_dest_dir)

  def _get_file_paths_in_remote_directory(
      self,
      remote_dir: pathlib.PureWindowsPath) -> Iterable[pathlib.PureWindowsPath]:
    """Yields the path to all files within a remote directory recursively.

    Args:
      remote_dir: The remote directory path.

    Yields:
      The PureWindowsPath to all files in the directory.
    """
    for entry in self._sftp.listdir_attr(str(remote_dir)):
      entry_path = remote_dir.joinpath(entry.filename)
      if stat.S_ISDIR(entry.st_mode):
        yield from self._get_file_paths_in_remote_directory(entry_path)
      else:
        yield entry_path

  def pull_remote_directory(self, remote_src_dir: str,
                            local_dest_dir: str) -> None:
    """Pulls all files within a remote directory to local directory.

    Args:
      remote_src_dir: The path to the remote source directory.
      local_dest_dir: The path to the local destination directory.
    """
    for remote_filepath in self._get_file_paths_in_remote_directory(
        pathlib.PureWindowsPath(remote_src_dir)):
      # Use Path.joinpath to avoid messing up the forward/backward slashes.
      local_filepath = pathlib.Path(local_dest_dir).joinpath(
          remote_filepath.relative_to(remote_src_dir))
      self.pull(str(remote_filepath), str(local_filepath))


def _get_error_message_from_clixml(raw_xml: str) -> str:
  """Sanitises tags and gets error messages from a CLIXML format string.

  When running a command in Windows Powershell, the stderr stream may contain
  some CLIXML. This method clears up the CLIXML tags and strips the error
  message from the string.

  Args:
    raw_xml: The raw decoded CLIXML string from Powershell.

  Returns:
    The error message stripped from the CLIXML string if the given string is in
    CLIXML format. Else returns the raw input.
  """
  if raw_xml.startswith(_POWERSHELL_XML_TAG):
    xml_tree = ElementTree.fromstring(
        raw_xml.replace(_POWERSHELL_XML_TAG, '')
        .replace(_CRLF_TAG, '\n')
        .strip()
    )

    target_node_tag = 'S[@S="Error"]'
    if namespace := re.match('{.*}', xml_tree.tag):
      target_node_tag = namespace.group(0) + target_node_tag
    return ''.join([node.text for node in xml_tree.findall(target_node_tag)])

  return raw_xml


def decode_bytes(raw_bytes: bytes) -> str:
  """Decodes given bytes from Windows to a string.

  This method will try to decode the given bytes with default encodings used
  by Windows console and Windows Powershell. It will first try the Windows
  console default encoding and then try the Powershell default encoding.
  This is because Powershell encoding depends on the cmdlet that runs in it
  and could be 'cp1252' or 'UTF-16LE'.
  https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding?view=powershell-7.3#character-encoding-in-windows-powershell

  Args:
    raw_bytes: The bytes to decode.

  Returns:
    The decoded string of given bytes.

  Raises:
    errors.DecodeError: Failed to decode given bytes with Windows console
      and Powershell encoding.
  """
  if not raw_bytes:
    return ''

  try:
    # First try: use Windows console's default encoding 'cp1252'.
    decoded_str = raw_bytes.decode(_DEFAULT_ENCODING)
    if '\0' not in decoded_str:
      return decoded_str
  except UnicodeDecodeError:
    pass

  try:
    # Second try: if `\0` in the decoded string, try to use Powershell's
    # default encoding 'UTF-16LE'.
    return raw_bytes.decode(_DEFAULT_ENCODING_POWERSHELL)
  except UnicodeDecodeError as e:
    raise errors.DecodeError(
        'Cannot decode byets stream, try to decode with cp1252 and utf-16LE'
        ' both failed.',
    ) from e
