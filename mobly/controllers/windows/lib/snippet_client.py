# Copyright 2024 Google LLC
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

"""Snippet Client for Interacting with Snippet Server on Windows Device."""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
import dataclasses
import os
import re
import socket
import time
from typing import Any, BinaryIO, TypeVar

from mobly import logger as mobly_logger
from mobly import utils
from mobly.snippet import client_base
from mobly.snippet import errors

from mobly.controllers.windows.lib import callback_handler
from mobly.controllers.windows.lib import errors as windows_lib_errors
from mobly.controllers.windows.lib import windows_scheduled_task

# Avoid directly importing windows_device, which causes circular dependencies
windows_device = Any

# We use a type parameter here because re.Match is a generic type and
# annotating type with it will cause the warning [g-bare-generic].
_ReMatchTypeVar = TypeVar('_ReMatchTypeVar', bound=re.Match)

# The name of the Windows firewall rule used by Mobly Windows snippet Server
_SERVER_FIREWALL_RULE_NAME = 'Mobly Snippet Server Firewall Rule'

# The remote path of Windows snippet server
_SNIPPET_BINARY_DEVICE_DIR = R'C:\snippet_server'

# The name of the Mobly Snippet Server Windows Scheduled Task
_SERVER_REMOTE_SCHEDULED_TASK_NAME = 'MoblySnippetServerScheduledTask'

# The regular expression used to filter the log indicating that the server
# started successfully
_SERVER_STARTUP_LOG_PATTERN = (
    '^Mobly Snippet Server is listening on: [0-9.localhost]+:([0-9]+)')

# The command used to filter the server startup log on the Windows device
_FILTER_SERVER_STARTUP_LOG_COMMAND_PATTERN = (
    f'Get-Content {{log_device_path}} -Wait | '
    f'Select-String "{_SERVER_STARTUP_LOG_PATTERN}" | '
    '%{{ Write-Host $_; break}}')

# The RPC command used for stopping the snippet server gracefully
_SERVER_STOP_COMMAND_RPC_NAME = 'stop_server'

# The encoding of the socket response
_SOCKET_RESP_ENCODING = 'cp1252'

# Maximum time to wait for the server to be ready
_SERVER_STARTUP_TIMEOUT_SEC = 60

# Maximum time to wait for the server to stop
_SERVER_STOP_TIMEOUT_SEC = 30

# Maximum time to wait for the socket to open on the device.
_SOCKET_CONNECTION_TIMEOUT_SEC = 60

# Maximum time to wait for a response message on the socket.
_SOCKET_READ_TIMEOUT_SEC = 600

# The default timeout for callback handlers returned by this client
_CALLBACK_DEFAULT_TIMEOUT_SEC = 60 * 2


@dataclasses.dataclass(frozen=True)
class DevicePaths:
  """The class for managing the device paths for a snippet client."""

  # The device directory for saving snippet artifacts.
  snippet_device_dir: str

  # The device path of the snippet binary.
  snippet_binary_device_path: str | None = dataclasses.field(
      default=None, init=False)

  # The device path of the snippet binary log.
  snippet_log_device_path: str | None = dataclasses.field(
      default=None, init=False)

  def __post_init__(self):
    object.__setattr__(self, 'snippet_binary_device_path',
                       fR'{self.snippet_device_dir}\snippet_server.exe')

    object.__setattr__(self, 'snippet_log_device_path',
                       fR'{self.snippet_device_dir}\snippet_server_output.log')


class SnippetClient(client_base.ClientBase):
  """Snippet client for interacting with snippet server on Windows Device.

  To enable snippet functions to interact with io devices, this client launches
  the snippet server in the current user session. Without launching the server
  in this session, any interaction with these io devices will result in
  an error. More details can be found:
  https://docs.google.com/document/d/1ayoVYLH3OMsfA-T62pGFm4Hw-7vYcn_g6hHt6sydBo0/edit#bookmark=id.boex0xt6ud8g

  To launch the server in the current user session, this client utilizes the
  Windows Task Scheduler to launch it. SSH channel cannot run tasks in this
  session.

  The server will run asynchronously on the Windows device, like all the other
  tasks launched by this scheduler.

  See base class documentation for a list of public attributes and communication
  protocols.
  """

  def __init__(self,
               device: 'windows_device.WindowsDevice',
               snippet_binary_host_path: str | None = None,
               snippet_additional_file_host_paths: list[str] | None = None,
               snippet_binary_device_path: str | None = None) -> None:
    """Initializes the instance of Snippet Client V2.

    Each client object takes a server binary file to start the server.

    The snippet client can manage binary related files on the device side.
    Set `snippet_binary_host_path`, then the client will upload the binary file
    to the device when launching the snippet and delete it when stopping. If
    there are some additional files used by the  binary, the client will also
    manage them.

    Users can manage the files on the device by themselves for custom
    optimization. Set the parameter `snippet_binary_device_path`, then the
    snippet client will not upload or delete the binary file, but only run the
    binary to launch the snippet. When `snippet_binary_device_path` is set,
    the `snippet_binary_host_path` and `snippet_additional_file_host_paths`
    should be None.

    Args:
      device: the Windows device object associated with this client.
      snippet_binary_host_path: the host path of the snippet binary. If this
        argument is set, the snippet client will manage the binary file on the
        device side. This argument must not be used together with
        `snippet_binary_device_path`.
      snippet_additional_file_host_paths: an optional host path list of
        additional files that are needed by the snippet binary, e.g. DLL files.
        The snippet client will manage these files. These files will be uploaded
        to the same directory as the snippet binary. This argument can only be
        used when `snippet_binary_host_path` is set.
      snippet_binary_device_path: the device path of the snippet binary. If this
        argument is set, users should manage the files on the device by
        themselves. The snippet client only uses this binary to launch the
        snippet. This argument must not be used together with
        `snippet_binary_host_path`.
    """
    self._validate_snippet_path_arguments(snippet_binary_host_path,
                                          snippet_additional_file_host_paths,
                                          snippet_binary_device_path)
    package_name = snippet_binary_host_path or snippet_binary_device_path
    super().__init__(package_name, device)

    self._device_paths = self.get_device_paths()

    self._snippet_binary_host_path = snippet_binary_host_path
    self._snippet_additional_file_host_paths = (
        snippet_additional_file_host_paths or [])
    self._snippet_binary_device_path = (
        snippet_binary_device_path or
        self._device_paths.snippet_binary_device_path)

    self._hostname = device.config.hostname
    self._firewall_rule_name = None
    self._device_port = 0
    self._host_port = 0
    # Set _counter in the constructor so we can try to kill the server by
    # sending an RPC command when the server startup fails.
    self._counter = self._id_counter()
    timestamp = mobly_logger.get_log_file_timestamp()
    self._server_task_on_device = windows_scheduled_task.WindowsScheduledTask(
        task_name=f'{_SERVER_REMOTE_SCHEDULED_TASK_NAME}-{timestamp}',
        log=self._device.log,
        ssh=self._device.ssh,
    )

  def get_device_paths(self) -> DevicePaths:
    """Gets the object that manages the device paths for this snippet client.

    If a subclass is designed to use together with `SnippetClient`, it should
    override this method to save artifacts in a different device directory than
    `SnippetClient`.

    Returns:
      The object that manages the device paths for this snippet client.
    """
    timestamp = mobly_logger.get_log_file_timestamp()
    return DevicePaths(f'{_SNIPPET_BINARY_DEVICE_DIR}-{timestamp}')

  def _validate_snippet_path_arguments(
      self,
      snippet_binary_host_path: str | None,
      snippet_additional_file_host_paths: list[str] | None,
      snippet_binary_device_path: str | None) -> None:
    """Validates the snippet path arguments are legal."""
    exactly_one_path_is_none = ((snippet_binary_host_path is None)
                                ^ (snippet_binary_device_path is None))

    if not exactly_one_path_is_none:
      raise ValueError(
          'Please set exactly one of the two arguments snippet_binary_host_path'
          ' and snippet_binary_device_path. Got snippet_binary_host_path ='
          f' {snippet_binary_host_path}, snippet_binary_device_path ='
          f' {snippet_binary_device_path}.'
      )

    if (snippet_binary_host_path is None
        and snippet_additional_file_host_paths is not None):
      raise ValueError(
          'snippet_additional_file_host_paths should only be set when '
          'snippet_binary_host_path is set.')

  def before_starting_server(self):
    """Performs the preparation steps before starting the remote server.

    This function performs following preparation steps:
    * Push the snippet server binary from local file system to the Windows
      device.
    * Ensure the Windows firewall allows TCP access from the client to
      the server.

    Raises:
      errors.ServerStartPreCheckError: if the preparation steps failed.
    """
    self._clean_device_env_before_starting_server()
    self._push_artifacts_to_device()
    self._ensure_firewall_access()

  def _clean_device_env_before_starting_server(self) -> None:
    """Cleans the device environment before starting server."""
    # We should stop the remaining running server task before removing and
    # pushing any file. One of the common reasons for remaining running tasks is
    # that the last test skipped the `stop` process, which can happen when the
    # test timed out or was manually interrupted by the user.
    self._server_task_on_device.stop_and_unregister()
    self._device.ssh.rm_dir(self._device_paths.snippet_device_dir)
    self._device.ssh.make_dirs(self._device_paths.snippet_device_dir)

  def _push_artifacts_to_device(self) -> None:
    """Pushes server binary and additional files to the Windows device."""
    if self._snippet_binary_host_path is None:
      self.log.debug('Skip pushing artifacts to device.')
      self._ensure_binary_exists_on_device()
      return

    self._push_local_file_to_device(self._snippet_binary_host_path,
                                    self._snippet_binary_device_path)

    device_dir = self._device_paths.snippet_device_dir
    for file_host_path in self._snippet_additional_file_host_paths:
      file_basename = os.path.basename(file_host_path)
      file_device_path = f'{device_dir}\\{file_basename}'
      self._push_local_file_to_device(file_host_path, file_device_path)

  def _ensure_binary_exists_on_device(self):
    if self._device.ssh.is_file(self._snippet_binary_device_path):
      return

    raise errors.ServerStartPreCheckError(
        self._device,
        'Snippet binary file does not exist on the device. binary path: '
        f'{self._snippet_binary_device_path}')

  def _push_local_file_to_device(self, local_path: str,
                                 remote_path: str) -> None:
    """Pushes a single local file to the Windows device."""
    if not (local_path and os.path.isfile(local_path)):
      raise errors.ServerStartPreCheckError(
          self._device, f'No file exists at the given path: {local_path}.')

    self._device.ssh.push(local_path, remote_path, change_permission=True)

  def _ensure_firewall_access(self):
    """Ensures the Windows firewall allows TCP access to the server.

    Windows firewall is a packet filter that allows or blocks network traffic
    according to its configuration. If the firewall rule already exists, it was
    created by a previous test, we should delete it and add a new one.
    """
    try:
      firewall_rule_name = (
          f'{_SERVER_FIREWALL_RULE_NAME} '
          f'{mobly_logger.get_log_file_timestamp()}'
      )
      self._device.add_firewall_rule_if_not_exists(
          firewall_rule_name, self._snippet_binary_device_path)
      self._firewall_rule_name = firewall_rule_name
    except windows_lib_errors.Error as e:
      raise errors.ServerStartPreCheckError(
          self._device,
          'Failed to ensure Windows firewall TCP access.') from e

  def start_server(self):
    """Starts the server on the remote device.

    This function utilizes Windows Task Scheduler to launch the snippet server
    in the current user session. This enables snippet functions to interact
    with io devices in this session, e.g. keyboard, display and WiFi.

    It parses the log of the server on the device side and expects that the
    log contains the port on which the server is listening. Otherwise, this
    function treats the server startup process as a failure and throws
    an error. Then it forwards the server port from the device to the host side
    through SSH.

    Raises:
      errors.ServerStartError: raised if failed to start the server
        successfully.
    """
    self._execute_server_startup_command()
    try:
      server_log_filtered = self._wait_for_server_startup_log()
      self._parse_device_port_from_server_startup_log(server_log_filtered)
    except errors.ServerStartError:
      self._pull_server_log_from_device()
      raise
    self._host_port = self._device.ssh.forward_port(self._device_port)
    self.log.debug(('Snippet server of %s is listening on %s:%d '
                    '(forwarded to localhost:%d)'),
                   self.package, self._hostname,
                   self._device_port, self._host_port)

  def _execute_server_startup_command(self):
    """Executes the server startup command on the Windows device.

    Raises:
      errors.ServerStartError: raised if failed to register and start a Windows
        scheduled task for the server.
    """
    server_startup_cmd = self._construct_server_startup_cmd()
    self.log.debug('Starting server with cmd: %s', server_startup_cmd)
    try:
      self._server_task_on_device.register_and_start(server_startup_cmd)
    except windows_lib_errors.ScheduledTaskError as e:
      raise errors.ServerStartError(self._device, str(e)) from e

  def _construct_server_startup_cmd(self):
    """Constructs the server startup command."""
    # The snippet server always uses a random unused port to listen on.
    start_server_cmd_list = [
        self._snippet_binary_device_path,
        f'--hostname={self._hostname}',
        '--port=0',
        f'--local_log_dir={self._device_paths.snippet_device_dir}',
    ]

    if self.verbose_logging:
      start_server_cmd_list.append('--debug')

    # If the server crashes before accumulating enough output, it won't generate
    # the log file. So we redirect the output of the server process to not lose
    # log content.
    start_server_cmd_list.append(
        '*>&1 | Tee-Object -FilePath '
        f'{self._device_paths.snippet_log_device_path}')

    return ' '.join(start_server_cmd_list)

  def _wait_for_server_startup_log(self):
    """Parses and waits for the server startup log."""
    deadline_time = time.perf_counter() + _SERVER_STARTUP_TIMEOUT_SEC
    while (timeout := deadline_time - time.perf_counter()) > 0:
      cmd = (
          _FILTER_SERVER_STARTUP_LOG_COMMAND_PATTERN.format(
              log_device_path=self._device_paths.snippet_log_device_path))
      try:
        server_log_filtered = self._device.ssh.execute_ps_command(
            cmd, timeout=timeout)
        return server_log_filtered
      except windows_lib_errors.ExecuteCommandError as e:
        if 'PathNotFound' not in str(e):
          raise

        # As the error is reported because the log file does not exist,
        # first we need to check whether the server is running normally
        if not self._server_task_on_device.is_running():
          raise errors.ServerStartError(self._device,
                                        f'The snippet server {self.package} '
                                        'crashed immediately after we ran the '
                                        'startup command. Check the log of the '
                                        'snippet server.') from e

        # The server is running normally, wait for the log file
        self.log.debug('Wait 1s for server startup log file.')
        time.sleep(1)

    raise errors.ServerStartError(
        self._device,
        'Timeout expired when waiting on the output of the server startup '
        'process.')

  def _parse_device_port_from_server_startup_log(self,
                                                 server_startup_log_filtered):
    match = re.search(_SERVER_STARTUP_LOG_PATTERN, server_startup_log_filtered)
    if not match:
      raise errors.ServerStartError(
          self._device,
          f'Got invalid log from snippet {self.package}: '
          f'{server_startup_log_filtered}')
    self._device_port = int(match.group(1))

  def make_connection(self) -> None:
    """Does nothing at this stage."""
    # TODO(mhaoli): send a handshake request to check that the server is ready

  def check_server_proc_running(self) -> None:
    """Does nothing at this stage."""

  @contextlib.contextmanager
  def _handle_socket_connection(self) -> Iterator[BinaryIO]:
    """The context manager for creating a socket connection and closing it.

    Yields:
      The socket file object which is used for sending and receiving messages.

    Raises:
      errors.Error: when failed to create a socket connection.
    """
    connection_hostname = '127.0.0.1'
    if not self._host_port:
      raise errors.Error(
          self._device,
          ('Trying to build a socket connection while the host port is unknown.'
           ' The snippet client might not being started correctly.'))
    self.log.debug('Creating socket connection to %s:%d', connection_hostname,
                   self._host_port)
    try:
      conn = socket.create_connection((connection_hostname, self._host_port),
                                      _SOCKET_CONNECTION_TIMEOUT_SEC)
    except socket.error as e:
      raise errors.Error(
          self._device, f'Failed to connect to {connection_hostname}:'
          f'{self._host_port}. Error: {e}') from e

    conn.settimeout(_SOCKET_READ_TIMEOUT_SEC)
    client = conn.makefile(mode='brw')

    try:
      yield client  # pytype: disable=bad-return-type
    finally:
      client.close()
      conn.close()

  def send_rpc_request(self, request: str) -> str:
    """Sends an RPC request to the server and receives a response.

    This function builds a socket connection to send the RPC request and closes
    the connection after receiving a response.

    Args:
      request: the request that will be sent to the server.

    Returns:
      The response received from the server.

    Raises:
      errors.Error: when failed to communicate with the server through a socket
        connection.
      errors.ProtocolError: when received an empty response from the server.
    """
    with self._handle_socket_connection() as client:
      try:
        client.write(request.encode('utf8'))
        client.flush()
      except socket.error as e:
        raise errors.Error(
            self._device,
            f'Encountered socket error "{e}" sending RPC message "{request}".'
        )

      try:
        response = client.readline()
      except socket.error as e:
        raise errors.Error(
            self._device,
            f'Encountered socket error "{e}" reading RPC response.') from e

      if not response:
        raise errors.ProtocolError(self._device,
                                   errors.ProtocolError.NO_RESPONSE_FROM_SERVER)

      response = str(response, encoding=_SOCKET_RESP_ENCODING)
      return response

  def handle_callback(self, callback_id: str, ret_value: Any,
                      rpc_func_name: str) -> callback_handler.CallbackHandler:
    """Creates a callback handler object for the asynchronous RPC."""
    return callback_handler.CallbackHandler(
        callback_id=callback_id,
        event_client=self,
        ret_value=ret_value,
        method_name=rpc_func_name,
        device=self._device,
        rpc_max_timeout_sec=_SOCKET_READ_TIMEOUT_SEC,
        default_timeout_sec=_CALLBACK_DEFAULT_TIMEOUT_SEC)

  def stop(self) -> None:
    """Releases all the resources acquired in `initialize`.

    This function releases following resources:
    1. Stop the snippet server.
    2. Pull snippet server's log files from the Windows device.
    3. Delete the remote directory used by the snippet server.
    4. Delete the firewall rule of the snippet server.

    Regardless of the success of the other steps, this function will perform
    the last two cleanup steps.
    """
    self._device.log.debug('Stopping snippet server of package %s',
                           self.package)
    try:
      self._stop_server()
      self._pull_server_log_from_device()
    finally:
      self._delete_device_log_directory()
      self._delete_firewall_rule()
    self._device.log.debug('Snippet server of package %s stopped.',
                           self.package)

  def _stop_server(self) -> None:
    """Stops the server running on the Windows device."""
    try:
      self._send_server_stop_command_and_wait()
    except (errors.Error, ConnectionResetError) as e:
      # Only print the error here in order because server will be force killed
      self.log.error('Error occurred trying to stop the snippet server, '
                     'the server will be force killed by stopping the '
                     'scheduled task: %s', e)
    finally:
      self._device_port = 0
      self._host_port = 0
      self._server_task_on_device.stop_and_unregister()

  def _send_server_stop_command_and_wait(self) -> None:
    """Sends a stop command to the snippet server and waits until it exits.

    Raises:
      errors.Error: if failed to stop the server.
    """
    if not self._device_port:
      self.log.debug('Skip sending RPC command to stop the snippet server '
                     'because device port equals %s', self._device_port)
      return

    self.log.debug('Sending RPC command %s to stop the snippet server of '
                   'package %s', _SERVER_STOP_COMMAND_RPC_NAME, self.package)
    self._rpc(_SERVER_STOP_COMMAND_RPC_NAME)
    self._wait_for_server_task_to_exit()

  def _wait_for_server_task_to_exit(self) -> None:
    """Waits for the server task to exit.

    Raises:
      errors.Error: if timeout expired when waiting for the server task to
        exit.
    """
    deadline_time = time.perf_counter() + _SERVER_STOP_TIMEOUT_SEC
    while time.perf_counter() <= deadline_time:
      if not self._server_task_on_device.is_running():
        break
    else:
      raise errors.Error(self._device,
                         'Timeout expired when waiting for the server to exit.')

  def _pull_server_log_from_device(self) -> None:
    """Pulls snippet server's log files from the Windows device.

    This function will place log files in the local directory
    `{self._device.log_path}/snippet_server`. This function will only pull files
    with `log` as the filename extension.
    """
    timestamp_str = mobly_logger.get_log_file_timestamp()
    local_log_dir_name = f'snippet_server,{timestamp_str}'
    local_log_dir_path = os.path.join(self._device.log_path, local_log_dir_name)
    utils.create_dir(local_log_dir_path)

    device_dir = self._device_paths.snippet_device_dir
    for filename in self._device.ssh.list_dir(device_dir):
      # The snippet server binary could be large, thus we only pull log files.
      if filename.endswith('.log'):
        remote_filename = f'{device_dir}\\{filename}'
        self._device.ssh.pull(remote_filename,
                              os.path.join(local_log_dir_path, filename))

  def _delete_device_log_directory(self) -> None:
    self._device.ssh.rm_dir(self._device_paths.snippet_device_dir)

  def _delete_firewall_rule(self) -> None:
    if self._firewall_rule_name is not None:
      try:
        self._device.delete_firewall_rule(self._firewall_rule_name)
      except windows_lib_errors.Error as e:
        self.log.debug('Ignoring the error when trying to clean existing '
                       'firewall rule: %s', e)
      self._firewall_rule_name = None

  def close_connection(self) -> None:
    """Does nothing at this stage.

    This is a stage used for cleanup after all tests are done. This client
    doesn't need to close any connection. Because it only establishes a
    connection every time it needs to send an RPC, and closes the connection
    right after completing the RPC.
    """

  # TODO: Temporarily override these abstract methods so that we can initialize
  # the instances in unit tests. We are implementing these functions in the
  # next PR as soon as possible.
  def restore_server_connection(self, port: int | None = None):
    raise NotImplementedError('To be implemented.')
