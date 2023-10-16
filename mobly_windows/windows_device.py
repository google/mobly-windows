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

"""Mobly controller module for a Windows device."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import dataclasses
import enum
import logging
import os
import pathlib
from typing import Any

from mobly import logger as mobly_logger

from mobly_windows import device_config
from mobly_windows.lib import errors
from mobly_windows.lib import ssh
from mobly_windows.lib import win32_cim_info

# This is used in the config file located in the test lab's home directory.
MOBLY_CONTROLLER_CONFIG_NAME = 'WindowsDevice'

# Templates for querying and modifying the Windows firewall rules.
_FIREWALL_ADD_RULE_TEMPLATE = ('netsh advfirewall firewall add rule name='
                               '"{rule_name}" dir=in action=allow program='
                               '"{program_path}" enable=yes')
_FIREWALL_DELETE_RULE_TEMPLATE = (
    'netsh advfirewall firewall delete rule name="{rule_name}"')
_FIREWALL_SHOW_RULE_TEMPLATE = ('netsh advfirewall firewall show '
                                'rule name="{rule_name}"')


def create(configs: Sequence[dict[str, Any]]) -> list[WindowsDevice]:
  """Creates WindowsDevice controller objects.

  Mobly uses this to instantiate WindowsDevice controller objects from configs.
  The configs come from Mobly configs that look like:

    ```config.yaml
    TestBeds:
    - Name: SampleTestBed
      Controllers:
        WindowsDevice:
        - device_id: 'XXXX0000-XXXX-0000-XXXX-0000XXXX0000'
          hostname: '127.0.0.1'
    ```

  Each config should have the required key-value pair 'device_id' and
  'hostname'.

  Args:
    configs: a list of dicts, each representing a configuration for a Windows
      device.

  Returns:
    A list of WindowsDevice objects.
  """
  devices = []
  wind_configs = device_config.from_dicts(configs)
  for wind_config in wind_configs:
    logging.debug('Creating Windows device %s', wind_config.device_id)
    devices.append(WindowsDevice(wind_config))

  return devices


def destroy(devices: Sequence[WindowsDevice]) -> None:
  """Destroys WindowsDevice objects.

  Mobly uses this to destroy WindowsDevice objects created by `create`.

  Args:
    devices: list of WindowsDevice.
  """
  # Templorarily do nothing here.
  for device in devices:
    try:
      device.destroy()
    except Exception:  # pylint: disable=broad-except
      logging.exception('Failed to clean up device properly: %s', repr(device))


def get_info(devices: Sequence[WindowsDevice]) -> Sequence[dict[str, Any]]:
  """Gets info from the WindowsDevice objects used in a test run.

  Args:
    devices: A list of WindowsDevice objects.

  Returns:
    list of dict, each representing info for input devices.
  """
  return [d.device_info for d in devices]


def get_devices(winds: Sequence[WindowsDevice],
                **kwargs) -> list[WindowsDevice]:
  """Finds a list of WindowsDevice that has specific key-value pairs in config.

  Users can query data fields in the DeviceConfig, or custom keywords in the
  `custom_configs` field of the device config.

  Example:
    get_devices(windows_devices, hostname='100.100.100.100')
    get_devices(windows_devices, label='foo', number='1234567890')

  Args:
    winds: A list of WindowsDevice instances.
    **kwargs: keyword arguments used to filter WindowsDevice instances.

  Returns:
    A list of target WindowsDevice instances.

  Raises:
    errors.Error: No devices are matched.
  """

  def _get_device_filter(wind):
    for k, v in kwargs.items():
      if hasattr(wind.config, k) and getattr(wind.config, k) == v:
        continue
      if wind.config.custom_configs.get(k) == v:
        continue
      return False
    return True

  filtered = [wind for wind in winds if _get_device_filter(wind)]
  if not filtered:
    raise errors.Error(
        'Could not find a target device that matches condition: %s.' % kwargs)
  return filtered


class WindowsDevice:
  """Mobly controller for a Windows device.

  Each object of this class represents one Windows device in Mobly. This class
  provides various ways, like ssh, Mobly snippets, and ACUITI to control
  a Windows device.

  Attributes:
    ssh: The underlying SSH client object.
    win32_info: The build information collected from the Windows device.
    config: The configurations for the Windows device.
    device_id: A string that identifies a unique Windows device. The Windows
      Device ID only changes if the user reset or install new Windows. More
      details in //testing/mobly/platforms/windows/lib/device_config.py.
    log_path: A string that is the local path where all logs collected on this
      Windows device should be stored.
    debug_tag: A string that represents this Windows device in the debug info.
    log: A logger adapted from root logger with an added prefix
      '[WindowsDevice|<hostname>:<ssh_port>] 'specific to a remote test machine.
  """

  # Timeout to wait for ssh connection.
  SSH_CONNECT_TIMEOUT_SECONDS = None

  # Timeout to wait for banner to be presented.
  SSH_BANNER_TIMEOUT_SECONDS = None

  # Class variable annotations.
  config: device_config.DeviceConfig
  device_id: str
  log: mobly_logger.PrefixLoggerAdapter
  log_path: str

  _ssh: ssh.SSHProxy | None = None
  _win32_info: win32_cim_info.Win32CIMInfoCollection | None = None
  _debug_tag: str

  def __init__(self, config: device_config.DeviceConfig) -> None:
    self.config = config
    self.device_id = config.device_id

    # logging.log_path only exists when this is used in a Mobly test run.
    log_path_base = getattr(logging, 'log_path', '/tmp/logs')
    device_log_directory_name = mobly_logger.sanitize_filename(
        f'WindowsDevice_{self.device_id}({config.hostname}:{config.ssh_port})')
    self.log_path = os.path.join(log_path_base, device_log_directory_name)
    self._debug_tag = f'{config.hostname}:{config.ssh_port}'
    self.log = mobly_logger.PrefixLoggerAdapter(
        logging.getLogger(),
        {
            mobly_logger.PrefixLoggerAdapter.EXTRA_KEY_LOG_PREFIX:
                f'[WindowsDevice|{self.debug_tag}]'
        },
    )

  @property
  def debug_tag(self) -> str:
    """A string that represents this device in the debug info.

    This will be used as part of the prefix of debugging messages emitted by
    this device object, like log lines and the message of DeviceError. Default
    value is 'hostname:ssh_port'.
    """
    return self._debug_tag

  @debug_tag.setter
  def debug_tag(self, tag: str) -> None:
    """Setter for the debug tag."""
    self.log.set_log_prefix(f'[WindowsDevice|{tag}]')
    self.log.debug('Logging debug tag set to "%s"', tag)
    self._debug_tag = tag

  def __repr__(self) -> str:
    return f'<WindowsDevice|{self.debug_tag}>'

  @property
  def ssh(self) -> ssh.SSHProxy:
    """The ssh connection to the Windows device."""
    if self._ssh is None:
      ssh_connection = ssh.SSHProxy(self.config)
      ssh_connection.connect(self.SSH_CONNECT_TIMEOUT_SECONDS,
                             self.SSH_BANNER_TIMEOUT_SECONDS)
      self._ssh = ssh_connection
    return self._ssh

  @property
  def win32_info(self) -> win32_cim_info.Win32CIMInfoCollection:
    """Gets the Win32 CIM information collected from this Windows device."""
    if self._win32_info is None:
      self._win32_info = win32_cim_info.Win32CIMInfoCollection.collect(
          self.ssh, self.log, ignore_error=True
      )
    return self._win32_info

  @property
  def device_info(self) -> dict[str, Any]:
    """Information to be pulled into controller info in the test summary file.

    The device ID, computer system information and OS information are included.
    """
    model_name = (
        self.win32_info.computer_system_info.model
        if self.win32_info.computer_system_info is not None
        else 'unknown'
    )
    os_name = (
        self.win32_info.operating_system_info.caption
        if self.win32_info.operating_system_info is not None
        else 'unknown'
    )

    def _enum_to_str(obj: Any) -> Any:
      """Converts enum.Enum to a name string to fit YAML representation."""
      if isinstance(obj, enum.Enum):
        return obj.name
      return obj

    return {
        'serial': self.device_id,
        'model': model_name,
        'build_info': os_name,
    } | dataclasses.asdict(
        self.win32_info,
        dict_factory=lambda x: {k: _enum_to_str(v) for k, v in x},
    )

  def destroy(self) -> None:
    """Tears WindowsDevice object down.

    This function releases following resources:
    * SSH session
    * User artifacts
    """
    if self._ssh:
      # Clears the user artifacts and closes the SSH session.
      self._clear_user_artifacts_dir()
      self._ssh.disconnect()
      self._ssh = None

  def _clear_user_artifacts_dir(self):
    if self.ssh.is_dir(self.config.user_artifacts_dir):
      self.ssh.rm_dir(self.config.user_artifacts_dir)

  def add_firewall_rule_if_not_exists(self, rule_name: str,
                                      program_path: str) -> None:
    """Adds a Windows firewall rule for inbound connections if not exists.

    After adding this rule, the Windows firewall allows the traffic trying to
    access the specified program.

    Note that Windows firewall can have multiple rules with the same rule name
    and program path, so the caller of this function is responsible for
    deleting the added rule.

    Args:
      rule_name: the specific Windows firewall rule to be added.
      program_path: the path of the specific program to be allowed for inbound
        connections.

    Raises:
      errors.Error: if failed to add the firewall rule.
    """
    try:
      show_rule_cmd = _FIREWALL_SHOW_RULE_TEMPLATE.format(rule_name=rule_name)
      self.ssh.execute_command(show_rule_cmd)
    except errors.ExecuteCommandError:
      self.log.debug("Firewall rule %s doesn't exist, adding the rule.",
                     rule_name)
      try:
        add_rule_cmd = _FIREWALL_ADD_RULE_TEMPLATE.format(
            rule_name=rule_name, program_path=program_path)
        self.ssh.execute_command(add_rule_cmd)
      except errors.ExecuteCommandError as e:
        raise errors.Error(
            f'Failed to add firewall rule "{rule_name}" for "{program_path}".'
        ) from e

  def delete_firewall_rule(self, rule_name: str) -> None:
    """Deletes the specific Windows firewall rule.

    If there are multiple rules with the same name, all the rules will be
    deleted.

    Args:
      rule_name: the specific Windows firewall rule to be deleted.

    Raises:
      errors.Error: if failed to delete the firewall rule.
    """
    try:
      delete_rule_cmd = _FIREWALL_DELETE_RULE_TEMPLATE.format(
          rule_name=rule_name)
      self.ssh.execute_command(delete_rule_cmd)
    except errors.ExecuteCommandError as e:
      raise errors.Error(
          f'Failed to delete firewall rule "{rule_name}".') from e

  def install_msi(
      self,
      msi_file: pathlib.Path,
      admin_mode: bool = True,
      quiet_mode: bool = True,
  ) -> None:
    """Installs an MSI file on the Windows device.

    Use Microsoft built-in command to install the MSI file.

    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec

    Args:
      msi_file: Full path of the MSI file on the local host.
      admin_mode: True to run as administrator, False otherwise.
      quiet_mode: True to install without user interaction, False otherwise.
    """
    remote_download_folder = str(
        pathlib.PureWindowsPath(r'C:\Users', self.config.username, 'Downloads'))
    remote_msi_file = pathlib.PureWindowsPath(remote_download_folder,
                                              msi_file.name)
    self.ssh.push(
        local_src_file=str(msi_file), remote_dest_file=str(remote_msi_file))

    timestamp = mobly_logger.get_log_file_timestamp()
    remote_log_file = pathlib.PureWindowsPath(
        remote_download_folder, f'msiexec,{msi_file.stem},{timestamp}.log')

    # TODO(b/233715298): Enable restart flag after controller support to reboot.
    command = [
        'msiexec',
        '/a' if admin_mode else '/i',
        f'"{remote_msi_file}"',
        '/q' if quiet_mode else '',
        '/norestart',  # '/forcerestart' if restart else '/norestart',
        f'/l*vx "{remote_log_file}"',
    ]
    self.ssh.execute_command(' '.join(command))

    local_log_file = pathlib.Path(self.log_path, remote_log_file.name)
    self.ssh.pull(
        remote_src_file=str(remote_log_file),
        local_dest_file=str(local_log_file))
    self.ssh.rm_file(str(remote_msi_file))
    self.ssh.rm_file(str(remote_log_file))
