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

"""Build info collector for a Windows device."""

from __future__ import annotations

from collections.abc import Mapping
import dataclasses
import datetime
import enum
import json
import re
from typing import Any, TypeVar

import dacite
from mobly import logger as mobly_logger

from mobly.controllers.windows.lib import errors
from mobly.controllers.windows.lib import ssh as ssh_lib

T = TypeVar('T')

# The regex for searching timestamps in CIM result
_TIMESTAMP_REGEX = re.compile(r'Date\(([0-9]*)\)')


@dataclasses.dataclass
class Win32CIMInfoCollection:
  """A collection of CIM information from the WindowsDevice.

  This data class is a collection of common information of the WindowsDevice
  retrieved from the Common Information Model (CIM) Win32 classes of the device.
  The CIM Win32 classes describe hardware or software available on Windows
  systems and the relationships between them.

  Attributes:
    computer_system_info: Information of the system.
    operating_system_info: Information of the operating system.
    processors_info: Information of the processors.
    bios_info: Information of the BIOS.
    active_network_adapters_info: Information of the active network adapters.
    logical_disks_info: Information of logical disks.
    desktop_monitors_info: Information of the desktop monitors.
    time_locale_info: Information of the time zone and locale.
    bluetooth_device_info: Information of the Bluetooth devices.
  """

  computer_system_info: ComputerSystemInfo | None
  operating_system_info: OperatingSystemInfo | None
  processors_info: list[ProcessorInfo] | None
  bios_info: BIOSInfo | None
  active_network_adapters_info: list[NetworkAdapterConfigurationInfo] | None
  logical_disks_info: list[LogicalDiskInfo] | None
  desktop_monitors_info: list[DesktopMonitorInfo] | None
  time_locale_info: TimeLocaleInfo | None
  bluetooth_device_info: list[PnPEntityInfo] | None

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> Win32CIMInfoCollection:
    """Collects build information of a remote device."""
    return Win32CIMInfoCollection(
        computer_system_info=ComputerSystemInfo
        .collect(ssh, log, ignore_error),
        operating_system_info=OperatingSystemInfo
        .collect(ssh, log, ignore_error),
        processors_info=ProcessorInfo
        .collect(ssh, log, ignore_error),
        bios_info=BIOSInfo
        .collect(ssh, log, ignore_error),
        active_network_adapters_info=NetworkAdapterConfigurationInfo
        .collect_active(ssh, log, ignore_error),
        logical_disks_info=LogicalDiskInfo
        .collect(ssh, log, ignore_error),
        desktop_monitors_info=DesktopMonitorInfo
        .collect(ssh, log, ignore_error),
        time_locale_info=TimeLocaleInfo
        .collect(ssh, log, ignore_error),
        bluetooth_device_info=PnPEntityInfo
        .collect('Bluetooth', ssh, log, ignore_error),
    )


@dataclasses.dataclass
class ComputerSystemInfo:
  """Information of the computer system on WindowsDevice.

  The properties of this class is retrieved from the "Win32_ComputerSystem" CIM
  class which represents the target Windows computer.

  Attributes:
    name: Name of the computer.
    manufacturer: Name of the computer manufacturer.
    model: Product name that a manufacturer gives to the computer.
    system_family: The family to which this computer belongs.
    system_type: System running on the Windows-based computer.
    domain: Name of the domain to which the computer belongs.
    total_physical_memory: Total physical memory, in GBytes.
    user_name: Name of a user that is logged on currently.
  """

  name: str
  manufacturer: str | None
  model: str | None
  system_family: str | None
  system_type: str | None
  domain: str | None
  total_physical_memory: float | None
  user_name: str | None

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> ComputerSystemInfo | None:
    """Collects information of system from a remote device."""
    build_info = _collect_build_info(
        ssh, 'Win32_ComputerSystem', ComputerSystemInfo, log, ignore_error
    )
    if build_info is not None:
      build_info.total_physical_memory = b_to_gb(
          build_info.total_physical_memory
      )
    return build_info


@dataclasses.dataclass(frozen=True)
class OperatingSystemInfo:
  """Information of the operating system on WindowsDevice.

  The properties of this class is retrieved from the "Win32_OperatingSystem" CIM
  class which represents a Windows-based operating system installed on the
  target Windows computer.

  Attributes:
    caption: Short description of the operating system.
    version: Version number of the operating system.
    build_number: Build number of the operating system.
    build_type: Type of build used for the operating system.
    os_architecture: Architecture of the operating system.
    code_set: Code page value the operating system uses.
    registered_user: Name of the registered user of the operating system.
    service_pack_major_version: Major version number of the service pack
      installed on the computer system. If no service pack has been installed,
      the value is 0.
    service_pack_minor_version: Minor version number of the service pack
      installed on the computer system. If no service pack has been installed,
      the value is 0.
  """

  caption: str
  version: str | None
  build_number: str | None
  build_type: str | None
  os_architecture: str | None
  code_set: str | None
  registered_user: str | None
  service_pack_major_version: int | None
  service_pack_minor_version: int | None

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> OperatingSystemInfo | None:
    """Collects information of operating system from a remote device."""
    return _collect_build_info(
        ssh, 'Win32_OperatingSystem', OperatingSystemInfo, log, ignore_error
    )


@dataclasses.dataclass
class ProcessorInfo:
  """Information of the processor on WindowsDevice.

  The properties of this class is retrieved from the "Win32_Processor" CIM class
  which represents a processor running on the Windows computer.

  Attributes:
    device_id: Unique identifier of the processor on the system.
    name: Name of the processor.
    description: Description of the processor.
    manufacturer: Name of the processor manufacturer.
    max_clock_speed: Maximum frequency of the processor, in GHz.
    number_of_cores: Number of cores of the processor.
  """

  device_id: str
  name: str | None
  description: str | None
  manufacturer: str | None
  max_clock_speed: float | None
  number_of_cores: int | None

  def __post_init__(self):
    trim_re = r' (@|processor|apu|soc|radeon).*|\(.*?\)| cpu'
    if self.name is not None:
      self.name = re.sub(trim_re, '', self.name, flags=re.IGNORECASE)

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> list[ProcessorInfo] | None:
    """Collects information of processors from a remote device."""
    info_list = _collect_build_info_list(
        ssh, 'Win32_Processor', ProcessorInfo, log, ignore_error
    )
    if info_list is not None:
      for info in info_list:
        info.max_clock_speed = mhz_to_ghz(info.max_clock_speed)
    return info_list


@dataclasses.dataclass(frozen=True)
class BIOSInfo:
  """Information of the BIOS on WindowsDevice.

  The properties of this class is retrieved from the "Win32_BIOS" CIM class
  which represents the attributes of the computer system's basic input/output
  services (BIOS) that are installed on the Windows computer.

  Attributes:
    name: Name of the BIOS.
    version: Version of the BIOS, created by the BIOS manufacturer.
    manufacturer: Manufacturer of the BIOS.
    release_date: Release date of the Windows BIOS.
  """

  name: str
  version: str | None
  manufacturer: str | None
  release_date: datetime.date | None

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> BIOSInfo | None:
    """Collects information of BIOS from a remote device."""
    return _collect_build_info(ssh, 'Win32_BIOS', BIOSInfo, log, ignore_error)


@dataclasses.dataclass
class NetworkAdapterConfigurationInfo:
  """Information of the network adapter on WindowsDevice.

  The properties of this class is retrieved from the
  "Win32_NetworkAdapterConfiguration" CIM class which represents the attributes
  and behaviors of a network adapter on the Windows computer.

  Attributes:
    caption: Short description of the network adapter.
    ip_enabled: If TCP/IP is bound and enabled on this network adapter.
    mac_address: Media Access Control (MAC) address of the network adapter.
    ip_address: A list of all of the IP addresses associated with the current
      network adapter.
    ip_subnet: A list of all of the subnet masks associated with the current
      network adapter.
    default_ip_gateway: A list of IP addresses of default gateways that the
      computer system uses.
    service_name: Service name of the network adapter.
  """

  caption: str
  ip_enabled: bool
  mac_address: str | None
  ip_address: list[str] | None
  ip_subnet: list[str] | None
  default_ip_gateway: list[str] | None
  service_name: str | None

  def __post_init__(self):
    self.caption = re.sub(r'\[[0-9]*\] ', '', self.caption)

  @classmethod
  def collect_active(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> list[NetworkAdapterConfigurationInfo] | None:
    """Collects information of active network adapter from a remote device."""
    adapter_info_list = _collect_build_info_list(
        ssh,
        'Win32_NetworkAdapterConfiguration',
        NetworkAdapterConfigurationInfo,
        log,
        ignore_error,
    )
    if adapter_info_list is None:
      return None
    return [
        adapter_info
        for adapter_info in adapter_info_list
        if adapter_info.ip_enabled
    ]


@enum.unique
class DiskType(enum.Enum):
  """Drive type of logical disks."""
  UNKNOWN = 0
  NO_ROOT_DIRECTORY = 1
  REMOVABLE_DISK = 2
  LOCAL_DISK = 3
  NETWORK_DRIVE = 4
  COMPACT_DISC = 5
  RAM_DISK = 6


@dataclasses.dataclass
class LogicalDiskInfo:
  """Information of the logical disk on WindowsDevice.

  The properties of this class is retrieved from the "Win32_LogicalDisk" CIM
  class which represents a data source that resolves to an actual local storage
  device on the Windows computer.

  Attributes:
    device_id: Unique identifier of the logical disk.
    volume_name: Volume name of the logical disk.
    description: Description of the logical disk.
    drive_type: The type of disk drive of the logical disk.
    free_space: Free space of the logical disk, in GBytes.
    size: Total size of the logical disk, in GBytes.
  """

  device_id: str
  volume_name: str | None
  description: str | None
  drive_type: DiskType | None
  free_space: float | None
  size: float | None

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> list[LogicalDiskInfo] | None:
    """Collects information of logic disks from a remote device."""
    info_list = _collect_build_info_list(
        ssh, 'Win32_LogicalDisk', LogicalDiskInfo, log, ignore_error
    )
    if info_list is None:
      return None
    for info in info_list:
      info.free_space = b_to_gb(info.free_space)
      info.size = b_to_gb(info.size)
    return info_list


@enum.unique
class DeviceAvailability(enum.Enum):
  """Availability and status of the device."""
  OTHER = 1
  UNKNOWN = 2
  # Running or Full Power
  RUNNING_FULL_POWER = 3
  WARNING = 4
  IN_TEST = 5
  NOT_APPLICABLE = 6
  POWER_OFF = 7
  OFF_LINE = 8
  OFF_DUTY = 9
  DEGRADED = 10
  NOT_INSTALLED = 11
  INSTALL_ERROR = 12
  # The device is known to be in a power save mode, but its exact status is
  # unknown.
  POWER_SAVE_UNKNOWN = 13
  # The device is in a power save state but still functioning, and may exhibit
  # degraded performance.
  POWER_SAVE_LOW_POWER_MODE = 14
  # The device is not functioning, but could be brought to full power quickly.
  POWER_SAVE_STANDBY = 15
  POWER_CYCLE = 16
  # The device is in a warning state, though also in a power save mode.
  POWER_SAVE_WARNING = 17
  PAUSED = 18
  NOT_READY = 19
  NOT_CONFIGURED = 20
  # The device is quiet.
  QUIESCED = 21


@dataclasses.dataclass(frozen=True)
class DesktopMonitorInfo:
  """Information of the desktop monitor on WindowsDevice.

  The properties of this class is retrieved from the "Win32_DesktopMonitor" CIM
  class which represents the type of monitor or display device attached to the
  Windows computer.

  Attributes:
    name: Name of the monitor.
    availability: Availability and status of the monitor.
    device_id: Unique identifier of the desktop monitor.
    screen_height: Logical height of the display in screen coordinates.
    screen_width: Logical width of the display in screen coordinates.
  """

  device_id: str
  name: str | None
  availability: DeviceAvailability | None
  screen_height: int | None
  screen_width: int | None

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> list[DesktopMonitorInfo] | None:
    """Collects information of monitors from a remote device."""
    return _collect_build_info_list(
        ssh, 'Win32_DesktopMonitor', DesktopMonitorInfo, log, ignore_error
    )


@dataclasses.dataclass
class PnPEntityInfo:
  """Information of the Plug and Play (PnP) devices on WindowsDevice.

  PnP devices includes Bluetooth devices, USB devices, MEDIA devices, etc.

  The properties of this class is retrieved from the "Win32_PnPEntity" CIM
  class which represents the attributes and behaviors of a PnP device on the
  Windows computer.

  Attributes:
    device_id: Unique identifier of the Plug and Play device.
    pnp_class: The name of the type of the Plug and Play device.
    name: Name of the Plug and Play device.
    manufacturer: Name of the manufacturer of the Plug and Play device.
    service: Name of the service that supports the Plug and Play device.
  """

  device_id: str
  pnp_class: str | None
  name: str | None
  manufacturer: str | None
  service: str | None

  @classmethod
  def collect(
      cls,
      pnp_class: str,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> list[PnPEntityInfo] | None:
    """Collects information of PnP device of given type from a remote device."""
    pnp_info_list = _collect_build_info_list(
        ssh,
        'Win32_PnPEntity',
        PnPEntityInfo,
        log,
        ignore_error,
    )
    if pnp_info_list is None:
      return None
    return [
        pnp_info
        for pnp_info in pnp_info_list
        if pnp_info.pnp_class == pnp_class
    ]


@dataclasses.dataclass(frozen=True)
class TimeLocaleInfo:
  """Information of the time zone and locale on WindowsDevice.

  Attributes:
    system_locale: The default language to use for non-Unicode programs.
    input_locale: The input language and keyboard layout for a Windows
      installation.
    time_zone: The time zone of the computer.
  """

  system_locale: str
  input_locale: str
  time_zone: str

  @classmethod
  def collect(
      cls,
      ssh: ssh_lib.SSHProxy,
      log: mobly_logger.PrefixLoggerAdapter,
      ignore_error: bool = False,
  ) -> TimeLocaleInfo | None:
    """Collects information of time and locale from a remote device.

    Args:
      ssh: The ssh connection to the Windows device.
      log: A logger specific to the Windows device.
      ignore_error: Whether to ignore the error when failed to collect build
        info.

    Returns:
      TimeLocaleInfo information dataclass. None if failed to collect
      information but the error is ignored.

    Raises:
      errors.BuildInfoError: An error occurred when collecting time and locale
        information and the error is not ignored.
    """
    try:
      sys_info = ssh.execute_ps_command('systeminfo')
      sys_property = lambda key: _get_systeminfo_property(sys_info, key)

      return TimeLocaleInfo(
          system_locale=sys_property('System Locale'),
          input_locale=sys_property('Input Locale'),
          time_zone=sys_property('Time Zone'),
      )
    except Exception as err:
      if ignore_error:
        log.exception(
            'An error occurred but ignored when collecting `%r`.', cls
        )
        return None
      raise errors.BuildInfoError(
          f'Failed to create `{cls}` instance.'
      ) from err


def _get_systeminfo_property(sys_info: str, key: str) -> str:
  match = re.search(rf'{key}:(.*)', sys_info)
  return match.group(1).strip() if match else ''


def _collect_build_info(
    ssh: ssh_lib.SSHProxy,
    cim_class_name: str,
    data_class: type[T],
    log: mobly_logger.PrefixLoggerAdapter,
    ignore_error: bool = False,
) -> T | None:
  """Collects CIM class information from a remote device.

  Args:
    ssh: The ssh connection to the Windows device.
    cim_class_name: The name of the CIM class to be collected.
    data_class: The data class to parse the CIM result into.
    log: A logger specific to the Windows device.
    ignore_error: Whether to ignore the error when failed to collect build info.

  Returns:
    A data class object of the CIM class instance. None if failed to collect
    build information but the error is ignored.

  Raises:
    errors.CimInstanceError: An error occurred when collecting CIM instance from
      the device, or the CIM result is a list, and the error is not ignored.
    errors.BuildInfoError: An error occurred when converting CIM instance into
      data class, and the error is not ignored.
  """
  try:
    cim_instance = _get_cim_instances(ssh, cim_class_name)
    if isinstance(cim_instance, list):
      raise errors.CimInstanceError(
          f'Expecting a single instance of CIM class: {cim_class_name},'
          ' but device returns a list.')
    return _dataclass_from_dict(data_class, _camel_dict_to_snake(cim_instance))

  except errors.BuildInfoBaseError:
    if ignore_error:
      log.exception(
          'An error occurred but ignored when collecting `%r`.', data_class
      )
      return None
    raise


def _collect_build_info_list(
    ssh: ssh_lib.SSHProxy,
    cim_class_name: str,
    data_class: type[T],
    log: mobly_logger.PrefixLoggerAdapter,
    ignore_error: bool = False,
) -> list[T] | None:
  """Collects a list of CIM class information from a remote device.

  Args:
    ssh: The ssh connection to the Windows device.
    cim_class_name: The name of the CIM class to be collected.
    data_class: The data class to parse the CIM result into.
    log: A logger specific to the Windows device.
    ignore_error: Whether to ignore the error when failed to collect build info.

  Returns:
    A list of data class objects of the CIM class instance. None if failed to
    collect build information list but the error is ignored.

  Raises:
    errors.CimInstanceError: An error occurred when collecting CIM instance from
      the device, and the error is not ignored.
    errors.BuildInfoError: An error occurred when converting CIM instance into
      data class, and the error is not ignored.
  """
  try:
    cim_instances = _get_cim_instances(ssh, cim_class_name)

    build = lambda x: _dataclass_from_dict(data_class, _camel_dict_to_snake(x))

    if not isinstance(cim_instances, list):
      return [build(cim_instances)]
    return [build(item) for item in cim_instances]

  except errors.BuildInfoBaseError:
    if ignore_error:
      log.exception(
          'An error occurred but ignored when collecting `%r`.', data_class
      )
      return None
    raise


def _get_cim_instances(
    ssh: ssh_lib.SSHProxy,
    class_name: str) -> list[dict[str, Any]] | dict[str, Any]:
  """Collects information of a CIM class from a remote device.

  Args:
    ssh: The ssh connection to the Windows device.
    class_name: The name of the CIM class to be collected.

  Returns:
    A list of property dicts, or a single dict of the CIM class instances.

  Raises:
    errors.CimInstanceError: CIM instance query encounters an error.
  """
  cmd = f'Get-CimInstance {class_name} | ConvertTo-Json -Compress'
  try:
    result = ssh.execute_ps_command(cmd)
    return json.loads(result)
  except Exception as err:
    raise errors.CimInstanceError(
        f'Failed to collect CIM instance of class: {class_name}') from err


def _dataclass_from_dict(data_class: type[T], data: dict[str, Any]) -> T:
  """Creates a build info dataclass instance from a dictionary.

  Args:
    data_class: Data class type of the instance.
    data: A dictionary of input data.

  Returns:
    An instance of a data class representing build info.

  Raises:
    errors.BuildInfoError: Invalid build info is given.
  """
  try:
    return dacite.from_dict(
        data_class=data_class,
        data=data,
        config=dacite.Config(
            cast=[enum.Enum], type_hooks={datetime.date: _parse_date}))
  except Exception as err:
    raise errors.BuildInfoError(
        f'Failed to create {data_class} instance from dict') from err


def _parse_date(win_date_str: str) -> datetime.date:
  """Converts the timestamp string to datetime.date."""
  match = re.search(_TIMESTAMP_REGEX, win_date_str)
  timestamp = int(match[1]) if match else 0
  return datetime.date.fromtimestamp(timestamp // 1000)


def _camel_dict_to_snake(camel_dict: Mapping[str, Any]) -> dict[str, Any]:
  """Converts the keys of the dict from CamelCase to snake_case."""
  return dict([(_camel_to_snake_case(k), v) for k, v in camel_dict.items()])


def _camel_to_snake_case(value: str) -> str:
  """Returns value converted from CamelCase to snake_case.

  Args:
    value: A string to be converted in CamelCase.

  Returns:
    The value string in snake_case.
  """
  # Add underscores before capital letters that are followed by lowercase
  # letters. This capital letter is a part of the lowercase letters that come
  # after it.
  value = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', value)

  # Remove double underscores in the text, if any.
  value = re.sub('__([A-Z])', r'_\1', value)

  # Add underscores before capital letters that are preceded by non-capital
  # letters. They are a part of the same word. Noticeably, this leaves
  # consecutive capital letters together as a word.
  value = re.sub('([a-z0-9])([A-Z])', r'\1_\2', value)
  return value.lower()


def b_to_gb(memory_size: float | None) -> float | None:
  """Convert memory to GBytes with 1 digit accuracy after the decimal point."""
  if memory_size is None:
    return None
  return round(memory_size / pow(1024, 3), 1)


def mhz_to_ghz(frequency: float | None) -> float | None:
  """Convert frequency to GHz with 1 digit accuracy after the decimal point."""
  if frequency is None:
    return None
  return round(frequency / 1000, 1)
