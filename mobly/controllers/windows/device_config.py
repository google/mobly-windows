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

"""Controller configurations for the Windows controller module."""

from __future__ import annotations

from collections.abc import Sequence
import dataclasses
import json
import logging
from typing import Any

import dacite

from mobly.controllers.windows.lib import errors

_WINDOWS_DEVICE_EMPTY_CONFIG_MSG = 'Configuration is empty, abort!'
_WINDOWS_DEVICE_CONFIGS_NOT_LIST_MSG = (
    'Configurations should be a list of dicts, abort!')
_WINDOWS_DEVICE_CONFIG_NOT_DICT_MSG = (
    'Each configuration for a Windows device should be a dict, abort!')
_WINDOWS_CONFIG_MISSING_REQUIRED_KEY_MSG = 'Missing required key in config'
_WINDOWS_CONFIG_INVALID_VALUE_MSG = 'Invalid value in config'
_WINDOWS_CONFIG_WRONG_TYPE_MSG = 'Wrong type in config'

_DEFAULT_LOGS_DIRECTORY = 'C:\\temp\\MoblySnippet\\logs'

_DEFAULT_USER_ARTIFACTS_DIRECTORY = 'C:\\temp\\MoblySnippet\\UserArtifacts'

# Key for attribute in configs that alternate the controller module behavior.
# If this is False for a device, errors from that device will be ignored
# during `create`. Default is True.
_KEY_DEVICE_REQUIRED = 'required'


def from_dicts(configs: Sequence[dict[str, Any]]) -> list[DeviceConfig]:
  """Create WindowsDeviceConfig objects from a list of dict configs.

  Args:
    configs: A list of dicts each representing the configuration of one Windows
      device.

  Returns:
    A list of WindowsDeviceConfig.

  Raises:
    errors.ConfigError: Invalid controller config is given.
  """
  device_configs = []
  if not configs:
    raise errors.ConfigError(_WINDOWS_DEVICE_EMPTY_CONFIG_MSG)
  elif not isinstance(configs, list):
    raise errors.ConfigError(_WINDOWS_DEVICE_CONFIGS_NOT_LIST_MSG)

  for config in configs:
    if not isinstance(config, dict):
      raise errors.ConfigError(
          f'{_WINDOWS_DEVICE_CONFIG_NOT_DICT_MSG}: {config}')
    is_required = config.get(_KEY_DEVICE_REQUIRED, True)
    try:
      logging.debug('Parsing Windows device config: %s', config)
      device_config = DeviceConfig.from_dict(config)
    except errors.ConfigError as err:
      if is_required:
        raise err
      continue
    device_configs.append(device_config)

  return device_configs


@dataclasses.dataclass
class DeviceConfig:
  """Provides configs and default values for WindowsDevice."""

  # The Device ID string of the test machine.
  # It only changes if the user reset or install new Windows.
  # The Device ID can be queried from Windows registry:
  # reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient /v MachineId
  # Reference:
  # https://docs.microsoft.com/en-us/windows-hardware/drivers/install/device-ids
  # https://stackoverflow.com/questions/47603786/where-do-windows-product-id-and-device-id-values-come-from-are-they-useful
  device_id: str

  # The IP address or hostname which SSH connects to.
  # In a WFH scenario, it should be 'localhost' or '127.0.0.1'.
  hostname: str

  # The SSH port of the test machine.
  ssh_port: int = 22

  # Username to log the device in.
  username: str | None = None

  # Password to log the device in.
  password: str | None = None

  # Log directory that can be constomized.
  log_path: str = _DEFAULT_LOGS_DIRECTORY

  # The directory for saving users' artifacts
  user_artifacts_dir: str = _DEFAULT_USER_ARTIFACTS_DIRECTORY

  # The file path of the UI Deamon Server binary on the Windows device.
  # The binary should be installed on the Windows device during device setup.
  # If not specified, the ACUITI UI detector and screen recorder cannot be used
  # for this device.
  ui_daemon_server_binary_path: str | None = None

  # The frame rate to record the screen, in FPS (frames per second).
  # Default is 30 FPS.
  recording_fps: int = 30

  # Maximum data-segment/address-space of the video encoding process on the host
  # machine, in GiB.
  # Increase this value if FFmpeg fails due to hitting sandbox memory limit.
  # Default is 4 GiB.
  ffmpeg_max_size_gib: float = 4.0

  # Whether errors from current device will be ignored.
  required: bool = True

  # The field for user to pass custom configs of the Windows device. The custom
  # configs can then be used to filter devices in the test.
  #
  # Example:
  #   ```config.yaml
  #   WindowsDevice:
  #   - device_id: 'XXXX0000-XXXX-0000-XXXX-0000XXXX0000'
  #     hostname: '127.0.0.1'
  #     custom_configs:
  #       role: 'sender'
  #   ```
  # The above Windows device can be filtered by:
  #   wind = windows_device.get_devices(winds, role='sender')[0]
  #
  custom_configs: dict[str, Any] = dataclasses.field(default_factory=dict)

  @classmethod
  def from_dict(cls, config: dict[str, Any]) -> DeviceConfig:
    """Parses controller configs from Mobly runner to DeviceConfig.

    Args:
      config: A dictionary of string parameters.

    Returns:
      DeviceConfig data class.

    Raises:
      errors.ConfigError: Invalid controller config is given.
    """

    # Callable used in dacite.Config.type_hooks to transform the input data
    def _convert_to_dict_if_json(data: Any) -> Any:
      """Converts the input data to a dict if the it is valid JSON string."""
      if isinstance(data, str):
        try:
          return json.loads(data)
        except json.decoder.JSONDecodeError:
          pass
      return data

    type_converters = {
        # Convert the input data to int for data fields of int type.
        int: int,
        # Convert the input data to float for data fields of float type.
        float: float,
        # Convert JSON strings to dict.
        dict[str, Any]: _convert_to_dict_if_json,
    }
    try:
      device_config = dacite.from_dict(
          data_class=DeviceConfig,
          data=config,
          config=dacite.Config(type_hooks=type_converters))
    except dacite.exceptions.MissingValueError as err:
      raise errors.ConfigError(
          f'{_WINDOWS_CONFIG_MISSING_REQUIRED_KEY_MSG}: {config}') from err
    except dacite.exceptions.WrongTypeError as err:
      raise errors.ConfigError(
          f'{_WINDOWS_CONFIG_WRONG_TYPE_MSG}: {config}') from err
    except ValueError as err:
      raise errors.ConfigError(
          f'{_WINDOWS_CONFIG_INVALID_VALUE_MSG}: {config}') from err

    return device_config
