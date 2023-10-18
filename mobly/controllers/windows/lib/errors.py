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

"""Module for errors thrown from google3.testing.mobly.platform.windows."""

from typing import Any

from mobly import signals

# This module is only used for type annotation. Instead of directly importing
# it, we use typing variables here to avoid potential circular dependencies.
# lib.ssh module under windows package
lib_ssh_module = Any


# Errors for device_config module
class DeviceConfigBaseError(Exception):
  """Base error class for mobly.platform.windows.device_config module."""


class ConfigError(DeviceConfigBaseError):
  """Raised for errors specific to invalid controller configs."""


# Errors for windows_device module
class Error(signals.ControllerError):
  """Raised for errors related to the Windows controller module."""


class SnippetLoadError(Error):
  """Raised for errors related to Mobly snippet load."""


# Errors for lib.ssh module
class SshBaseError(Exception):
  """Base error class for mobly.platform.windows.lib.ssh module."""

  def __init__(self, ssh: 'lib_ssh_module.SSHProxy', message: str) -> None:
    super().__init__(f'{repr(ssh)} {message}')


class ExecuteCommandError(SshBaseError):
  """Raised when a SSH command encounters an error."""

  _COMMAND_EXCEPTION_TEMPLATE = """
  Call exited with non-zero return code of "{status_code:d}".
  ****************************Call***************************
  {command}
  ****************************Stdout*************************
  {stdout}
  ****************************Stderr*************************
  {stderr}
  **********************End of error message*****************
  """

  def __init__(self, ssh: 'lib_ssh_module.SSHProxy', command: str,
               command_results: 'lib_ssh_module.CommandResults') -> None:
    message = self._COMMAND_EXCEPTION_TEMPLATE.format(
        command=command,
        status_code=command_results.exit_code,
        stdout=command_results.stdout,
        stderr=command_results.stderr,
    )
    super().__init__(ssh, message)


class SshRemoteError(SshBaseError):
  """Raised when a SSH operation encounters an error."""


class RemoteProcessError(SshBaseError):
  """A SSH remote process encounters an error."""


class RemoteProcessTimeoutError(RemoteProcessError):
  """A remote process times out."""


class PortForwardingError(SshBaseError):
  """Raised when a port forwarding operation encounters an error."""


class DecodeError(Exception):
  """Raised when failed to decode Windows command line output."""


# Errors for build_info module
class BuildInfoBaseError(Exception):
  """Base error class for mobly.platform.windows.lib.build_info module."""


class CimInstanceError(BuildInfoBaseError):
  """Raised when a CIM instance query encounters an error."""


class BuildInfoError(BuildInfoBaseError):
  """Raised for errors specific to invalid build info."""


# Errors for Windows scheduled tasks
class ScheduledTaskError(Exception):
  """Raised for errors specific to Windows scheduled tasks."""

