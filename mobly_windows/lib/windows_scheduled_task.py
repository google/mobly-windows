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

"""Proxy class for Windows scheduled tasks."""

import base64
import enum
import logging

from mobly_windows.lib import errors
from mobly_windows.lib import ssh as win_ssh


class WindowsScheduledTask:
  """Proxy class for Windows scheduled tasks.

  This class provides methods for interacting with a specified scheduled task
  on the Windows device. Windows scheduled tasks are all executed
  asynchronously, so this class just uses shell commands to launch a task,
  query the task state, and terminate the task. All methods are non-blocking
  calls.

  See the API doc of Windows scheduled task for more details:
  https://docs.microsoft.com/en-us/powershell/module/scheduledtasks/?view=windowsserver2022-ps
  """

  # The command to set the line width of the log, the grave accent character(`)
  # is the escape character in PowerShell
  SET_POWERSHELL_LINE_WIDTH_PARAM = (
      "`$PSDefaultParameterValues['out-file:width'] = 2000;")

  # The patterns for the commands used to interact with scheduled tasks on
  # the Windows device.
  START_TASK_CMD_PATTERN = 'Start-ScheduledTask -TaskName {task_name}'
  STOP_TASK_CMD_PATTERN = 'Stop-ScheduledTask -TaskName {task_name}'
  REGISTER_TASK_CMD_PATTERN = (
      'Register-ScheduledTask -TaskName {task_name} -User '
      '$((Get-CimInstance Win32_ComputerSystem).UserName) '
      '-RunLevel {privileges_level} '
      '-Force -Action $({action}) -Settings $({scheduled_task_settings_cmd})'
  )
  UNREGISTER_TASK_CMD_PATTERN = (
      'Unregister-ScheduledTask -TaskName {task_name} -Confirm:$false '
      '-ErrorAction SilentlyContinue')
  GET_TASK_STATE_CMD_PATTERN = '(Get-ScheduledTask -TaskName {task_name}).State'

  # Note that the `Argument` must be a double-quoted string, because in
  # PowerShell single-quoted strings are interpreted as string literals and thus
  # setting PowerShell parameters is not supported
  NEW_TASK_ACTION_CMD_PATTERN = (
      'New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument '
      '"-WindowStyle Hidden {command}"'
  )

  # The cmdlet to create a new scheduled task settings object. The Windows
  # Task Scheduler service uses it to determine how to run the task
  CREATE_TASK_SETTINGS_CMDLET = 'New-ScheduledTaskSettingsSet'
  # The list of task scheduling configuration
  TASK_SETTING_LIST = [
      '-AllowStartIfOnBatteries',
      '-DontStopIfGoingOnBatteries',
  ]

  class Status(enum.Enum):
    RUNNING = 1
    NOT_RUNNING = 2
    NON_EXISTENT = 3

  @enum.unique
  class PrivilegesLevel(enum.Enum):
    """The privileges level of running the scheduled task.

    Highest: Run with highest privileges (admin mode)
    Limited: Run with limited privileges (non-admin mode)

    See the parameters doc of Windows scheduled task for more details:
    https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask?source=recommendations&view=windowsserver2022-ps#-runlevel
    """

    HIGHEST = 'Highest'
    LIMITED = 'Limited'

  def __init__(
      self,
      task_name: str,
      ssh: win_ssh.SSHProxy,
      log: logging.LoggerAdapter,
      privileges_level: PrivilegesLevel = PrivilegesLevel.HIGHEST,
  ) -> None:
    """Initializes the instance of a specified Windows scheduled task.

    Args:
      task_name: The name of the scheduled task.
      ssh: The SSH connection to the Windows device.
      log: The logger to log debug information.
      privileges_level: The privileges level of running the task.
    """
    self.task_name = task_name
    self.log = log
    self.ssh = ssh
    self.privileges_level = privileges_level

  def register_and_start(self,
                         task_execution_cmd: str,
                         encode: bool = False,
                         force_register: bool = False) -> None:
    """Registers a scheduled task with the given command and starts it.

    Args:
      task_execution_cmd: The Powershell command to be run by this scheduled
        task. This command shouldn't contain any double quotation mark as it is
        used when constructing the task registration command.
      encode: If true, encode the task command to wrap up complex strings and
        execute command as "-EncodedCommand" argument in Powershell.
      force_register: If true, force stop and unregister existing task with the
        same name before registering a new task. Otherwise, an exception will be
        thrown if the task has been registered.

    Raises:
      errors.ScheduledTaskError: If the task has been registered and
        `force_register` is false.
    """
    if self._query_task_state() != WindowsScheduledTask.Status.NON_EXISTENT:
      if force_register:
        self.stop_and_unregister()
      else:
        raise errors.ScheduledTaskError(
            f'Failed to register Windows scheduled task {self.task_name} '
            'on Windows device because the task has been registered.'
        )

    if encode or '"' in task_execution_cmd:
      encoded_cmd = base64.b64encode(
          task_execution_cmd.encode('utf_16_le')
      ).decode('ascii')
      # `EncodedCommand` param has conflict with set line width command,
      # so disable setting line width.
      self._register(f'-EncodedCommand {encoded_cmd}', set_line_width=False)
    else:
      self._register(task_execution_cmd, set_line_width=True)

    self._start()
    self.log.debug(
        'Windows scheduled server task state: %s', self._query_task_state()
    )

  def _register(
      self, task_execution_cmd: str, set_line_width: bool = True
  ) -> None:
    """Registers a new Windows scheduled task with the specified command."""
    command_list = []
    if set_line_width:
      command_list.append(self.SET_POWERSHELL_LINE_WIDTH_PARAM)
    command_list.append(task_execution_cmd)
    new_action_cmd = self.NEW_TASK_ACTION_CMD_PATTERN.format(
        command=' '.join(command_list)
    )
    register_cmd = self.REGISTER_TASK_CMD_PATTERN.format(
        task_name=self.task_name,
        privileges_level=self.privileges_level.value,
        action=new_action_cmd,
        scheduled_task_settings_cmd=self._get_scheduled_task_settings_cmd(),
    )
    self.ssh.execute_ps_command(register_cmd)

  def _get_scheduled_task_settings_cmd(self) -> str:
    """Gets the command to specify the scheduled task settings."""
    return ' '.join([self.CREATE_TASK_SETTINGS_CMDLET] + self.TASK_SETTING_LIST)

  def _start(self) -> None:
    """Starts the Windows scheduled task on the Windows device."""
    self.ssh.execute_ps_command(
        self.START_TASK_CMD_PATTERN.format(task_name=self.task_name))

  def _query_task_state(self) -> Status:
    """Queries the state of the scheduled task on the Windows device."""
    cmd = self.GET_TASK_STATE_CMD_PATTERN.format(task_name=self.task_name)
    cmd_output = self.ssh.execute_ps_command(cmd).strip()

    if not cmd_output:
      return WindowsScheduledTask.Status.NON_EXISTENT

    if cmd_output == 'Running':
      return WindowsScheduledTask.Status.RUNNING

    return WindowsScheduledTask.Status.NOT_RUNNING

  def is_running(self) -> bool:
    """Returns whether the scheduled task is running on the Windows device."""
    return self._query_task_state() == WindowsScheduledTask.Status.RUNNING

  def stop_and_unregister(self) -> None:
    """Stops the scheduled task and unregisters it on the Windows device."""
    task_status = self._query_task_state()
    if task_status == WindowsScheduledTask.Status.NON_EXISTENT:
      return

    if task_status == WindowsScheduledTask.Status.RUNNING:
      self.ssh.execute_ps_command(
          self.STOP_TASK_CMD_PATTERN.format(task_name=self.task_name))

    self.ssh.execute_ps_command(
        self.UNREGISTER_TASK_CMD_PATTERN.format(task_name=self.task_name))
