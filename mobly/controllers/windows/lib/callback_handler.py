"""The callback handler module for Windows Mobly Snippet Lib."""

from __future__ import annotations

from typing import Any

from mobly.snippet import callback_handler_base
from mobly.snippet import errors

# The timeout error message when pulling events from the Windows snippet server
TIMEOUT_ERROR_MESSAGE = 'EventSnippetException: timeout.'


class CallbackHandler(callback_handler_base.CallbackHandlerBase):
  """The callback handler class for Windows Mobly Snippet Lib."""

  def callEventWaitAndGetRpc(self,
                             callback_id: str,
                             event_name: str,
                             timeout_sec: float) -> dict[str, Any]:
    """Returns an existing event or wait for a new one within the time limit.

    This function calls snippet lib's eventWaitAndGet RPC.

    Args:
      callback_id: the callback identifier.
      event_name: the callback name.
      timeout_sec: the number of seconds to wait for the event.

    Returns:
      The event dictionary.

    Raises:
      errors.CallbackHandlerTimeoutError: The expected event does not occur
        within the time limit.
    """
    timeout_ms = int(timeout_sec * 1000)
    try:
      return self._event_client.eventWaitAndGet(callback_id, event_name,
                                                timeout_ms)
    except Exception as e:
      if TIMEOUT_ERROR_MESSAGE in str(e):
        raise errors.CallbackHandlerTimeoutError(
            self._device, (f'Timed out after waiting {timeout_sec}s for event '
                           f'"{event_name}" triggered by {self._method_name} '
                           f'({self.callback_id}).')) from e
      raise

  def callEventGetAllRpc(
      self, callback_id: str, event_name: str) -> list[dict[str, Any]]:
    """Gets all existing events for the specified identifier without waiting.

    This function calls snippet lib's eventGetAll RPC.

    Args:
      callback_id: the callback identifier.
      event_name: the callback name.

    Returns:
      A list of event dictionaries.
    """
    return self._event_client.eventGetAll(callback_id, event_name)
