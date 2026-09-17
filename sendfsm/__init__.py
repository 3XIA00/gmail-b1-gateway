"""Send state machine: confirm-then-send / auto-send / outcome_unknown.

Public API:
  - SendFSM                       -- the state machine.
  - Actor                         -- HUMAN | AUTO_UNREACHABLE (no AGENT; gate 7).
  - SendResult / SendResultKind   -- what an injected sender returns.
  - errors: IllegalTransitionError, AutoSendNotEnabledError,
    AgentUnreachableRequiredError, NoAutoRetryError, AlreadySettledError.
"""

from __future__ import annotations

from .errors import (
    AgentUnreachableRequiredError,
    AlreadySettledError,
    AutoSendNotEnabledError,
    IllegalTransitionError,
    NoAutoRetryError,
)
from .fsm import Actor, SendFSM, SendResult, SendResultKind

__all__ = [
    "SendFSM",
    "Actor",
    "SendResult",
    "SendResultKind",
    "IllegalTransitionError",
    "AutoSendNotEnabledError",
    "AgentUnreachableRequiredError",
    "NoAutoRetryError",
    "AlreadySettledError",
]
