"""Agent-facing action-set projection for the Gmail Gateway (v1).

This package is a *projection* over the accepted M2 canonicalizer
(``canonicalizer.payload``). It exposes the closed set of actions an Agent
may invoke and never widens the content schema. See README.md.
"""

from .catalog import AGENT_ACTIONS, PREPARE_EMAIL, is_agent_action, require_agent_action
from .errors import UnknownActionError
from .prepare import PrepareEmailResult, prepare_email
from .switch import ActionSet, SwitchMode

__all__ = [
    "AGENT_ACTIONS",
    "PREPARE_EMAIL",
    "is_agent_action",
    "require_agent_action",
    "UnknownActionError",
    "PrepareEmailResult",
    "prepare_email",
    "ActionSet",
    "SwitchMode",
]
