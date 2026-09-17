"""The established action set and the confirm / auto-send switch (gate 7).

Gate 7: the confirm / auto-send switch has NO Agent-reachable write path.
It is modelled here as a value fixed at *establishment* of the action set:

  - ``ActionSet`` is a frozen dataclass, so ``switch_mode`` cannot be
    reassigned on an instance; and
  - ``project`` only ever dispatches actions in the closed catalog, none of
    which writes the switch.

Changing the mode therefore means an operator RE-ESTABLISHES the action set
(a new ``ActionSet`` instance) -- i.e. it "takes effect on the next
action-set establishment" (DESIGN sec 4), never through an Agent call.

The AUTO_SEND mode's own semantics (dispatch an approved proposal only when
the Agent is unreachable) are enforced downstream in the send FSM; this
module only carries the mode read-only.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Callable

from .catalog import AGENT_ACTIONS, PREPARE_EMAIL, require_agent_action
from .prepare import PrepareEmailResult, prepare_email


class SwitchMode(enum.Enum):
    CONFIRM_THEN_SEND = "confirm_then_send"
    AUTO_SEND_WHEN_AGENT_UNREACHABLE = "auto_send_when_agent_unreachable"


@dataclass(frozen=True)
class ActionSet:
    """An established Agent action-set projection (immutable)."""

    switch_mode: SwitchMode = SwitchMode.CONFIRM_THEN_SEND

    @property
    def actions(self) -> frozenset:
        """The closed set of action names this projection exposes."""
        return AGENT_ACTIONS

    def project(
        self,
        name: str,
        params,
        *,
        now: int,
        ttl_seconds: int,
        proposal_id_factory: Callable[[], str],
        message_id: str | None = None,
    ) -> PrepareEmailResult:
        """Dispatch a permitted Agent action; fail closed on anything else.

        ``message_id`` (§2.7) is a Gateway-minted value the caller injects; it is
        threaded through unchanged, never read from ``params``.
        """
        require_agent_action(name)  # closed set -> UnknownActionError
        # v1 has exactly one action. Dispatch it directly; no branch here
        # adds, wraps, or mutates any field or the switch.
        if name == PREPARE_EMAIL:
            return prepare_email(
                params,
                now=now,
                ttl_seconds=ttl_seconds,
                proposal_id_factory=proposal_id_factory,
                message_id=message_id,
            )
        # Unreachable while AGENT_ACTIONS == {PrepareEmail}; the guard above
        # already refused anything else. Kept as a fail-closed backstop so a
        # future catalog addition cannot silently fall through unimplemented.
        raise AssertionError("permitted action %r has no projection" % name)
