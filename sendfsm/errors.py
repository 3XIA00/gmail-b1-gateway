"""Send-FSM error types."""

from __future__ import annotations


class IllegalTransitionError(Exception):
    """A transition was requested from a state that does not allow it."""

    code = "illegal_transition"


class AutoSendNotEnabledError(Exception):
    """Auto-send was attempted while the switch is CONFIRM_THEN_SEND."""

    code = "auto_send_not_enabled"


class AgentUnreachableRequiredError(Exception):
    """Auto-send was attempted without a definitive 'agent unreachable' signal.

    Auto-send only fires when the Agent is *known* to be unreachable; an unknown
    or reachable state is not a licence to send without confirmation.
    """

    code = "agent_unreachable_required"


class NoAutoRetryError(Exception):
    """A dispatch was attempted on an OUTCOME_UNKNOWN proposal (gate 8).

    An indeterminate send is terminal: we do not know whether the provider
    accepted it, so retrying risks a duplicate send. v1 never auto-retries.
    """

    code = "no_auto_retry"


class AlreadySettledError(Exception):
    """A dispatch was attempted on a proposal already in a terminal state."""

    code = "already_settled"
