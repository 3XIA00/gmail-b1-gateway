"""The closed Agent action catalog (release gate 4, action level).

The catalog is an allow-list, not a deny-list: it expresses the boundary
(the set of *permitted* actions) so anything outside it fails closed. v1
exposes exactly one action -- building a proposal. There is deliberately:

  - NO send / dispatch action (confirm-then-send: an Agent builds a
    proposal and never dispatches it), and
  - NO switch-write action (gate 7: the confirm / auto-send switch has no
    Agent-reachable write path).

Widening the Agent's capability therefore means editing this frozen set,
which is a reviewable diff -- not a runtime parameter.
"""

from .errors import UnknownActionError

PREPARE_EMAIL = "PrepareEmail"

# The entire Agent-facing surface. Keep this a frozenset so it cannot be
# mutated at runtime.
AGENT_ACTIONS = frozenset({PREPARE_EMAIL})


def is_agent_action(name: str) -> bool:
    """True iff ``name`` is in the closed Agent action set."""
    return name in AGENT_ACTIONS


def require_agent_action(name: str) -> str:
    """Return ``name`` if permitted, else fail closed with UnknownActionError."""
    if name not in AGENT_ACTIONS:
        raise UnknownActionError(
            "%r is not in the closed Agent action set %s"
            % (name, sorted(AGENT_ACTIONS))
        )
    return name
