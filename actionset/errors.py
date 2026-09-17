"""Errors raised by the action-set projection."""


class UnknownActionError(Exception):
    """An action name outside the closed Agent action set was requested.

    Refuse-unknown (allow-list), not default-allow: the boundary is the set
    of *permitted* actions, so anything not in it fails closed.
    """

    code = "unknown_action"
