"""OAuth ``state`` parameter — CSRF binding for the callback.

We mint a random, opaque ``state`` for each authorization request and require
the callback to echo it back exactly. This stops a forged callback (an
attacker-chosen code delivered to our loopback listener) from being accepted
as if it were the response to our own request. Comparison is constant-time so
the check itself leaks nothing about the expected value.
"""

from __future__ import annotations

import secrets

_STATE_ENTROPY_BYTES = 32


def generate_state() -> str:
    """A fresh, URL-safe, high-entropy state token."""
    return secrets.token_urlsafe(_STATE_ENTROPY_BYTES)


def state_matches(expected: str, received: str) -> bool:
    """Constant-time equality of the issued vs. returned state."""
    # Reject empties explicitly: an empty expected state must never match.
    if not expected or not received:
        return False
    return secrets.compare_digest(expected, received)
