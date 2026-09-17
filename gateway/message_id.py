"""RFC 5322 Message-ID generation for the send-idempotency record (§2.7).

A unique Message-ID is minted once per send attempt and persisted in the
pre-send record, so a lost receipt can be correlated to its send on replay
without re-sending. It is a *verification/correlation* aid only -- NOT a Gmail
dedup guarantee (Gmail may assign its own message id independently).

This wraps stdlib ``make_msgid`` for one load-bearing reason: its default domain
is ``socket.getfqdn()``, which would leak the user's machine hostname into an
outbound header / a persisted record. The domain is therefore *required* here
and is never inferred from the host.
"""

from __future__ import annotations

from email.utils import make_msgid


def generate_message_id(*, domain: str) -> str:
    """Return a unique RFC 5322 ``<id@domain>``. ``domain`` is mandatory."""
    if not domain:
        raise ValueError("domain is required (never fall back to the local FQDN)")
    return make_msgid(domain=domain)
