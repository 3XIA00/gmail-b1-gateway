"""PrepareEmail projection -> proposal result.

This is a PROJECTION over the accepted M2 canonicalizer, not an expansion
of it (Chris code-time (1)). The ONLY path from Agent input to email
content is ``build_canonical_payload``'s closed schema (gate 4); this
module adds no header dict, no ``extra_params``, and no pass-through slot.
Any field outside the schema fails closed inside the canonicalizer, so an
injected field cannot ride along here.

``now`` and the proposal id are INJECTED (not computed here) so the
projection is a pure function of its inputs -- both for determinism in
tests and so the clock/id source is the caller's single, auditable choice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from canonicalizer.jcs import digest as _jcs_digest
from canonicalizer.payload import build_canonical_payload, enforce_v1_send_policy


@dataclass(frozen=True)
class PrepareEmailResult:
    """What the Agent gets back from PrepareEmail: identifiers only, no
    content and no direct send handle (confirm-then-send)."""

    proposal_id: str
    payload_digest: str
    expires_at: int


def prepare_email(
    params,
    *,
    now: int,
    ttl_seconds: int,
    proposal_id_factory: Callable[[], str],
    message_id: str | None = None,
) -> PrepareEmailResult:
    """Project a PrepareEmail action into a proposal result.

    Raises PayloadSchemaError for any field outside the closed schema and
    AttachmentsNotSupportedError for a non-empty v1 attachment slot -- both
    before any proposal is durably created or Gmail is contacted.

    ``message_id`` (§2.7) is INJECTED like ``now`` and the proposal id -- the
    caller mints it once (Gateway-side) and passes the value, so the projection
    stays a pure function of its inputs. It is never read from ``params`` (an
    Agent cannot supply it; see build_canonical_payload). When present it enters
    the canonical, so the returned digest binds the exact ID that will be sent.
    """
    if not isinstance(now, int) or isinstance(now, bool) or now < 0:
        raise ValueError("now must be a non-negative integer epoch")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")

    canonical = build_canonical_payload(params, message_id=message_id)  # gate 4 base
    enforce_v1_send_policy(canonical)             # v1 text/attachment gate

    return PrepareEmailResult(
        proposal_id=proposal_id_factory(),
        # digest of the exact canonical just validated -- identical to
        # canonicalizer.payload.payload_digest(params, message_id=...) by
        # construction, so the projection cannot diverge from the accepted digest.
        payload_digest=_jcs_digest(canonical),
        expires_at=now + ttl_seconds,
    )
