"""Proposal persistence + idempotency.

A *proposal* is the record produced by the Agent-facing `PrepareEmail` action
(see the actionset module): it carries the payload digest and an expiry, never
the email content or any token. This module persists proposals, enforces
one-live-proposal-per-idempotency-key, and answers "is this proposal still
live?" against an injected clock.

State *transitions* are owned by the send FSM (a later module); this store only
persists whatever status the FSM writes and refuses structurally invalid
records. Keeping transition rules out of here avoids two modules disagreeing on
the FSM.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, replace
from typing import Optional

from .backend import KVBackend
from .errors import (
    DuplicateIdempotencyError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalStateError,
)


class ProposalStatus(enum.Enum):
    PENDING = "pending"                 # created, awaiting confirm / auto-send
    CONFIRMED = "confirmed"             # approved, not yet dispatched
    SENT = "sent"                       # provider accepted
    FAILED = "failed"                   # terminal failure
    OUTCOME_UNKNOWN = "outcome_unknown"  # dispatched, result indeterminate


# A proposal that has reached one of these is settled: it no longer expires and
# its idempotency key stays claimed (so a retry cannot fork a second send).
_TERMINAL = frozenset({ProposalStatus.SENT, ProposalStatus.FAILED,
                       ProposalStatus.OUTCOME_UNKNOWN})


@dataclass(frozen=True)
class Proposal:
    proposal_id: str
    payload_digest: str
    expires_at: int
    created_at: int
    status: ProposalStatus = ProposalStatus.PENDING
    idempotency_key: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "proposal_id": self.proposal_id,
            "payload_digest": self.payload_digest,
            "expires_at": self.expires_at,
            "created_at": self.created_at,
            "status": self.status.value,
            "idempotency_key": self.idempotency_key,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Proposal:
        try:
            return cls(
                proposal_id=d["proposal_id"],
                payload_digest=d["payload_digest"],
                expires_at=d["expires_at"],
                created_at=d["created_at"],
                status=ProposalStatus(d["status"]),
                idempotency_key=d.get("idempotency_key"),
            )
        except (KeyError, ValueError) as exc:
            raise ProposalStateError("malformed proposal record: %s" % (exc,)) from exc


def _validate_ts(name: str, value) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProposalStateError("%s must be a non-negative int" % name)
    return value


class ProposalStore:
    def __init__(self, backend: KVBackend):
        self._backend = backend

    def _idem_index_key(self, idempotency_key: str) -> str:
        return "idem:" + idempotency_key

    def create(self, proposal: Proposal) -> Proposal:
        _validate_ts("expires_at", proposal.expires_at)
        _validate_ts("created_at", proposal.created_at)
        if proposal.expires_at <= proposal.created_at:
            raise ProposalStateError("expires_at must be after created_at")
        if self._backend.get(proposal.proposal_id) is not None:
            raise ProposalStateError("proposal_id already exists")
        if proposal.idempotency_key is not None:
            idx = self._idem_index_key(proposal.idempotency_key)
            if self._backend.get(idx) is not None:
                raise DuplicateIdempotencyError(
                    "idempotency key already has a proposal")
            # Claim the key up front so a concurrent duplicate cannot slip in
            # between this check and the write.
            self._backend.put(idx, {"proposal_id": proposal.proposal_id})
        self._backend.put(proposal.proposal_id, proposal.to_dict())
        return proposal

    def get(self, proposal_id: str) -> Proposal:
        raw = self._backend.get(proposal_id)
        if raw is None:
            raise ProposalNotFoundError(proposal_id)
        return Proposal.from_dict(raw)

    def find_by_idempotency(self, idempotency_key: str) -> Optional[Proposal]:
        idx = self._backend.get(self._idem_index_key(idempotency_key))
        if idx is None:
            return None
        return self.get(idx["proposal_id"])

    def is_live(self, proposal: Proposal, *, now: int) -> bool:
        """Live = not settled and not past expiry. Terminal states never expire."""
        _validate_ts("now", now)
        if proposal.status in _TERMINAL:
            return True
        return now < proposal.expires_at

    def get_live(self, proposal_id: str, *, now: int) -> Proposal:
        """Fetch a proposal, refusing a pending one that has expired."""
        p = self.get(proposal_id)
        if not self.is_live(p, now=now):
            raise ProposalExpiredError(proposal_id)
        return p

    def set_status(self, proposal_id: str, status: ProposalStatus) -> Proposal:
        p = self.get(proposal_id)
        updated = replace(p, status=status)
        self._backend.put(proposal_id, updated.to_dict())
        return updated
