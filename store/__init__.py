"""Gateway local persistence: proposals, idempotency, and the audit ledger.

Public API:
  - Proposal / ProposalStatus / ProposalStore  -- proposal lifecycle records.
  - AuditEvent / AuditEventType / AuditLedger   -- PII/token-free audit trail.
  - backends: InMemoryKV, InMemoryAppendLog + the KVBackend / AppendLog seams.
  - errors: ProposalNotFoundError, ProposalExpiredError,
    DuplicateIdempotencyError, ProposalStateError, AuditSchemaError.
"""

from __future__ import annotations

from .backend import (
    AppendLog,
    InMemoryAppendLog,
    InMemoryKV,
    KVBackend,
)
from .errors import (
    AuditSchemaError,
    DuplicateIdempotencyError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalStateError,
)
from .ledger import AuditEvent, AuditEventType, AuditLedger
from .proposals import Proposal, ProposalStatus, ProposalStore

__all__ = [
    "Proposal",
    "ProposalStatus",
    "ProposalStore",
    "AuditEvent",
    "AuditEventType",
    "AuditLedger",
    "KVBackend",
    "AppendLog",
    "InMemoryKV",
    "InMemoryAppendLog",
    "ProposalNotFoundError",
    "ProposalExpiredError",
    "DuplicateIdempotencyError",
    "ProposalStateError",
    "AuditSchemaError",
]
