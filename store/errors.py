"""Store error types (proposals / idempotency / audit)."""

from __future__ import annotations


class ProposalNotFoundError(KeyError):
    code = "proposal_not_found"


class ProposalExpiredError(Exception):
    code = "proposal_expired"


class DuplicateIdempotencyError(Exception):
    """A second proposal reused a live idempotency key.

    The point of the idempotency key is that one logical send maps to one
    proposal; a duplicate must be refused rather than create a second send path.
    """

    code = "duplicate_idempotency_key"


class ProposalStateError(ValueError):
    code = "proposal_state_invalid"


class AuditSchemaError(ValueError):
    """An audit entry did not match the closed, PII/token-free schema."""

    code = "audit_schema_invalid"
