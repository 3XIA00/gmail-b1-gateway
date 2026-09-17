"""Internal authz decision audit -- closed, token-free schema (L5 §6).

Mirrors the send ledger's property-not-enumeration guarantee (store/ledger.py):
an authz audit entry is a frozen dataclass whose field set is a closed
allow-list. There is no free-form field, so it is structurally incapable of
holding a token, a recipient address, a subject, or a body.

This is the ONLY place the rich internal ``code`` + ``detail`` are retained.
The caller never sees them (existence-oracle rule); an operator reading this
log does.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from store.backend import AppendLog

# Closed schema contract; a future field must be a deliberate edit here.
# Every value is a non-secret opaque id, digest, enum, or boolean -- the schema
# remains structurally incapable of holding a token, address, subject, or body.
_ALLOWED_FIELDS: Tuple[str, ...] = (
    "at",                  # int epoch seconds (injected clock)
    "request_id",          # opaque request id, not content
    "grant_id",            # opaque grant id, not content (may be None if unparseable)
    "grant_id_verified",   # bool: was grant_id taken from an AUTHENTICATED decision
                           # (True) or peeked from unverified envelope bytes (False)?
    "subject_kind",        # "os_account" | "agent_key" | None
    "code",                # internal audit code: "authorized"/"needs_approval"/"denied_*"
    "detail",              # finer note, e.g. "missing_approval_mode"; None if absent
    "approval_mode",       # "auto" | "per_call" | None -- distinguishes auto-grant
                           # from a per-call outcome without reading the FSM ledger
    "decision_id",         # opaque id of the service decision this row references
    "state_version",       # canonical decimal version of the head the decision bound
    "authz_state_digest",  # digest of that verified head
    "action_digest",       # payload digest the decision authorized == FSM ledger join key
)


@dataclass(frozen=True)
class AuthzAuditEvent:
    at: int
    request_id: str
    code: str
    grant_id: Optional[str] = None
    grant_id_verified: bool = False
    subject_kind: Optional[str] = None
    detail: Optional[str] = None
    approval_mode: Optional[str] = None
    decision_id: Optional[str] = None
    state_version: Optional[str] = None
    authz_state_digest: Optional[str] = None
    action_digest: Optional[str] = None

    def to_dict(self) -> dict:
        # Derived from the closed allow-list, so to_dict() keys can never drift
        # from _ALLOWED_FIELDS silently (Boris's schema-integrity trap).
        return {name: getattr(self, name) for name in _ALLOWED_FIELDS}


def _assert_closed_schema() -> None:
    fields = frozenset(AuthzAuditEvent.__dataclass_fields__.keys())
    allowed = frozenset(_ALLOWED_FIELDS)
    if fields != allowed:
        raise AssertionError(
            "AuthzAuditEvent fields %r drifted from closed schema %r"
            % (sorted(fields), sorted(allowed)))
    # to_dict() must emit EXACTLY the allow-list -- the field-name check above
    # alone missed a hand-written to_dict() diverging from the dataclass.
    probe = AuthzAuditEvent(at=0, request_id="", code="").to_dict()
    if frozenset(probe) != allowed:
        raise AssertionError(
            "AuthzAuditEvent.to_dict() keys %r drifted from closed schema %r"
            % (sorted(probe), sorted(allowed)))


class AuthzAuditLog:
    def __init__(self, log: AppendLog):
        _assert_closed_schema()  # guard drift at construction
        self._log = log

    def record(self, *, at: int, request_id: str, code: str,
               grant_id: Optional[str] = None,
               grant_id_verified: bool = False,
               subject_kind: Optional[str] = None,
               detail: Optional[str] = None,
               approval_mode: Optional[str] = None,
               decision_id: Optional[str] = None,
               state_version: Optional[str] = None,
               authz_state_digest: Optional[str] = None,
               action_digest: Optional[str] = None) -> None:
        self._log.append(AuthzAuditEvent(
            at=at, request_id=request_id, code=code, grant_id=grant_id,
            grant_id_verified=grant_id_verified, subject_kind=subject_kind,
            detail=detail, approval_mode=approval_mode, decision_id=decision_id,
            state_version=state_version, authz_state_digest=authz_state_digest,
            action_digest=action_digest).to_dict())

    def entries(self) -> List[dict]:
        return self._log.entries()
