"""Append-only audit ledger with a closed, PII/token-free schema (DESIGN sec 7).

Chris code-time item (2): the audit schema must be structurally incapable of
holding a token, a full recipient address, a subject, or a body -- a "zero-hit"
guarantee. We get that by *construction*, not by scanning values for bad
content: `AuditEvent` is a fixed dataclass whose field set is a closed allow-list
of safe, non-identifying fields. There is no free-form dict, no `extra`, no
`detail` string, so there is nowhere to put PII/token even by mistake. This is
the property-not-enumeration form of the control (express the boundary; don't
chase a deny-list of bad values).

Anything content-derived that must be recorded is recorded as a **hash** (e.g.
`payload_digest`, `message_id_sha256`, `thread_id_sha256`) or a **host name**
(`egress_hosts`) -- both of which themselves survive the E7 leak scan.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass
from typing import List, Optional, Tuple

from .backend import AppendLog
from .errors import AuditSchemaError


class AuditEventType(enum.Enum):
    PROPOSAL_CREATED = "proposal_created"
    PROPOSAL_CONFIRMED = "proposal_confirmed"
    PROPOSAL_EXPIRED = "proposal_expired"
    SEND_ATTEMPTED = "send_attempted"
    SEND_SUCCEEDED = "send_succeeded"
    SEND_FAILED = "send_failed"
    OUTCOME_UNKNOWN = "outcome_unknown"


# The complete, closed set of fields an audit entry may carry. Every one is a
# hash, an id, a host, a code, a timestamp, or an enum -- none can carry a
# token, address, subject, or body. This tuple IS the schema contract; the test
# suite asserts AuditEvent's fields equal exactly this set.
_ALLOWED_FIELDS: Tuple[str, ...] = (
    "event_type",          # AuditEventType
    "at",                  # int epoch seconds (injected clock)
    "proposal_id",         # opaque id, not content
    "payload_digest",      # SHA-256 hex of the canonical payload
    "outcome",             # short status string, e.g. "accepted"
    "error_code",          # machine code, never a message body
    "message_id_sha256",   # hash of provider message id
    "thread_id_sha256",    # hash of provider thread id
    "egress_hosts",        # allow-listed host names contacted
)


@dataclass(frozen=True)
class AuditEvent:
    event_type: AuditEventType
    at: int
    proposal_id: str
    payload_digest: Optional[str] = None
    outcome: Optional[str] = None
    error_code: Optional[str] = None
    message_id_sha256: Optional[str] = None
    thread_id_sha256: Optional[str] = None
    egress_hosts: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        d["egress_hosts"] = list(self.egress_hosts)
        return d


def _assert_closed_schema() -> None:
    """Fail loudly if the dataclass ever drifts from the declared allow-list."""
    fields = tuple(AuditEvent.__dataclass_fields__.keys())
    if fields != _ALLOWED_FIELDS:
        raise AuditSchemaError(
            "AuditEvent fields %r drifted from the closed schema %r"
            % (fields, _ALLOWED_FIELDS))


class AuditLedger:
    def __init__(self, log: AppendLog):
        _assert_closed_schema()  # guard at construction; cheap, catches drift
        self._log = log

    def record(self, event: AuditEvent) -> None:
        if not isinstance(event, AuditEvent):
            # Only the typed event may be appended -- no raw dicts, so no path
            # exists to append an arbitrary (possibly PII-bearing) payload.
            raise AuditSchemaError("audit entries must be AuditEvent instances")
        if not isinstance(event.at, int) or isinstance(event.at, bool) or event.at < 0:
            raise AuditSchemaError("at must be a non-negative int")
        self._log.append(event.to_dict())

    def entries(self) -> List[dict]:
        return self._log.entries()
