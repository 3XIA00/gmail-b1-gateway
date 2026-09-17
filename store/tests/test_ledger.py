"""Audit ledger tests.

The load-bearing test is `test_audit_schema_is_the_closed_allow_list`: it pins
AuditEvent's field set to the declared safe allow-list, so any future field that
could carry a token/address/subject/body fails the suite. The rest exercise
append-only recording and the typed-only append path.
"""

import pytest

from store.backend import InMemoryAppendLog
from store.errors import AuditSchemaError
from store.ledger import (
    AuditEvent,
    AuditEventType,
    AuditLedger,
    _ALLOWED_FIELDS,
)


def _ledger():
    return AuditLedger(InMemoryAppendLog())


def test_audit_schema_is_the_closed_allow_list():
    # If a field is ever added/removed, this must be a conscious edit here --
    # which is the review point where "does this field carry PII/token?" is asked.
    assert tuple(AuditEvent.__dataclass_fields__.keys()) == _ALLOWED_FIELDS


def test_no_free_form_field_exists():
    forbidden = {"extra", "detail", "details", "body", "content", "raw",
                 "token", "to", "recipient", "subject", "headers", "payload"}
    assert forbidden.isdisjoint(set(_ALLOWED_FIELDS))


def test_record_and_read_back():
    led = _ledger()
    led.record(AuditEvent(event_type=AuditEventType.PROPOSAL_CREATED,
                          at=100, proposal_id="p1", payload_digest="d" * 64))
    led.record(AuditEvent(event_type=AuditEventType.SEND_SUCCEEDED,
                          at=200, proposal_id="p1", outcome="accepted",
                          message_id_sha256="a" * 64, thread_id_sha256="b" * 64,
                          egress_hosts=("gmail.googleapis.com",)))
    entries = led.entries()
    assert [e["event_type"] for e in entries] == [
        "proposal_created", "send_succeeded"]
    assert entries[1]["egress_hosts"] == ["gmail.googleapis.com"]


def test_append_only_typed_path():
    led = _ledger()
    with pytest.raises(AuditSchemaError):
        led.record({"event_type": "send_succeeded", "token": "ya29.secret"})  # type: ignore[arg-type]


def test_bad_timestamp_rejected():
    led = _ledger()
    for bad in (-1, True, 1.5, "100"):
        with pytest.raises(AuditSchemaError):
            led.record(AuditEvent(event_type=AuditEventType.PROPOSAL_CREATED,
                                  at=bad, proposal_id="p1"))


def test_entries_are_copies():
    led = _ledger()
    led.record(AuditEvent(event_type=AuditEventType.PROPOSAL_CREATED,
                          at=100, proposal_id="p1"))
    got = led.entries()
    got[0]["proposal_id"] = "tampered"
    assert led.entries()[0]["proposal_id"] == "p1"


def test_event_dict_has_only_allowed_keys():
    ev = AuditEvent(event_type=AuditEventType.SEND_FAILED, at=1, proposal_id="p1",
                    error_code="rejected")
    assert set(ev.to_dict().keys()) == set(_ALLOWED_FIELDS)
