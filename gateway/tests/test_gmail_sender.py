"""Gmail sender tests (ASSEMBLY_PLAN step ii).

Actuated variables:
  - HTTP status / exception type -> SendResultKind + a coarse, sanitized code.
    2xx -> ACCEPTED, 4xx -> REJECTED (definitely not sent), 5xx/3xx/transport ->
    INDETERMINATE (true outcome unknown, no retry). The code is a pure function
    of status-or-type: never the response body / exception message (which could
    carry a recipient address, PII, or token -- §8 sanitization / M1).
  - the canonical payload -> the RFC 5322 bytes POSTed: deterministic and
    faithful (what was approved is what is sent -- gate 7b).
  - real-FSM integration: GmailSender plugged into the actual SendFSM drives a
    proposal to SENT / OUTCOME_UNKNOWN and the ledger stays token-free.
"""

import base64
import email
import email.policy
import hashlib
import json
import socket
from urllib.error import URLError

import pytest

from gateway.egress import EgressBlockedError, HttpResponse
from gateway.gmail_sender import (
    GMAIL_HOST,
    GMAIL_SEND_URL,
    GmailSender,
    build_raw_message,
)
from sendfsm.errors import NoAutoRetryError
from sendfsm.fsm import Actor, SendResultKind, SendFSM
from actionset.switch import SwitchMode
from store.backend import InMemoryAppendLog, InMemoryKV
from store.ledger import AuditLedger
from store.proposals import Proposal, ProposalStatus, ProposalStore


def _sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _canon(to=None, cc=None, bcc=None, subject="Hi", content="Hello",
           fmt="text", attachments=None):
    return {
        "account_handle": "me@example.com",
        "to": to or ["a@example.com"],
        "cc": cc or [],
        "bcc": bcc or [],
        "subject": subject,
        "body": {"format": fmt, "content": content},
        "attachments": attachments or [],
    }


class FakeClient:
    """Stands in for EgressGuardedClient: returns a canned response or raises."""

    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc
        self.calls = []

    def post(self, url, *, headers, body):
        self.calls.append((url, dict(headers), body))
        if self._exc is not None:
            raise self._exc
        return self._response


def _sender(client, canonical=None, token="tok"):
    return GmailSender(
        client,
        payload_provider=lambda pid: canonical if canonical is not None else _canon(),
        token_provider=lambda: token)


# --- happy path -----------------------------------------------------------

def test_accepted_maps_ids_and_records_egress():
    client = FakeClient(HttpResponse(200, b'{"id":"m1","threadId":"t1"}', GMAIL_HOST))
    r = _sender(client)("p1")
    assert r.kind is SendResultKind.ACCEPTED
    assert r.message_id_sha256 == _sha("m1")
    assert r.thread_id_sha256 == _sha("t1")
    assert r.egress_hosts == (GMAIL_HOST,)


def test_request_shape_url_bearer_and_raw_body():
    client = FakeClient(HttpResponse(200, b'{"id":"m","threadId":"t"}', GMAIL_HOST))
    _sender(client, _canon(subject="Hi", content="Hello"), token="tok123")("p1")
    url, headers, body = client.calls[0]
    assert url == GMAIL_SEND_URL
    assert headers["Authorization"] == "Bearer tok123"
    assert headers["Content-Type"] == "application/json"
    raw = base64.urlsafe_b64decode(json.loads(body)["raw"])
    assert b"Subject: Hi" in raw and b"To: a@example.com" in raw and b"Hello" in raw


def test_accepted_with_missing_ids_is_still_accepted():
    client = FakeClient(HttpResponse(200, b"{}", GMAIL_HOST))
    r = _sender(client)("p1")
    assert r.kind is SendResultKind.ACCEPTED
    assert r.message_id_sha256 is None and r.thread_id_sha256 is None


# --- failure classification (status / type only, sanitized) ---------------

@pytest.mark.parametrize("status,kind,code", [
    (400, SendResultKind.REJECTED, "rejected_400"),
    (401, SendResultKind.REJECTED, "rejected_401"),
    (403, SendResultKind.REJECTED, "rejected_403"),
    (429, SendResultKind.REJECTED, "rejected_429"),
    (500, SendResultKind.INDETERMINATE, "server_500"),
    (503, SendResultKind.INDETERMINATE, "server_503"),
    (302, SendResultKind.INDETERMINATE, "server_302"),  # unfollowed redirect
])
def test_status_classification(status, kind, code):
    client = FakeClient(HttpResponse(status, b'{"error":"x"}', GMAIL_HOST))
    r = _sender(client)("p1")
    assert r.kind is kind and r.error_code == code
    assert r.egress_hosts == (GMAIL_HOST,)


def test_error_code_never_leaks_body_token_or_recipient():
    client = FakeClient(HttpResponse(400, b'{"error":"invalid to secret@corp"}', GMAIL_HOST))
    r = _sender(client, _canon(to=["secret@corp"]), token="supertok")("p1")
    blob = "%r %s" % (r, r.error_code)
    assert "supertok" not in blob
    assert "secret@corp" not in blob
    assert "invalid" not in blob  # response body is dropped entirely


def test_timeout_is_indeterminate_not_transport():
    r = _sender(FakeClient(exc=socket.timeout()))("p1")
    assert r.kind is SendResultKind.INDETERMINATE
    assert r.error_code == "TIMEOUT" and r.egress_hosts == (GMAIL_HOST,)


def test_urlerror_is_transport_and_message_dropped():
    r = _sender(FakeClient(exc=URLError("boom at 10.0.0.1")))("p1")
    assert r.kind is SendResultKind.INDETERMINATE
    assert r.error_code == "TRANSPORT"  # fixed code, not the exception text
    assert "boom" not in r.error_code and "10.0.0.1" not in r.error_code


def test_generic_oserror_is_transport():
    r = _sender(FakeClient(exc=ConnectionRefusedError("refused")))("p1")
    assert r.kind is SendResultKind.INDETERMINATE and r.error_code == "TRANSPORT"


def test_egress_blocked_is_rejected_and_records_attempted_host():
    client = FakeClient(exc=EgressBlockedError("evil.example", "host_not_allowed"))
    r = _sender(client)("p1")
    assert r.kind is SendResultKind.REJECTED
    assert r.error_code == "egress_blocked"
    assert r.egress_hosts == ("evil.example",)  # positive zero-cloud-touch artifact


def test_policy_violation_blocks_before_any_network():
    client = FakeClient(HttpResponse(200, b"{}", GMAIL_HOST))
    r = _sender(client, _canon(attachments=[{"content_ref": "x"}]))("p1")
    assert r.kind is SendResultKind.REJECTED and r.error_code == "policy_blocked"
    assert client.calls == []  # never reached the wire


def test_non_text_body_is_policy_blocked():
    client = FakeClient(HttpResponse(200, b"{}", GMAIL_HOST))
    r = _sender(client, _canon(fmt="html"))("p1")
    assert r.kind is SendResultKind.REJECTED and r.error_code == "policy_blocked"
    assert client.calls == []


# --- MIME construction: deterministic + faithful (gate 7b) ----------------

def test_build_raw_message_is_deterministic_and_carries_all_fields():
    c = _canon(cc=["c@example.com"], bcc=["b@example.com"], content="héllo 😀")
    r1, r2 = build_raw_message(c), build_raw_message(c)
    assert r1 == r2  # pure function of payload -> no drift between show and send
    m = email.message_from_bytes(r1, policy=email.policy.default)
    assert m["To"] == "a@example.com"
    assert m["Cc"] == "c@example.com"
    assert m["Bcc"] == "b@example.com"
    assert m["Subject"] == "Hi"
    assert m.get_content().rstrip("\n") == "héllo 😀"


def test_what_is_posted_decodes_to_the_approved_body():
    client = FakeClient(HttpResponse(200, b'{"id":"m","threadId":"t"}', GMAIL_HOST))
    content = "Approve THIS exact text 😀"
    _sender(client, _canon(content=content))("p1")
    _, _, body = client.calls[0]
    raw = base64.urlsafe_b64decode(json.loads(body)["raw"])
    m = email.message_from_bytes(raw, policy=email.policy.default)
    assert m.get_content().rstrip("\n") == content


# --- §2.7 Message-ID: rendered verbatim from the frozen canonical ---------

_FROZEN_MID = "<kat-fixed-id-2p7@gateway.test>"


def test_build_raw_message_stamps_the_frozen_message_id():
    # The exact frozen value appears in the header -- not merely "some header".
    # This is the oracle 测试姬 205564 ① requires: it asserts the SPECIFIC ID
    # survived. Dropping the `msg["Message-ID"] = ...` render line makes
    # m["Message-ID"] None, so this goes red (the paired mutation).
    c = dict(_canon(), message_id=_FROZEN_MID)
    m = email.message_from_bytes(build_raw_message(c), policy=email.policy.default)
    assert m["Message-ID"] == _FROZEN_MID


def test_build_raw_message_message_id_is_deterministic():
    c = dict(_canon(content="héllo 😀"), message_id=_FROZEN_MID)
    assert build_raw_message(c) == build_raw_message(c)  # retry -> identical bytes


def test_build_raw_message_omits_header_when_no_frozen_id():
    # Positive control that the canonical field is what drives the header:
    # without it, no Message-ID is emitted (so the assertion above is not
    # vacuously true for every input).
    m = email.message_from_bytes(build_raw_message(_canon()),
                                 policy=email.policy.default)
    assert m["Message-ID"] is None


def test_posted_bytes_carry_the_exact_frozen_message_id():
    # End-to-end through the sender: the ID in the bytes actually POSTed equals
    # the ID frozen in the canonical (which is the digested/authorized value) --
    # "the digested bytes are the sent bytes" for the Message-ID.
    client = FakeClient(HttpResponse(200, b'{"id":"m","threadId":"t"}', GMAIL_HOST))
    canonical = dict(_canon(), message_id=_FROZEN_MID)
    _sender(client, canonical)("p1")
    _, _, body = client.calls[0]
    raw = base64.urlsafe_b64decode(json.loads(body)["raw"])
    m = email.message_from_bytes(raw, policy=email.policy.default)
    assert m["Message-ID"] == canonical["message_id"] == _FROZEN_MID


# --- real SendFSM integration ---------------------------------------------

def _fsm_with(sender):
    store = ProposalStore(InMemoryKV())
    ledger = AuditLedger(InMemoryAppendLog())
    fsm = SendFSM(store, ledger, sender, switch_mode=SwitchMode.CONFIRM_THEN_SEND)
    store.create(Proposal(
        proposal_id="p1", payload_digest="d" * 64, expires_at=1000,
        created_at=0, status=ProposalStatus.PENDING, idempotency_key=None))
    return store, ledger, fsm


def test_fsm_dispatch_reaches_sent_and_ledger_is_token_free():
    client = FakeClient(HttpResponse(200, b'{"id":"m1","threadId":"t1"}', GMAIL_HOST))
    sender = _sender(client, token="secret-access-token")
    store, ledger, fsm = _fsm_with(sender)

    fsm.confirm("p1", actor=Actor.HUMAN, now=10)
    assert fsm.dispatch("p1", now=20) is ProposalStatus.SENT

    entries = ledger.entries()
    succeeded = [e for e in entries if e["event_type"] == "send_succeeded"]
    assert succeeded and succeeded[0]["egress_hosts"] == ["gmail.googleapis.com"]
    assert succeeded[0]["message_id_sha256"] == _sha("m1")
    assert "secret-access-token" not in json.dumps(entries)  # token never audited


def test_fsm_server_error_settles_unknown_with_no_retry():
    client = FakeClient(HttpResponse(500, b'{"error":"oops"}', GMAIL_HOST))
    store, ledger, fsm = _fsm_with(_sender(client))

    fsm.confirm("p1", actor=Actor.HUMAN, now=10)
    assert fsm.dispatch("p1", now=20) is ProposalStatus.OUTCOME_UNKNOWN
    unknown = [e for e in ledger.entries() if e["event_type"] == "outcome_unknown"]
    assert unknown and unknown[0]["error_code"] == "server_500"
    # gate 8: an indeterminate outcome is terminal -- no auto-retry.
    with pytest.raises(NoAutoRetryError):
        fsm.dispatch("p1", now=21)
