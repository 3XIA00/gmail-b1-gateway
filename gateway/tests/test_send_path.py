"""Confirm + dispatch send-path tests (ASSEMBLY_PLAN step v, Option B).

Covers the two step-(v) pieces and their HTTP surface:

- `SealedTokenStore` — round-trips a token through keystore AEAD (ciphertext at
  rest, plaintext never in the record) and fails closed (tamper / missing DEK /
  no record) with no plaintext fallback.
- `ConfirmDispatcher` over the *real* `SendFSM` + `GmailSender` + a fake egress
  transport: propose -> relayed-human-confirm -> SENT, with a token-free /
  PII-free ledger and the token never reaching the Agent surface. INDETERMINATE
  -> OUTCOME_UNKNOWN with no second send (gate 8). Double-confirm can't fork a
  second send (idempotency).
- The `POST /proposal/{id}/confirm` route — served only when a dispatcher is
  mounted (the Option-B relaxation is opt-in); unknown id / wrong bearer stay
  uniform 404; the token never appears in a response.

Actuated variables:
  - the egress HTTP status -> the terminal proposal status (200 -> sent,
    5xx -> outcome_unknown).
  - re-issuing confirm on a settled proposal -> the send count does NOT
    increase (assert the fake transport was called exactly once).
  - mounting/omitting the dispatcher -> the confirm route exists / 404s.
"""

import base64
import json
import threading
import urllib.error
import urllib.request

import pytest

from actionset.switch import SwitchMode
from keystore.aead import AEADCipher
from keystore.errors import DecryptionError, KeyMaterialError, KeyUnavailableError
from keystore.providers import InMemoryKeyProvider
from sendfsm.fsm import SendFSM
from store.backend import InMemoryAppendLog, InMemoryKV
from store.errors import ProposalNotFoundError
from store.ledger import AuditLedger
from store.proposals import ProposalStore
from gateway.egress import EgressGuardedClient
from gateway.gmail_sender import GmailSender
from gateway.proposal_api import ProposalServer, ProposalService, mint_session_bearer
from gateway.send_path import ConfirmDispatcher, SealedTokenStore

_ACCESS = "ya29.SECRET-ACCESS-TOKEN"
_DEK = bytes(range(32))


def _params(**over):
    p = {
        "account_handle": "me@example.com",
        "to": ["alice@example.com"],
        "subject": "Hi",
        "body": {"format": "text", "content": "hello alice"},
    }
    p.update(over)
    return p


def _wire(send_status=200, send_body=b'{"id":"MID","threadId":"TID"}',
          blind_token=False):
    clock = {"t": 1000}
    ids = {"n": 0}

    def now():
        return clock["t"]

    def factory():
        ids["n"] += 1
        return "prop-%d" % ids["n"]

    proposals = ProposalStore(InMemoryKV())
    payloads = InMemoryKV()
    ledger = AuditLedger(InMemoryAppendLog())

    # Seal a token with a real DEK. The *reading* store may or may not have the
    # DEK when the sender opens it: blind_token=True drops the DEK to exercise
    # the missing-DEK-at-dispatch path (L3(a)) over the same ciphertext at rest.
    token_backend = InMemoryKV()
    SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), token_backend).store(
        access_token=_ACCESS, refresh_token="1//REFRESH")
    read_provider = (InMemoryKeyProvider.empty() if blind_token
                     else InMemoryKeyProvider(_DEK))
    tokstore = SealedTokenStore(AEADCipher(read_provider), token_backend)

    calls = []

    def transport(method, url, headers, body, *, timeout=30.0):
        calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        return send_status, send_body

    client = EgressGuardedClient({"gmail.googleapis.com"}, transport=transport)
    prop_service = ProposalService(
        proposals=proposals, payloads=payloads, now=now,
        ttl_seconds=3600, proposal_id_factory=factory)
    sender = GmailSender(
        client, payload_provider=prop_service.load_payload,
        token_provider=tokstore.access_token)
    fsm = SendFSM(proposals, ledger, sender, switch_mode=SwitchMode.CONFIRM_THEN_SEND)
    confirm = ConfirmDispatcher(fsm, now=now)

    return {
        "clock": clock, "prop_service": prop_service, "confirm": confirm,
        "ledger": ledger, "calls": calls, "tokstore": tokstore,
    }


# --- SealedTokenStore ------------------------------------------------------

def test_sealed_token_roundtrip_ciphertext_at_rest():
    backend = InMemoryKV()
    store = SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), backend)
    store.store(access_token=_ACCESS, refresh_token="1//REFRESH")
    assert store.access_token() == _ACCESS
    # what is at rest is ciphertext -- no plaintext token in the record
    at_rest = json.dumps(backend.get("sealed_token"))
    assert _ACCESS not in at_rest
    assert "1//REFRESH" not in at_rest
    assert backend.get("sealed_token")["write_origin"] == "authorize"


def test_sealed_token_write_provenance_tamper_fails_closed():
    backend = InMemoryKV()
    store = SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), backend)
    store.store(access_token=_ACCESS, issued_at=100)
    record = backend.get("sealed_token")
    record["write_origin"] = "refresh"
    backend.put("sealed_token", record)
    with pytest.raises(KeyMaterialError):
        store.access_token()


def test_sealed_token_tamper_fails_closed():
    backend = InMemoryKV()
    store = SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), backend)
    store.store(access_token=_ACCESS)
    rec = backend.get("sealed_token")
    ct = bytearray(base64.b64decode(rec["ciphertext"]))
    ct[0] ^= 0xFF
    rec["ciphertext"] = base64.b64encode(bytes(ct)).decode("ascii")
    backend.put("sealed_token", rec)
    with pytest.raises(DecryptionError):
        store.access_token()


def test_sealed_token_missing_record_fails_closed():
    store = SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), InMemoryKV())
    with pytest.raises(KeyUnavailableError):
        store.access_token()


def test_sealed_token_no_dek_fails_closed_no_plaintext():
    backend = InMemoryKV()
    SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), backend).store(access_token=_ACCESS)
    # a store with no DEK cannot open -> KeyUnavailableError, never plaintext
    blind = SealedTokenStore(AEADCipher(InMemoryKeyProvider.empty()), backend)
    with pytest.raises(KeyUnavailableError):
        blind.access_token()


# --- confirm + dispatch (service level) -----------------------------------

def test_confirm_dispatch_reaches_sent_token_and_pii_free_ledger():
    w = _wire()
    r = w["prop_service"].propose(_params())
    status = w["confirm"].confirm_and_dispatch(r["proposal_id"])
    assert status == "sent"
    assert len(w["calls"]) == 1
    # the sender DID present the bearer to Gmail...
    assert w["calls"][0]["headers"]["Authorization"] == "Bearer " + _ACCESS
    # ...but the token / recipient never reach the audit ledger
    dumped = json.dumps(w["ledger"].entries())
    assert _ACCESS not in dumped
    assert "alice@example.com" not in dumped
    assert "hello alice" not in dumped


def test_indeterminate_send_settles_unknown_no_second_send():
    w = _wire(send_status=503, send_body=b"upstream unavailable")
    r = w["prop_service"].propose(_params())
    assert w["confirm"].confirm_and_dispatch(r["proposal_id"]) == "outcome_unknown"
    assert len(w["calls"]) == 1
    # gate 8: no re-send of an indeterminate outcome
    with pytest.raises(Exception):
        w["confirm"].confirm_and_dispatch(r["proposal_id"])
    assert len(w["calls"]) == 1


def test_double_confirm_cannot_fork_a_second_send():
    w = _wire()
    r = w["prop_service"].propose(_params())
    assert w["confirm"].confirm_and_dispatch(r["proposal_id"]) == "sent"
    with pytest.raises(Exception):
        w["confirm"].confirm_and_dispatch(r["proposal_id"])
    assert len(w["calls"]) == 1


def test_confirm_unknown_proposal_fails_closed():
    w = _wire()
    with pytest.raises(ProposalNotFoundError):
        w["confirm"].confirm_and_dispatch("nope")
    assert len(w["calls"]) == 0


def test_missing_dek_at_dispatch_settles_unknown_no_second_send():
    # L3(a) end-to-end: the token is sealed, but the DEK is unavailable when the
    # sender opens it. access_token() raises KeyUnavailableError *inside* the
    # sender; fsm.dispatch's bare-except settles OUTCOME_UNKNOWN
    # (error_code "sender_raised") -- it never guesses SENT and never re-sends.
    w = _wire(blind_token=True)
    r = w["prop_service"].propose(_params())
    assert w["confirm"].confirm_and_dispatch(r["proposal_id"]) == "outcome_unknown"
    # the wire is never reached: the token fetch fails before the HTTP send.
    assert len(w["calls"]) == 0
    # audit boundary as emitted: send_attempted (pre-wire, fsync anchor) then the
    # terminal outcome_unknown -- no send_succeeded.
    events = [e["event_type"] for e in w["ledger"].entries()]
    assert events == ["proposal_confirmed", "send_attempted", "outcome_unknown"]
    # gate 8: a re-confirm on the settled-unknown proposal cannot fork a send.
    with pytest.raises(Exception):
        w["confirm"].confirm_and_dispatch(r["proposal_id"])
    assert len(w["calls"]) == 0


# --- HTTP confirm route ----------------------------------------------------

def _serve(with_confirm=True):
    w = _wire()
    bearer = mint_session_bearer()
    server = ProposalServer(
        w["prop_service"], bearer,
        confirm=w["confirm"] if with_confirm else None)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, bearer, w


def _req(server, method, path, *, bearer=None, body=None):
    url = "http://127.0.0.1:%d%s" % (server.port, path)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if bearer is not None:
        req.add_header("Authorization", "Bearer " + bearer)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def test_http_propose_confirm_sends_and_hides_token():
    server, bearer, w = _serve()
    try:
        s1, b1 = _req(server, "POST", "/proposal", bearer=bearer, body=_params())
        pid = b1["proposal_id"]
        s2, b2 = _req(server, "POST", "/proposal/%s/confirm" % pid, bearer=bearer)
        assert s2 == 200
        assert b2 == {"proposal_id": pid, "status": "sent"}
        assert _ACCESS not in json.dumps(b2)
        assert len(w["calls"]) == 1
    finally:
        server.shutdown()
        server.server_close()


def test_http_confirm_route_absent_when_not_mounted():
    server, bearer, w = _serve(with_confirm=False)
    try:
        s1, b1 = _req(server, "POST", "/proposal", bearer=bearer, body=_params())
        pid = b1["proposal_id"]
        s2, b2 = _req(server, "POST", "/proposal/%s/confirm" % pid, bearer=bearer)
        assert s2 == 404 and b2 == {"error": "not_found"}
        assert len(w["calls"]) == 0  # nothing dispatched
    finally:
        server.shutdown()
        server.server_close()


def test_http_confirm_unknown_id_and_bad_bearer_are_uniform_404():
    server, bearer, w = _serve()
    try:
        s1, b1 = _req(server, "POST", "/proposal/nope/confirm", bearer=bearer)
        s2, b2 = _req(server, "POST", "/proposal/nope/confirm", bearer="wrong")
        assert s1 == s2 == 404
        assert b1 == b2 == {"error": "not_found"}
    finally:
        server.shutdown()
        server.server_close()


def test_http_double_confirm_is_conflict_not_second_send():
    server, bearer, w = _serve()
    try:
        _, b1 = _req(server, "POST", "/proposal", bearer=bearer, body=_params())
        pid = b1["proposal_id"]
        s2, _ = _req(server, "POST", "/proposal/%s/confirm" % pid, bearer=bearer)
        s3, b3 = _req(server, "POST", "/proposal/%s/confirm" % pid, bearer=bearer)
        assert s2 == 200
        assert s3 == 409 and b3 == {"error": "conflict"}
        assert len(w["calls"]) == 1
    finally:
        server.shutdown()
        server.server_close()
