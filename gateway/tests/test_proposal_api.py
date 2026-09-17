"""Proposal endpoint tests (ASSEMBLY_PLAN step iv).

Two levels: `ProposalService` over in-memory backends (the propose/status
logic — closed schema, fail-closed, idempotency, audit-safe view, content
freeze), and `ProposalServer` over a real 127.0.0.1 loopback socket (the
boundary — bearer auth, served-set == closed-set, uniform 404 with no
route-existence oracle).

Actuated variables:
  - an out-of-schema field / a non-empty attachment slot -> the propose fails
    closed *before* any store write (assert nothing persisted).
  - the session bearer -> a wrong/absent bearer is indistinguishable from an
    unknown route (identical 404 + body).
  - the requested path/method -> only the two closed-set routes are served;
    every other path/method is the same uniform 404.
"""

import json
import threading
import urllib.error
import urllib.request

import pytest

from canonicalizer.payload import (
    AttachmentsNotSupportedError,
    PayloadSchemaError,
    build_canonical_payload,
    payload_digest,
)
from store.backend import InMemoryKV
from store.errors import DuplicateIdempotencyError, ProposalNotFoundError
from store.proposals import ProposalStore
from gateway.proposal_api import (
    MessageIdNotConfiguredError,
    ProposalServer,
    ProposalService,
    mint_session_bearer,
)


def _params(idem=None, **over):
    p = {
        "account_handle": "me@example.com",
        "to": ["alice@example.com"],
        "subject": "Hi",
        "body": {"format": "text", "content": "hello alice"},
    }
    if idem is not None:
        p["idempotency_key"] = idem
    p.update(over)
    return p


def _service(ttl=3600, start=1000):
    clock = {"t": start}
    ids = {"n": 0}

    def now():
        return clock["t"]

    def factory():
        ids["n"] += 1
        return "prop-%d" % ids["n"]

    payloads = InMemoryKV()
    svc = ProposalService(
        proposals=ProposalStore(InMemoryKV()), payloads=payloads,
        now=now, ttl_seconds=ttl, proposal_id_factory=factory)
    return svc, clock, payloads


# --- service: propose / status --------------------------------------------

def test_propose_creates_pending_and_freezes_content():
    svc, _, payloads = _service()
    r = svc.propose(_params())
    assert r["proposal_id"] == "prop-1"
    assert r["expires_at"] == 1000 + 3600
    assert r["payload_digest"] == payload_digest(_params())

    st = svc.get_status("prop-1")
    assert st["status"] == "pending"
    assert st["payload_digest"] == r["payload_digest"]
    # content frozen and digest-consistent
    assert svc.load_payload("prop-1") == build_canonical_payload(_params())
    assert len(list(payloads.values())) == 1


# --- §2.7 Message-ID: minted once, frozen, digest-binding, Gateway-only ----

def _service_mid(mid="<fixed-2p7@gateway.test>", ttl=3600, start=1000):
    """A service whose Message-ID factory is counted, to prove 'mint once'."""
    clock = {"t": start}
    ids = {"n": 0}
    mints = {"n": 0}

    def factory():
        ids["n"] += 1
        return "prop-%d" % ids["n"]

    def mid_factory():
        mints["n"] += 1
        return mid

    payloads = InMemoryKV()
    svc = ProposalService(
        proposals=ProposalStore(InMemoryKV()), payloads=payloads,
        now=lambda: clock["t"], ttl_seconds=ttl,
        proposal_id_factory=factory, message_id_factory=mid_factory)
    return svc, payloads, mints


def test_propose_mints_and_freezes_the_message_id():
    mid = "<fixed-2p7@gateway.test>"
    svc, payloads, mints = _service_mid(mid)
    r = svc.propose(_params())
    # The frozen canonical carries the exact minted ID...
    assert svc.load_payload("prop-1")["message_id"] == mid
    # ...and the digest returned to the Agent binds that same canonical.
    assert r["payload_digest"] == payload_digest(_params(), message_id=mid)
    assert mints["n"] == 1  # generated exactly once


def test_message_id_changes_the_authorized_digest():
    # The whole point of making it a canonical field: a different frozen ID is a
    # different digest, so a swapped ID no longer matches the cloud's authorized
    # action_digest (Jeff 205645: changing the frozen ID invalidates authz).
    svc_a, _, _ = _service_mid("<id-a@gateway.test>")
    svc_b, _, _ = _service_mid("<id-b@gateway.test>")
    da = svc_a.propose(_params())["payload_digest"]
    db = svc_b.propose(_params())["payload_digest"]
    assert da != db
    # ...and both differ from the no-Message-ID digest.
    assert da != payload_digest(_params())


def test_retry_reads_the_same_frozen_message_id():
    # A re-send reads the frozen record rather than re-minting: load_payload is
    # stable across reads and no second mint occurs.
    svc, _, mints = _service_mid("<once@gateway.test>")
    svc.propose(_params())
    first = svc.load_payload("prop-1")["message_id"]
    second = svc.load_payload("prop-1")["message_id"]
    assert first == second == "<once@gateway.test>"
    assert mints["n"] == 1


def test_agent_supplied_message_id_is_rejected():
    # An Agent that tries to set the ID itself hits the closed schema: message_id
    # is not in the input allow-list, so it fails closed (Gateway-minted only).
    svc, _, _ = _service_mid()
    with pytest.raises(PayloadSchemaError):
        svc.propose(_params(message_id="<forged@evil.test>"))


def test_no_factory_means_no_message_id():
    # Additive default: a service without a factory freezes a canonical with no
    # message_id (unchanged behavior for non-§2.7 / legacy golden-vector paths).
    svc, _, _ = _service()
    svc.propose(_params())
    assert "message_id" not in svc.load_payload("prop-1")


# --- §2.7 single-minter fail-closed: the PRODUCTION propose entry (Jeff 205708)
#
# Gateway is the sole Message-ID minter. A production sender (require_message_id)
# with no configured factory/domain must REFUSE at propose -- before any
# authorize (prepare_email) or persist -- never silently freeze/send an ID-less
# mail and never defer to a send-time fabricated ID. The oracle is the pair
# {refusal raised, nothing persisted}; a mutation that dropped the guard ("send
# when unconfigured") would freeze a proposal and go red on the second half.

def _service_require(mid_factory=None, start=1000):
    ids = {"n": 0}

    def factory():
        ids["n"] += 1
        return "prop-%d" % ids["n"]

    payloads = InMemoryKV()
    proposals = ProposalStore(InMemoryKV())
    svc = ProposalService(
        proposals=proposals, payloads=payloads,
        now=lambda: start, ttl_seconds=3600,
        proposal_id_factory=factory, message_id_factory=mid_factory,
        require_message_id=True)
    return svc, payloads


def test_production_propose_refuses_without_a_factory_and_persists_nothing():
    svc, payloads = _service_require(mid_factory=None)
    with pytest.raises(MessageIdNotConfiguredError):
        svc.propose(_params())
    assert list(payloads.values()) == []          # no content frozen ...
    with pytest.raises(ProposalNotFoundError):
        svc.get_status("prop-1")                    # ... and no proposal authorized


def test_production_propose_refuses_when_factory_yields_empty():
    # A configured-but-broken factory (empty id) is a broken deployment, not a
    # valid ID-less proposal: still refuse, still persist nothing.
    svc, payloads = _service_require(mid_factory=lambda: "")
    with pytest.raises(MessageIdNotConfiguredError):
        svc.propose(_params())
    assert list(payloads.values()) == []


def test_production_propose_succeeds_with_a_configured_factory():
    # Positive control: the guard must not bar a properly configured production
    # sender -- an "always refuse" impl would fail here. The frozen canonical
    # carries the minted ID and the digest binds it.
    mid = "<prod-2p7@gateway.test>"
    svc, payloads = _service_require(mid_factory=lambda: mid)
    r = svc.propose(_params())
    assert svc.load_payload("prop-1")["message_id"] == mid
    assert r["payload_digest"] == payload_digest(_params(), message_id=mid)


def test_message_id_not_configured_is_a_payload_schema_error():
    # It subclasses PayloadSchemaError so the HTTP surface maps it to the same
    # coarse `invalid_payload` as any closed-schema refusal (uniform rejection,
    # no new probe surface). Assert the subtype relationship the wire relies on.
    assert issubclass(MessageIdNotConfiguredError, PayloadSchemaError)


def test_status_is_audit_safe_no_pii():
    svc, _, _ = _service()
    svc.propose(_params(subject="SECRET-SUBJECT", to=["victim@corp.com"],
                        body={"format": "text", "content": "SECRET-BODY"}))
    st = svc.get_status("prop-1")
    blob = json.dumps(st)
    assert "SECRET-SUBJECT" not in blob
    assert "SECRET-BODY" not in blob
    assert "victim@corp.com" not in blob
    assert set(st) == {"proposal_id", "status", "payload_digest", "expires_at", "created_at"}


def test_unknown_field_fails_closed_no_write():
    svc, _, payloads = _service()
    with pytest.raises(PayloadSchemaError):
        svc.propose(_params(injected="x"))
    assert list(payloads.values()) == []          # content never frozen
    with pytest.raises(ProposalNotFoundError):
        svc.get_status("prop-1")                    # no proposal minted


def test_v1_attachment_rejected_before_write():
    svc, _, payloads = _service()
    p = _params()
    p["attachments"] = [{"name": "a.pdf", "media_type": "application/pdf",
                         "content_ref": "cid:1", "sha256": "0" * 64, "size": 10}]
    with pytest.raises(AttachmentsNotSupportedError):
        svc.propose(p)
    assert list(payloads.values()) == []


def test_bad_idempotency_key_type_rejected():
    svc, _, payloads = _service()
    p = _params()
    p["idempotency_key"] = 123
    with pytest.raises(PayloadSchemaError):
        svc.propose(p)
    assert list(payloads.values()) == []


def test_idempotent_replay_returns_original():
    svc, clock, payloads = _service()
    r1 = svc.propose(_params(idem="k1"))
    clock["t"] += 10
    # same key, different content -> the original wins, no second mint/freeze
    r2 = svc.propose(_params(idem="k1", subject="different"))
    assert r2["proposal_id"] == r1["proposal_id"] == "prop-1"
    assert r2["payload_digest"] == r1["payload_digest"]
    assert len(list(payloads.values())) == 1


def test_distinct_keys_make_distinct_proposals():
    svc, _, payloads = _service()
    a = svc.propose(_params(idem="a"))
    b = svc.propose(_params(idem="b"))
    assert a["proposal_id"] != b["proposal_id"]
    assert len(list(payloads.values())) == 2


# --- P1: server_bind must not do a reverse-DNS lookup ---------------------

def test_server_bind_never_calls_getfqdn(monkeypatch):
    # P1 counterfactual (NON-timing, interpreter-independent): the server_bind
    # override must never invoke socket.getfqdn -- on py3.14/macOS that reverse-DNS
    # lookup stalls ~35s past the 15s ready timeout, so the Gateway never comes up.
    # We replace getfqdn with a RAISING counter so a regression is a deterministic
    # failure here, not a 35s stall we'd have to time (which would be a false-green
    # on the faster 3.10/3.12 interpreters that don't reproduce the stall).
    import socket

    calls = {"n": 0}

    def _boom(*a, **k):
        calls["n"] += 1
        raise AssertionError("server_bind must not call socket.getfqdn (P1)")

    monkeypatch.setattr(socket, "getfqdn", _boom)

    svc, _, _ = _service()
    server = ProposalServer(svc, mint_session_bearer())  # must not stall / getfqdn
    try:
        assert calls["n"] == 0
        assert server.port > 0                # bound to a real ephemeral port
        assert server.server_name == "127.0.0.1"
    finally:
        server.server_close()


# --- HTTP boundary --------------------------------------------------------

def _server():
    svc, clock, payloads = _service()
    bearer = mint_session_bearer()
    server = ProposalServer(svc, bearer)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, bearer


def _req(server, method, path, *, bearer=None, body=None, raw=None):
    url = "http://127.0.0.1:%d%s" % (server.port, path)
    data = raw if raw is not None else (
        json.dumps(body).encode("utf-8") if body is not None else None)
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


def test_http_propose_and_status_roundtrip():
    server, bearer = _server()
    try:
        s1, b1 = _req(server, "POST", "/proposal", bearer=bearer, body=_params())
        assert s1 == 200
        pid = b1["proposal_id"]
        s2, b2 = _req(server, "GET", "/proposal/" + pid, bearer=bearer)
        assert s2 == 200
        assert b2["status"] == "pending"
        assert b2["payload_digest"] == b1["payload_digest"]
    finally:
        server.shutdown()
        server.server_close()


def test_missing_or_wrong_bearer_is_uniform_404():
    server, bearer = _server()
    try:
        s1, b1 = _req(server, "POST", "/proposal", body=_params())            # no bearer
        s2, b2 = _req(server, "POST", "/proposal", bearer="wrong", body=_params())
        s3, b3 = _req(server, "GET", "/secret-admin", bearer=bearer)          # unknown route
        assert s1 == s2 == s3 == 404
        assert b1 == b2 == b3 == {"error": "not_found"}
    finally:
        server.shutdown()
        server.server_close()


def test_served_set_is_exactly_the_closed_set():
    server, bearer = _server()
    try:
        # Even WITH the bearer, everything outside the two routes is 404.
        probes = [
            ("POST", "/send"), ("POST", "/confirm"), ("POST", "/switch"),
            ("GET", "/token"), ("GET", "/proposal"), ("POST", "/proposal/123"),
            ("DELETE", "/proposal/123"), ("PUT", "/proposal"), ("GET", "/"),
            ("POST", "/proposalx"),
        ]
        for m, p in probes:
            s, b = _req(server, m, p, bearer=bearer,
                        body=({} if m == "POST" else None))
            assert s == 404 and b == {"error": "not_found"}, (m, p, s, b)
        # The two served routes ARE reachable with the bearer.
        s, b = _req(server, "POST", "/proposal", bearer=bearer, body=_params())
        assert s == 200
        s2, _ = _req(server, "GET", "/proposal/" + b["proposal_id"], bearer=bearer)
        assert s2 == 200
    finally:
        server.shutdown()
        server.server_close()


def test_nonstandard_verbs_are_uniform_404():
    # M1 (Chris): the no-route-oracle property must hold on the method axis too
    # -- an exotic verb must not fall to the stdlib's distinguishable 501.
    server, bearer = _server()
    try:
        for verb in ("PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "FOOBAR"):
            s, b = _req(server, verb, "/proposal", bearer=bearer)
            assert s == 404 and b == {"error": "not_found"}, (verb, s, b)
    finally:
        server.shutdown()
        server.server_close()


def test_schema_violation_over_http_is_400_not_404():
    server, bearer = _server()
    try:
        s, b = _req(server, "POST", "/proposal", bearer=bearer,
                    body=_params(injected="x"))
        assert s == 400 and b == {"error": "invalid_payload"}
    finally:
        server.shutdown()
        server.server_close()


def test_invalid_json_body_is_400():
    server, bearer = _server()
    try:
        s, b = _req(server, "POST", "/proposal", bearer=bearer, raw=b"{not json")
        assert s == 400 and b == {"error": "invalid_request"}
    finally:
        server.shutdown()
        server.server_close()


# --- orphan-payload cleanup on a lost idempotency race --------------------

class _RacingProposals:
    """A store whose create() loses an idempotency race: the pre-create lookup
    sees nothing, create() then raises, and the post-race lookup finds the
    winner -- the exact interleaving that would orphan the loser's payload."""

    def __init__(self, winner):
        self._winner = winner
        self._finds = 0

    def find_by_idempotency(self, key):
        self._finds += 1
        return None if self._finds == 1 else self._winner

    def create(self, proposal):
        raise DuplicateIdempotencyError(proposal.idempotency_key)


class _Winner:
    proposal_id = "winner"
    payload_digest = "d" * 64
    expires_at = 4600


def test_orphan_payload_deleted_on_lost_idempotency_race():
    payloads = InMemoryKV()
    svc = ProposalService(
        proposals=_RacingProposals(_Winner()), payloads=payloads,
        now=lambda: 1000, ttl_seconds=3600, proposal_id_factory=lambda: "loser")
    r = svc.propose(_params(idem="key1"))
    # the winner's identifiers are returned...
    assert r["proposal_id"] == "winner"
    # ...and the payload frozen under the losing id is not left orphaned.
    assert payloads.get("loser") is None
    assert list(payloads.values()) == []
