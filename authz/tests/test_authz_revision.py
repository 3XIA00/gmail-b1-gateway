"""Sealed-revision behaviours (2026-09-05): the code blockers + test gaps the
three-reviewer gate required, each proven red->green.

  finding 2  agent sig bound to grant A can't be replayed against grant B
  finding 3  a not-yet-valid (future) cert is refused, with a skew control
  finding 4  the gate authenticates the decision sig; the authorized audit row
             carries the decision reference (id/versions/digests/mode)
  finding 5  os_account subject is an IDENTITY match: a peer changed by request
             time is refused
  finding 6  a valid grant whose from_account != this Gateway's send account is
             denied_scope
  B1         (in test_authz_behaviors) no authorized precedes an action-digest
             binding failure
  B2         a grant_id peeked from an unverified/forged envelope is audited with
             grant_id_verified=False
  B3         auto vs per_call are distinguishable in the authz audit alone
  gap a      a success does not cache an allow: a later outage still fails closed
  gap b      the single-use check->consume is atomic; removing the lock is caught
  gap c      the caller-facing exception cannot leak the fine code on any surface
"""

from __future__ import annotations

import threading
from dataclasses import replace

import pytest

from authz.errors import AuthorizationDenied, DenialSignal
from authz.service import PeerIdentity
from store.proposals import ProposalStatus

from ._fixtures import (
    GRANT_ID,
    NOW,
    PAYLOAD_DIGEST,
    agent_subject,
    grant_body,
    make_slice,
    new_keypair,
    sign_grant,
)

_OTHER_GRANT_ID = "ffffffffffffffffffffffffffffffff"


def _last_authz(slc):
    return slc.authz_audit.entries()[-1]


# --- finding 6: scope is the send account, not just a signed field ---------

def test_wrong_from_account_is_denied_scope():
    slc = make_slice()  # gateway sends from me@test.example
    env = slc.grant_envelope(scope={"from_account": "someone-else@test.example"})

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert slc.store.get(slc.proposal_id).status is ProposalStatus.PENDING
    assert _last_authz(slc)["code"] == "denied_scope"


def test_matching_from_account_control_sends():
    # control for finding 6: the SAME shape with the Gateway's own account sends.
    slc = make_slice()
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope(
            scope={"from_account": "me@test.example"})))
    assert outcome.sent is True


# --- finding 3: valid_from is a real lower bound (with skew) ----------------

def test_not_yet_valid_grant_is_refused():
    slc = make_slice()
    env = slc.grant_envelope(valid_from=NOW + 10_000, valid_until=NOW + 20_000)

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert _last_authz(slc)["code"] == "denied_expired"


def test_valid_from_within_skew_is_allowed():
    # control: a valid_from just inside the +-5min skew window still authorizes.
    slc = make_slice()
    env = slc.grant_envelope(valid_from=NOW + 200, valid_until=NOW + 10_000)
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))
    assert outcome.sent is True


# --- finding 2: agent sig is bound to a specific grant_id -------------------

def test_agent_sig_bound_to_other_grant_is_rejected():
    # Both grants are ACTIVE in the head, so this isolates the agent-sig binding
    # (finding 2) from active-set membership (§0b).
    slc = make_slice(active_grants={GRANT_ID: "1", _OTHER_GRANT_ID: "1"})
    agent_priv, agent_pub = new_keypair()
    env_b = slc.grant_envelope(grant_id=_OTHER_GRANT_ID,
                               subject=agent_subject(agent_pub))
    # The agent signs a request binding for a DIFFERENT grant (grant A's id) with
    # the SAME key, then presents grant B. grant_id is in the binding, so the sig
    # does not verify against B -> mode_mismatch (no grant-swap).
    req = slc.request(env_b, agent_priv=agent_priv, bind_grant_id=GRANT_ID)

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert _last_authz(slc)["code"] == "denied_mode_mismatch"


def test_agent_sig_bound_to_its_own_grant_control_sends():
    # control for finding 2: signing the binding for the presented grant works.
    slc = make_slice(active_grants={GRANT_ID: "1", _OTHER_GRANT_ID: "1"})
    agent_priv, agent_pub = new_keypair()
    env_b = slc.grant_envelope(grant_id=_OTHER_GRANT_ID,
                               subject=agent_subject(agent_pub))
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env_b, agent_priv=agent_priv))  # binds env_b's id
    assert outcome.sent is True


# --- finding 5: os_account subject is an identity match, not a bool ---------

def test_peer_identity_changed_by_request_time_is_refused():
    # A peer verified at connect (m1/acct-1) but resolved as a DIFFERENT identity
    # by request time must be refused -- a static bool could not model this.
    slc = make_slice(peer_resolver=lambda req: PeerIdentity("m2", "acct-2"))
    env = slc.grant_envelope()  # subject m1/acct-1

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))

    assert outcome.public_code == "denied"
    last = _last_authz(slc)
    assert last["code"] == "denied_mode_mismatch"
    assert last["detail"] == "subject_identity_mismatch"


def test_peer_identity_match_control_sends():
    # control for finding 5: the resolved identity equals the grant subject.
    slc = make_slice(peer_resolver=lambda req: PeerIdentity("m1", "acct-1"))
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))
    assert outcome.sent is True


def test_default_resolver_wrong_machine_is_refused():
    # The default resolver reads the request's observed peer identity; a verified
    # peer on the WRONG machine still fails the isomorphic subject comparison.
    slc = make_slice()
    env = slc.grant_envelope()  # subject m1/acct-1
    req = slc.request(env, peer_verified=True, peer_machine_id="mX")

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.public_code == "denied"
    assert _last_authz(slc)["detail"] == "subject_identity_mismatch"


# --- finding 4: decision is signed; gate authenticates it -------------------

class _CorruptingService:
    """Wraps a service and returns decisions with a broken signature."""

    def __init__(self, inner):
        self._inner = inner

    def decide(self, request, *, now):
        return replace(self._inner.decide(request, now=now), sig=b"\x00" * 64)

    @property
    def decision_public_key(self):
        return self._inner.decision_public_key


def test_gate_refuses_decision_with_invalid_signature():
    slc = make_slice()
    slc.gate._decision_service = _CorruptingService(slc.service)  # unauthenticated

    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    last = _last_authz(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "decision_sig_invalid"
    # The decision's own sig is rejected, so the decision is not trusted for
    # anything. But the audit id no longer comes from the decision at all -- it
    # comes from the gate's OWN independently-verified grant envelope -- so the
    # recorded grant_id is the real, verified one (R6: identity is never the
    # decision's self-report).
    assert last["grant_id"] == GRANT_ID
    assert last["grant_id_verified"] is True


def test_authorized_audit_carries_decision_reference():
    slc = make_slice()
    slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))

    rec = _last_authz(slc)
    assert rec["code"] == "authorized"
    assert rec["approval_mode"] == "auto"
    assert rec["decision_id"]                       # opaque, present
    assert rec["state_version"] == "1"
    assert rec["authz_state_digest"] == slc.state_digest
    assert rec["action_digest"] == PAYLOAD_DIGEST   # == FSM ledger join key
    assert rec["grant_id_verified"] is True


# --- B2: unverified/forged grant_id is flagged, never trusted --------------

def test_forged_grant_audit_marks_grant_id_unverified():
    slc = make_slice()
    other_priv, _ = new_keypair()
    forged_id = "deadbeefdeadbeefdeadbeefdeadbeef"
    # A well-formed grant with an attacker-chosen grant_id, signed by the WRONG
    # key: the audit may record the id for correlation but MUST flag it unverified.
    env = sign_grant(other_priv, grant_body(issuer_fp=slc.issuer_fp, grant_id=forged_id))

    slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))

    rec = _last_authz(slc)
    assert rec["code"] == "denied_invalid_artifact"
    assert rec["grant_id"] == forged_id
    assert rec["grant_id_verified"] is False


# --- B3: auto vs per_call distinguishable from the authz audit alone -------

def test_audit_distinguishes_auto_from_per_call():
    slc_auto = make_slice()
    slc_auto.orchestrator.authorize_and_send(
        slc_auto.proposal_id,
        slc_auto.request(slc_auto.grant_envelope(approval_mode="auto")))
    a = _last_authz(slc_auto)

    slc_pc = make_slice()
    slc_pc.orchestrator.authorize_and_send(
        slc_pc.proposal_id,
        slc_pc.request(slc_pc.grant_envelope(approval_mode="per_call")))
    p = _last_authz(slc_pc)

    assert a["code"] == "authorized" and a["approval_mode"] == "auto"
    assert p["code"] == "needs_approval" and p["approval_mode"] == "per_call"
    assert a["decision_id"] != p["decision_id"]


# --- gap a: a success caches no allow; a later outage still fails closed ----

def test_success_then_outage_rejects_no_cache():
    slc = make_slice()
    first = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope(), request_id="s1"))
    assert first.sent is True

    slc.service.set_reachable(False)
    second = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope(), request_id="s2"))

    assert second.public_code == "denied"
    assert _last_authz(slc)["code"] == "denied_cloud_unreachable"
    assert slc.sender.calls == [slc.proposal_id]     # still only the first send


# --- gap b: single-use lives in an atomic consume_once seam -----------------
#
# Jeff's ruling (2026-09-04): the atomicity load-bearing point is a narrow
# ``consume_once`` operation, not a lock wrapped around scattered code. The
# discriminating test INJECTS a deliberately non-atomic check-then-set consumer
# whose barrier lives inside the test double (NOT in production), so two
# concurrent decides both pass the CHECK before either SETs -> both authorized.
# The real LockedConsumer must instead yield exactly one authorized + one replay.
#
# What this proves, precisely (Boris/Jeff, per revision notes): the test has
# DETERMINISTIC DISCRIMINATING POWER against a non-atomic implementation, and the
# locked implementation satisfies the single-use contract. It does NOT force a
# particular interleaving inside the real critical section, and is not a claim
# that "concurrency is tested".


class _NonAtomicConsumer:
    """A deliberately non-atomic check-then-set consumer (the mutation target).

    A two-party barrier BETWEEN the check and the set forces both concurrent
    callers to observe "free" before either records the consume -> both return
    True. This is the fail-open a real atomic consumer must not exhibit. The key
    is the gate's composite (grant_id, request_id) string; the double treats it
    opaquely.
    """

    def __init__(self):
        self._consumed: set = set()
        self._between_check_and_set = threading.Barrier(2, timeout=3)

    def consume_once(self, key: str, action_digest: str) -> bool:
        free = key not in self._consumed              # CHECK
        self._between_check_and_set.wait()            # both threads have now CHECKED
        self._consumed.add(key)                       # SET (too late to matter)
        return free


def _run_two_authorize(slc, req):
    """Two concurrent gate.authorize of the SAME request. Classifies each as ok
    (returns an Authorization) or denied (coarse AuthorizationDenied)."""
    results: list = []
    guard = threading.Lock()

    def run():
        try:
            authz = slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
            r = ("ok", authz.decision.disposition)
        except AuthorizationDenied:
            r = ("denied", None)
        with guard:
            results.append(r)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(4)
    return results


def test_nonatomic_consumer_double_authorizes_red_proof():
    # RED: injected non-atomic REQUEST consumer -> concurrent double-submit both
    # pass the (grant_id,request_id) consume -> both authorize (fail-open).
    slc = make_slice(request_consumer=_NonAtomicConsumer())
    req = slc.request(slc.grant_envelope())

    results = _run_two_authorize(slc, req)

    assert sorted(r[0] for r in results) == ["ok", "ok"]


def test_locked_consumer_is_single_use_green():
    # GREEN: the real LockedConsumer -> exactly one authorized, one denied, under
    # the same concurrent double-submit. Deterministic (lock serializes; no sleep,
    # no probability loop). The denial is the request-axis replay.
    slc = make_slice()  # default LockedConsumer request_consumer
    req = slc.request(slc.grant_envelope())

    results = _run_two_authorize(slc, req)

    assert sorted(r[0] for r in results) == ["denied", "ok"]
    codes = [e["code"] for e in slc.authz_audit.entries()]
    assert "authorized" in codes
    assert any(c == "denied_replay" for c in codes)


# --- gap c: the caller-facing exception cannot leak the fine code -----------

def test_caller_facing_denied_exposes_no_fine_code():
    exc = AuthorizationDenied()
    assert str(exc) == "denied"
    assert exc.args == ("denied",)
    assert exc.public_code == "denied"
    assert vars(exc) == {}                 # __dict__ holds no reason/detail
    assert "denied_" not in repr(exc)      # no fine denied_* token in repr


def test_internal_signal_is_not_the_caller_type():
    # DenialSignal (fine, internal) must not be an AuthorizationDenied, so an
    # `except AuthorizationDenied` at the caller can never catch the fine one.
    sig = DenialSignal.__mro__
    assert AuthorizationDenied not in sig
