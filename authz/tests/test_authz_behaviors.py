"""The first-cut authorization behaviours, end to end through a Gmail stub.

Jeff's five (L5 §6) + the discriminating controls Tester (msg_740fb04a) and Jeff
(msg_539f3343) asked for -- each denial is proven to be caused by the variable
under test (revoke / unreachable / missing-field / replay), not by some other
check happening to fire. Plus the `authz_state_digest` green/red binding, the
per_call `needs_approval` path, subject modes, and single-use atomicity.

The caller only ever sees the coarse code; the fine internal code + detail are
asserted against the internal authz audit log.
"""

from __future__ import annotations

import threading

import pytest

from authz.errors import AuthorizationDenied
from store.ledger import AuditEventType
from store.proposals import ProposalStatus

from ._fixtures import (
    GRANT_ID,
    NOW,
    PAYLOAD_DIGEST,
    ReplayService,
    agent_subject,
    capture_decision,
    make_slice,
    new_keypair,
)


def _send_event_types(slc):
    return [e["event_type"] for e in slc.send_ledger.entries()]


def _last_authz(slc):
    return slc.authz_audit.entries()[-1]


# --- 1. allow -> send ------------------------------------------------------

def test_allow_sends():
    slc = make_slice()
    req = slc.request(slc.grant_envelope())  # os_account, approval_mode=auto

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.authorized is True and outcome.sent is True
    assert outcome.public_code == "sent"
    assert slc.sender.calls == [slc.proposal_id]
    assert slc.store.get(slc.proposal_id).status is ProposalStatus.SENT
    assert AuditEventType.SEND_SUCCEEDED.value in _send_event_types(slc)
    assert _last_authz(slc)["code"] == "authorized"


# --- 2. revoke -> reject (with discriminating control) ---------------------

def test_revoke_rejects_and_does_not_send():
    slc = make_slice()
    env = slc.grant_envelope()

    # control: the SAME grant/params authorize before revocation (fresh id).
    before = slc.gate.authorize(slc.request(env, request_id="r-before"),
                                expected_action_digest=PAYLOAD_DIGEST)
    assert before.decision.disposition == "authorized"

    slc.service.revoke(GRANT_ID)

    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env, request_id="r-after"))

    assert outcome.authorized is False and outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert slc.store.get(slc.proposal_id).status is ProposalStatus.PENDING
    assert _last_authz(slc)["code"] == "denied_revoked"


# --- 3. cloud unreachable -> reject, no cache bypass -----------------------

def test_cloud_unreachable_fails_closed_no_cache():
    slc = make_slice(reachable=False)
    env = slc.grant_envelope()

    out1 = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env, request_id="u1"))
    # A second unreachable call must ALSO be denied -- a prior deny caches no allow.
    out2 = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env, request_id="u2"))

    assert out1.public_code == "denied" and out2.public_code == "denied"
    assert slc.sender.calls == []
    assert _last_authz(slc)["code"] == "denied_cloud_unreachable"

    # control: same params authorize once the cloud is reachable.
    slc.service.set_reachable(True)
    ok = slc.gate.authorize(slc.request(env, request_id="u3"),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"


# --- 4. missing approval_mode -> hard reject (NOT silent per_call) ---------

def test_missing_approval_mode_is_invalid_artifact():
    slc = make_slice()
    env = slc.grant_envelope(include_approval_mode=False)

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))

    assert outcome.authorized is False and outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert slc.store.get(slc.proposal_id).status is ProposalStatus.PENDING
    last = _last_authz(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "missing_approval_mode"


def test_present_auto_field_control_sends():
    # control for #4: WITH approval_mode=auto the same shape auto-sends.
    slc = make_slice()
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope(approval_mode="auto")))
    assert outcome.sent is True


def test_per_call_is_pending_not_auto_and_not_denied():
    # per_call is a VALID grant that must not auto-send: needs_approval, no send.
    slc = make_slice()
    env = slc.grant_envelope(approval_mode="per_call")

    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))

    assert outcome.authorized is True and outcome.sent is False
    assert outcome.public_code == "pending_approval"
    assert slc.sender.calls == []
    assert _last_authz(slc)["code"] == "needs_approval"


# --- 5. replay -> reject (with control + single-use atomicity) -------------

def test_replayed_request_is_rejected():
    slc = make_slice()
    req = slc.request(slc.grant_envelope())

    first = slc.orchestrator.authorize_and_send(slc.proposal_id, req)
    assert first.sent is True                       # control: first use authorized
    assert slc.sender.calls == [slc.proposal_id]

    second = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert second.authorized is False and second.public_code == "denied"
    assert slc.sender.calls == [slc.proposal_id]     # still exactly one send
    last = _last_authz(slc)
    # A full request replay is caught at the REQUEST axis (§2 (grant_id,request_id)
    # consume), BEFORE the cloud is re-invoked -- the request is killed, so this is
    # request_id_reused, not the decision-consume axis (test_authz_policy_map).
    assert last["code"] == "denied_replay" and last["detail"] == "request_id_reused"


def test_single_use_is_atomic_under_concurrency():
    # Two concurrent submits of the SAME request through the GATE: exactly one
    # authorized, exactly one denied_replay -- never two authorizations (no double
    # send). The atomic point is the request consumer's consume_once seam.
    slc = make_slice()
    req = slc.request(slc.grant_envelope())
    barrier = threading.Barrier(2)
    results: list = []
    lock = threading.Lock()

    def run():
        barrier.wait()
        try:
            authz = slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
            with lock:
                results.append(("ok", authz.decision.disposition))
        except AuthorizationDenied:
            with lock:
                # Coarse to the caller; read the fine code from the audit.
                results.append(("denied", slc.authz_audit.entries()[-1]["code"]))

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    oks = [r for r in results if r[0] == "ok"]
    denials = [r for r in results if r[0] == "denied"]
    assert len(oks) == 1
    assert len(denials) == 1 and denials[0][1] == "denied_replay"


# --- authz_state_digest binding: green passes, red is refused --------------

def test_state_digest_match_authorizes_green():
    slc = make_slice()  # gate-derived digest == the head the decision binds
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))
    assert outcome.sent is True


def test_state_digest_mismatch_is_refused_red():
    # Jeff's strict red: the gate accepts head N+1, but a decision bound to an
    # OLD head digest (captured at N) is presented via a relay -> the policy map
    # cross-check against the ACCEPTED head refuses it (decision_head_mismatch).
    slc = make_slice()
    # Capture a genuinely-signed decision while the head is at N.
    captured = capture_decision(slc, slc.grant_envelope())
    # Operator advances the head (adds an unrelated grant): GRANT_ID stays active
    # at v1, but the head digest + state_version change -> the gate will accept
    # the NEW head, so the captured decision now binds to a stale digest.
    slc.service.add("11111111111111111111111111111111", "1")
    slc.gate._decision_service = ReplayService(slc.service, captured)

    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))

    assert outcome.authorized is False and outcome.public_code == "denied"
    assert slc.sender.calls == []
    last = _last_authz(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "decision_head_mismatch"


# --- subject modes: os_account vs specific agent_key -----------------------

def test_agent_key_mode_with_valid_signature_sends():
    slc = make_slice()
    agent_priv, agent_pub = new_keypair()
    env = slc.grant_envelope(subject=agent_subject(agent_pub))
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env, agent_priv=agent_priv))
    assert outcome.sent is True


def test_agent_key_mode_without_signature_is_mode_mismatch():
    slc = make_slice()
    _, agent_pub = new_keypair()
    env = slc.grant_envelope(subject=agent_subject(agent_pub))
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env, agent_priv=None, peer_verified=True))
    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert _last_authz(slc)["code"] == "denied_mode_mismatch"


def test_agent_key_mode_with_wrong_key_is_mode_mismatch():
    slc = make_slice()
    _, agent_pub = new_keypair()
    wrong_priv, _ = new_keypair()
    env = slc.grant_envelope(subject=agent_subject(agent_pub))
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env, agent_priv=wrong_priv))
    assert outcome.public_code == "denied"
    assert _last_authz(slc)["code"] == "denied_mode_mismatch"


def test_os_account_without_peer_credential_is_mode_mismatch():
    slc = make_slice()
    env = slc.grant_envelope()  # os_account
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(env, peer_verified=False))
    assert outcome.public_code == "denied"
    assert _last_authz(slc)["code"] == "denied_mode_mismatch"


# --- other grant-body checks (L5 §2 first-cut behaviours) ------------------

def test_untrusted_issuer_is_refused():
    slc = make_slice()
    env = slc.grant_envelope(issuer_fp="not-the-pinned-fingerprint")
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))
    assert outcome.public_code == "denied"
    last = _last_authz(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "untrusted_issuer"


def test_expired_grant_is_refused():
    slc = make_slice()
    env = slc.grant_envelope(valid_from=NOW - 10_000, valid_until=NOW - 5_000)
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))
    assert outcome.public_code == "denied"
    assert _last_authz(slc)["code"] == "denied_expired"


def test_validity_span_over_cap_is_refused():
    slc = make_slice()
    env = slc.grant_envelope(valid_from=NOW - 100,
                             valid_until=NOW + 8 * 24 * 3600)  # > 7-day cap
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))
    assert outcome.public_code == "denied"
    assert _last_authz(slc)["code"] == "denied_validity_exceeds_policy"


def test_superseded_grant_version_is_refused():
    slc = make_slice()
    slc.service.supersede(GRANT_ID, new_version=2)  # head lists GRANT_ID at v2
    env = slc.grant_envelope(grant_version="1")            # this grant is v1
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))
    assert outcome.public_code == "denied"
    assert _last_authz(slc)["code"] == "denied_superseded"


def test_forged_grant_signature_is_invalid_artifact():
    slc = make_slice()
    other_priv, _ = new_keypair()
    # A well-formed grant signed by the WRONG key.
    from ._fixtures import grant_body, sign_grant
    env = sign_grant(other_priv, grant_body(issuer_fp=slc.issuer_fp))
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, slc.request(env))
    assert outcome.public_code == "denied"
    assert _last_authz(slc)["code"] == "denied_invalid_artifact"


# --- existence oracle: coarse to caller, rich only in the audit ------------

@pytest.mark.parametrize("setup, expected_code", [
    ("revoke", "denied_revoked"),
    ("unreachable", "denied_cloud_unreachable"),
    ("expired", "denied_expired"),
    ("missing_field", "denied_invalid_artifact"),
])
def test_denial_is_coarse_to_caller_rich_in_audit(setup, expected_code):
    slc = make_slice(reachable=(setup != "unreachable"))
    if setup == "expired":
        env = slc.grant_envelope(valid_from=NOW - 10_000, valid_until=NOW - 5_000)
    elif setup == "missing_field":
        env = slc.grant_envelope(include_approval_mode=False)
    else:
        env = slc.grant_envelope()

    if setup == "revoke":
        slc.service.revoke(GRANT_ID)

    with pytest.raises(AuthorizationDenied) as ei:
        slc.gate.authorize(slc.request(env), expected_action_digest=PAYLOAD_DIGEST)

    assert ei.value.public_code == "denied"
    assert str(ei.value) == "denied"          # no reason leaked to the caller
    assert _last_authz(slc)["code"] == expected_code  # rich code only in the audit


# --- action-digest binding: authorization must be for THIS payload ---------

def test_action_digest_mismatch_does_not_send():
    # B1 red-proof: a decision bound to a DIFFERENT action_digest than the
    # proposal about to be sent is refused as invalid_artifact, and NO
    # "authorized" is ever written to the audit before the refusal. Historically
    # the gate logged "authorized" and the orchestrator caught the mismatch
    # after -- so the audit had an authorized row for a send that never happened.
    slc = make_slice()
    req = slc.request(slc.grant_envelope(), action_digest="c" * 64)
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.authorized is False and outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert slc.store.get(slc.proposal_id).status is ProposalStatus.PENDING

    codes = [e["code"] for e in slc.authz_audit.entries()]
    assert "authorized" not in codes                 # no authorized precedes the refusal
    last = _last_authz(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "action_digest_mismatch"
    assert last["grant_id_verified"] is True          # from an authenticated decision
