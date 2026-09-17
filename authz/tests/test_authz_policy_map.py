"""Exhaustive per-field decision-binding policy (sealed 2026-09-05, R1/R6/R7).

The relay threat (service.py header): a validly-signed ``Decision`` held by the
UNTRUSTED cloud can be replayed against a request it was never issued for, with
ANY field swapped. Previously the gate verified only 2 of 11 binding fields. The
proof obligation now has three legs, all here:

  * UNIT: every (a)/(c) field has a mismatch that ``check_binding`` catches with
    the right detail, and an all-correct decision passes -- exhaustive coverage.
  * E2E (relay): the GATE actually runs the policy map + gate-side decision_id
    consume BEFORE any authorized audit or send -- a genuinely-signed decision
    replayed for another request / grant / mode / a second time is refused, with
    no ``authorized`` row and no send side-effect. (Signatures are never forged;
    the relay only replays real service decisions -- the actual threat.)
  * STRUCTURAL: the policy map covers exactly ``Decision``'s fields, so a new
    field is red by default (the R1/R6/R7 defect: added a field, forgot the check).

(d) ``decided_at``: time rule PENDING @linus-torv (§4.5). The unbounded-staleness
gap 测试姬 proved (a 31.7yr-stale decision still authorizes) is characterized by a
strict xfail so it flips the moment enforcement lands. (e): empty this round;
growth gated on a registered poison-value projection-invariance test.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authz.capability import SubjectKind
from authz.decision_policy import (
    CLASS_E,
    ExpectedBinding,
    assert_policy_covers_decision,
    check_binding,
    fields_in_class,
)
from authz.errors import AuthorizationDenied
from authz.service import Decision, Disposition, decision_signing_input
from store.proposals import Proposal

from ._fixtures import (
    GRANT_ID,
    NOW,
    PAYLOAD_DIGEST,
    ReplayService,
    capture_decision,
    make_slice,
)

_OTHER_GRANT_ID = "ffffffffffffffffffffffffffffffff"

# (e) fields that have a registered poison-value projection-invariance test.
# Must equal the policy map's (e) members: adding an (e) field without its poison
# test turns test_e_class_growth_is_gated red (Boris's preventive red light).
_POISON_TESTED_E_FIELDS: frozenset = frozenset()


def _last(slc):
    return slc.authz_audit.entries()[-1]


def _codes(slc):
    return [e["code"] for e in slc.authz_audit.entries()]


# --- UNIT: check_binding is exhaustive over the (a)/(c) fields ---------------

def _matching_pair():
    """A decision whose every field matches the Gateway's independent derivation."""
    expected = ExpectedBinding(
        request_id="req-1", action_digest=PAYLOAD_DIGEST,
        authz_state_digest="d" * 64, state_version="1",
        grant_id=GRANT_ID, grant_version="1",
        approval_mode="auto", subject_kind=SubjectKind.OS_ACCOUNT.value,
        disposition=Disposition.AUTHORIZED)
    decision = Decision(
        decision_id="op4qu3", grant_id=GRANT_ID, grant_version="1",
        state_version="1", authz_state_digest="d" * 64,
        request_id="req-1", action_digest=PAYLOAD_DIGEST, decided_at=NOW,
        disposition=Disposition.AUTHORIZED, approval_mode="auto",
        subject_kind=SubjectKind.OS_ACCOUNT.value, sig=b"")
    return decision, expected


def test_all_fields_matching_passes():
    decision, expected = _matching_pair()
    assert check_binding(decision, expected) is None


@pytest.mark.parametrize("field, bad_value, detail", [
    ("request_id", "req-OTHER", "decision_request_mismatch"),
    ("action_digest", "b" * 64, "action_digest_mismatch"),
    ("authz_state_digest", "e" * 64, "decision_head_mismatch"),
    ("grant_id", _OTHER_GRANT_ID, "decision_grant_id_mismatch"),
    ("grant_version", "2", "decision_grant_version_mismatch"),
    ("state_version", "2", "decision_version_mismatch"),
    ("approval_mode", "per_call", "decision_approval_mode_mismatch"),
    ("approval_mode", "bogus_mode", "decision_approval_mode_mismatch"),
    ("subject_kind", SubjectKind.AGENT_KEY.value, "decision_subject_kind_mismatch"),
    ("subject_kind", "alien_kind", "decision_subject_kind_mismatch"),
    ("disposition", Disposition.NEEDS_APPROVAL, "decision_disposition_mismatch"),
])
def test_each_bound_field_mismatch_is_caught(field, bad_value, detail):
    decision, expected = _matching_pair()
    tampered = replace(decision, **{field: bad_value})
    assert check_binding(tampered, expected) == detail


# --- STRUCTURAL: the map covers exactly Decision's fields --------------------

def test_policy_map_covers_every_decision_field():
    # Also asserted at gate construction; explicit here as the regression guard
    # against "added a Decision field, forgot to classify/verify it" (R1/R6/R7).
    assert_policy_covers_decision()


def test_e_class_growth_is_gated_on_a_poison_test():
    # (e) is the scheme's only silent bypass: a field marked (e) passes the
    # structural assertion while "never read" rests on discipline. Growth must be
    # gated on registering a poison-value projection-invariance test.
    assert set(fields_in_class(CLASS_E)) == _POISON_TESTED_E_FIELDS


def authorization_projection(outcome, audit_last, sender_calls):
    """Jeff's (e) invariant (msg_106652d5): the authorization-relevant projection
    a poison in an (e) field must NOT change -- disposition, coarse code, selected
    grant/actor/mode, consume state, and send side-effect. Deliberately EXCLUDES
    the poisoned field's own verbatim audit record, which is allowed to differ.
    Ready for the first (e) member; unused while (e) is empty.
    """
    return (
        outcome.public_code, outcome.sent, outcome.authorized,
        audit_last["code"], audit_last["approval_mode"],
        audit_last["grant_id"], audit_last["grant_id_verified"],
        tuple(sender_calls),
    )


# --- E2E (relay): the gate runs the map + consume before audit/send ----------

def test_relay_replays_decision_for_another_request_is_denied():
    # R1: a decision genuinely issued for request "req-A", replayed against a
    # DIFFERENT request. Without the request_id (a) check this authorizes.
    slc = make_slice()
    captured = capture_decision(slc, slc.grant_envelope(), request_id="req-A")
    slc.gate._decision_service = ReplayService(slc.service, captured)

    req = slc.request(slc.grant_envelope(), request_id="req-B")
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert "authorized" not in _codes(slc)
    assert _last(slc)["code"] == "denied_invalid_artifact"
    assert _last(slc)["detail"] == "decision_request_mismatch"


def test_relay_swaps_grant_id_is_denied_and_never_verified():
    # R6 / B2 re-opened: a decision genuinely signed for a DIFFERENT grant (ffff…),
    # replayed against a request whose envelope is the real grant. The forged id
    # must never enter the audit as verified.
    slc = make_slice()
    captured = capture_decision(slc, slc.grant_envelope(grant_id=_OTHER_GRANT_ID))
    slc.gate._decision_service = ReplayService(slc.service, captured)

    req = slc.request(slc.grant_envelope())  # envelope grant_id == GRANT_ID
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    last = _last(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "decision_grant_id_mismatch"
    # Identity is the gate's OWN verified grant, not the decision's swapped id.
    assert last["grant_id"] == GRANT_ID
    assert last["grant_id_verified"] is True


def test_relay_swaps_approval_mode_to_auto_is_denied_no_send():
    # R7 / B3 re-opened: a genuinely-signed AUTO decision replayed against a
    # PER_CALL grant would, unchecked, turn a per-call grant into an auto send.
    slc = make_slice()
    captured = capture_decision(slc, slc.grant_envelope(approval_mode="auto"))
    slc.gate._decision_service = ReplayService(slc.service, captured)

    req = slc.request(slc.grant_envelope(approval_mode="per_call"))
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []          # crucially NOT auto-sent
    last = _last(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "decision_approval_mode_mismatch"


# --- R7: a VALIDLY-SIGNED decision carrying an unknown raw enum value ---------
#
# The relay tests above replay REAL decisions (a relay cannot re-sign). The R7
# fail-closed threat is different in kind: the signer the gate trusts emits a
# decision whose subject_kind / approval_mode / disposition is OUTSIDE the closed
# set. Before the fix subject_kind was an enum and decision_body did `.value`, so
# an unknown raw value threw a bare AttributeError inside verify_decision_sig --
# no coarse denied, no audit. subject_kind is now a raw str symmetric with the
# other two, so the closed-set guard is the single validation point: an unknown
# value -> denied_invalid_artifact + *_mismatch + zero send + NO exception.


class _EmitService:
    """A decision service the gate trusts BY KEY that emits a validly-signed
    decision with caller-chosen raw field overrides. Only the signer the gate
    trusts can put a valid signature over an unknown enum value (a replaying relay
    cannot re-sign), so this is the sole faithful way to stage the R7 threat."""

    def __init__(self, base_decision, **overrides):
        self._key = Ed25519PrivateKey.generate()
        body = replace(base_decision, sig=b"", **overrides)
        self._decision = replace(body, sig=self._key.sign(decision_signing_input(body)))

    def decide(self, request, *, now):
        return self._decision

    @property
    def decision_public_key(self):
        return self._key.public_key()


@pytest.mark.parametrize("overrides, detail", [
    ({"subject_kind": "alien_kind"}, "decision_subject_kind_mismatch"),
    ({"approval_mode": "sideways"}, "decision_approval_mode_mismatch"),
    ({"disposition": "whenever"}, "decision_disposition_mismatch"),
])
def test_valid_sig_unknown_enum_value_is_fail_closed(overrides, detail):
    slc = make_slice()
    honest = capture_decision(slc, slc.grant_envelope())     # request_id "req-1"
    slc.gate._decision_service = _EmitService(honest, **overrides)

    req = slc.request(slc.grant_envelope())    # request_id "req-1": all (a) fields match
    # Must NOT raise. A bare AttributeError (the R7 bug) would propagate out of
    # authorize_and_send and error this test rather than returning a coarse deny.
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.public_code == "denied"
    assert slc.sender.calls == []
    assert "authorized" not in _codes(slc)
    last = _last(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == detail


class _AlwaysFreeConsumer:
    """A pass-through consumer that never records a consume -- used to ISOLATE the
    decision-id axis from the request-id axis (which would otherwise fire first)."""

    def consume_once(self, key: str, action_digest: str) -> bool:
        return True


def test_gateway_consumes_decision_id_second_feed_is_replay():
    # (b): the decision-id single-use consume lives on the GATEWAY side, so a
    # relay that never re-touches the service cannot reuse a decision. Isolated
    # from the request axis with a pass-through request consumer, so the second
    # feed reaches the decision_id consume -> denied_replay/decision_reused.
    slc = make_slice(request_consumer=_AlwaysFreeConsumer())
    captured = capture_decision(slc, slc.grant_envelope())  # request_id "req-1"
    slc.gate._decision_service = ReplayService(slc.service, captured)
    req = slc.request(slc.grant_envelope())  # request_id "req-1" (matches captured)

    first = slc.orchestrator.authorize_and_send(slc.proposal_id, req)
    second = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert first.sent is True
    assert second.public_code == "denied"
    assert slc.sender.calls == [slc.proposal_id]   # only the first sent
    last = _last(slc)
    assert last["code"] == "denied_replay"
    assert last["detail"] == "decision_reused"


# --- R4: an outage is CONTINUOUSLY denied; a success caches no allow ----------

def test_repeated_outage_is_continuously_denied_no_cache():
    slc = make_slice()
    first = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope(), request_id="s1"))
    assert first.sent is True

    slc.store.create(Proposal(
        proposal_id="prop-2", payload_digest=PAYLOAD_DIGEST,
        expires_at=NOW + 100_000, created_at=NOW - 1000))
    slc.service.set_reachable(False)

    # Two SEPARATE later requests (different request_id, different pending
    # proposal) are BOTH denied -- the outage is not one-shot and the earlier
    # success cached nothing.
    d1 = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope(), request_id="o1"))
    d2 = slc.orchestrator.authorize_and_send(
        "prop-2", slc.request(slc.grant_envelope(), request_id="o2"))

    assert d1.public_code == "denied" and d2.public_code == "denied"
    codes = _codes(slc)
    assert codes.count("authorized") == 1          # only the first, ever
    assert codes[-1] == "denied_cloud_unreachable"
    assert codes[-2] == "denied_cloud_unreachable"
    assert slc.sender.calls == [slc.proposal_id]   # no new send after the outage


# --- (d) decided_at: hygiene window on the Gateway wall clock (§1) ------------
#
# The 2026-09-05 ruling (Linus §1) resolved the (d) gap 测试姬 proved: decided_at
# is NOT a security deadline (that is the Gateway MONOTONIC response deadline) and
# NOT a decision TTL. It is bounded ONLY as a HYGIENE window on the Gateway wall
# clock: [t_request_sent-5min, t_response_verified+5min]. A validly-signed
# decision whose decided_at lies outside that window is refused. This isolates the
# rule from grant-validity by signing an out-of-window decided_at while the grant
# stays valid at the (unchanged) gate clock.

def test_stale_decided_at_is_refused_by_hygiene_window():
    slc = make_slice()
    # A genuinely-signed decision whose decided_at is ~11.6 days in the past
    # (signed as such, so the signature is valid and the field is not tampered).
    captured = slc.service.decide(
        slc.request(slc.grant_envelope()), now=NOW - 1_000_000)
    slc.gate._decision_service = ReplayService(slc.service, captured)
    req = slc.request(slc.grant_envelope())

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_invalid_artifact"
    assert _last(slc)["detail"] == "decided_at_out_of_window"


def test_decided_at_within_window_control_authorizes():
    # control: a decision decided at NOW (within the hygiene window) authorizes,
    # so the window is not vacuously rejecting everything.
    slc = make_slice()
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))
    assert outcome.sent is True
