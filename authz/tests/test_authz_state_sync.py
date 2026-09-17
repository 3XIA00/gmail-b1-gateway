"""Step ① sync + accept: active-set membership, the revocation causal chain,
high-water anti-rollback, and §4.6 fail-closed (seam-split rebuild 2026-09-05).

The 2026-09-05 ruling (Linus §0b) makes revocation/supersede take effect through
active-set MEMBERSHIP against the user-root-signed head the Gateway verifies each
execution, so a malicious relay cannot hide a revocation: it cannot produce an
acceptable head that still lists the grant. These tests exercise that mechanism
end to end plus its safety envelope.
"""

from __future__ import annotations

import pytest

from authz.capability import parse_envelope
from authz.errors import AuthorizationDenied
from authz.service import HighWaterMark
from authz.state import (
    HeadState,
    Membership,
    VerifiedHead,
    parse_head_body,
    parse_revocation_body,
    parse_sync_envelope,
)

from ._fixtures import (
    GRANT_ID,
    NOW,
    PAYLOAD_DIGEST,
    make_slice,
    new_keypair,
)

_OTHER = "ffffffffffffffffffffffffffffffff"


def _last(slc):
    return slc.authz_audit.entries()[-1]


def _sync_set_revoked_ids(slc):
    """The grant_ids whose revocation artifact rides the CURRENT sync set, read
    straight from the relay (independent of the gate). Lets the two separated reds
    self-assert their fixture state before running -- a fixture-leak defense so a
    mis-wired deliver/withhold can't false-green (Boris 186211-1 / Jeff 186212)."""
    _head_env, rev_envs = parse_sync_envelope(slc.sync_source.sync())
    ids = set()
    for rev in rev_envs:
        _type, body, _sig = parse_envelope(rev)
        ids.add(parse_revocation_body(body))
    return ids


# --- unit: VerifiedHead.membership classifies the active set ------------------

def _head(pairs, seen_revocations=frozenset()):
    return VerifiedHead(state_version="1", state_version_int=1,
                        active_grants=frozenset(pairs), digest="d" * 64,
                        seen_revocations=frozenset(seen_revocations))


def test_membership_active_when_exact_pair_present():
    h = _head({(GRANT_ID, "1")})
    assert h.membership(GRANT_ID, "1") == Membership.ACTIVE


def test_membership_superseded_when_grant_present_at_other_version():
    h = _head({(GRANT_ID, "2")})
    assert h.membership(GRANT_ID, "1") == Membership.SUPERSEDED


def test_membership_is_tuple_granular_not_id_granular():
    # supersede leg② at TUPLE granularity (Linus 186258 / 测试姬 186151, carried as
    # an additional test -- not an isolation vector): membership keys on the
    # (grant_id, grant_version) PAIR, not grant_id alone. On a head that lists G
    # only at the NEW version, the OLD tuple is absent and the NEW tuple present,
    # so a version bump ALONE flips old->SUPERSEDED / new->ACTIVE. This pins that a
    # relay cannot pass a stale grant_version off as active on an advanced head.
    h = _head({(GRANT_ID, "2")})
    assert (GRANT_ID, "1") not in h.active_grants          # old tuple absent
    assert (GRANT_ID, "2") in h.active_grants              # new tuple present
    assert h.membership(GRANT_ID, "1") == Membership.SUPERSEDED   # old version
    assert h.membership(GRANT_ID, "2") == Membership.ACTIVE       # new version


def test_membership_no_grant_when_absent_and_no_revocation_artifact():
    # §6 ③: mere ABSENCE from the head, with NO revocation artifact seen, is
    # NO_GRANT -- absence alone is not evidence of revocation.
    h = _head({(_OTHER, "1")})
    assert h.membership(GRANT_ID, "1") == Membership.NO_GRANT


def test_membership_revoked_when_revocation_artifact_seen():
    # §6 ①: a SEEN revocation artifact for grant_id is positive revocation
    # evidence -> REVOKED, distinct from the plain-absence NO_GRANT above.
    h = _head({(_OTHER, "1")}, seen_revocations={GRANT_ID})
    assert h.membership(GRANT_ID, "1") == Membership.REVOKED


def test_membership_revocation_wins_even_if_head_still_lists_grant():
    # Relay inconsistency (artifact says revoked, head still lists it) must fail
    # closed: REVOKED wins over ACTIVE, never allow.
    h = _head({(GRANT_ID, "1")}, seen_revocations={GRANT_ID})
    assert h.membership(GRANT_ID, "1") == Membership.REVOKED


# --- unit: HeadState advances monotonically and re-signs a real head ----------

def test_headstate_revoke_bumps_version_and_changes_digest():
    priv, _ = new_keypair()
    hs = HeadState(priv, {GRANT_ID: "1"})
    before_digest = hs.head_digest()
    before_version = hs.state_version

    hs.revoke(GRANT_ID)

    assert hs.state_version != before_version           # monotonic +1
    assert int(hs.state_version) == int(before_version) + 1
    assert hs.head_digest() != before_digest            # digest provably changes
    # the grant is gone from the signed active set
    _, _, pairs = parse_head_body(hs.signed_head()["body"])
    assert (GRANT_ID, "1") not in pairs


def test_headstate_signed_head_is_verifiable_and_parses():
    priv, pub = new_keypair()
    hs = HeadState(priv, {GRANT_ID: "1"})
    env = hs.signed_head()
    assert env["type"] == "authz_state"
    sv, sv_int, pairs = parse_head_body(env["body"])
    assert sv == "1" and sv_int == 1 and (GRANT_ID, "1") in pairs


# --- e2e: the §6 revoked/no_grant split, two SEPARATED reds -------------------
# Both reds start from the SAME control-plane action (revoke -> head drops G) and
# the SAME resulting head. The ONLY variable that moves between them is whether
# the relay DELIVERS the revocation artifact. Revoke is the clean isolator: it is
# what makes "seen a revocation" separable from "merely absent" (Jeff 186136).

def test_positive_control_active_grant_authorizes():
    # Positive control FIRST (Linus/Boris): the grant is active, no revocation
    # -> authorized. Without this, a red that denies proves nothing.
    slc = make_slice()
    ok = slc.gate.authorize(slc.request(slc.grant_envelope(), request_id="r0"),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"


def test_red_a_revocation_artifact_delivered_is_denied_revoked():
    slc = make_slice()
    # control: authorizes while active (accepts head v1, advances HW to 1).
    ok = slc.gate.authorize(slc.request(slc.grant_envelope(), request_id="r0"),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"

    before = slc.head_state.head_digest()
    slc.service.revoke(GRANT_ID)                 # re-signs a NEW head (v2)
    after = slc.head_state.head_digest()
    assert before != after                       # necessary-but-not-sufficient red line

    # Fixture self-assertion (pre-run): the sync set for THIS red DOES carry G's
    # revocation artifact -- the deliver leg is actually wired to deliver.
    assert GRANT_ID in _sync_set_revoked_ids(slc)

    # The relay delivers the revocation artifact (default) -> REVOKED.
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope(), request_id="r1"),
                           expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_revoked"


def test_red_b_revocation_artifact_withheld_is_denied_no_grant():
    slc = make_slice()
    ok = slc.gate.authorize(slc.request(slc.grant_envelope(), request_id="r0"),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"

    slc.service.revoke(GRANT_ID)                 # SAME action, SAME resulting head
    # ...but the relay DROPS the revocation artifact. The head still omits G, so
    # the grant is absent -- with no artifact the outcome is NO_GRANT, not REVOKED.
    slc.service.withhold_revocations()

    # Fixture self-assertion (pre-run): the sync set for THIS red does NOT carry
    # G's revocation artifact -- the withhold leg is actually wired to withhold, so
    # the NO_GRANT below is genuinely the artifact-absent path, not a leaked fixture.
    assert GRANT_ID not in _sync_set_revoked_ids(slc)

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope(), request_id="r1"),
                           expected_action_digest=PAYLOAD_DIGEST)
    entry = _last(slc)
    assert entry["code"] == "denied_no_grant"
    assert entry["detail"] == "inactive_in_verified_head"


def test_supersede_denies_old_version_via_membership():
    slc = make_slice()
    slc.service.supersede(GRANT_ID, new_version=2)   # head now lists GRANT_ID at v2
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope(grant_version="1")),
                           expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_superseded"


# --- high-water anti-rollback (§4-2) -----------------------------------------

def test_synced_head_below_high_water_is_version_regress():
    # The Gateway already accepted state_version 2 (HW=2); a relay that withholds
    # the newer head and serves v1 cannot roll authorization back.
    slc = make_slice(high_water_mark=HighWaterMark(initial=2))  # head is at v1
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope()),
                           expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_version_regress"


def test_head_at_or_above_high_water_is_accepted_control():
    # control: a synced head at exactly the high-water mark is accepted.
    slc = make_slice(high_water_mark=HighWaterMark(initial=1))  # head is at v1
    ok = slc.gate.authorize(slc.request(slc.grant_envelope()),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"


# --- §4.6 fail-closed: local safety state unavailable -> denied_state_unavailable

class _FailingHighWaterMark:
    """A HW double whose reads fail -- models corrupt/lost local safety state."""

    def get(self) -> int:
        raise RuntimeError("high-water state unavailable")

    def raise_to(self, version_int: int) -> None:
        raise RuntimeError("high-water state unavailable")


class _FailingConsumer:
    def consume_once(self, key: str, action_digest: str) -> bool:
        raise RuntimeError("consume state unavailable")


def test_high_water_read_failure_fails_closed():
    slc = make_slice(high_water_mark=_FailingHighWaterMark())
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope()),
                           expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_state_unavailable"


def test_request_consumer_failure_fails_closed():
    slc = make_slice(request_consumer=_FailingConsumer())
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope()),
                           expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_state_unavailable"


def test_decision_consumer_failure_fails_closed():
    slc = make_slice(decision_consumer=_FailingConsumer())
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope()),
                           expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_state_unavailable"


# --- forged/withheld head signature -> denied_invalid_artifact ---------------

def test_head_signed_by_wrong_key_is_refused():
    # A relay that ships a head signed by a key other than the pinned user-root
    # cannot get it accepted, even if well-formed.
    slc = make_slice()
    wrong_priv, _ = new_keypair()
    forged_head_state = HeadState(wrong_priv, {GRANT_ID: "1"})
    # Replace the relay's head with one signed by the wrong key.
    slc.sync_source._head_state = forged_head_state  # type: ignore[attr-defined]
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope()),
                           expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_invalid_artifact"
