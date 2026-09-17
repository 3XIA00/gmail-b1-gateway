"""authz_state_digest KAT oracle + the digest-preimage red (2026-09-05).

The §4/R3 binding is ``authz_state_digest = SHA-256(JCS(head.body))`` -- one byte
domain, the same canonical byte string the head signature is over, no projection
(Jeff 186163). This file pins that with a KNOWN-ANSWER TEST whose oracle is
INDEPENDENT of the code under test, and proves ``active_grants`` is inside the
digest preimage at two levels (Boris 186137: function-level + Gateway-level).

D0/D1 PROVENANCE (declare on every change -- Boris 186172 / Jeff 186170):
  * B0 and B1 below are the EXACT head bodies. B1 is byte-identical to B0 except
    it adds ONE unrelated grant ``G_OTHER`` to active_grants; the referenced grant
    (G, "1") and state_version are byte-identical between them (the green legs).
  * JCS_B0/JCS_B1 and D0/D1 were derived TEST-SIDE by an INDEPENDENT oracle --
    stdlib ``json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)``
    then SHA-256 -- NOT by ``canonicalizer.jcs`` (the code under test) and NOT read
    back from the Gateway. For these ASCII-only, integer-free bodies that stdlib
    canonicalization equals RFC 8785 JCS (see canonicalizer/jcs.py docstring), so
    it is a valid independent oracle. ``test_kat_constants_self_consistent`` proves
    the pinned constants match that oracle; ``test_production_digest_matches_kat``
    is the positive control that the code under test equals the oracle. If B0/B1
    ever change, RE-DERIVE D0/D1 independently (never backfill via the digest
    function under test -- that degrades the oracle to f(x)==f(x)).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from authz.audit import AuthzAuditLog
from authz.errors import AuthorizationDenied
from authz.gate import AuthorizationGate
from authz.service import (
    AuthorizationRequest,
    StubDecisionService,
    decision_signing_input,
)
from authz.state import HeadState, StubSyncSource, head_body
from canonicalizer.jcs import digest as authz_digest
from store.backend import InMemoryAppendLog

from ._fixtures import (
    CHANNEL_CHALLENGE,
    GATEWAY_ACCOUNT,
    GRANT_ID,
    NOW,
    PAYLOAD_DIGEST,
    PEER_ACCOUNT,
    PEER_MACHINE_ID,
    FakeMonotonic,
    grant_body,
    issuer_fp_of,
    new_keypair,
    sign_grant,
)

G_OTHER = "ffffffffffffffffffffffffffffffff"   # an UNRELATED grant, only in B1

# --- the exact paired head bodies (fixture-only manifest quotes these) --------
B0 = head_body("1", [(GRANT_ID, "1")])
B1 = head_body("1", [(GRANT_ID, "1"), (G_OTHER, "1")])

# --- pinned KAT constants (independent oracle; see PROVENANCE above) -----------
JCS_B0 = (b'{"active_grants":[{"grant_id":"00112233445566778899aabbccddeeff",'
          b'"grant_version":"1"}],"state_version":"1"}')
D0 = "b1240c7258634087220e7f0f4c573d3884544553743eb32b6bdbeec2fb757ca8"
JCS_B1 = (b'{"active_grants":[{"grant_id":"00112233445566778899aabbccddeeff",'
          b'"grant_version":"1"},{"grant_id":"ffffffffffffffffffffffffffffffff",'
          b'"grant_version":"1"}],"state_version":"1"}')
D1 = "f4e41db13d116396d8de0dc2fda17f619f358e794cf0c3103818178b0bbbf250"


def _independent_jcs(body: dict) -> bytes:
    """Independent canonicalizer: stdlib json, NOT canonicalizer.jcs. Valid as an
    oracle only for the ASCII-only, integer-free bodies here (see PROVENANCE)."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# --- the KAT itself -----------------------------------------------------------

def test_kat_constants_self_consistent():
    # The pinned constants match the INDEPENDENT oracle over the exact B0/B1.
    assert _independent_jcs(B0) == JCS_B0
    assert hashlib.sha256(JCS_B0).hexdigest() == D0
    assert _independent_jcs(B1) == JCS_B1
    assert hashlib.sha256(JCS_B1).hexdigest() == D1


def test_production_digest_matches_kat():
    # Positive control: the code under test == the independent KAT oracle. Without
    # this, a negative red proves nothing about the production digest.
    assert authz_digest(B0) == D0
    assert authz_digest(B1) == D1


def test_active_grants_is_inside_digest_preimage_function_level():
    # Function-level preimage red: B0 and B1 differ ONLY in active_grants (an extra
    # unrelated grant), yet their digests differ -> active_grants IS inside the
    # SHA-256(JCS(body)) preimage. Were it not, D0 would equal D1 and the whole
    # membership/head binding would be decorative (Boris 186137).
    assert D0 != D1
    assert authz_digest(B0) != authz_digest(B1)
    # ...with the OTHER legs held byte-identical (the "green legs"):
    assert B0["state_version"] == B1["state_version"]                    # version leg
    ref = {"grant_id": GRANT_ID, "grant_version": "1"}
    assert ref in B0["active_grants"] and ref in B1["active_grants"]     # referenced grant unchanged
    assert B1["active_grants"] == B0["active_grants"] + [
        {"grant_id": G_OTHER, "grant_version": "1"}]                     # sole diff = unrelated grant


# --- Gateway-level preimage red -----------------------------------------------
# Construction per the corrected extract (76564ec0…, §4) / Jeff msg_6e582e2d:
# ONLY B1 is signed and delivered; D0 is computed OFFLINE as a test constant and
# is NEVER instantiated as a second signed head at the same state_version (that
# would be an impossible "same-version double head"). The negative control just
# swaps the decision's authz_state_digest to the D0 CONSTANT on an otherwise
# byte-honest decision over B1, isolating the digest as the sole moving variable.


class _DigestPinnedDecisionService:
    """Wraps the honest decision service but overwrites the emitted decision's
    ``authz_state_digest`` with a PINNED test constant, re-signing with the SAME
    decision key so the gate's signature leg stays green. This is the "B0 离线算
    D0 不投递" construction: no second signed head exists; the decision differs
    from the honest one in exactly one field."""

    def __init__(self, inner: StubDecisionService, signing_key: Ed25519PrivateKey,
                 pinned_digest: str):
        self._inner = inner
        self._key = signing_key
        self._pinned = pinned_digest

    @property
    def decision_public_key(self):
        return self._inner.decision_public_key

    def decide(self, request, *, now):
        d = self._inner.decide(request, now=now)
        d = replace(d, authz_state_digest=self._pinned, sig=b"")
        return replace(d, sig=self._key.sign(decision_signing_input(d)))


def _gate_over_b1(pinned_decision_digest: str):
    """A gate that SYNCS + accepts head B1 (digest D1), whose decision is honest in
    every field EXCEPT authz_state_digest, which is pinned to
    ``pinned_decision_digest``. Only hs1 (B1) is ever signed/delivered."""
    user_priv, user_pub = new_keypair()
    issuer_fp = issuer_fp_of(user_pub)
    hs1 = HeadState(user_priv, {GRANT_ID: "1", G_OTHER: "1"}, state_version_int=1)  # B1/D1
    dkey = Ed25519PrivateKey.generate()
    inner = StubDecisionService(hs1, decision_signing_key=dkey)
    decision_service = _DigestPinnedDecisionService(inner, dkey, pinned_decision_digest)
    audit = AuthzAuditLog(InMemoryAppendLog())
    gate = AuthorizationGate(
        decision_service, StubSyncSource(hs1), audit,
        user_root_public_key=user_pub, pinned_issuer_fp=issuer_fp,
        gateway_account=GATEWAY_ACCOUNT, now=lambda: NOW,
        continuous_clock_ns=FakeMonotonic(step=0.0),
        channel_challenge=CHANNEL_CHALLENGE)
    env = sign_grant(user_priv, grant_body(issuer_fp=issuer_fp))
    return gate, audit, env


def _os_request(env, *, authz_state_digest):
    return AuthorizationRequest(
        grant_envelope=env, request_id="kat-1", action_digest=PAYLOAD_DIGEST,
        authz_state_digest=authz_state_digest, issued_at=NOW,
        channel_binding=CHANNEL_CHALLENGE, peer_verified=True,
        peer_machine_id=PEER_MACHINE_ID, peer_account=PEER_ACCOUNT)


def test_gateway_digest_binding_positive_control():
    # Control: sync head B1 AND decision digest pinned to the D1 CONSTANT -> every
    # one of the five legs is green [head sig / decision sig / state_version /
    # membership / sync-set fact] AND the digest matches -> authorized. This both
    # pins the five green legs for the red below and proves the D1 KAT constant
    # equals what the gate derives live from B1.
    gate, _audit, env = _gate_over_b1(D1)
    ok = gate.authorize(_os_request(env, authz_state_digest=D1),
                        expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"
    assert ok.decision.authz_state_digest == D1


def test_gateway_stale_digest_is_decision_head_mismatch():
    # Red: sync head B1 (digest D1) but the decision's authz_state_digest is the
    # OLD B0 constant D0 -- every other field is byte-honest over B1 (valid decision
    # sig, state_version "1" == accepted head, G active, no revocation in the sync
    # set). The five legs are green (the positive control above proves it); the
    # ONLY moved variable is the digest. Since D0 != D1 comes purely from
    # active_grants, this attributes uniquely to the digest<->head binding.
    gate, audit, env = _gate_over_b1(D0)
    with pytest.raises(AuthorizationDenied):
        gate.authorize(_os_request(env, authz_state_digest=D0),
                       expected_action_digest=PAYLOAD_DIGEST)
    entry = audit.entries()[-1]
    assert entry["code"] == "denied_invalid_artifact"
    assert entry["detail"] == "decision_head_mismatch"
