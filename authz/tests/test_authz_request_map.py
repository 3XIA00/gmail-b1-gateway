"""Step ②/③ request map + response deadline (seam-split rebuild 2026-09-05).

Covers the §2/§5 request-envelope checks the Gateway now owns and the §1 security
clock:

  * agent_key request-envelope freshness (issued_at ±5 min) and channel-binding
    echo -- both real reds at the agent_key tier;
  * the Gateway MONOTONIC response deadline: a late response is discarded even
    with a valid signature and a FRESH decided_at, proving the security clock is
    the Gateway's monotonic clock and NOT decided_at (the adversary's domain).

The deadline is exercised with a SCRIPTED monotonic clock (injected values), so
the assertion moves the exact variable it claims to test -- never a real sleep,
so it can never be a timing-based false-green (true on 3.10/3.12 by luck).
"""

from __future__ import annotations

import pytest

from authz.errors import AuthorizationDenied
from authz.service import RESPONSE_DEADLINE_NS

_SECOND_NS = 1_000_000_000

from ._fixtures import (
    NOW,
    PAYLOAD_DIGEST,
    FakeMonotonic,
    agent_subject,
    make_slice,
    new_keypair,
)


def _last(slc):
    return slc.authz_audit.entries()[-1]


def _agent_slice():
    slc = make_slice()
    agent_priv, agent_pub = new_keypair()
    env = slc.grant_envelope(subject=agent_subject(agent_pub))
    return slc, agent_priv, env


# --- agent_key request-envelope freshness (issued_at ±5 min) -----------------

def test_stale_issued_at_is_refused():
    slc, agent_priv, env = _agent_slice()
    req = slc.request(env, agent_priv=agent_priv, issued_at=NOW - 3600)  # 1h stale

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
    last = _last(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "issued_at_out_of_window"


def test_future_issued_at_is_refused():
    slc, agent_priv, env = _agent_slice()
    req = slc.request(env, agent_priv=agent_priv, issued_at=NOW + 3600)

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["detail"] == "issued_at_out_of_window"


def test_issued_at_within_window_control_sends():
    slc, agent_priv, env = _agent_slice()
    req = slc.request(env, agent_priv=agent_priv, issued_at=NOW - 100)  # within 5min
    ok = slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"


# --- channel-binding echo (agent_key tier) -----------------------------------

def test_wrong_channel_binding_is_refused():
    slc, agent_priv, env = _agent_slice()
    # Sign a request whose channel_binding does NOT match the gate's challenge.
    req = slc.request(env, agent_priv=agent_priv, channel_binding="wrong-cb")

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
    last = _last(slc)
    assert last["code"] == "denied_invalid_artifact"
    assert last["detail"] == "channel_binding_mismatch"


# --- §1 monotonic response deadline ------------------------------------------

def test_response_past_deadline_is_discarded():
    # Scripted continuous clock (ns): mono_sent=0, mono_verified just past deadline.
    late = FakeMonotonic(values=[0, RESPONSE_DEADLINE_NS + _SECOND_NS // 2])
    slc = make_slice(continuous_clock_ns=late)

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope()),
                           expected_action_digest=PAYLOAD_DIGEST)
    # A timeout fails closed as cloud-unreachable (§1).
    assert _last(slc)["code"] == "denied_cloud_unreachable"


def test_response_within_deadline_control_authorizes():
    fast = FakeMonotonic(values=[0, RESPONSE_DEADLINE_NS - _SECOND_NS // 2])
    slc = make_slice(continuous_clock_ns=fast)
    ok = slc.gate.authorize(slc.request(slc.grant_envelope()),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"


def test_response_at_exact_deadline_boundary_authorizes():
    # Exact-boundary case (Linus 186486-6, non-blocking): the deadline is a STRICT
    # `>` (`mono_response_verified - mono_sent > RESPONSE_DEADLINE_NS`), so an
    # elapsed of EXACTLY RESPONSE_DEADLINE_NS is within budget and MUST authorize;
    # one ns more is the red in test_response_past_deadline_is_discarded. Pins the
    # inclusive `==` edge the DELTA claims, so a future `>=` regression is caught.
    edge = FakeMonotonic(values=[0, RESPONSE_DEADLINE_NS])
    slc = make_slice(continuous_clock_ns=edge)
    ok = slc.gate.authorize(slc.request(slc.grant_envelope()),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"


def test_security_clock_is_monotonic_not_decided_at():
    # The honest decision's decided_at is NOW -- INSIDE the decided_at hygiene
    # window -- yet a continuous-clock delta past the deadline still refuses it.
    # This proves the deadline reads the Gateway continuous clock, never decided_at:
    # were decided_at the security clock, this fresh-decided_at decision would pass.
    late = FakeMonotonic(values=[0, RESPONSE_DEADLINE_NS + 10 * _SECOND_NS])
    slc = make_slice(continuous_clock_ns=late)
    req = slc.request(slc.grant_envelope())

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
    # Not decided_at_out_of_window (decided_at is fresh) -- the continuous deadline.
    assert _last(slc)["code"] == "denied_cloud_unreachable"
    assert _last(slc)["detail"] != "decided_at_out_of_window"


def test_late_response_kills_the_request_id():
    # A request whose response missed the deadline is dead: the (grant_id,
    # request_id) was consumed before the cloud call, so a retry with the same
    # request_id is a replay -- the late request cannot be silently re-driven.
    late = FakeMonotonic(values=[0, RESPONSE_DEADLINE_NS + _SECOND_NS])
    slc = make_slice(continuous_clock_ns=late)
    req = slc.request(slc.grant_envelope(), request_id="stuck")

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(req, expected_action_digest=PAYLOAD_DIGEST)
    assert _last(slc)["code"] == "denied_cloud_unreachable"

    # Retry with the SAME request_id (now reachable in time) -> request replay.
    slc.gate._clock = FakeMonotonic(step=0.0)  # responses are timely again
    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope(), request_id="stuck"),
                           expected_action_digest=PAYLOAD_DIGEST)
    last = _last(slc)
    assert last["code"] == "denied_replay"
    assert last["detail"] == "request_id_reused"


# --- R8: the deadline covers response VERIFICATION, not just the round trip ---
#
# The old order read the endpoint clock right after decide() and left signature
# verify / binding cross-check / decided_at hygiene OUTSIDE the deadline. Each
# stage below is monkeypatched to advance the shared continuous clock past the
# deadline; because the endpoint clock is now read AFTER all three (R8), each
# stage ALONE trips the deadline -- proving the deadline covers verification time.

class _AdvanceableClock:
    """A continuous clock (ns) that returns its current value on every read and
    moves only when a monkeypatched STAGE explicitly advances it -- so elapsed
    time is attributable to exactly one verification stage."""

    def __init__(self) -> None:
        self.t = 0

    def __call__(self) -> int:
        return self.t

    def advance(self, dt: int) -> None:
        self.t += dt


@pytest.mark.parametrize("stage", [
    "verify_decision_sig",
    "check_binding",
    "_decided_at_in_hygiene_window",
])
def test_deadline_covers_each_verification_stage(monkeypatch, stage):
    import authz.gate as gate_mod
    clock = _AdvanceableClock()
    slc = make_slice(continuous_clock_ns=clock)
    real = getattr(gate_mod, stage)

    def slow(*args, **kwargs):
        clock.advance(RESPONSE_DEADLINE_NS + 1)   # this stage alone burns the budget
        return real(*args, **kwargs)

    monkeypatch.setattr(gate_mod, stage, slow)

    with pytest.raises(AuthorizationDenied):
        slc.gate.authorize(slc.request(slc.grant_envelope()),
                           expected_action_digest=PAYLOAD_DIGEST)
    # A stage that ran over the budget fails closed as cloud-unreachable (§1),
    # NOT as a stage-specific error -- the response is simply too late.
    assert _last(slc)["code"] == "denied_cloud_unreachable"


def test_no_stage_delay_control_authorizes():
    # Positive control: with the SAME advanceable clock but no injected delay the
    # request authorizes -- so the reds above are the delay, not the harness.
    clock = _AdvanceableClock()
    slc = make_slice(continuous_clock_ns=clock)
    ok = slc.gate.authorize(slc.request(slc.grant_envelope()),
                            expected_action_digest=PAYLOAD_DIGEST)
    assert ok.decision.disposition == "authorized"
