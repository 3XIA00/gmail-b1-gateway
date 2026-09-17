"""Tests for the action-set projection.

These actuate the two release-gate variables the module owns:
  - gate 4 (parameter-level closed action set): the ONLY entry into content
    is the M2 closed schema; nothing bypasses it, and the action *name* set
    is itself closed;
  - gate 7 (confirm / auto-send switch): no Agent-reachable write path.
Plus the Chris code-time (1) invariant: the projection is not an expansion
-- known fields round-trip and its digest is byte-identical to the accepted
canonicalizer's.
"""

import dataclasses

import pytest
from hypothesis import given, strategies as st

from canonicalizer.payload import (
    AttachmentsNotSupportedError,
    PayloadSchemaError,
    payload_digest,
)
from actionset.catalog import AGENT_ACTIONS, PREPARE_EMAIL, require_agent_action
from actionset.errors import UnknownActionError
from actionset.prepare import PrepareEmailResult, prepare_email
from actionset.switch import ActionSet, SwitchMode


_BASE = {
    "account_handle": "gmail:test-account",
    "to": ["recipient@example.test"],
    "subject": "s",
    "body": {"format": "text", "content": "c"},
}

# The set of top-level fields the M2 schema accepts (used to generate
# fields that must be *rejected*).
_ALLOWED_TOP = {
    "account_handle", "to", "cc", "bcc", "subject", "body",
    "attachments", "idempotency_key",
}

_FIXED_ID = lambda: "pid-fixed"  # noqa: E731 - tiny injected factory for tests


# --- gate 4: action name set is a closed allow-list -----------------------

def test_only_prepare_email_is_permitted():
    assert AGENT_ACTIONS == frozenset({PREPARE_EMAIL})
    assert require_agent_action(PREPARE_EMAIL) == PREPARE_EMAIL


def test_no_send_or_dispatch_action_exists():
    # confirm-then-send: there is no Agent action that dispatches.
    for name in ("Send", "SendEmail", "DispatchEmail", "Dispatch", "Approve"):
        with pytest.raises(UnknownActionError):
            require_agent_action(name)


def test_no_switch_write_action_exists():
    # gate 7: no Agent action writes the confirm / auto-send switch.
    for name in ("SetSwitch", "SetAutoSend", "EnableAutoSend", "ConfigureSwitch"):
        with pytest.raises(UnknownActionError):
            require_agent_action(name)


@given(st.text().filter(lambda n: n != PREPARE_EMAIL))
def test_any_non_prepare_action_is_refused(name):
    with pytest.raises(UnknownActionError):
        require_agent_action(name)


# --- gate 4 / Chris (1): no bypass of the closed content schema -----------

def test_prepare_rejects_unknown_top_field():
    with pytest.raises(PayloadSchemaError):
        prepare_email(dict(_BASE, raw_mime="From: x"),
                      now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)


def test_prepare_has_no_header_or_extra_params_slot():
    for bad in ("headers", "extra_params", "extra_headers", "mime", "passthrough"):
        params = dict(_BASE)
        params[bad] = {"X": "y"}
        with pytest.raises(PayloadSchemaError):
            prepare_email(params, now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)


@given(st.text().filter(lambda k: k not in _ALLOWED_TOP))
def test_any_unknown_field_fails_closed(k):
    params = dict(_BASE)
    params[k] = "v"
    with pytest.raises(PayloadSchemaError):
        prepare_email(params, now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)


def test_known_fields_round_trip():
    full = dict(
        _BASE,
        cc=["c@example.test"],
        bcc=["b@example.test"],
        idempotency_key="idem-1",
    )
    r = prepare_email(full, now=100, ttl_seconds=300, proposal_id_factory=_FIXED_ID)
    assert isinstance(r, PrepareEmailResult)


def test_digest_is_identical_to_canonicalizer():
    # The projection must not diverge from the accepted M2 digest.
    r = prepare_email(_BASE, now=100, ttl_seconds=300, proposal_id_factory=_FIXED_ID)
    assert r.payload_digest == payload_digest(_BASE)


def test_idempotency_key_excluded_from_digest_via_projection():
    a = prepare_email(dict(_BASE, idempotency_key="k1"),
                      now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)
    b = prepare_email(_BASE, now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)
    assert a.payload_digest == b.payload_digest


# --- §2.7: message_id is injected (Gateway-minted), never Agent-supplied ---

def test_injected_message_id_enters_the_projection_digest():
    mid = "<m1@gateway.test>"
    r = prepare_email(_BASE, now=0, ttl_seconds=1,
                      proposal_id_factory=_FIXED_ID, message_id=mid)
    # The projection's digest matches the canonicalizer's for the same injected
    # ID, and differs from the no-ID digest -> the ID is in the bound bytes.
    assert r.payload_digest == payload_digest(_BASE, message_id=mid)
    assert r.payload_digest != payload_digest(_BASE)


def test_agent_supplied_message_id_is_rejected_by_projection():
    # message_id is not in the accepted top-level set (see _ALLOWED_TOP); an Agent
    # passing it through params fails closed, same as any out-of-schema field.
    assert "message_id" not in _ALLOWED_TOP
    with pytest.raises(PayloadSchemaError):
        prepare_email(dict(_BASE, message_id="<forged@evil.test>"),
                      now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)


# --- v1 attachment gate flows through the projection ----------------------

def test_v1_attachment_slot_rejected_through_projection():
    params = dict(_BASE, attachments=[{
        "name": "a", "media_type": "text/plain",
        "content_ref": "local-object:x", "sha256": "0" * 64, "size": 1,
    }])
    with pytest.raises(AttachmentsNotSupportedError):
        prepare_email(params, now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)


# --- result shape / injected clock ----------------------------------------

def test_result_fields_and_expiry():
    r = prepare_email(_BASE, now=1000, ttl_seconds=250, proposal_id_factory=_FIXED_ID)
    assert r.proposal_id == "pid-fixed"
    assert r.expires_at == 1250


def test_result_is_immutable_and_carries_no_content():
    r = prepare_email(_BASE, now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.payload_digest = "x"
    # No body/recipients leak into what the Agent gets back.
    assert set(dataclasses.asdict(r)) == {"proposal_id", "payload_digest", "expires_at"}


@pytest.mark.parametrize("bad_now", [-1, 1.5, True, "0"])
def test_now_must_be_nonneg_int(bad_now):
    with pytest.raises(ValueError):
        prepare_email(_BASE, now=bad_now, ttl_seconds=1, proposal_id_factory=_FIXED_ID)


@pytest.mark.parametrize("bad_ttl", [0, -5, 1.0, True, "1"])
def test_ttl_must_be_positive_int(bad_ttl):
    with pytest.raises(ValueError):
        prepare_email(_BASE, now=0, ttl_seconds=bad_ttl, proposal_id_factory=_FIXED_ID)


# --- gate 7: switch has no Agent-reachable write path ---------------------

def test_switch_defaults_to_confirm_then_send():
    assert ActionSet().switch_mode is SwitchMode.CONFIRM_THEN_SEND


def test_switch_mode_is_frozen():
    a = ActionSet()
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.switch_mode = SwitchMode.AUTO_SEND_WHEN_AGENT_UNREACHABLE


def test_project_refuses_switch_write_and_send_actions():
    a = ActionSet(switch_mode=SwitchMode.AUTO_SEND_WHEN_AGENT_UNREACHABLE)
    for bad in ("SetAutoSend", "SendEmail", "Dispatch"):
        with pytest.raises(UnknownActionError):
            a.project(bad, _BASE, now=0, ttl_seconds=1, proposal_id_factory=_FIXED_ID)
    # the mode did not change as a side effect of the refused calls
    assert a.switch_mode is SwitchMode.AUTO_SEND_WHEN_AGENT_UNREACHABLE


def test_project_prepare_email_matches_direct_projection():
    a = ActionSet()
    r = a.project(PREPARE_EMAIL, _BASE, now=10, ttl_seconds=5,
                  proposal_id_factory=_FIXED_ID)
    direct = prepare_email(_BASE, now=10, ttl_seconds=5, proposal_id_factory=_FIXED_ID)
    assert r == direct


def test_actions_view_is_the_closed_set():
    assert ActionSet().actions == AGENT_ACTIONS
