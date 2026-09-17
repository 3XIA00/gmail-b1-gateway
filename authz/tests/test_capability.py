"""Grant.body + envelope parsing: fail-closed, and the approval/subject/scope
boundaries (L5 §1/§2)."""

from __future__ import annotations

import pytest

from authz.capability import (
    ApprovalMode,
    SubjectKind,
    parse_envelope,
    parse_grant_body,
    signing_input,
)
from authz.errors import DETAIL_MISSING_APPROVAL_MODE, CertificateError

from ._fixtures import agent_subject, grant_body, new_keypair, pubkey_hex

_IFP = "issuer-fp-fixture"


def test_auto_permits_auto():
    g = parse_grant_body(grant_body(issuer_fp=_IFP, approval_mode="auto"))
    assert g.approval_mode is ApprovalMode.AUTO and g.permits_auto is True


def test_per_call_does_not_permit_auto():
    g = parse_grant_body(grant_body(issuer_fp=_IFP, approval_mode="per_call"))
    assert g.approval_mode is ApprovalMode.PER_CALL and g.permits_auto is False


def test_missing_approval_mode_raises_with_detail():
    with pytest.raises(CertificateError) as ei:
        parse_grant_body(grant_body(issuer_fp=_IFP, include_approval_mode=False))
    assert ei.value.detail == DETAIL_MISSING_APPROVAL_MODE


def test_unknown_approval_mode_refused():
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, approval_mode="whenever"))


def test_unknown_subject_kind_refused():
    body = grant_body(issuer_fp=_IFP, subject={"kind": "root"})
    with pytest.raises(CertificateError):
        parse_grant_body(body)


def test_os_account_subject_parses():
    g = parse_grant_body(grant_body(issuer_fp=_IFP))
    assert g.subject.kind is SubjectKind.OS_ACCOUNT
    assert g.subject.account == "acct-1"


def test_agent_key_subject_requires_pubkey_and_slug():
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, subject={"kind": "agent_key"}))


def test_agent_key_subject_parses():
    _, pub = new_keypair()
    g = parse_grant_body(grant_body(issuer_fp=_IFP, subject=agent_subject(pub, "bob")))
    assert g.subject.kind is SubjectKind.AGENT_KEY
    assert g.subject.agent_pubkey_hex == pubkey_hex(pub)
    assert g.subject.agent_slug == "bob"


def test_tool_action_closed_enum():
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, tool="calendar"))
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, action="read"))


def test_scope_rejects_unknown_keys():
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(
            issuer_fp=_IFP, scope={"from_account": "me@x", "cc": "y@x"}))


def test_scope_requires_from_account():
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, scope={}))


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("grant_id"),
    lambda d: d.update(grant_version="one"),   # not decimal
    lambda d: d.pop("issuer_fp"),
    lambda d: d.update(valid_from="soon"),
    lambda d: d.update(valid_until="2020-01-01T00:00:00"),  # naive, no tz
    lambda d: d.pop("subject"),
])
def test_malformed_grant_fails_closed(mutate):
    d = grant_body(issuer_fp=_IFP)
    mutate(d)
    with pytest.raises(CertificateError):
        parse_grant_body(d)


def test_valid_until_before_valid_from_refused():
    from ._fixtures import NOW
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(
            issuer_fp=_IFP, valid_from=NOW + 100, valid_until=NOW - 100))


# --- envelope + domain-separated signing -----------------------------------

def test_envelope_parses_and_signing_input_is_domain_separated():
    body = grant_body(issuer_fp=_IFP)
    priv, _ = new_keypair()
    sig = priv.sign(signing_input("grant", body))
    env = {"v": 1, "type": "grant", "body": body, "sig": sig.hex()}
    typ, parsed_body, parsed_sig = parse_envelope(env)
    assert typ == "grant" and parsed_body == body and parsed_sig == sig
    # A grant signature is not valid for a different artifact type (domain sep).
    assert signing_input("grant", body) != signing_input("revocation", body)


@pytest.mark.parametrize("env", [
    {"v": 2, "type": "grant", "body": {}, "sig": "00"},   # wrong version
    {"v": 1, "type": "", "body": {}, "sig": "00"},        # empty type
    {"v": 1, "type": "grant", "body": "x", "sig": "00"},  # body not object
    {"v": 1, "type": "grant", "body": {}, "sig": "zz"},   # sig not hex
])
def test_malformed_envelope_fails_closed(env):
    with pytest.raises(CertificateError):
        parse_envelope(env)


# --- closed schemas: unknown keys are refused, not ignored (finding 1) -----

def test_envelope_rejects_unknown_top_level_key():
    # An extra key rides alongside {v,type,body,sig} -> refused, so nothing
    # unsigned can be smuggled in the envelope.
    body = grant_body(issuer_fp=_IFP)
    priv, _ = new_keypair()
    sig = priv.sign(signing_input("grant", body))
    env = {"v": 1, "type": "grant", "body": body, "sig": sig.hex(), "extra": 1}
    with pytest.raises(CertificateError):
        parse_envelope(env)


def test_grant_body_rejects_unknown_key():
    body = grant_body(issuer_fp=_IFP)
    body["priority"] = "high"          # not in the closed grant.body schema
    with pytest.raises(CertificateError):
        parse_grant_body(body)


def test_os_account_subject_rejects_agent_key_field():
    # An os_account subject must not carry agent_key fields (or vice versa):
    # closed per-kind schema, so keys can't smuggle across kinds.
    body = grant_body(issuer_fp=_IFP, subject={
        "kind": "os_account", "machine_id": "m1", "account": "acct-1",
        "agent_pubkey": "deadbeef"})
    with pytest.raises(CertificateError):
        parse_grant_body(body)


def test_agent_key_subject_rejects_os_account_field():
    _, pub = new_keypair()
    subj = agent_subject(pub, "bob")
    subj["machine_id"] = "m1"          # os_account field on an agent_key subject
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, subject=subj))


@pytest.mark.parametrize("bad_id", [
    "00112233445566778899aabbccddeef",     # 31 chars (too short)
    "00112233445566778899aabbccddeeff00",  # 34 chars (too long)
    "00112233445566778899AABBCCDDEEFF",     # uppercase
    "00112233445566778899aabbccddeegg",     # non-hex chars
])
def test_grant_id_must_be_128_bit_lowercase_hex(bad_id):
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, grant_id=bad_id))


@pytest.mark.parametrize("bad_version", [
    "01",          # leading zero -> not canonical
    "１",      # unicode digit ONE (str.isdigit() would accept it)
    "1_000",       # underscore
    " 1",          # leading space
])
def test_version_must_be_canonical_ascii_decimal(bad_version):
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, grant_version=bad_version))
    with pytest.raises(CertificateError):
        parse_grant_body(grant_body(issuer_fp=_IFP, state_version=bad_version))


def test_zero_version_is_canonical():
    # "0" itself IS canonical (only LEADING zeros are refused).
    g = parse_grant_body(grant_body(issuer_fp=_IFP, grant_version="0"))
    assert g.grant_version == "0" and g.grant_version_int == 0
