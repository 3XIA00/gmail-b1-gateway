"""Property and boundary tests for the JCS serializer and normalization.

These actuate the specific variables that separate a real JCS impl from a
generic key-sorting serializer (the one DESIGN.md sec 8.5 forbids in
production): UTF-16 vs code-point key order, JCS string escaping, the
integer-only number domain, and normalization invariants.
"""

import pytest
from hypothesis import given, strategies as st

from canonicalizer.jcs import canonicalize, digest, JcsError
from canonicalizer.payload import (
    build_canonical_payload,
    payload_digest,
    enforce_v1_send_policy,
    AttachmentsNotSupportedError,
    PayloadSchemaError,
)


# --- JCS structural correctness -------------------------------------------

def test_object_key_order_is_utf16_not_codepoint():
    # U+FFFF is one UTF-16 unit (0xFFFF); U+10000 is the surrogate pair
    # (0xD800, 0xDC00). By code point FFFF < 10000, but by UTF-16 code unit
    # 0xD800 < 0xFFFF, so the supplementary key must sort FIRST. A generic
    # code-point sort would place it last -- this asserts real JCS order.
    out = canonicalize({"￿": 1, "\U00010000": 2}).decode("utf-8")
    assert out.index("\U00010000") < out.index("￿")


def test_string_escaping_rules():
    s = "\b\t\n\f\r\"\\\x00\x1f"
    out = canonicalize(s).decode("utf-8")
    assert out == '"\\b\\t\\n\\f\\r\\"\\\\\\u0000\\u001f"'


def test_non_ascii_emitted_as_raw_utf8():
    out = canonicalize("café 😀")
    assert b"\\u" not in out                     # no \u escaping
    assert "😀".encode("utf-8") in out
    assert "é".encode("utf-8") in out


def test_no_insignificant_whitespace():
    out = canonicalize({"a": [1, 2], "b": {"c": 3}}).decode("utf-8")
    assert out == '{"a":[1,2],"b":{"c":3}}'


# --- number domain --------------------------------------------------------

def test_integers_serialize_plainly():
    assert canonicalize(3) == b"3"
    assert canonicalize(0) == b"0"
    assert canonicalize(-5) == b"-5"


def test_non_integer_number_rejected():
    with pytest.raises(JcsError):
        canonicalize(1.5)


def test_unsafe_integer_rejected():
    with pytest.raises(JcsError):
        canonicalize(2 ** 53)


def test_bool_and_null():
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(None) == b"null"


# --- normalization invariants ---------------------------------------------

_BASE = {
    "account_handle": "gmail:test-account",
    "to": ["recipient@example.test"],
    "subject": "s",
    "body": {"format": "text", "content": "c"},
}


def test_idempotency_key_excluded_from_digest():
    with_key = dict(_BASE, idempotency_key="abc-123")
    assert payload_digest(with_key) == payload_digest(_BASE)


def test_unknown_field_rejected():
    with pytest.raises(PayloadSchemaError):
        build_canonical_payload(dict(_BASE, raw_mime="From: x"))


def test_unknown_attachment_field_rejected():
    bad = dict(
        _BASE,
        attachments=[{
            "name": "a", "media_type": "text/plain",
            "content_ref": "local-object:x", "sha256": "0" * 64,
            "size": 1, "headers": {"X": "y"},
        }],
    )
    with pytest.raises(PayloadSchemaError):
        build_canonical_payload(bad)


def test_v1_rejects_non_empty_attachments():
    canonical = build_canonical_payload(dict(
        _BASE,
        attachments=[{
            "name": "a", "media_type": "text/plain",
            "content_ref": "local-object:x", "sha256": "0" * 64, "size": 1,
        }],
    ))
    with pytest.raises(AttachmentsNotSupportedError):
        enforce_v1_send_policy(canonical)


def test_v1_accepts_empty_slot():
    enforce_v1_send_policy(build_canonical_payload(_BASE))  # no raise


# --- hypothesis properties -------------------------------------------------

@given(st.dictionaries(
    st.text(),
    st.integers(min_value=-(2 ** 53) + 1, max_value=2 ** 53 - 1),
    max_size=8,
))
def test_digest_invariant_to_key_insertion_order(d):
    reordered = dict(reversed(list(d.items())))
    assert digest(d) == digest(reordered)


@given(st.text(), st.text())
def test_distinct_subjects_give_distinct_digest(s1, s2):
    if s1 == s2:
        return
    p1 = dict(_BASE, subject=s1)
    p2 = dict(_BASE, subject=s2)
    assert payload_digest(p1) != payload_digest(p2)


@given(
    st.lists(st.text(), max_size=4),
    st.lists(st.text(), max_size=4),
)
def test_cc_bcc_omitted_equals_empty(cc, bcc):
    # Empty lists must normalize identically to omission.
    if cc or bcc:
        return
    explicit = dict(_BASE, cc=[], bcc=[])
    assert payload_digest(_BASE) == payload_digest(explicit)
