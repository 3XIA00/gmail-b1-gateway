"""§2.7: message_id as a Gateway-minted, digested canonical field.

These are the IMPLEMENTER's self-verification of the *mechanism* (the ID enters
the canonical and the digest; it is not Agent-suppliable). They assert RELATIONAL
properties, never a frozen "golden" digest value: a frozen expected digest for a
message_id-bearing vector is 测试姬's independent-acceptance seat (see
test_golden_vectors.py's docstring -- she constructs inputs independently and the
frozen values are the oracle). The existing VECTOR_A/B are deliberately left
untouched (they remain valid no-message_id canonical shapes).
"""

import pytest

from canonicalizer.jcs import canonicalize
from canonicalizer.payload import (
    PayloadSchemaError,
    build_canonical_payload,
    payload_digest,
)

_BASE = {
    "account_handle": "gmail:test-account",
    "to": ["recipient@example.test"],
    "subject": "s",
    "body": {"format": "text", "content": "c"},
}
_MID = "<abc.123@gateway.test>"


def test_injected_message_id_is_in_the_canonical():
    canonical = build_canonical_payload(_BASE, message_id=_MID)
    assert canonical["message_id"] == _MID
    # JCS serializes the new key like any other (UTF-16 code-unit key order); the
    # point is only that it is present in the digested bytes.
    assert b"message_id" in canonicalize(canonical)


def test_message_id_changes_the_digest():
    # Adding the ID changes the approved/authorized digest...
    assert payload_digest(_BASE) != payload_digest(_BASE, message_id=_MID)


def test_different_message_ids_give_different_digests():
    # ...and two different frozen IDs are two different digests -> a swapped ID
    # cannot match the authorization bound to the original (Jeff 205645).
    a = payload_digest(_BASE, message_id="<one@gateway.test>")
    b = payload_digest(_BASE, message_id="<two@gateway.test>")
    assert a != b


def test_absent_message_id_is_backward_compatible():
    # Omitting it yields exactly the pre-§2.7 canonical (no stray key), so the
    # frozen golden vectors stay valid.
    assert "message_id" not in build_canonical_payload(_BASE)
    assert payload_digest(_BASE) == payload_digest(_BASE, message_id=None)


def test_agent_supplied_message_id_fails_closed():
    # Supplied through the params dict (as an Agent would) it is out-of-schema and
    # rejected -- the ID is Gateway-injected via the keyword only.
    with pytest.raises(PayloadSchemaError):
        build_canonical_payload(dict(_BASE, message_id=_MID))


@pytest.mark.parametrize("bad", ["", 123, b"<x@y>", ["<x@y>"]])
def test_injected_message_id_must_be_a_nonempty_string(bad):
    with pytest.raises(PayloadSchemaError):
        build_canonical_payload(_BASE, message_id=bad)
