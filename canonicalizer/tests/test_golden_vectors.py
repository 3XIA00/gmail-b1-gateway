"""Golden-vector reproduction for the M2 canonicalizer.

These are the IMPLEMENTER's self-verification. Independent acceptance
(sec 8.4) is 测试姬's seat: she constructs the A/B inputs independently
from DESIGN.md's code-point sequences, runs THIS real JCS impl, and
compares to the frozen golden values. The frozen values are always the
oracle -- never this test's fixtures.

Vector B's three Unicode fields are built from the DESIGN.md code-point
sequences, not from copied glyphs, so an editor's NFC/NFD normalization
cannot silently alter the scalars under test.
"""

from canonicalizer.jcs import canonicalize
from canonicalizer.payload import build_canonical_payload, payload_digest

VECTOR_A_BYTES = 208
VECTOR_A_DIGEST = "4fd1ec7eca2244bfda40ed3255e575428db5ee46e4a1cd2da9ebd3b42cc38c7a"
VECTOR_B_BYTES = 388
VECTOR_B_DIGEST = "8a0410875447f7ad0f2354e6f5ccc6b6200cebc564d9d1750ffd979af382c26b"


def _cp(*codepoints: int) -> str:
    return "".join(chr(c) for c in codepoints)


# DESIGN.md sec 8.5 canonical code-point sequences for vector B.
SUBJECT_B = _cp(
    0x4E3B, 0x9898, 0x0020, 0x1F600, 0x0020, 0x2014, 0x0020,
    0x0072, 0x00E9, 0x0073, 0x0075, 0x006D, 0x00E9,
)
BODY_B = _cp(
    0x6B63, 0x6587, 0x0020, 0x1F600, 0x0020, 0x2014, 0x0020,
    0x0063, 0x0061, 0x0066, 0x00E9,
)
NAME_B = _cp(
    0x9644, 0x4EF6, 0x002D, 0x1F600, 0x002D, 0x0072, 0x00E9,
    0x0073, 0x0075, 0x006D, 0x00E9, 0x002E, 0x0074, 0x0078, 0x0074,
)


def test_vector_a_empty_attachment_slot():
    # cc / bcc / attachments omitted -> normalized to [].
    prepare = {
        "account_handle": "gmail:test-account",
        "to": ["recipient@example.test"],
        "subject": "Digest fixture: empty attachments",
        "body": {"format": "text", "content": "Plain text fixture."},
    }
    canonical_bytes = canonicalize(build_canonical_payload(prepare))
    assert len(canonical_bytes) == VECTOR_A_BYTES
    assert payload_digest(prepare) == VECTOR_A_DIGEST


def test_vector_b_populated_slot_and_unicode():
    prepare = {
        "account_handle": "gmail:test-account",
        "to": ["recipient@example.test"],
        "cc": [],
        "bcc": [],
        "subject": SUBJECT_B,
        "body": {"format": "text", "content": BODY_B},
        "attachments": [
            {
                "name": NAME_B,
                "media_type": "text/plain",
                "content_ref": "local-object:fixture-001",
                "sha256": "0" * 64,
                "size": 3,
            }
        ],
    }
    canonical_bytes = canonicalize(build_canonical_payload(prepare))
    assert len(canonical_bytes) == VECTOR_B_BYTES
    assert payload_digest(prepare) == VECTOR_B_DIGEST


def test_omit_vs_empty_slots_same_digest():
    # DESIGN.md sec 8.5: omitted attachments and [] must normalize equal.
    base = {
        "account_handle": "gmail:test-account",
        "to": ["recipient@example.test"],
        "subject": "Digest fixture: empty attachments",
        "body": {"format": "text", "content": "Plain text fixture."},
    }
    explicit = dict(base, attachments=[], cc=[], bcc=[])
    assert payload_digest(base) == payload_digest(explicit) == VECTOR_A_DIGEST
