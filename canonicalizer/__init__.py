"""Gmail Gateway payload canonicalizer (M2).

Implements the RFC 8785 (JCS) canonicalization + SHA-256 digest that the
Gmail Gateway confirm-then-send flow pins in DESIGN.md v0.1 §5.1 / §8.5.

Public surface:
    jcs.canonicalize(value) -> bytes        # RFC 8785 JCS UTF-8 bytes
    jcs.digest(value) -> str                # lowercase-hex SHA-256 of JCS bytes
    payload.build_canonical_payload(prepare) -> dict
    payload.payload_digest(prepare) -> str
    payload.enforce_v1_send_policy(canonical) -> None
"""

from .jcs import canonicalize, digest, sha256_hex, JcsError
from .payload import (
    build_canonical_payload,
    payload_digest,
    enforce_v1_send_policy,
    AttachmentsNotSupportedError,
)

__all__ = [
    "canonicalize",
    "digest",
    "sha256_hex",
    "JcsError",
    "build_canonical_payload",
    "payload_digest",
    "enforce_v1_send_policy",
    "AttachmentsNotSupportedError",
]
