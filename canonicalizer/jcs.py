"""RFC 8785 JSON Canonicalization Scheme (JCS) serializer.

Scope: the JSON value domain the Gmail Gateway PrepareEmail canonical
payload can contain -- objects, arrays, strings, non-negative integers,
booleans and null.

WHY NOT ``json.dumps(sort_keys=True, ...)``:
    That sorts object keys by Unicode code point and would diverge from
    JCS on supplementary-plane keys, which JCS orders by *UTF-16 code
    unit*. DESIGN.md v0.1 sec 8.5 explicitly forbids a generic key-sorting
    serializer in the production impl; it only agrees with JCS on the two
    frozen fixtures because those avoid non-ASCII keys, non-integer
    numbers and special control characters. This module implements the
    real JCS rules so it stays correct beyond those two fixtures.

NUMBER DOMAIN:
    The canonical payload's only number is an attachment ``size`` (a
    non-negative integer). Full JCS number output for non-integers is the
    ECMAScript shortest-round-trip double algorithm; implementing it
    half-correctly is worse than not at all, so non-integer numbers are
    rejected as out-of-domain (fail closed) rather than served. Integers
    are restricted to the ECMAScript safe-integer range for the same
    reason (beyond it, ECMAScript treats the value as a double).
"""

from __future__ import annotations

import hashlib

# ECMAScript Number.MAX_SAFE_INTEGER; beyond this integers are doubles.
_MAX_SAFE_INTEGER = 2 ** 53 - 1

# JCS / ECMAScript JSON.stringify two-char escapes.
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: "\\\"",
    0x5C: "\\\\",
}


class JcsError(ValueError):
    """Value outside the supported JCS serialization domain."""


def _serialize_string(s: str) -> str:
    # JCS strings: escape ", \\ and C0 controls (short form where defined,
    # else lowercase \\u00xx); every other code point -- including all
    # non-ASCII -- is emitted literally and carried by the UTF-8 encode.
    out = ["\""]
    for ch in s:
        cp = ord(ch)
        short = _SHORT_ESCAPES.get(cp)
        if short is not None:
            out.append(short)
        elif cp < 0x20:
            out.append("\\u%04x" % cp)
        else:
            out.append(ch)
    out.append("\"")
    return "".join(out)


def _serialize_number(value: int) -> str:
    # bool is handled by the caller (it is a subtype of int in Python).
    if not isinstance(value, int):
        raise JcsError(
            "non-integer number %r is out of the canonical payload number "
            "domain (only integer attachment sizes occur)" % (value,)
        )
    if abs(value) > _MAX_SAFE_INTEGER:
        raise JcsError(
            "integer %d exceeds the ECMAScript safe-integer range and is "
            "out of the canonical payload number domain" % value
        )
    return str(value)


def _utf16_sort_key(key: str) -> bytes:
    # JCS orders members by UTF-16 code units. Lexicographic comparison of
    # UTF-16 big-endian byte strings reproduces code-unit order exactly
    # (each unit is one big-endian 16-bit value).
    if not isinstance(key, str):
        raise JcsError(
            "object keys must be strings, got %r" % type(key).__name__
        )
    return key.encode("utf-16-be")


def _serialize(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, float):
        return _serialize_number(value)  # raises: out of domain
    if isinstance(value, int):
        return _serialize_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        members = sorted(value.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        return (
            "{"
            + ",".join(
                _serialize_string(k) + ":" + _serialize(v) for k, v in members
            )
            + "}"
        )
    raise JcsError("unsupported value type: %r" % type(value).__name__)


def canonicalize(value) -> bytes:
    """Return the RFC 8785 (JCS) UTF-8 byte serialization of ``value``."""
    return _serialize(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Lowercase-hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()


def digest(value) -> str:
    """Lowercase-hex SHA-256 of the JCS UTF-8 bytes of ``value``."""
    return sha256_hex(canonicalize(value))
