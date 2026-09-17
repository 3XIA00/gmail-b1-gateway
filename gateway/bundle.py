"""Load the daemon-bundled Google client, gated by a pinned content hash.

Deployment ("one-click authorize") mode ships one shared Google OAuth client
JSON inside the daemon install, instead of the operator passing
`--client-secret-file`. Before that file is ever parsed or used, its *raw bytes*
are verified against a pinned SHA-256; a one-byte mismatch fails closed with zero
side effect. This is the runtime half of the supply-chain contract -- the
load-bearing attack it denies is a swapped `client_id` in the bundled file.

Design decisions (the *why*):

- **Hash the raw file bytes, in binary, with no transcoding.** The pin is over
  `open(path, "rb").read()` exactly; we never text-decode-then-reencode and never
  normalize newlines. (keystore's text-mode 0x1A/0x0A truncation/inflation is the
  precedent this clause exists to avoid.) So a `0x0A -> 0x0D0A`, a trailing-EOF,
  or a lone `0x1A` mutation is a different hash and fails closed like any other
  byte change.
- **Parse the already-verified bytes; never re-read the path.** Re-opening the
  file to parse it (e.g. via `authorize._read_client_credentials`, which takes a
  path) would be a TOCTOU: the file could be swapped between verify and parse. So
  we json-decode the same in-memory bytes we hashed. The parse mirrors
  `_read_client_credentials` (Desktop `{"installed": {...}}` or bare object;
  client_id required, client_secret optional) -- kept here rather than shared so
  `gateway/authorize.py` stays untouched except its `main`.
- **The expected hash is injected and must be well-formed.** v1 pins the module
  constant `EXPECTED_CLIENT_SHA256`; a manifest value is a drop-in later. Either
  way `load_bundled_client` refuses an absent/empty/malformed/all-zero pin
  *before* touching the file, so a misconfig can never silently mint a bundle
  under an unset or test-shaped pin. This is a well-formedness gate, not an
  enumerated denylist of fakes.
- **This loader proves "on-disk file == pinned bytes", nothing more.** Whether
  the pin itself is authentic -- that these are the bytes of a real,
  Google-verified client -- is the installer signature's job (c2). This module
  never vouches for the pin's provenance.
"""

from __future__ import annotations

import hashlib
import hmac
import json

# The pinned SHA-256 of the shared client JSON's raw bytes. Set at build/install
# time (c2) to the real digest once the shared client exists; left None here so
# deployment authorize *fails closed* until a real pin is configured -- an unset
# build cannot authorize under an unverified client. Tests inject their own pin
# via the `expected_sha256` argument and do not depend on this value.
EXPECTED_CLIENT_SHA256: str | None = None

_SHA256_HEX_LEN = 64
_HEX_DIGITS = frozenset("0123456789abcdef")


class BundleError(Exception):
    """The bundled client's pin is unusable, or the file is absent/bad/mismatched."""


def _validate_expected(expected_sha256: str | None) -> str:
    """Return the normalized pin, or raise if it is not a usable SHA-256 digest.

    Rejects absent/empty/malformed/all-zero pins -- a real pin is 64 hex chars.
    'testfake', 'REPLACE_ME', '', None, and uppercase-or-short strings all fail
    "is 64 lowercase-hex chars"; the classic all-zero unset sentinel is refused
    explicitly. This runs before the file is opened, so a bad pin never reaches a
    side effect.
    """
    if not isinstance(expected_sha256, str):
        raise BundleError("expected client hash is missing")
    pin = expected_sha256.strip().lower()
    if len(pin) != _SHA256_HEX_LEN or any(c not in _HEX_DIGITS for c in pin):
        raise BundleError("expected client hash is not a SHA-256 hex digest")
    if pin == "0" * _SHA256_HEX_LEN:
        raise BundleError("expected client hash is the unset all-zero sentinel")
    return pin


def _parse_verified_client(raw: bytes) -> tuple[str, str | None]:
    """(client_id, client_secret) from the *already hash-verified* bytes.

    Mirrors `authorize._read_client_credentials` but operates on bytes, so the
    file is never re-read after verification (TOCTOU-free).
    """
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise BundleError("bundled client is not valid JSON")
    if isinstance(data, dict) and isinstance(data.get("installed"), dict):
        data = data["installed"]
    if not isinstance(data, dict) or not isinstance(data.get("client_id"), str):
        raise BundleError("bundled client has no client_id")
    secret = data.get("client_secret")
    return data["client_id"], secret if isinstance(secret, str) else None


def load_bundled_client(
    bundle_path: str, expected_sha256: str | None
) -> tuple[str, str | None]:
    """Verify the bundled client file against its pin, then parse it.

    Fails closed (raises `BundleError`) with no side effect if the pin is
    unusable, the file is unreadable, or its raw bytes do not match the pin.
    Returns `(client_id, client_secret_or_None)` on success.
    """
    pin = _validate_expected(expected_sha256)  # before touching the file
    try:
        with open(bundle_path, "rb") as f:     # binary: hash the raw bytes as-is
            raw = f.read()
    except OSError as exc:
        # Type only -- a path/errno string is not secret, but keep the boundary
        # uniform with authorize.py's sanitizing style.
        raise BundleError("bundled client is unreadable: %s" % type(exc).__name__)
    actual = hashlib.sha256(raw).hexdigest()
    if not hmac.compare_digest(actual, pin):   # constant-time compare
        raise BundleError("bundled client hash does not match the pinned value")
    return _parse_verified_client(raw)
