"""PKCE (RFC 7636) — proof key for code exchange.

The Gateway is a public client (installed app): it has no way to keep a
client_secret secret, so PKCE is what actually binds the authorization code to
*this* flow. We generate a high-entropy ``code_verifier``, send only its
SHA-256 ``code_challenge`` in the authorization request, and reveal the
verifier only at token exchange. An attacker who intercepts the code cannot
exchange it without the verifier, which never left this process.

Boundary note: this module is pure logic — verifier/challenge derivation and
validation. It performs no network I/O; the token exchange itself is the
assembly layer's job (see ``token_request``).
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass

from .errors import PKCEError

# RFC 7636 sec 4.1: code_verifier = 43*128 chars from the unreserved set.
_VERIFIER_ALPHABET = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")

# 32 random bytes -> 43 base64url chars, the RFC's recommended entropy.
_VERIFIER_ENTROPY_BYTES = 32

CODE_CHALLENGE_METHOD = "S256"


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_code_verifier() -> str:
    """A fresh, cryptographically-random RFC 7636 code_verifier."""
    return _b64url_nopad(secrets.token_bytes(_VERIFIER_ENTROPY_BYTES))


def validate_code_verifier(verifier: str) -> None:
    """Raise ``PKCEError`` unless *verifier* is a well-formed code_verifier."""
    if not _VERIFIER_ALPHABET.match(verifier):
        raise PKCEError(
            "code_verifier must be 43-128 chars of the unreserved set")


def code_challenge(verifier: str) -> str:
    """The S256 challenge for *verifier*: base64url(sha256(verifier)).

    Validates the verifier first so a malformed one cannot silently produce a
    challenge that would later fail exchange.
    """
    validate_code_verifier(verifier)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url_nopad(digest)


@dataclass(frozen=True)
class PKCEPair:
    """A verifier + its S256 challenge, generated together."""

    verifier: str
    challenge: str
    method: str = CODE_CHALLENGE_METHOD


def generate_pkce_pair() -> PKCEPair:
    """Generate a matched (verifier, challenge) pair in one call."""
    verifier = generate_code_verifier()
    return PKCEPair(verifier=verifier, challenge=code_challenge(verifier))
