"""Envelope AEAD for tokens at rest (DESIGN sec 6 / gate 6).

The Gateway holds OAuth access/refresh tokens. They are never stored in the
clear: each is sealed with AES-256-GCM under a data-encryption key (DEK) that
lives in the OS keychain, reached only through an injected ``KeyProvider``.

Two invariants this module enforces, both code-time re-gated (Chris task #18):

  1. **Fail closed, no plaintext fallback.** Every ``open`` path requires a
     successful AEAD decrypt. If the DEK is unavailable the provider raises
     ``KeyUnavailableError`` and it propagates -- there is no branch that
     returns bytes without an authenticated decrypt.

  2. **Associated data binds type + version.** The GCM AAD is derived from the
     record's ``record_type`` and ``version`` (never from attacker-influenced
     content). A ciphertext sealed as one (type, version) cannot be opened as
     another -- it authenticates as a different message and fails closed.

Nonces are 96-bit and drawn fresh per seal from an injected factory
(``os.urandom`` by default), so the (key, nonce) pair is not reused across
records; the version in the AAD additionally separates key-schedule versions.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import (
    DecryptionError,
    KeyMaterialError,
    SealedRecordError,
)
from .providers import KeyProvider

# AES-256 -> 32-byte DEK; GCM standard nonce -> 12 bytes (96 bit).
_DEK_LEN = 32
_NONCE_LEN = 12


def _require_dek(key_provider: KeyProvider) -> bytes:
    dek = key_provider.get_dek()  # may raise KeyUnavailableError -> fail closed
    if not isinstance(dek, (bytes, bytearray)) or len(dek) != _DEK_LEN:
        raise KeyMaterialError("DEK must be %d bytes" % _DEK_LEN)
    return bytes(dek)


def _aad(record_type: str, version: int) -> bytes:
    """Associated data = a canonical, content-independent (type, version) tag.

    Load-bearing: this is what makes a sealed token non-transplantable across
    record kinds or schema versions. It must never include recipient/body/etc.
    """
    if not isinstance(record_type, str) or not record_type:
        raise SealedRecordError("record_type must be a non-empty str")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise SealedRecordError("version must be an int >= 1")
    return ("gmail-gateway/keystore/v%d/%s" % (version, record_type)).encode("utf-8")


def _default_nonce_factory() -> bytes:
    return os.urandom(_NONCE_LEN)


@dataclass(frozen=True)
class SealedRecord:
    """An at-rest ciphertext plus the minimum needed to open it.

    Carries no plaintext and no key. ``record_type``/``version`` are stored so
    the reader can reconstruct the exact AAD; they are authenticated by GCM, so
    tampering with them makes ``open`` fail closed.
    """

    version: int
    record_type: str
    nonce: bytes
    ciphertext: bytes  # GCM ciphertext, tag appended by the AEAD

    def to_dict(self) -> dict:
        """Storage form: bytes as base64 so the record is JSON-serialisable."""
        return {
            "version": self.version,
            "record_type": self.record_type,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, d: dict) -> SealedRecord:
        try:
            nonce = base64.b64decode(d["nonce"], validate=True)
            ciphertext = base64.b64decode(d["ciphertext"], validate=True)
            version = d["version"]
            record_type = d["record_type"]
        except (KeyError, TypeError, ValueError, base64.binascii.Error) as exc:
            raise SealedRecordError("malformed sealed record: %s" % (exc,)) from exc
        if len(nonce) != _NONCE_LEN:
            raise SealedRecordError("nonce must be %d bytes" % _NONCE_LEN)
        # Re-validate type/version through the same guard used to build the AAD.
        _aad(record_type, version)
        return cls(version=version, record_type=record_type, nonce=nonce,
                   ciphertext=ciphertext)


class AEADCipher:
    """Seal/open bytes under a DEK sourced from an injected ``KeyProvider``."""

    def __init__(self, key_provider: KeyProvider):
        self._key_provider = key_provider

    def seal(
        self,
        plaintext: bytes,
        *,
        record_type: str,
        version: int,
        nonce_factory: Callable[[], bytes] = _default_nonce_factory,
    ) -> SealedRecord:
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        aad = _aad(record_type, version)  # validates type/version too
        nonce = nonce_factory()
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != _NONCE_LEN:
            raise SealedRecordError("nonce must be %d bytes" % _NONCE_LEN)
        dek = _require_dek(self._key_provider)
        ciphertext = AESGCM(dek).encrypt(bytes(nonce), bytes(plaintext), aad)
        return SealedRecord(version=version, record_type=record_type,
                            nonce=bytes(nonce), ciphertext=ciphertext)

    def open(self, sealed: SealedRecord) -> bytes:
        """Authenticated decrypt. No path returns bytes without this succeeding."""
        aad = _aad(sealed.record_type, sealed.version)
        dek = _require_dek(self._key_provider)  # KeyUnavailableError => fail closed
        try:
            return AESGCM(dek).decrypt(sealed.nonce, sealed.ciphertext, aad)
        except InvalidTag as exc:
            # Tamper, wrong key, or mismatched (type, version): one fail-closed
            # error, never recovered plaintext.
            raise DecryptionError("AEAD authentication failed") from exc
