"""Keystore error types.

These are deliberately distinct so callers can tell the *fail-closed* case
(no key material available -> refuse, never fall back to plaintext) apart from
a *cryptographic* failure (tamper / wrong key / wrong associated data).
"""

from __future__ import annotations


class KeyUnavailableError(Exception):
    """The data-encryption key (DEK) is not available.

    Raised by a ``KeyProvider`` when no DEK is present. The keystore never
    catches this to synthesise a plaintext fallback -- absence of the key is a
    hard stop (DESIGN gate 6: fail closed on missing key, no plaintext path).
    """

    code = "key_unavailable"


class KeyBackendUnavailableError(Exception):
    """The keychain backend itself failed to answer (locked / permission denied
    / service down / unreachable), as opposed to answering "no such entry".

    This is the *temporarily unreachable* case: the sealed record is intact and
    the DEK may well exist -- we simply could not reach the backend to read it.
    It must never be conflated with ``KeyUnavailableError`` (a definite absence,
    signalled by the backend returning ``None``): treating an outage as absence
    is what lets a locked keychain masquerade as "no credentials" and trigger a
    spurious clear / re-auth. Distinct type so the store can map it to the
    keychain-unavailable bucket and keep the record.
    """

    code = "key_backend_unavailable"


class KeyMaterialError(ValueError):
    """The key material is present but structurally invalid (e.g. wrong size)."""

    code = "key_material_invalid"


class SealedRecordError(ValueError):
    """A sealed record is malformed (bad field, bad base64, bad nonce length)."""

    code = "sealed_record_invalid"


class DecryptionError(Exception):
    """AEAD authentication/decryption failed.

    Wraps the underlying ``InvalidTag`` so a tampered ciphertext, a wrong key,
    or mismatched associated data (record_type/version) all surface as one
    fail-closed error and never as recovered plaintext.
    """

    code = "decryption_failed"
