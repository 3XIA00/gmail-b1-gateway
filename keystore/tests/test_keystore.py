"""Tests for the token-at-rest keystore.

They actuate the two re-gated invariants (Chris task #18):
  - fail closed / no plaintext fallback: an unavailable DEK stops both seal
    and open, and no path returns bytes without an authenticated decrypt;
  - AAD binds (record_type, version): a ciphertext cannot be opened as a
    different type or version, and tamper/wrong-key all fail closed.
Plus nonce discipline (96-bit, fresh per seal) and serialisation round-trips.
"""

import base64
import dataclasses

import pytest
from hypothesis import given, strategies as st

from keystore.aead import AEADCipher, SealedRecord, _NONCE_LEN
from keystore.errors import (
    DecryptionError,
    KeyBackendUnavailableError,
    KeyMaterialError,
    KeyUnavailableError,
    SealedRecordError,
)
from keystore.providers import InMemoryKeyProvider, KeyringKeyProvider


def _cipher():
    return AEADCipher(InMemoryKeyProvider.generate())


# --- round-trip -----------------------------------------------------------

@given(
    plaintext=st.binary(max_size=4096),
    record_type=st.sampled_from(["oauth_refresh_token", "oauth_access_token"]),
    version=st.integers(min_value=1, max_value=9),
)
def test_seal_open_round_trip(plaintext, record_type, version):
    c = _cipher()
    sealed = c.seal(plaintext, record_type=record_type, version=version)
    assert c.open(sealed) == plaintext


def test_sealed_record_carries_no_plaintext():
    c = _cipher()
    secret = b"ya29.super-secret-refresh-token"
    sealed = c.seal(secret, record_type="oauth_refresh_token", version=1)
    # The secret must not appear anywhere in the record's stored form.
    blob = repr(sealed) + str(sealed.to_dict())
    assert "super-secret" not in blob
    assert secret not in sealed.ciphertext


# --- fail closed / no plaintext fallback ----------------------------------

def test_seal_fails_closed_without_key():
    c = AEADCipher(InMemoryKeyProvider.empty())
    with pytest.raises(KeyUnavailableError):
        c.seal(b"x", record_type="oauth_refresh_token", version=1)


def test_open_fails_closed_without_key():
    # Seal with a real key, then try to open under a provider with no key.
    good = _cipher()
    sealed = good.seal(b"secret", record_type="oauth_refresh_token", version=1)
    blind = AEADCipher(InMemoryKeyProvider.empty())
    with pytest.raises(KeyUnavailableError):
        blind.open(sealed)


def test_wrong_key_fails_closed():
    sealed = _cipher().seal(b"secret", record_type="oauth_refresh_token", version=1)
    other = AEADCipher(InMemoryKeyProvider.generate())
    with pytest.raises(DecryptionError):
        other.open(sealed)


# --- AAD binds (record_type, version) -------------------------------------

def test_ciphertext_not_openable_as_other_record_type():
    c = _cipher()
    sealed = c.seal(b"secret", record_type="oauth_refresh_token", version=1)
    forged = dataclasses.replace(sealed, record_type="oauth_access_token")
    with pytest.raises(DecryptionError):
        c.open(forged)


def test_ciphertext_not_openable_as_other_version():
    c = _cipher()
    sealed = c.seal(b"secret", record_type="oauth_refresh_token", version=1)
    forged = dataclasses.replace(sealed, version=2)
    with pytest.raises(DecryptionError):
        c.open(forged)


def test_tampered_ciphertext_fails_closed():
    c = _cipher()
    sealed = c.seal(b"secret-body", record_type="oauth_refresh_token", version=1)
    flipped = bytearray(sealed.ciphertext)
    flipped[0] ^= 0x01
    forged = dataclasses.replace(sealed, ciphertext=bytes(flipped))
    with pytest.raises(DecryptionError):
        c.open(forged)


# --- nonce discipline -----------------------------------------------------

def test_nonce_is_96_bit():
    sealed = _cipher().seal(b"x", record_type="oauth_refresh_token", version=1)
    assert len(sealed.nonce) == _NONCE_LEN == 12


def test_nonces_are_fresh_per_seal():
    c = _cipher()
    nonces = {
        c.seal(b"x", record_type="oauth_refresh_token", version=1).nonce
        for _ in range(200)
    }
    assert len(nonces) == 200  # random 96-bit -> no collisions at this scale


def test_bad_nonce_length_rejected():
    c = _cipher()
    with pytest.raises(SealedRecordError):
        c.seal(b"x", record_type="oauth_refresh_token", version=1,
               nonce_factory=lambda: b"\x00" * 8)


# --- invalid type / version -----------------------------------------------

@pytest.mark.parametrize("bad_version", [0, -1, True, 1.0, "1"])
def test_bad_version_rejected(bad_version):
    c = _cipher()
    with pytest.raises(SealedRecordError):
        c.seal(b"x", record_type="oauth_refresh_token", version=bad_version)


@pytest.mark.parametrize("bad_type", ["", None, 5])
def test_bad_record_type_rejected(bad_type):
    c = _cipher()
    with pytest.raises(SealedRecordError):
        c.seal(b"x", record_type=bad_type, version=1)


# --- DEK material validation ----------------------------------------------

@pytest.mark.parametrize("bad", [b"", b"\x00" * 16, b"\x00" * 31, b"\x00" * 33])
def test_wrong_size_dek_rejected(bad):
    with pytest.raises(KeyMaterialError):
        InMemoryKeyProvider(bad)


# --- serialisation --------------------------------------------------------

def test_to_from_dict_round_trip():
    c = _cipher()
    sealed = c.seal(b"secret", record_type="oauth_refresh_token", version=3)
    restored = SealedRecord.from_dict(sealed.to_dict())
    assert restored == sealed
    assert c.open(restored) == b"secret"


def test_to_dict_is_base64_text():
    sealed = _cipher().seal(b"secret", record_type="oauth_refresh_token", version=1)
    d = sealed.to_dict()
    # base64 fields decode cleanly (JSON-safe storage form).
    assert base64.b64decode(d["nonce"], validate=True) == sealed.nonce
    assert base64.b64decode(d["ciphertext"], validate=True) == sealed.ciphertext


@pytest.mark.parametrize("mangle", [
    {"nonce": "!!notbase64!!"},
    {"nonce": base64.b64encode(b"\x00" * 8).decode()},  # wrong nonce length
    {"version": 0},
])
def test_from_dict_rejects_malformed(mangle):
    sealed = _cipher().seal(b"x", record_type="oauth_refresh_token", version=1)
    d = sealed.to_dict()
    d.update(mangle)
    with pytest.raises(SealedRecordError):
        SealedRecord.from_dict(d)


# --- KeyringKeyProvider with an injected fake backend ---------------------

class _FakeKeychain:
    def __init__(self):
        self._store = {}

    def get_password(self, service, username):
        return self._store.get((service, username))

    def set_password(self, service, username, password):
        self._store[(service, username)] = password


def test_keyring_provider_provision_then_get():
    kc = _FakeKeychain()
    p = KeyringKeyProvider("gmail-gateway", "dek", backend=kc)
    with pytest.raises(KeyUnavailableError):
        p.get_dek()  # fail closed before provisioning
    p.provision()
    dek = p.get_dek()
    assert len(dek) == 32
    # A cipher built on this provider round-trips.
    c = AEADCipher(p)
    sealed = c.seal(b"secret", record_type="oauth_refresh_token", version=1)
    assert c.open(sealed) == b"secret"


def test_keyring_provider_refuses_overwrite():
    kc = _FakeKeychain()
    p = KeyringKeyProvider("gmail-gateway", "dek", backend=kc)
    p.provision()
    with pytest.raises(KeyMaterialError):
        p.provision()  # never silently rotate the key


def test_keyring_provider_rejects_corrupt_entry():
    kc = _FakeKeychain()
    kc.set_password("gmail-gateway", "dek", "!!notbase64!!")
    p = KeyringKeyProvider("gmail-gateway", "dek", backend=kc)
    with pytest.raises(KeyMaterialError):
        p.get_dek()


# --- backend RAISES (locked/down) is distinct from returns-None (absent) --
#
# Actuated variable: how the backend fails to yield a key.
#   returns None  -> KeyUnavailableError      (genuinely absent -> missing bucket)
#   RAISES        -> KeyBackendUnavailableError (outage -> keychain bucket, keep)
# The two must NOT collapse: an outage reported as absence lets a locked
# keychain masquerade as "no credentials" and trigger a spurious clear/re-auth.

class _RaisingKeychain:
    """A backend whose read path raises, like a locked/unreachable keychain."""

    def __init__(self, exc):
        self._exc = exc

    def get_password(self, service, username):
        raise self._exc

    def set_password(self, service, username, password):
        raise self._exc


def test_keyring_backend_raise_is_backend_unavailable_not_absent():
    p = KeyringKeyProvider(
        "gmail-gateway", "dek",
        backend=_RaisingKeychain(RuntimeError("keychain is locked")))
    with pytest.raises(KeyBackendUnavailableError):
        p.get_dek()


def test_keyring_backend_returns_none_is_absent_not_backend_unavailable():
    # Positive control on the other branch: the SAME method, the None path,
    # must stay KeyUnavailableError -- so the raise-branch above is really the
    # thing under test, not a blanket remap.
    p = KeyringKeyProvider("gmail-gateway", "dek", backend=_FakeKeychain())
    with pytest.raises(KeyUnavailableError):
        p.get_dek()


def test_keyring_backend_unavailable_does_not_echo_exception_text():
    # The mapped error must not carry the backend's message (which could name a
    # path / account); it is a fixed, sanitized string.
    secret = "user=alice@corp path=C:/secret/vault"
    p = KeyringKeyProvider(
        "gmail-gateway", "dek", backend=_RaisingKeychain(RuntimeError(secret)))
    try:
        p.get_dek()
        assert False, "expected KeyBackendUnavailableError"
    except KeyBackendUnavailableError as exc:
        assert "alice@corp" not in str(exc) and "secret/vault" not in str(exc)
