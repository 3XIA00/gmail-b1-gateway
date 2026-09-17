# Gmail Gateway keystore (tokens at rest)

Envelope AEAD for the OAuth tokens the Gateway holds. Implements **DESIGN.md
v0.1 sec 6 / release gate 6**: tokens are never at rest in the clear, and a
missing key is a hard stop — never a plaintext fallback.

## Scope

**In scope (this module):**
- `aead.py` — `AEADCipher` (AES-256-GCM) + `SealedRecord`; `seal`/`open`.
- `providers.py` — `KeyProvider` protocol, `InMemoryKeyProvider` (tests),
  `KeyringKeyProvider` (real OS keychain via `keyring`).
- `errors.py` — the fail-closed / crypto-failure error split.

**Out of scope (adjacent Gateway pieces):** which records get sealed and when
(that is the proposal/idempotency **store**), the send FSM, OAuth, transport.
This module only turns *bytes ⇄ sealed bytes* under a keychain-held DEK.

## Design decisions

1. **Fail closed, no plaintext fallback (gate 6).** The DEK is fetched from an
   injected `KeyProvider`; if absent it raises `KeyUnavailableError`, which
   propagates through both `seal` and `open`. There is deliberately **no**
   branch that returns bytes without a successful authenticated decrypt
   (`test_seal_fails_closed_without_key`, `test_open_fails_closed_without_key`).

2. **AAD binds `(record_type, version)`, never content (Chris code-time ③).**
   The GCM associated data is `gmail-gateway/keystore/v{version}/{record_type}`
   — derived only from the record's kind and schema version, never from
   recipient/body/etc. A token sealed as one `(type, version)` fails to open as
   another (`test_ciphertext_not_openable_as_other_record_type` /
   `_other_version`). This makes a sealed token non-transplantable across record
   kinds and across schema versions.

3. **96-bit nonce, fresh per seal.** Nonce comes from an injected factory
   (`os.urandom(12)` by default), so the `(key, nonce)` pair is not reused
   across records (`test_nonces_are_fresh_per_seal`); the version in the AAD
   additionally separates key-schedule versions. A wrong-length nonce is
   rejected (`test_bad_nonce_length_rejected`).

4. **Key material lives behind a Protocol, not in the crypto.** The module
   never generates or embeds a DEK inline; `KeyProvider` is the only source.
   `KeyringKeyProvider` keeps the DEK in the OS keychain (WinVault / macOS
   Keychain / SecretService) and **refuses to overwrite** an existing key on
   `provision`, so a running install never silently rotates the key out from
   under sealed data (`test_keyring_provider_refuses_overwrite`). Per-platform
   DEK accessibility is the keystore code-time re-gate item (Chris task #18,
   subitem 6). The `keyring` backend is injectable so this logic is testable
   with a fake keychain — no live keychain needed in unit tests.

5. **Sealed form is JSON-safe and self-describing for the reader only.**
   `SealedRecord.to_dict()` base64-encodes the nonce/ciphertext; `from_dict`
   re-validates lengths and `(type, version)` before use. `record_type` and
   `version` are stored so the reader can rebuild the exact AAD — and because
   GCM authenticates them, tampering with either fails the open.

## V2 note

Same-UID at-rest exposure (a co-resident same-user process reading the DEK /
sealed files) is DESIGN sec 2.6 / L58's honestly-recorded v1 limitation, not
something this module claims to close. Keeping the DEK in the OS keychain (not
a world-readable file) is the v1 posture; separate OS identity / service-ization
is the deferred v2 hardening.

## Run

```
cd gmail-gateway
python -m pytest keystore/tests -q
```

31 tests: seal/open round-trip (hypothesis over bytes/type/version), fail-closed
on missing key, wrong-key / tamper / cross-type / cross-version rejection, nonce
discipline, DEK-size validation, serialisation round-trips, and the keyring
provider (provision → get, refuse-overwrite, corrupt-entry) via an injected
fake keychain.

## Depends on

`cryptography` (AES-256-GCM) and, for `KeyringKeyProvider` only, `keyring`.
Repo-independent: no import of the other Gateway modules.
