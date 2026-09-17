"""Key providers: where the DEK comes from.

The keystore never generates or embeds key material itself; it asks a
``KeyProvider`` for the DEK and fails closed if none is available. Isolating
this behind a Protocol keeps the crypto module free of any platform/keychain
dependency and lets tests inject a fake instead of touching a real OS keychain.

  - ``InMemoryKeyProvider``   -- deterministic, for tests and ephemeral use.
  - ``KeyringKeyProvider``    -- the real one: DEK in the OS keychain via the
    ``keyring`` library (WinVault / macOS Keychain / SecretService). The backend
    is injectable so its provisioning/refuse-overwrite logic is testable without
    a live keychain. Per-platform DEK accessibility here is the subject of the
    keystore code-time re-gate item (Chris task #18, subitem 6).
"""

from __future__ import annotations

import base64
import os
from typing import Optional, Protocol, runtime_checkable

from .errors import (
    KeyBackendUnavailableError,
    KeyMaterialError,
    KeyUnavailableError,
)

_DEK_LEN = 32


@runtime_checkable
class KeyProvider(Protocol):
    def get_dek(self) -> bytes:
        """Return the 32-byte DEK, or raise ``KeyUnavailableError``."""
        ...


class InMemoryKeyProvider:
    """Holds a DEK in memory. ``None`` -> fail closed on ``get_dek``."""

    def __init__(self, dek: Optional[bytes]):
        if dek is not None and (not isinstance(dek, (bytes, bytearray))
                                or len(dek) != _DEK_LEN):
            raise KeyMaterialError("DEK must be %d bytes" % _DEK_LEN)
        self._dek = None if dek is None else bytes(dek)

    @classmethod
    def generate(cls) -> InMemoryKeyProvider:
        return cls(os.urandom(_DEK_LEN))

    @classmethod
    def empty(cls) -> InMemoryKeyProvider:
        """A provider with no key -- exercises the fail-closed path."""
        return cls(None)

    def get_dek(self) -> bytes:
        if self._dek is None:
            raise KeyUnavailableError("no DEK provisioned")
        return self._dek


class _KeyringBackend(Protocol):
    def get_password(self, service: str, username: str) -> Optional[str]: ...
    def set_password(self, service: str, username: str, password: str) -> None: ...


class KeyringKeyProvider:
    """DEK stored in the OS keychain as base64 text.

    ``get_dek`` fails closed if the entry is absent. ``provision`` creates a
    fresh random DEK *only if none exists* -- it refuses to overwrite, so a
    running install never silently rotates the key out from under sealed data.
    """

    def __init__(self, service: str, username: str, backend: Optional[_KeyringBackend] = None):
        if backend is None:
            import keyring  # imported lazily so unit tests need no real backend
            backend = keyring
        self._service = service
        self._username = username
        self._backend = backend

    def get_dek(self) -> bytes:
        try:
            stored = self._backend.get_password(self._service, self._username)
        except Exception as exc:
            # The backend *raised* rather than returning None: the keychain is
            # locked / permission-denied / the service is down / unreachable.
            # This is "temporarily unavailable", NOT "absent" -- absence is only
            # ever the backend returning None below. Fail to the conservative
            # bucket (keep the record) rather than let an outage look like a
            # missing credential. Broad by design: any backend read failure is
            # an outage from our side, and we must not import `keyring` just to
            # enumerate its error subclasses.
            raise KeyBackendUnavailableError(
                "keychain backend unavailable for %s/%s"
                % (self._service, self._username)) from exc
        if stored is None:
            raise KeyUnavailableError("no DEK in keychain for %s/%s"
                                      % (self._service, self._username))
        try:
            dek = base64.b64decode(stored, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise KeyMaterialError("keychain DEK is not valid base64") from exc
        if len(dek) != _DEK_LEN:
            raise KeyMaterialError("keychain DEK must be %d bytes" % _DEK_LEN)
        return dek

    def provision(self) -> None:
        """Create a DEK iff absent. Refuses to overwrite an existing key."""
        if self._backend.get_password(self._service, self._username) is not None:
            raise KeyMaterialError("refusing to overwrite an existing DEK")
        dek = os.urandom(_DEK_LEN)
        self._backend.set_password(
            self._service, self._username,
            base64.b64encode(dek).decode("ascii"),
        )
