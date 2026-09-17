"""Token-at-rest keystore: envelope AEAD with the DEK in the OS keychain.

Public API:
  - AEADCipher / SealedRecord      -- seal & open bytes (AES-256-GCM).
  - KeyProvider (Protocol)         -- where the DEK comes from.
  - InMemoryKeyProvider            -- deterministic provider for tests.
  - KeyringKeyProvider             -- real OS-keychain provider.
  - errors: KeyUnavailableError, KeyMaterialError, SealedRecordError,
    DecryptionError.
"""

from __future__ import annotations

from .aead import AEADCipher, SealedRecord
from .errors import (
    DecryptionError,
    KeyBackendUnavailableError,
    KeyMaterialError,
    KeyUnavailableError,
    SealedRecordError,
)
from .providers import InMemoryKeyProvider, KeyProvider, KeyringKeyProvider

__all__ = [
    "AEADCipher",
    "SealedRecord",
    "KeyProvider",
    "InMemoryKeyProvider",
    "KeyringKeyProvider",
    "KeyUnavailableError",
    "KeyBackendUnavailableError",
    "KeyMaterialError",
    "SealedRecordError",
    "DecryptionError",
]
