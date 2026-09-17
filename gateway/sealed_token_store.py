"""Concrete :class:`TokenStore`: sealed OAuth credentials + commit record.

This implements the daemon<->store seam defined in ``token_store.py`` by
composing the pieces that already exist in this tree:

  - ``keystore`` (AEAD envelope + injected DEK provider) seals the credentials,
  - ``persistence.SqliteKV`` (WAL + ``synchronous=FULL``) is the durable spine.

Design decisions (the *why*):

- **One row, so a commit is atomic.** The sealed credentials and the commit
  record live together under a single KV key, written in a single
  ``SqliteKV.put`` (one SQLite transaction). That is what makes ``save_commit``
  both-or-neither: there is no window where the credential landed but the commit
  did not, or vice versa. Two keys would be two transactions — not atomic — and
  the seam's rule 1 (a call fully lands or does not land) is load-bearing for
  the daemon's lock/cancel discipline.

- **``load_commit`` never decrypts.** The commit fields sit beside the sealed
  bytes as plain JSON, so recovery can read "there was a commit" without a DEK.
  A locked keychain must not look like an absent commit (seam rule for
  ``load_commit``).

- **The path is passed in; we own only our own key.** ``token.db`` is chosen by
  the daemon (its private data root). This store touches exactly one KV key
  (``_STATE_KEY``); it never issues a whole-database delete, so send-dedup /
  recorded-results / unknown-outcome / anti-revival rows kept by other
  subsystems in the same ``token.db`` survive ``clear_credentials`` untouched.

- **Failures map to the four buckets, which never impersonate each other.** The
  mapping is the whole point of the seam; see ``_open`` below.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from keystore.aead import AEADCipher, SealedRecord
from keystore.errors import (
    DecryptionError,
    KeyBackendUnavailableError,
    KeyMaterialError,
    KeyUnavailableError,
    SealedRecordError,
)
from keystore.providers import KeyProvider

from .persistence import ABORT, SqliteKV
from .token_store import (
    CommitInvalidated,
    CommitRecord,
    CredentialsCorrupt,
    CredentialsMissing,
    KeychainUnavailable,
    TokenStoreError,
)

# The single KV key this store owns. Everything else in token.db belongs to
# other subsystems and is out of bounds for clear_credentials.
#
# The row is one JSON object:
#   {"sealed": <SealedRecord|None>,
#    "commit": <CommitRecord|None>,
#    "invalidated_ops": [operation_id, ...],   # operation-scope voids
#    "barrier": <int>,                          # generation barrier (monotone)
#    "last_generation": <int>}                  # highest generation ever reserved
# Keeping them all in one key is what makes save_commit's "check the voids AND
# the barrier, then decide whether to write, in one transaction" (seam rule 4)
# a single atomic read-modify-write rather than a check split across two calls;
# it also makes reserve_generation's allocate-and-persist atomic.
_STATE_KEY = "gmail_oauth_state"

# AAD binding for the sealed credentials (see keystore.aead._aad).
_RECORD_TYPE = "oauth_credentials"
_SEAL_VERSION = 1


class SealedTokenStore:
    """Synchronous, atomic :class:`TokenStore`.

    Not thread-safe by itself and deliberately so: the daemon serialises every
    call under one lock (seam rule 1), so the store must hold no async lock and
    start no tasks. ``SqliteKV`` has its own connection mutex for cursor safety.
    """

    def __init__(self, db_path: str, key_provider: KeyProvider):
        # db_path is chosen by the daemon (its private data_root); the store
        # never resolves it (seam rule 2).
        self._kv = SqliteKV(db_path)
        self._cipher = AEADCipher(key_provider)

    # --- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        self._kv.close()

    def __enter__(self) -> "SealedTokenStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- TokenStore methods ------------------------------------------------

    def reserve_generation(self) -> int:
        # Allocate the next connection generation up front (Connect, before the
        # external op). Strictly greater than every value ever allocated AND the
        # barrier: a barrier that leads the local counter (a library restore, or
        # a barrier raised for a generation this machine never allocated) must
        # not hand out a number the barrier already covers -- that would make
        # every later commit refuse and look like a permanent, silent void.
        holder: dict = {}

        def _txn(current):
            current = dict(current or {})
            last = current.get("last_generation", 0)
            g = max(last, current.get("barrier", 0)) + 1
            # Persisted so it is never reclaimed or reused, even after a failed
            # or cancelled flow (reuse would let a later flow inherit a number an
            # earlier barrier already covers).
            current["last_generation"] = g
            holder["g"] = g
            return current

        self._kv.update(_STATE_KEY, _txn)
        return holder["g"]

    def current_barrier(self) -> int:
        row = self._kv.get(_STATE_KEY)
        return 0 if row is None else row.get("barrier", 0)

    def void_generation(self, generation: int) -> None:
        # Monotone: barrier = max(barrier, generation). Disconnect raises it for
        # the connection being torn down; Cancel never calls this.
        def _txn(current):
            current = dict(current or {})
            current["barrier"] = max(current.get("barrier", 0), generation)
            return current

        self._kv.update(_STATE_KEY, _txn)

    def save_commit(
        self,
        *,
        operation_id: str,
        connection_id: str,
        result_id: str,
        version: int,
        generation: int,
        credentials: dict,
        ack_pending: bool,
    ) -> CommitRecord:
        # Seal outside the transaction: it is pure (no DB) and keeps the
        # lock-held critical section short.
        sealed = self._cipher.seal(
            json.dumps(credentials).encode("utf-8"),
            record_type=_RECORD_TYPE,
            version=_SEAL_VERSION,
        )
        holder: dict = {}

        def _txn(current):
            current = dict(current or {})
            # Same-transaction double-check (seam rule 4). Refuse -- writing
            # NOTHING, so there is no partial commit -- if either scope voided
            # this write: the operation was invalidated (Cancel/Disconnect,
            # possibly before any commit and across a restart), OR its reserved
            # generation is at or below the barrier a Disconnect raised. Both
            # must be checked here, in the same transaction as the write, so a
            # void/barrier landing between a would-be external check and the
            # write cannot be lost.
            if operation_id in current.get("invalidated_ops", []):
                holder["refused"] = "operation was voided before commit"
                return ABORT
            if generation <= current.get("barrier", 0):
                holder["refused"] = "generation is at or below the barrier"
                return ABORT
            # generation is the value reserved when the flow began: record it as
            # given, never allocate a fresh one (allocating here would let an old
            # result step over a barrier raised while it was in flight).
            record = CommitRecord(
                operation_id=operation_id,
                connection_id=connection_id,
                result_id=result_id,
                version=version,
                generation=generation,
                ack_pending=ack_pending,
                invalidated=False,   # a fresh commit is live
            )
            holder["record"] = record
            current["sealed"] = sealed.to_dict()
            current["commit"] = asdict(record)
            current.setdefault("invalidated_ops", [])  # carried forward
            return current

        self._kv.update(_STATE_KEY, _txn)
        if holder.get("refused"):
            raise CommitInvalidated(holder["refused"])
        return holder["record"]

    def load_credentials(self) -> dict:
        row = self._kv.get(_STATE_KEY)
        if row is None or row.get("sealed") is None:
            raise CredentialsMissing("no sealed credentials")
        return self._open(row["sealed"])

    def load_commit(self) -> CommitRecord | None:
        # Reads the commit fields only; never opens (decrypts) the credentials.
        return self._read_commit()

    def mark_ack_confirmed(
        self, *, operation_id: str, result_id: str, version: int
    ) -> bool:
        holder = {"matched": False}

        def _txn(current):
            if current is None or current.get("commit") is None:
                return ABORT
            commit = current["commit"]
            # Must match all three. A late ACK for a superseded operation
            # matches none of them, so it returns False and the newer record is
            # untouched.
            if (commit["operation_id"] != operation_id
                    or commit["result_id"] != result_id
                    or commit["version"] != version):
                return ABORT
            holder["matched"] = True
            if not commit["ack_pending"]:
                return ABORT               # matched but already clear: no write
            commit["ack_pending"] = False
            return current                 # keeps sealed + invalidated_ops intact

        self._kv.update(_STATE_KEY, _txn)
        return holder["matched"]

    def invalidate_commit(self, *, operation_id: str) -> bool:
        holder = {"hit": False}

        def _txn(current):
            current = dict(current or {})
            # ALWAYS persist the invalidation fact for this operation -- even
            # with no commit yet, or a different operation currently committed.
            # The return value only reports whether the CURRENT commit was hit;
            # False does not mean nothing was written (Jeff 205615, Boris 205653).
            ops = list(current.get("invalidated_ops", []))
            if operation_id not in ops:
                ops.append(operation_id)
            current["invalidated_ops"] = ops
            commit = current.get("commit")
            if commit is not None and commit["operation_id"] == operation_id:
                commit["invalidated"] = True   # also flip the live commit's bit
                holder["hit"] = True
            return current

        self._kv.update(_STATE_KEY, _txn)
        return holder["hit"]

    def clear_credentials(self) -> bool:
        holder = {"had": False}

        def _txn(current):
            if current is None or current.get("sealed") is None:
                return ABORT
            holder["had"] = True
            current = dict(current)
            # Destroy the sealed credentials and nothing else: keep the commit
            # record, the operation-scope voids AND the generation barrier, and
            # never touch other keys in token.db (dedup / results / unknown live
            # under their own keys). Dropping invalidated_ops or the barrier would
            # re-admit exactly the in-flight writes this Disconnect just voided --
            # the call meant to end the connection would be the one that lets it
            # come back -- so both must survive (they live in this same row and
            # are untouched here).
            current["sealed"] = None
            return current

        self._kv.update(_STATE_KEY, _txn)
        return holder["had"]

    # --- internals ---------------------------------------------------------

    def _read_commit(self) -> CommitRecord | None:
        row = self._kv.get(_STATE_KEY)
        if row is None or row.get("commit") is None:
            return None
        c = row["commit"]
        try:
            return CommitRecord(
                operation_id=c["operation_id"],
                connection_id=c["connection_id"],
                result_id=c["result_id"],
                version=c["version"],
                generation=c["generation"],
                ack_pending=c["ack_pending"],
                invalidated=c.get("invalidated", False),
            )
        except (KeyError, TypeError) as exc:
            # Our own write is malformed -> an internal fault, not one of the
            # credential buckets (the credential may be perfectly openable).
            raise TokenStoreError("commit record is malformed") from exc

    def _open(self, sealed_dict: dict) -> dict:
        """Decrypt + parse, mapping every failure onto exactly one bucket.

        absent key material   -> CredentialsMissing   (genuinely absent)
        backend outage         -> KeychainUnavailable  (keep the record)
        bad DEK / tamper / AAD -> CredentialsCorrupt    (present, won't open)
        damaged stored record  -> CredentialsCorrupt
        The reason codes are fixed strings; no ciphertext / key / body text is
        ever echoed (the chained cause carries detail for logs only).
        """
        try:
            sealed = SealedRecord.from_dict(sealed_dict)
        except SealedRecordError as exc:
            raise CredentialsCorrupt("sealed record is malformed") from exc
        try:
            plaintext = self._cipher.open(sealed)
        except KeyUnavailableError as exc:
            # No DEK at all == no required key material == genuinely absent.
            raise CredentialsMissing("key material absent") from exc
        except KeyBackendUnavailableError as exc:
            # Keychain locked / down / unreachable: record intact, keep it.
            raise KeychainUnavailable("keychain unavailable") from exc
        except (KeyMaterialError, DecryptionError) as exc:
            # DEK present but unusable, or AEAD auth failed: present, won't open.
            raise CredentialsCorrupt("credentials will not open") from exc
        try:
            return json.loads(plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CredentialsCorrupt("decrypted credentials are malformed") from exc
