"""The daemon <-> sealed-token-store seam.

This file is the *contract only*. The sealed store itself (AEAD sealing,
the OS-keychain DEK provider, the sqlite persistence layer) lands as a
separate subsystem; nothing equivalent exists in this tree today, so the
seam is defined here first and implemented behind it.

Four rules the implementation must respect, because the daemon depends on
them rather than re-checking them:

1. **Every method is synchronous and atomic.** The store must not start
   tasks and must not hold an async lock of its own. Locking and
   cancellation discipline belong to the daemon (see `ops.py`): the daemon
   holds one lock across commit-vs-cancel, and a `to_thread` call being
   cancelled does *not* stop the thread already writing. The daemon
   therefore waits for the write to finish before releasing the lock, and
   that is only sound if a single call either fully lands or does not land.

2. **The daemon passes the path in.** The store never resolves
   `data_root` itself. `token.db` must live under the daemon's private
   data root, never under an agent home or workspace directory, because
   those two are mounted into agent containers — writing it to the wrong
   place hands the sealed ciphertext straight into the container.

3. **Read failures are reported as one of three buckets**, which never
   impersonate each other: absent vs. temporarily unreachable vs.
   present-but-unopenable. The fourth bucket in
   `status_store.DAEMON_REASONS`, `reauth_required`, is *not* one of
   these: it means Google rejected the credential, which is a fact the
   refresh path learns and the store never sees. A store that could
   raise it would be claiming to know something it cannot observe.

4. **Voiding happens at two scopes, and one does not imply the other.**
   `invalidate_commit` voids a single operation and always persists,
   even when it matches no commit. `void_generation` raises a barrier
   over a whole connection generation, which is the only way to reach an
   in-flight refresh running under an operation id nobody can name after
   a restart. Cancel uses the first; Disconnect uses both. `save_commit`
   checks both in its own transaction, and startup recovery checks the
   barrier as well — Disconnect raises it before it clears credentials
   or flags the record, so a crash in between leaves a commit that every
   other check would wave through.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class TokenStoreError(RuntimeError):
    """Base for store failures that map onto a credential bucket."""

    reason = "internal_error"


class CredentialsMissing(TokenStoreError):
    """No sealed record, or no required key material. Genuinely absent."""

    reason = "credentials_missing"


class KeychainUnavailable(TokenStoreError):
    """Keychain locked, permission denied, or the service is down.

    The sealed record is intact and must be kept: do not clear the store,
    do not mint a replacement DEK, do not send the user to re-authorize.
    """

    reason = "keychain_error"


class CredentialsCorrupt(TokenStoreError):
    """The record is present and will not open.

    AEAD verification failed, the stored structure is damaged, or the
    provenance does not match. Stop using it, keep it, and do not report
    this as a keychain fault or as a Google rejection. Error text must not
    echo ciphertext or key material.
    """

    reason = "credentials_corrupt"


class CommitInvalidated(RuntimeError):
    """`save_commit` refused: this operation was voided before it landed.

    Deliberately *not* a `TokenStoreError`. Nothing is wrong with the
    store — this is the guard doing its job — and inheriting would let
    `except TokenStoreError` blocks swallow it as a credential fault and
    report a working machine as broken.

    It is an exception rather than a `None` return so the refusal cannot
    be walked past by a caller that assumes a record came back.
    """


@dataclass(frozen=True)
class CommitRecord:
    """What the daemon committed, and enough to decide recovery.

    `ack_pending` drives ACK re-delivery at startup.

    `generation` and `version` are different axes and must not be
    conflated. `generation` is the **local connection generation**: it
    identifies which connection this belongs to, is reserved before the
    external operation starts, and a refresh inherits it rather than
    advancing it. `version` counts credential updates *within* a
    connection. `operation_id` names the individual operation.
    """

    operation_id: str
    connection_id: str
    result_id: str
    version: int
    generation: int
    ack_pending: bool
    # Set by cancel or Disconnect. Durable on purpose: an in-memory mark
    # cannot survive the restart it is meant to guard, and recovering a
    # commit the user disconnected would silently reconnect an account
    # they explicitly cut off.
    invalidated: bool = False

    # `invalidated` and the generation barrier are both consulted by
    # recovery, and they fail in different windows. This field is written
    # by the same step that tears the connection down; the barrier is
    # written *first* and on its own. If the process dies after the
    # barrier lands but before this field is set, only the barrier is
    # there to stop the recovery — which is exactly why recovery must
    # gate on it too.
    #
    # An earlier version of this comment said the barrier must never gate
    # recovery, on the grounds that cancelling a new connect flow would
    # then retroactively disqualify the good connection committed before
    # it. That was true only of a design where *cancel* advanced a
    # process-wide counter. Cancel voids an operation and leaves the
    # barrier alone; only Disconnect advances it, and only for the
    # connection being disconnected.


class TokenStore(Protocol):
    """Synchronous, atomic. Called from the daemon via ``to_thread``."""

    def reserve_generation(self) -> int:
        """Allocate and persist the next connection generation, atomically.

        Called by Connect **before** the external operation starts.
        Strictly greater than every value previously allocated and than
        the current barrier. Never reclaimed and never reused, including
        after a failed or cancelled flow — reuse would let a later flow
        inherit a number an earlier barrier already covers.

        Reserving up front is what makes the barrier work. If a
        generation were assigned when the commit succeeds instead, an old
        result arriving after a Disconnect would be handed a fresh number
        at that moment and would step straight over the barrier meant to
        stop it.
        """

    def current_barrier(self) -> int:
        """The generation barrier. Gates writes *and* startup recovery."""

    def void_generation(self, generation: int) -> None:
        """Raise the barrier to at least `generation`. Durable, monotone.

        Disconnect calls it for the connection being torn down. Cancel
        does **not**: cancelling a new flow voids that operation only and
        must leave an existing connection recoverable.
        """

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
        """Seal `credentials` and record the commit in one atomic step.

        Either both land or neither does. `generation` is the value
        reserved when the flow began; this call must record it as given
        and must never allocate a fresh one.

        Raises `CommitInvalidated` if this operation has been voided, or
        if `generation` is at or below the barrier.

        **Those checks and this write must be one transaction.** Checking
        outside and then calling in is a time-of-check race: a void or a
        barrier landing in between is lost and the commit it was supposed
        to stop goes in.
        """

    def load_credentials(self) -> dict:
        """Open the sealed credentials.

        Raises one of the three read buckets rather than returning a
        sentinel, so "absent", "keychain unreachable" and "present but
        unopenable" stay distinguishable at the call site.

        Disconnect reads through this *before* clearing: revocation needs
        the token value, and a value can be held in memory across the
        delete. Treating "must revoke before clearing" as an ordering
        constraint would be mistaking one implementation choice for a
        property of the problem.
        """

    def load_commit(self) -> CommitRecord | None:
        """The current commit record, or None if there is no commit.

        Must not require opening the credentials: startup recovery needs
        to distinguish "committed" from "openable", and a locked keychain
        must not look like an absent commit.
        """

    def mark_ack_confirmed(
        self, *, operation_id: str, result_id: str, version: int
    ) -> bool:
        """Clear `ack_pending` for exactly this commit.

        Must match all three fields. A late ACK for a superseded operation
        must leave a newer commit untouched and return False; it must
        never clear the newer record's pending flag.
        """

    def invalidate_commit(self, *, operation_id: str) -> bool:
        """Durably void this operation. Always persists. Idempotent.

        The return value reports **only** whether the call hit the current
        commit. False does *not* mean nothing was written: a void for an
        operation with no commit yet, or for an operation superseded by a
        newer one, is still recorded. That is the whole point — the case
        this has to cover is an old claim or refresh still in flight with
        nothing committed to mark, which would otherwise land afterwards
        or resume after a restart.

        It therefore does two jobs at two scopes: the persisted void stops
        a *future* write for that operation, and `CommitRecord.invalidated`
        stops an *already committed* connection from being recovered.
        """

    def clear_credentials(self) -> bool:
        """Disconnect: destroy the sealed credentials. Nothing else.

        Explicitly out of scope for this call, even when they share
        `token.db` — a whole-database delete is not an acceptable
        implementation:

        - send de-duplication records and recorded send results,
        - `unknown` send outcomes,
        - the voided-operation records and the generation barrier, which
          must survive this call. Dropping either would re-admit
          precisely the in-flight writes the Disconnect just voided, so
          the call that is supposed to end the connection would be the
          one that lets it come back.

        Those exist precisely to survive this moment: a user who
        disconnects must not thereby make a previously-sent message
        eligible to send again. Returns True if credentials were present
        and are now gone.
        """
