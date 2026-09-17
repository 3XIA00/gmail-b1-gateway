"""Confirm + dispatch send path (ASSEMBLY_PLAN step v, Option B).

Two Gateway-internal pieces that turn a confirmed proposal into a real Gmail
send, wiring the pure `sendfsm` to the concrete `GmailSender`, content store,
and sealed token:

- `SealedTokenStore` — the `token_provider` seam. The OAuth token is held only
  as AES-256-GCM ciphertext (keystore AEAD, DEK in the OS keychain) in a
  Gateway-local record; `access_token()` opens it for the sender. This store is
  never reachable from any Agent route (C7 ②): no Agent-facing endpoint returns
  a token, and what is at rest is ciphertext.

- `ConfirmDispatcher` — the Agent-relay confirm (Option B).

**Option B / gate-7 relaxed-for-POC (DESIGN §2.6/§9 residual).**
Under Option B the Agent relays the human's confirmation directly; the Gateway
marks the approval `Actor.HUMAN` on the strength of that relay. It therefore
**cannot cryptographically distinguish a genuine human confirmation from one an
injected Agent forged (gate 7(a) approval-authenticity, not in effect), nor
guarantee the human saw the exact bytes that are sent (gate 7(b)
content-fidelity / WYSIWYS, not in effect)** — the Agent controls what it shows
the human. This is accepted for POC by Jeremy at
msg_bea7d785-9fda-4353-80a0-1d476c540fc5, to be tightened before broader use
(the first-class Gateway-identity confirm surface, Option A). The Gateway-side
half of content-fidelity that *does* hold — the sent bytes equal the frozen,
digested proposal payload — is enforced upstream in `proposal_api` (single
content ref + digest match); it does not close 7(b), it only prevents the
Gateway from itself diverging.
"""

from __future__ import annotations

import json
from typing import Callable, Optional

from keystore.aead import AEADCipher, SealedRecord
from keystore.errors import KeyMaterialError, KeyUnavailableError
from sendfsm.fsm import Actor, SendFSM
from store.backend import KVBackend


class SealedTokenStore:
    """OAuth token at rest: keystore AEAD ciphertext over a KV record.

    `access_token` is the simplest `token_provider` callable handed to
    `GmailSender`. Refresh metadata and the Desktop-client credentials required
    by Google's refresh grant are sealed in the same record. Older v1 records
    remain readable, but require one reauthorization before automatic refresh.
    """

    _RECORD_TYPE = "oauth_token"
    _VERSION = 1
    _KEY = "sealed_token"
    _WRITE_ORIGINS = frozenset(("authorize", "refresh"))

    def __init__(self, cipher: AEADCipher, backend: KVBackend):
        self._cipher = cipher
        self._backend = backend

    def store(
        self,
        *,
        access_token: str,
        refresh_token: Optional[str] = None,
        issued_at: Optional[int] = None,
        expires_at: Optional[int] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scope: Optional[str] = None,
        write_origin: str = "authorize",
    ) -> None:
        if write_origin not in self._WRITE_ORIGINS:
            raise ValueError("invalid token write origin")
        blob = json.dumps({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
            # Duplicated outside the ciphertext below for cheap forensic
            # inspection, and inside it so tampering is detected on read.
            "write_origin": write_origin,
            "written_at": issued_at,
        }).encode("utf-8")
        sealed = self._cipher.seal(
            blob, record_type=self._RECORD_TYPE, version=self._VERSION)
        record = sealed.to_dict()
        record.update({"write_origin": write_origin, "written_at": issued_at})
        # One row replacement keeps credential + provenance atomic.
        self._backend.put(self._KEY, record)

    def access_token(self) -> str:
        return self._open()["access_token"]

    def token_record(self) -> dict:
        """Return the decrypted Gateway-internal record.

        This method must never be exposed on an Agent-facing route. It exists
        so the refresh provider can rotate the access token without copying any
        token material through argv, logs, or messages.
        """
        return dict(self._open())

    def replace_access_token(
        self,
        *,
        access_token: str,
        issued_at: int,
        expires_at: Optional[int],
        refresh_token: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> None:
        current = self._open()
        self.store(
            access_token=access_token,
            refresh_token=refresh_token or current.get("refresh_token"),
            issued_at=issued_at,
            expires_at=expires_at,
            client_id=current.get("client_id"),
            client_secret=current.get("client_secret"),
            scope=scope or current.get("scope"),
            write_origin="refresh",
        )

    def _open(self) -> dict:
        raw = self._backend.get(self._KEY)
        if raw is None:
            raise KeyUnavailableError("no sealed token stored")
        # AEAD open fails closed on tamper / wrong key / mismatched (type,version).
        data = json.loads(self._cipher.open(SealedRecord.from_dict(raw)).decode("utf-8"))
        if not isinstance(data.get("access_token"), str):
            raise KeyMaterialError("sealed token missing access_token")
        # New records expose non-secret write provenance for incident review,
        # but authenticate it by matching the copy inside the ciphertext.
        # Legacy records have neither field and remain readable.
        outer_origin, inner_origin = raw.get("write_origin"), data.get("write_origin")
        outer_at, inner_at = raw.get("written_at"), data.get("written_at")
        if ((outer_origin is not None or inner_origin is not None)
                and (outer_origin != inner_origin
                     or outer_origin not in self._WRITE_ORIGINS
                     or outer_at != inner_at)):
            raise KeyMaterialError("sealed token write provenance mismatch")
        return data


class ConfirmDispatcher:
    """Option B (Agent-relay) confirm + dispatch. See the module docstring for
    the accepted gate-7(a)/(b) POC relaxation."""

    def __init__(self, fsm: SendFSM, *, now: Callable[[], int]):
        self._fsm = fsm
        self._now = now

    def confirm_and_dispatch(self, proposal_id: str) -> str:
        """Confirm (as the relayed human) then dispatch; return the terminal
        status value (sent / failed / outcome_unknown).

        Raises the FSM/store transition errors unchanged — an unknown/expired/
        already-settled proposal fails closed here, never a second send. The
        FSM's own gate 8 (no auto-retry of OUTCOME_UNKNOWN) and idempotency
        (AlreadySettledError) are the structural guarantees behind that.
        """
        now = self._now()
        # Actor.HUMAN on the relay is the accepted 7(a) relaxation: the Gateway
        # trusts the Agent's assertion that the human confirmed.
        self._fsm.confirm(proposal_id, actor=Actor.HUMAN, now=now)
        return self._fsm.dispatch(proposal_id, now=now).value
