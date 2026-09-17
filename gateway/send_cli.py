"""`gmail-gateway send --proposal <id>` -- confirm + dispatch one proposal.

The local, human-run half of Option B: a specific, already-proposed and
already-approved `proposal_id` is confirmed (Actor.HUMAN -- the operator running
this command *is* the human) and dispatched over the real egress-guarded client
to Gmail. It assembles the step-(v) send path over the on-disk backends at the
shared data-root, so the proposal it confirms is exactly the one the running
proposal server froze (cross-process handoff rides on the WAL-durable stores).

Design decisions (the *why*):

- **`--proposal` is required and explicit; there is no "send the latest".** On a
  real, irreversible send an implicit default is exactly where a hand-slip sends
  the wrong mail. The operator types the id every time (friction on purpose).
- **Terminal status drives the exit code.** sent -> 0; failed / outcome_unknown
  / any fail-closed refusal -> non-zero, so a wrapper script or a human sees
  non-success without parsing stdout.
- **Only the id + status are printed -- never the payload.** Recipient / subject
  / body live in the content store and stay there; this command's output is
  audit-safe.
- **Side effects injected for tests** (egress transport, key provider, clock),
  defaulting to the real OS keychain + the live urllib transport.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Callable

from actionset.switch import SwitchMode
from keystore.aead import AEADCipher
from keystore.providers import KeyProvider, KeyringKeyProvider
from sendfsm.errors import (
    AlreadySettledError,
    IllegalTransitionError,
    NoAutoRetryError,
)
from sendfsm.fsm import SendFSM
from store.errors import ProposalExpiredError, ProposalNotFoundError
from store.ledger import AuditLedger
from store.proposals import ProposalStore

from . import paths
from .egress import EgressGuardedClient, Transport
from .gmail_sender import GMAIL_HOST, GmailSender
from .persistence import SqliteAppendLog, SqliteKV
from .proposal_api import ProposalService
from .send_path import ConfirmDispatcher, SealedTokenStore
from .token_refresh import RefreshingTokenProvider

_KEYRING_SERVICE = "gmail-gateway"
_KEYRING_DEK_USER = "dek-v1"
_SENT = "sent"


def _no_new_ids() -> str:
    # The send path only reads/confirms an existing proposal; it must never mint
    # one. A ProposalService needs the factory, so make a stray call fail loud.
    raise RuntimeError("send path must not mint proposal ids")


def run_send(
    *,
    data_root: str,
    proposal_id: str,
    transport: Transport | None = None,
    key_provider: KeyProvider | None = None,
    now: Callable[[], int] | None = None,
) -> str:
    """Confirm + dispatch `proposal_id`. Returns the terminal status string.

    Opens the shared on-disk backends, wires the real send path, and always
    closes the backends before returning (Windows locks open SQLite files).
    """
    clock = now or (lambda: int(time.time()))
    provider = key_provider or KeyringKeyProvider(_KEYRING_SERVICE, _KEYRING_DEK_USER)

    proposals_kv = SqliteKV(paths.proposals_db(data_root))
    payloads_kv = SqliteKV(paths.payloads_db(data_root))
    token_kv = SqliteKV(paths.token_db(data_root))
    audit_log = SqliteAppendLog(paths.audit_db(data_root))
    try:
        service = ProposalService(
            proposals=ProposalStore(proposals_kv), payloads=payloads_kv,
            now=clock, ttl_seconds=0, proposal_id_factory=_no_new_ids)
        tokstore = SealedTokenStore(AEADCipher(provider), token_kv)
        refresh_client = EgressGuardedClient(
            {"oauth2.googleapis.com"}, transport=transport)
        token_provider = RefreshingTokenProvider(
            tokstore, refresh_client, now=clock)
        client = EgressGuardedClient({GMAIL_HOST}, transport=transport)
        sender = GmailSender(
            client, payload_provider=service.load_payload,
            token_provider=token_provider.access_token)
        fsm = SendFSM(ProposalStore(proposals_kv), AuditLedger(audit_log), sender,
                      switch_mode=SwitchMode.CONFIRM_THEN_SEND)
        return ConfirmDispatcher(fsm, now=clock).confirm_and_dispatch(proposal_id)
    finally:
        for backend in (proposals_kv, payloads_kv, token_kv, audit_log):
            backend.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gmail-gateway send")
    parser.add_argument("--data-root", required=True)
    parser.add_argument(
        "--proposal", required=True, dest="proposal_id",
        help="the exact proposal_id to send (required; no implicit default)")
    args = parser.parse_args(argv)

    try:
        status = run_send(data_root=args.data_root, proposal_id=args.proposal_id)
    except ProposalNotFoundError:
        sys.stderr.write("send: no such proposal: %s\n" % args.proposal_id)
        return 4
    except ProposalExpiredError:
        sys.stderr.write("send: proposal expired: %s\n" % args.proposal_id)
        return 5
    except (IllegalTransitionError, AlreadySettledError, NoAutoRetryError) as exc:
        # Already confirmed/settled, or an indeterminate outcome that must not be
        # re-sent (gate 8). Re-running `send` on the same id lands here -- the
        # anti-double-send guard, surfaced as a non-zero exit.
        sys.stderr.write(
            "send: cannot send %s: %s\n" % (args.proposal_id, type(exc).__name__))
        return 6
    except Exception as exc:  # noqa: BLE001 -- top-level sanitizing boundary
        sys.stderr.write("send: failed: %s\n" % type(exc).__name__)
        return 1

    # id + status only; the payload never appears here.
    sys.stdout.write("proposal %s: %s\n" % (args.proposal_id, status))
    return 0 if status == _SENT else 7


if __name__ == "__main__":
    raise SystemExit(main())
