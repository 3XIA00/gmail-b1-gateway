"""Local POC scaffold: seed one proposal so an end-to-end real send can run.

This is **not** a product verb. The Agent-facing way to create a proposal is
`POST /proposal` on the running Gateway (`gateway.proposal_api`); the operator
verb set stays exactly `{authorize, send}` (see `gateway.__main__`). But an
operator running the full local smoke — authorize -> seed -> send — needs a
proposal frozen in the shared data-root without standing up the HTTP server and
minting a bearer. This module is that one step, and nothing more:

    python -m gateway.seed_proposal \
        --data-root <dir> --account-handle <acct> \
        --to <addr> --subject <s> --body <text>

It **reuses `ProposalService.propose` verbatim** — the same closed gate-4 schema,
the same v1 text/attachment policy, the same content freeze and digest tripwire.
It adds no field, no pass-through, and no bypass: any input outside the closed
schema fails closed here exactly as it would on the Agent route. It writes only
the two stores `send` later reads (`proposals`, `payloads`) at the same
data-root, so the proposal it freezes is byte-for-byte the one `send` confirms.

It performs no send and holds no token: seeding a proposal is inert until an
explicit, separately-approved `send --proposal <id>` confirms and dispatches it.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from typing import Callable

from canonicalizer.payload import (
    AttachmentsNotSupportedError,
    PayloadSchemaError,
)
from store.proposals import ProposalStore

from . import paths
from .persistence import SqliteKV
from .proposal_api import ProposalService

# Mirror the running Gateway's defaults (gateway.entrypoint) so a seeded
# proposal behaves identically to an Agent-proposed one: same id shape, same
# lifetime. 3600s leaves comfortable room between seeding and the separately
# gated send (the per-send approval sits in that window).
_DEFAULT_TTL_SECONDS = 3600


def run_seed(
    *,
    data_root: str,
    params: dict,
    ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    now: Callable[[], int] | None = None,
) -> dict:
    """Freeze one proposal from `params` into the shared data-root.

    A thin file-lifecycle wrapper around `ProposalService.propose` (exactly as
    `run_send` is around `confirm_and_dispatch`): it opens the on-disk backends,
    delegates the closed-schema projection + freeze to the unmodified service,
    and always closes the backends before returning (Windows locks open SQLite
    files). Returns `{proposal_id, payload_digest, expires_at}` — identifiers
    only; the content lives in the payload store, not in this return value.
    """
    clock = now or (lambda: int(time.time()))

    proposals_kv = SqliteKV(paths.proposals_db(data_root))
    payloads_kv = SqliteKV(paths.payloads_db(data_root))
    try:
        service = ProposalService(
            proposals=ProposalStore(proposals_kv),
            payloads=payloads_kv,
            now=clock,
            ttl_seconds=ttl_seconds,
            proposal_id_factory=lambda: uuid.uuid4().hex,
        )
        return service.propose(params)
    finally:
        for backend in (proposals_kv, payloads_kv):
            backend.close()


def _params_from_args(args: argparse.Namespace) -> dict:
    """Map the CLI flags onto a closed PrepareEmail params dict.

    The body format is fixed to ``text`` (the only v1 body) and cc/bcc are
    omitted when empty; every field here is a schema field — there is no
    pass-through slot for the operator to inject an unmodelled key through.
    """
    params: dict = {
        "account_handle": args.account_handle,
        "to": list(args.to),
        "subject": args.subject,
        "body": {"format": "text", "content": args.body},
    }
    if args.cc:
        params["cc"] = list(args.cc)
    if args.bcc:
        params["bcc"] = list(args.bcc)
    return params


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gateway.seed_proposal",
        description="POC scaffold: freeze one proposal for a local end-to-end "
                    "send. Not a product command.")
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--account-handle", required=True,
                        help="the authorized send-from account descriptor")
    parser.add_argument("--to", required=True, action="append", metavar="ADDR",
                        help="recipient (repeat for several); use a TEST account")
    parser.add_argument("--subject", required=True)
    parser.add_argument("--body", required=True, help="plain-text body content")
    parser.add_argument("--cc", action="append", default=[], metavar="ADDR")
    parser.add_argument("--bcc", action="append", default=[], metavar="ADDR")
    parser.add_argument("--ttl-seconds", type=int, default=_DEFAULT_TTL_SECONDS)
    args = parser.parse_args(argv)

    try:
        result = run_seed(
            data_root=args.data_root, params=_params_from_args(args),
            ttl_seconds=args.ttl_seconds)
    except AttachmentsNotSupportedError:
        # Unreachable from these flags (no attachment slot is offered), but the
        # reused gate could still refuse it -- surface fail-closed, coarsely.
        sys.stderr.write("seed: attachments are not supported in v1\n")
        return 2
    except (PayloadSchemaError, ValueError) as exc:
        # A closed-schema / policy violation. Name the class, never the content.
        sys.stderr.write("seed: rejected: %s\n" % type(exc).__name__)
        return 2
    except Exception as exc:  # noqa: BLE001 -- top-level sanitizing boundary
        sys.stderr.write("seed: failed: %s\n" % type(exc).__name__)
        return 1

    # Echo the operator's own input back (their local terminal, not a channel):
    # the id `send` needs, the digest to relay for approval, and the recipients/
    # subject so the per-send approval gate has the exact target to sign off.
    sys.stdout.write(
        "seeded proposal:\n"
        "  proposal_id:    %s\n"
        "  payload_digest: %s\n"
        "  expires_at:     %s\n"
        "  to:             %s\n"
        "  subject:        %s\n"
        "  body:           %d chars (text)\n"
        "next: send with  python -m gateway send --proposal %s --data-root %s\n"
        % (result["proposal_id"], result["payload_digest"], result["expires_at"],
           ", ".join(args.to), args.subject, len(args.body),
           result["proposal_id"], args.data_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
