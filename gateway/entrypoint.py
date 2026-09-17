"""The summoned Gateway process (ASSEMBLY_PLAN step v-b target).

This is the entrypoint the supervisor spawns as a *distinct* OS process
(`python -m gateway.entrypoint --data-root ...`). It assembles the already-built
cores over the on-disk backends and serves the closed Agent-facing proposal set
(step iv). It is deliberately a real, minimal process — not a stub — so that the
supervisor's C7 ① guarantee ("the token-holding part runs in a separate
process") is realised, not merely asserted.

Design decisions (the *why*):

- **Port on stdout, bearer via env.** The child prints exactly one readiness
  line — `{"status":"ready","port":N}` — to stdout, then serves. The port is not
  a secret; the session bearer is, so it is passed *in* through the environment
  (`GATEWAY_SESSION_BEARER`) and never echoed to stdout, a log, or the handshake.
  A parent that captures stdout thus learns the port without ever seeing the
  capability credential on a pipe.
- **Serves only the step-(iv) closed set.** No confirm route is mounted here
  (`ProposalServer` without a `ConfirmDispatcher`) and no token is loaded: this
  slice proves the *summon/lifecycle*, so the summoned surface is the pure closed
  `{POST /proposal, GET /proposal/{id}}`. Wiring dispatch (which loads the sealed
  token) into the entrypoint is a later assembly step; keeping it out here means
  the supervised process holds no token at all, so the lifecycle tests never
  touch a credential.
- **Graceful shutdown where the OS allows it.** `serve_forever` runs on the main
  thread; a SIGTERM/SIGINT handler asks a helper thread to `shutdown()` (calling
  it inline would deadlock the serve loop). On Windows `terminate()` is a hard
  TerminateProcess with no handler — that is fine: WAL + `synchronous=FULL` makes
  the SQLite state crash-safe, so a hard kill loses no committed audit row.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
import uuid

from store.proposals import ProposalStore

from . import paths
from .message_id import generate_message_id
from .persistence import SqliteKV
from .proposal_api import ProposalServer, ProposalService

_READY_ENV_BEARER = "GATEWAY_SESSION_BEARER"
_DEFAULT_TTL_SECONDS = 3600


def build_server(*, data_root: str, session_bearer: str,
                 ttl_seconds: int = _DEFAULT_TTL_SECONDS,
                 host: str = "127.0.0.1",
                 message_id_domain: str | None = None) -> ProposalServer:
    """Assemble the closed proposal server over the on-disk backends.

    Split out from `main` so a test can build the exact same server in-process
    without spawning, and so the data-root layout lives in one place.

    `message_id_domain` (§2.7): proposals mint an RFC 5322 Message-ID under this
    domain (frozen into the authorized bytes). The domain is a deployment choice
    the spawner supplies. This is a *production* sender, so the Message-ID is
    required (single-minter ruling, Jeff 205708): when the domain is absent,
    `propose` fails closed rather than freezing/sending an ID-less mail.
    """
    proposals = SqliteKV(paths.proposals_db(data_root))
    payloads = SqliteKV(paths.payloads_db(data_root))
    # Bind the domain once; the factory itself takes no args (mints one ID/call).
    message_id_factory = (
        (lambda: generate_message_id(domain=message_id_domain))
        if message_id_domain else None)
    service = ProposalService(
        proposals=ProposalStore(proposals),
        payloads=payloads,
        now=lambda: int(time.time()),
        ttl_seconds=ttl_seconds,
        proposal_id_factory=lambda: uuid.uuid4().hex,
        message_id_factory=message_id_factory,
        # Production entry: Gateway is the single Message-ID minter, so a
        # deployment with no domain refuses at propose (before authorize/send)
        # instead of silently emitting ID-less mail.
        require_message_id=True,
    )
    server = ProposalServer(service, session_bearer, host=host)
    # Hand the backends to the server so shutdown can close them (Windows locks
    # an open SQLite file); no Agent route reaches these.
    server._backends = (proposals, payloads)  # type: ignore[attr-defined]
    return server


def _install_shutdown(server: ProposalServer) -> None:
    def handler(signum, frame):  # noqa: ANN001
        # serve_forever holds the main thread; shutdown() must run off it.
        threading.Thread(target=server.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            # Not all signals are settable on every platform / thread.
            pass


def _announce_ready(server: ProposalServer) -> None:
    # The one and only line the supervisor parses. Flush so the parent's blocking
    # readline unblocks immediately regardless of stdout buffering.
    sys.stdout.write(json.dumps({"status": "ready", "port": server.port}) + "\n")
    sys.stdout.flush()


def main(argv: "list[str] | None" = None) -> int:
    parser = argparse.ArgumentParser(prog="gateway.entrypoint")
    parser.add_argument("--data-root", required=True)
    parser.add_argument("--ttl-seconds", type=int, default=_DEFAULT_TTL_SECONDS)
    parser.add_argument("--host", default="127.0.0.1")
    # §2.7: the Message-ID domain (a deployment/supervisor choice). Absent ->
    # this production sender refuses to propose (single-minter fail-closed), so
    # it can never emit ID-less mail; it is not an optional "no-ID" mode.
    parser.add_argument("--message-id-domain", default=None)
    args = parser.parse_args(argv)

    bearer = os.environ.get(_READY_ENV_BEARER)
    if not bearer:
        # Fail closed: an unbound proposal surface (no bearer) would 404 on the
        # legitimate caller anyway, but refusing to start makes the misconfig loud.
        sys.stderr.write("gateway.entrypoint: %s not set\n" % _READY_ENV_BEARER)
        return 2

    server = build_server(
        data_root=args.data_root, session_bearer=bearer,
        ttl_seconds=args.ttl_seconds, host=args.host,
        message_id_domain=args.message_id_domain)
    _install_shutdown(server)
    _announce_ready(server)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        for backend in getattr(server, "_backends", ()):
            backend.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
