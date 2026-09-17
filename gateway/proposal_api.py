"""Agent-facing proposal endpoint (ASSEMBLY_PLAN step iv).

This is the closed IPC surface the Agent process may call. Its entire reachable
vocabulary is "propose an email, ask its status" — that set *is* gate 3/4/7,
structurally, because a route that is not served cannot be reached by any
caller, injected-prompt Agent included.

Two layers, mirroring `oauth` (pure) / `oauth_listener` (I/O):

- `ProposalService` — transport-independent. `propose()` runs the closed
  `actionset.prepare_email` projection (gate 4 closed schema + v1 policy, both
  fail-closed *before* anything is persisted), records a digest-only `Proposal`
  in the store, and freezes the canonical payload in a **separate content
  store**. `get_status()` returns audit-safe fields only.
- `ProposalServer` / `_ProposalHandler` — loopback HTTP wrapping the service.

Boundary properties:
- **Closed set (gates 3/4/7 / C7 ③).** The served routes are *exactly*
  `{POST /proposal, GET /proposal/{id}}`. No confirm, no send/raw, no
  token/key, no switch — those routes do not exist, so the Agent cannot express
  them. Enforcement is the served route table, not a naming convention.
- **Uniform rejection (测试姬 pt 2).** Every path/method outside the served set,
  *and* every request without the valid session bearer, gets one identical
  404. There is deliberately no 404-route-absent vs 401-route-exists response,
  so an injected Agent cannot probe the surface for a non-public route's
  existence.
- **Content stays off the audit/proposal records.** The canonical payload holds
  recipients/subject/body (PII); it is frozen in its own content store, never
  in the digest-only `Proposal` record or the token/PII-free ledger, and no
  Agent route returns it. `get_status` exposes the digest (a hash) and status
  only.
- **Content fidelity (gate 7b groundwork).** The stored canonical's JCS digest
  is asserted equal to the digest returned to the Agent, so the bytes frozen
  for send match exactly what the digest commits to.
- **Bearer is a capability credential.** It is compared in constant time, never
  logged (the handler's request log is silenced — the body carries PII), and
  never echoed in a response.
"""

from __future__ import annotations

import hmac
import json
import secrets
import socketserver
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit

from actionset.prepare import prepare_email
from canonicalizer.jcs import digest as _jcs_digest
from canonicalizer.payload import (
    AttachmentsNotSupportedError,
    PayloadSchemaError,
    build_canonical_payload,
)
from sendfsm.errors import (
    AlreadySettledError,
    IllegalTransitionError,
    NoAutoRetryError,
)
from store.backend import KVBackend
from store.errors import (
    DuplicateIdempotencyError,
    ProposalExpiredError,
    ProposalNotFoundError,
)
from store.proposals import Proposal, ProposalStatus, ProposalStore

from .send_path import ConfirmDispatcher

# Cap the request body: a proposal is small; an unbounded read is a local DoS.
_MAX_BODY_BYTES = 1 << 20  # 1 MiB


class MessageIdNotConfiguredError(PayloadSchemaError):
    """A production propose was attempted with no Message-ID factory configured.

    §2.7 single-minter ruling (Jeff 205708): the Message-ID is minted *once* at
    Gateway propose and frozen into the authorized bytes; the daemon only
    consumes it. A production sender therefore MUST have a configured factory
    (its domain is a deployment choice). With none, `propose` refuses here --
    before any authorize/persist -- rather than silently freezing an ID-less
    proposal that would later send a mail with no Message-ID (or tempt a
    send-time fabrication, which the ruling forbids).

    Subclasses `PayloadSchemaError` so the HTTP surface already maps it to the
    same coarse `invalid_payload` as any other closed-schema refusal: no new
    wire code, no probe surface, uniform rejection preserved.
    """


def mint_session_bearer() -> str:
    """A fresh per-session capability token for the proposal channel.

    Minted by the supervisor (step v) and handed only to the Agent process;
    treated like any other secret (never logged / emitted to evidence).
    """
    return secrets.token_urlsafe(32)


class ProposalService:
    """Propose / status logic over the injected stores and clock.

    `proposals` is the digest-only `ProposalStore`; `payloads` is a *separate*
    content store (a `KVBackend`) that freezes the canonical payload for the
    later confirmed send. Keeping them apart is what keeps the audit/proposal
    records PII-free while still letting the sender reproduce the exact
    confirmed bytes.
    """

    def __init__(
        self,
        *,
        proposals: ProposalStore,
        payloads: KVBackend,
        now: Callable[[], int],
        ttl_seconds: int,
        proposal_id_factory: Callable[[], str],
        message_id_factory: Callable[[], str] | None = None,
        require_message_id: bool = False,
    ):
        self._proposals = proposals
        self._payloads = payloads
        self._now = now
        self._ttl = ttl_seconds
        self._id_factory = proposal_id_factory
        # §2.7: mints the Gateway-owned RFC 5322 Message-ID once per new proposal.
        # Injected (the domain is a deployment choice the entrypoint supplies), so
        # this service never derives an ID from the host. When None, no ID is
        # minted -- the additive default that keeps non-send/legacy paths (the
        # gate golden vectors, schema tests) unchanged.
        self._message_id_factory = message_id_factory
        # §2.7 single-minter (Jeff 205708): a *production* sender must have a
        # configured factory. When True, propose refuses if no ID can be minted,
        # so an unconfigured deployment fails closed rather than sending ID-less
        # mail. False keeps the additive default above for non-production callers.
        self._require_message_id = require_message_id

    def propose(self, params: dict) -> dict:
        """Create a pending proposal from a closed PrepareEmail action.

        Returns `{proposal_id, payload_digest, expires_at}` — identifiers only,
        never content or a send handle. Raises `PayloadSchemaError` /
        `AttachmentsNotSupportedError` for anything outside the closed v1 schema
        (fail-closed, before any store write).
        """
        # §2.7 single-minter fail-closed (Jeff 205708): a production sender with
        # no configured Message-ID factory refuses HERE -- before any authorize
        # (prepare_email) or persist -- so a missing deployment domain can never
        # silently freeze/send an ID-less mail, nor defer to a send-time fabricated
        # ID (which the ruling forbids). Non-production callers leave the flag off.
        if self._require_message_id and self._message_id_factory is None:
            raise MessageIdNotConfiguredError(
                "message_id is required but no factory/domain is configured")

        idempotency_key = params.get("idempotency_key")
        if idempotency_key is not None and not isinstance(idempotency_key, str):
            raise PayloadSchemaError("idempotency_key must be a string")

        # Idempotent replay: an existing live-or-settled proposal for this key
        # wins; we neither re-mint an id nor re-freeze content.
        if idempotency_key is not None:
            existing = self._proposals.find_by_idempotency(idempotency_key)
            if existing is not None:
                return self._identifiers(existing)

        now = self._now()
        # §2.7: mint the Message-ID ONCE, here, before either digest derivation,
        # so the exact ID is inside the authorized frozen bytes. The one value is
        # threaded into BOTH derivations below; a re-mint per derivation would
        # trip the digest tripwire (and break "generate once").
        message_id = (
            self._message_id_factory() if self._message_id_factory else None)
        # Defence in depth: a configured factory that yields an empty/None id is
        # a broken deployment, not a valid ID-less proposal -- refuse rather than
        # freeze one (still before any persist). (canonicalizer also rejects an
        # empty string; this also catches None from a misbehaving factory.)
        if self._require_message_id and not message_id:
            raise MessageIdNotConfiguredError(
                "message_id factory yielded no id")
        # gate 4 closed schema + v1 policy both fail closed in here, before we
        # persist anything.
        result = prepare_email(
            params, now=now, ttl_seconds=self._ttl,
            proposal_id_factory=self._id_factory, message_id=message_id)

        canonical = build_canonical_payload(params, message_id=message_id)
        # Consistency guard across the two independent digest call sites: the
        # value prepare_email returned to the Agent, and a fresh digest of the
        # bytes about to be frozen for send. Equal while the two paths agree
        # (including on the one minted message_id); kept as a cheap fail-closed
        # tripwire for the day they drift, so a proposal can never freeze bytes
        # its committed digest omits.
        if _jcs_digest(canonical) != result.payload_digest:
            raise PayloadSchemaError("payload digest mismatch")

        # Freeze content before the proposal is discoverable, so a proposal is
        # never live without the bytes it commits to.
        self._payloads.put(result.proposal_id, canonical)
        try:
            self._proposals.create(Proposal(
                proposal_id=result.proposal_id,
                payload_digest=result.payload_digest,
                expires_at=result.expires_at,
                created_at=now,
                status=ProposalStatus.PENDING,
                idempotency_key=idempotency_key))
        except DuplicateIdempotencyError:
            # Lost a race to a concurrent duplicate; the winner stands. Drop the
            # payload just frozen under the losing id -- otherwise its canonical
            # (PII-bearing) bytes are orphaned in the content store with no
            # proposal to reference them or drive their expiry.
            self._payloads.delete(result.proposal_id)
            existing = self._proposals.find_by_idempotency(idempotency_key)
            if existing is not None:
                return self._identifiers(existing)
            raise
        return self._identifiers(result)

    def get_status(self, proposal_id: str) -> dict:
        """Audit-safe view: digest + status + timestamps. No content, no token."""
        p = self._proposals.get(proposal_id)  # raises ProposalNotFoundError
        return {
            "proposal_id": p.proposal_id,
            "status": p.status.value,
            "payload_digest": p.payload_digest,
            "expires_at": p.expires_at,
            "created_at": p.created_at,
        }

    def load_payload(self, proposal_id: str) -> dict:
        """The frozen canonical payload for a proposal (the sender's seam).

        Not reachable from any Agent route — this is the Gateway-internal read
        side of the content store, consumed by the send path (step v).
        """
        raw = self._payloads.get(proposal_id)
        if raw is None:
            raise ProposalNotFoundError(proposal_id)
        return raw

    @staticmethod
    def _identifiers(p) -> dict:
        return {
            "proposal_id": p.proposal_id,
            "payload_digest": p.payload_digest,
            "expires_at": p.expires_at,
        }


class _ProposalHandler(BaseHTTPRequestHandler):
    # The only two served routes. Everything else is a uniform 404.
    #
    # Every request body is drained before the response, even on rejection: on
    # Windows, closing a socket with unread request data sends an RST that
    # aborts the client before it can read our reply.
    def do_POST(self):  # noqa: N802 (stdlib naming)
        body = self._read_request_body()
        path = urlsplit(self.path).path
        if not self._authed():
            return self._uniform_404()
        if path == "/proposal":
            return self._handle_propose(body)
        # The confirm route exists only when a ConfirmDispatcher is mounted --
        # i.e. only under Option B (Agent-relay confirm). Mounting it is itself
        # the accepted gate-7 POC relaxation (see gateway.send_path).
        cid = self._confirm_id_from_path(path)
        if cid is not None and self.server.confirm is not None:
            return self._handle_confirm(cid)
        self._uniform_404()

    def do_GET(self):  # noqa: N802
        self._read_request_body()
        pid = self._proposal_id_from_path(urlsplit(self.path).path)
        if not self._authed() or pid is None:
            return self._uniform_404()
        self._handle_status(pid)

    # Every other method -- a standard verb (HEAD/PUT/DELETE/...) or an exotic
    # one (TRACE/CONNECT/FOOBAR) alike -- resolves here to the SAME uniform 404.
    # Expressed as "any do_* we don't explicitly define" (the boundary as a
    # property) rather than a verb allow/deny list (an enumeration an exotic verb
    # slips past into the stdlib's distinguishable 501). So the no-route-oracle
    # guarantee holds across the method dimension too, not just the path.
    def __getattr__(self, name):
        if name.startswith("do_"):
            def reject():
                self._read_request_body()
                self._uniform_404()
            return reject
        raise AttributeError(name)

    def _read_request_body(self) -> bytes | None:
        """Read (and thus drain) the request body. None => absent or too large."""
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0:
            return None
        if length > _MAX_BODY_BYTES:
            self.rfile.read(_MAX_BODY_BYTES)  # bounded drain so the socket closes clean
            return None
        return self.rfile.read(length)

    def _handle_propose(self, body: bytes | None):
        if not body:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
        try:
            params = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
        if not isinstance(params, dict):
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
        try:
            result = self.server.service.propose(params)
        except AttachmentsNotSupportedError as exc:
            return self._json(HTTPStatus.BAD_REQUEST, {"error": exc.code})
        except (PayloadSchemaError, ValueError):
            # A closed-schema violation. The message can name the offending
            # field, but never the body content, so we return a coarse code.
            return self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
        self._json(HTTPStatus.OK, result)

    def _handle_status(self, proposal_id):
        try:
            result = self.server.service.get_status(proposal_id)
        except ProposalNotFoundError:
            return self._uniform_404()
        self._json(HTTPStatus.OK, result)

    def _handle_confirm(self, proposal_id):
        try:
            status = self.server.confirm.confirm_and_dispatch(proposal_id)
        except ProposalNotFoundError:
            return self._uniform_404()  # same as an unknown proposal on GET
        except ProposalExpiredError:
            return self._json(HTTPStatus.CONFLICT, {"error": "expired"})
        except (IllegalTransitionError, AlreadySettledError, NoAutoRetryError):
            # Already confirmed/settled, or an indeterminate outcome that must
            # not be re-sent (gate 8). Only reachable by the bearer-holder.
            return self._json(HTTPStatus.CONFLICT, {"error": "conflict"})
        self._json(HTTPStatus.OK, {"proposal_id": proposal_id, "status": status})

    def _authed(self) -> bool:
        header = self.headers.get("Authorization", "")
        prefix = "Bearer "
        # Always run the constant-time compare, even when the prefix is absent,
        # so a malformed/absent header can't be told apart from a wrong token by
        # an early-return timing difference. presented="" just compares unequal.
        presented = header[len(prefix):] if header.startswith(prefix) else ""
        return hmac.compare_digest(presented, self.server.session_bearer)

    @staticmethod
    def _proposal_id_from_path(path: str) -> str | None:
        prefix = "/proposal/"
        if not path.startswith(prefix):
            return None
        pid = path[len(prefix):]
        # Exactly one non-empty id segment (no nested path, no trailing slash).
        if not pid or "/" in pid:
            return None
        return pid

    @staticmethod
    def _confirm_id_from_path(path: str) -> str | None:
        prefix, suffix = "/proposal/", "/confirm"
        if not (path.startswith(prefix) and path.endswith(suffix)):
            return None
        pid = path[len(prefix):-len(suffix)]
        if not pid or "/" in pid:
            return None
        return pid

    def _json(self, status, payload) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _uniform_404(self) -> None:
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def log_message(self, *args):
        # Silence the default stderr request log: the request line/body carry
        # recipient addresses and the bearer must never be written anywhere.
        return


class ProposalServer(ThreadingHTTPServer):
    """Loopback proposal channel. Concurrent Agent calls are fine — the SQLite
    backends are thread-safe (lock + check_same_thread=False)."""

    daemon_threads = True

    def __init__(self, service: ProposalService, session_bearer: str,
                 *, confirm: ConfirmDispatcher | None = None,
                 host: str = "127.0.0.1"):
        super().__init__((host, 0), _ProposalHandler)  # port 0 -> ephemeral
        self.service = service
        self.session_bearer = session_bearer
        # When set, mounts POST /proposal/{id}/confirm (Option B relaxation).
        self.confirm = confirm

    def server_bind(self) -> None:
        """Bind WITHOUT the stdlib's reverse-DNS lookup (P1).

        ``HTTPServer.server_bind`` sets ``self.server_name = socket.getfqdn(host)``.
        On CPython 3.14 / macOS (the deployment host's default ``python3``,
        Homebrew 3.14.5) ``getfqdn`` on a loopback bind can stall ~35s on a DNS
        reverse lookup -- past the 15s ready timeout -- so the Gateway never comes
        up. 3.12 does not reproduce (interpreter-gated). This is a loopback-only
        control channel; the FQDN is never used, so we bind via TCPServer (no
        getfqdn) and derive server_name/server_port from the bound socket."""
        # TCPServer.server_bind binds + sets server_address; it does NOT call
        # getfqdn -- that is the HTTPServer layer we are deliberately skipping.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host          # loopback literal, not a reverse-DNS name
        self.server_port = port

    @property
    def port(self) -> int:
        return self.server_address[1]
