"""Test fixtures for the authz vertical slice (seam-split rebuild 2026-09-05).

Everything uses freshly generated Ed25519 FIXTURE keypairs, an ADVANCEABLE
user-root-signed state head (not a frozen constant -- 测试姬/Boris's red line),
and a Gmail STUB sender. No real credentials, no network, no real Gmail send.

The cloud is modelled as two UNTRUSTED channels off one facade:
  * a ``StubSyncSource`` shipping the signed ``authz_state`` head (step ①), which
    can be made unreachable or made to WITHHOLD the newest head;
  * a ``StubDecisionService`` giving the signed second opinion (step ③).
Plus the operator CONTROL PLANE (``HeadState``): ``revoke``/``supersede`` mutate
the active set and re-sign a genuinely new head, so a revocation provably changes
the head digest and drops the grant from ``active_grants``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from actionset.switch import SwitchMode
from authz.audit import AuthzAuditLog
from authz.capability import signing_input
from authz.dispatch_record import DispatchRecordLog
from authz.gate import AuthorizationGate
from authz.orchestrator import AuthorizedGmailSend
from authz.service import (
    AuthorizationRequest,
    HighWaterMark,
    StubDecisionService,
    request_binding,
)
from authz.state import HeadState, StubSyncSource
from canonicalizer.jcs import sha256_hex
from sendfsm.fsm import SendFSM, SendResult, SendResultKind
from store.backend import InMemoryAppendLog, InMemoryKV
from store.ledger import AuditLedger
from store.proposals import Proposal, ProposalStore

# Fixed clock (epoch seconds) so RFC3339 validity windows are deterministic.
NOW = 1_780_000_000
PAYLOAD_DIGEST = "a" * 64          # stand-in SHA-256 hex of the frozen email payload
GRANT_ID = "00112233445566778899aabbccddeeff"  # default grant_id used by grant_body
GATEWAY_ACCOUNT = "me@test.example"  # the account this Gateway sends from (§6 config)
PEER_MACHINE_ID = "m1"             # default os_account subject identity (matches grant_body)
PEER_ACCOUNT = "acct-1"
CHANNEL_CHALLENGE = "cb-1"         # fixture connection-level one-time challenge (agent_key)
GRANT_VERSION = "1"


def new_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def raw_pub(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)


def pubkey_hex(pub: Ed25519PublicKey) -> str:
    return raw_pub(pub).hex()


def issuer_fp_of(pub: Ed25519PublicKey) -> str:
    return sha256_hex(raw_pub(pub))


def rfc3339(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def grant_body(
    *,
    issuer_fp: str,
    grant_id: str = GRANT_ID,
    grant_version: str = GRANT_VERSION,
    state_version: str = "1",
    subject: Optional[dict] = None,
    tool: str = "gmail",
    action: str = "send",
    scope: Optional[dict] = None,
    approval_mode: str = "auto",
    include_approval_mode: bool = True,
    valid_from: Optional[int] = None,
    valid_until: Optional[int] = None,
) -> dict:
    if subject is None:
        subject = {"kind": "os_account", "machine_id": "m1", "account": "acct-1"}
    if scope is None:
        scope = {"from_account": "me@test.example"}
    vf = NOW - 3600 if valid_from is None else valid_from
    vu = NOW + 3600 if valid_until is None else valid_until
    body: dict = {
        "grant_id": grant_id,
        "grant_version": grant_version,
        "issuer_fp": issuer_fp,
        "subject": subject,
        "tool": tool,
        "action": action,
        "scope": scope,
        "valid_from": rfc3339(vf),
        "valid_until": rfc3339(vu),
        "state_version": state_version,
    }
    if include_approval_mode:
        body["approval_mode"] = approval_mode
    return body


def sign_grant(user_priv: Ed25519PrivateKey, body: dict,
               *, artifact_type: str = "grant") -> dict:
    sig = user_priv.sign(signing_input(artifact_type, body))
    return {"v": 1, "type": artifact_type, "body": body, "sig": sig.hex()}


def agent_subject(agent_pub: Ed25519PublicKey, slug: str = "bob") -> dict:
    return {"kind": "agent_key", "agent_pubkey": pubkey_hex(agent_pub), "agent_slug": slug}


class FakeMonotonic:
    """Deterministic continuous-clock (ns) stand-in for the response-deadline /
    R2 offsets. Values are nanoseconds, matching ``authz.clock`` (the real seam
    reads ``time.clock_gettime_ns``).

    Injected so a test controls the elapsed value DIRECTLY -- the deadline
    assertion moves the variable it claims to test (a scripted delta), never a
    real wall-clock sleep, so it can never be a timing-based false-green. It also
    keeps the platform continuous-clock resolution (which fails closed off
    macOS/Linux) out of the test path, so the suite runs on any platform."""

    def __init__(self, values: Optional[List[float]] = None, step: float = 0.0):
        self._values = list(values) if values is not None else None
        self._step = step
        self._t = 0.0
        self._i = 0

    def __call__(self) -> float:
        if self._values is not None:
            v = self._values[min(self._i, len(self._values) - 1)]
            self._i += 1
            return v
        v = self._t
        self._t += self._step
        return v


class CloudFacade:
    """The untrusted cloud, as tests see it: operator control plane + two relay
    channels + the decision service, behind one handle."""

    def __init__(self, head_state: HeadState, sync_source: StubSyncSource,
                 decision_service: StubDecisionService):
        self._head = head_state
        self._sync = sync_source
        self._decision = decision_service

    # operator control plane (re-signs a genuinely new head) ----------------
    def revoke(self, grant_id: str) -> None:
        self._head.revoke(grant_id)

    def supersede(self, grant_id: str, new_version: int) -> None:
        self._head.supersede(grant_id, new_version)

    def add(self, grant_id: str, grant_version: str) -> None:
        self._head.add(grant_id, grant_version)

    # relay reachability -----------------------------------------------------
    def set_reachable(self, reachable: bool) -> None:
        # Both channels down == "the cloud is unreachable" -> fail closed.
        self._sync.set_reachable(reachable)
        self._decision.set_reachable(reachable)

    def set_sync_reachable(self, reachable: bool) -> None:
        self._sync.set_reachable(reachable)

    def set_decision_reachable(self, reachable: bool) -> None:
        self._decision.set_reachable(reachable)

    def withhold(self) -> None:
        self._sync.pin_and_withhold()

    def withhold_revocations(self) -> None:
        # Deliver the advanced head but DROP the revocation artifacts (§6 red B):
        # the grant is gone from active_grants, but with no artifact the outcome
        # is NO_GRANT, not REVOKED.
        self._sync.withhold_revocations()

    def resume(self) -> None:
        self._sync.resume()

    # decision service -------------------------------------------------------
    def decide(self, request: AuthorizationRequest, *, now: int):
        return self._decision.decide(request, now=now)

    @property
    def decision_public_key(self) -> Ed25519PublicKey:
        return self._decision.decision_public_key

    @property
    def head_state(self) -> HeadState:
        return self._head


@dataclass
class StubSender:
    """Records every invocation; returns a provider-ACCEPTED result by default."""

    kind: SendResultKind = SendResultKind.ACCEPTED
    calls: List[str] = field(default_factory=list)

    def __call__(self, proposal_id: str) -> SendResult:
        self.calls.append(proposal_id)
        return SendResult(kind=self.kind, message_id_sha256="b" * 64,
                          egress_hosts=("gmail.googleapis.com",))


@dataclass
class Slice:
    user_priv: Ed25519PrivateKey
    issuer_fp: str
    state_digest: str
    service: CloudFacade
    head_state: HeadState
    sync_source: StubSyncSource
    gate: AuthorizationGate
    authz_audit: AuthzAuditLog
    orchestrator: AuthorizedGmailSend
    store: ProposalStore
    send_ledger: AuditLedger
    dispatch_records: DispatchRecordLog
    sender: StubSender
    proposal_id: str

    # --- convenience builders bound to this slice's keys/state -------------

    def grant_envelope(self, **kw) -> dict:
        kw.setdefault("issuer_fp", self.issuer_fp)
        return sign_grant(self.user_priv, grant_body(**kw))

    def request(
        self,
        envelope: dict,
        *,
        request_id: str = "req-1",
        action_digest: str = PAYLOAD_DIGEST,
        authz_state_digest: Optional[str] = None,
        peer_verified: bool = True,
        peer_machine_id: str = PEER_MACHINE_ID,
        peer_account: str = PEER_ACCOUNT,
        agent_priv: Optional[Ed25519PrivateKey] = None,
        bind_grant_id: Optional[str] = None,
        issued_at: int = NOW,
        channel_binding: str = CHANNEL_CHALLENGE,
    ) -> AuthorizationRequest:
        # authz_state_digest is advisory now -- the gate derives its own from the
        # head it accepts. Default to the current head digest for realism.
        asd = self.head_state.head_digest() if authz_state_digest is None else authz_state_digest
        agent_sig = None
        if agent_priv is not None:
            # Bind to the grant_id the gate will verify (overridable to model a
            # same-key grant-swap: sign against grant A, present against grant B).
            gid = bind_grant_id or envelope.get("body", {}).get("grant_id", GRANT_ID)
            agent_sig = agent_priv.sign(request_binding(
                gid, request_id, action_digest, issued_at, channel_binding))
            peer_verified = False
        return AuthorizationRequest(
            grant_envelope=envelope, request_id=request_id,
            action_digest=action_digest, authz_state_digest=asd,
            issued_at=issued_at, channel_binding=channel_binding,
            peer_verified=peer_verified, peer_machine_id=peer_machine_id,
            peer_account=peer_account, agent_sig=agent_sig)


def make_slice(*, reachable: bool = True,
               sender_kind: SendResultKind = SendResultKind.ACCEPTED,
               proposal_id: str = "prop-1",
               gateway_account: str = GATEWAY_ACCOUNT,
               active_grants: Optional[dict] = None,
               state_version_int: int = 1,
               channel_challenge: str = CHANNEL_CHALLENGE,
               continuous_clock_ns: Optional[Callable[[], int]] = None,
               peer_resolver=None,
               request_consumer=None, decision_consumer=None,
               high_water_mark: Optional[HighWaterMark] = None) -> Slice:
    user_priv, user_pub = new_keypair()
    issuer_fp = issuer_fp_of(user_pub)

    # Advanceable authoritative head: the grant is active at its own version.
    if active_grants is None:
        active_grants = {GRANT_ID: GRANT_VERSION}
    head_state = HeadState(user_priv, active_grants, state_version_int=state_version_int)
    sync_source = StubSyncSource(head_state, reachable=reachable)
    decision_service = StubDecisionService(head_state, reachable=reachable)
    cloud = CloudFacade(head_state, sync_source, decision_service)

    # ONE continuous security clock shared by the gate AND the orchestrator (§1):
    # all five readings (gate's send/received/verified + orchestrator's
    # gmail-commit-start/response-complete) come from the same source, so the three
    # R2 events are strictly ordered and provable. A step-1ns default makes reads
    # distinct; a test may inject a scripted clock for the deadline (it denies in
    # the gate, so the orchestrator never reads it).
    clock = continuous_clock_ns or FakeMonotonic(step=1.0)

    authz_audit = AuthzAuditLog(InMemoryAppendLog())
    gate = AuthorizationGate(
        decision_service, sync_source, authz_audit,
        user_root_public_key=user_pub, pinned_issuer_fp=issuer_fp,
        gateway_account=gateway_account, now=lambda: NOW,
        continuous_clock_ns=clock,
        channel_challenge=channel_challenge, peer_resolver=peer_resolver,
        request_consumer=request_consumer, decision_consumer=decision_consumer,
        high_water_mark=high_water_mark)

    store = ProposalStore(InMemoryKV())
    store.create(Proposal(
        proposal_id=proposal_id, payload_digest=PAYLOAD_DIGEST,
        expires_at=NOW + 100_000, created_at=NOW - 1000))

    send_ledger = AuditLedger(InMemoryAppendLog())
    dispatch_records = DispatchRecordLog(InMemoryAppendLog())
    sender = StubSender(kind=sender_kind)
    fsm = SendFSM(store, send_ledger, sender, switch_mode=SwitchMode.CONFIRM_THEN_SEND)
    orchestrator = AuthorizedGmailSend(
        gate, fsm, store, now=lambda: NOW,
        dispatch_records=dispatch_records,
        continuous_clock_ns=clock)

    return Slice(
        user_priv=user_priv, issuer_fp=issuer_fp,
        state_digest=head_state.head_digest(), service=cloud,
        head_state=head_state, sync_source=sync_source, gate=gate,
        authz_audit=authz_audit, orchestrator=orchestrator, store=store,
        send_ledger=send_ledger, dispatch_records=dispatch_records,
        sender=sender, proposal_id=proposal_id)


class ReplayService:
    """An UNTRUSTED relay: returns a fixed, pre-captured decision for EVERY
    request, ignoring the request it is handed. Models a cloud relay that replays
    or withholds. It NEVER forges a signature -- the captured decision is one the
    real service actually issued -- which is exactly the R1/R6/R7 threat: a
    validly-signed decision presented against a request it was not issued for.
    """

    def __init__(self, inner, captured_decision):
        self._inner = inner
        self._decision = captured_decision

    def decide(self, request, *, now):
        return self._decision

    @property
    def decision_public_key(self):
        return self._inner.decision_public_key


def capture_decision(slc: Slice, envelope: dict, **request_kw):
    """Obtain a genuinely service-signed decision for ``envelope`` (+ request
    overrides), to be replayed via ``ReplayService`` against a DIFFERENT request.
    Uses the real service, so the signature is authentic and non-forged.
    """
    return slc.service.decide(slc.request(envelope, **request_kw), now=NOW)
