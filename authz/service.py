"""Cloud decision service: the UNTRUSTED second opinion (L5 §5, ruling §0).

The 2026-09-05 ruling (Linus msg_9e866093 §0) split the old ``decide()`` seam.
It used to do two incompatible jobs at once -- act as the state-sync authority
AND run every grant/revocation/subject check in-process -- so swapping in a real
relay would have silently dropped §4-1/2/3. Those two jobs are now separated:

  * The authoritative state is the user-root-signed head (``authz.state``); the
    Gateway syncs and verifies it and runs ALL locally-derivable decisions
    (membership, validity, scope, subject, request freshness) itself.
  * This service is only the CLOUD's signed opinion -- a "second sync check +
    §5 reconciliation artifact" (§0 step ③). It is UNTRUSTED: it may withhold,
    replay, or swap any field. The Gateway authenticates its signature and
    cross-checks every binding field against its own derivation (the policy map)
    before the decision is used for anything, and it is consumed single-use
    Gateway-side. The decision authorizes NOTHING on its own.

This module keeps the pieces shared across the split: the ``Decision`` shape and
its signing/verification, the request binding the agent signs, the request/
decision single-use consumer seam, and the peer-identity type.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, replace
from typing import Dict, Optional, Protocol

from canonicalizer.jcs import canonicalize
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .capability import parse_envelope, parse_grant_body
from .errors import AuthorizationUnavailable
from .state import HeadState

# Domain tag for a service DECISION signature. Distinct from the user-artifact
# tags (grant/revocation/authz_state/...) so a decision sig can never be replayed
# as a user artifact and vice versa. A decision sig proves "this is the service's
# answer for this (request_id, action_digest) bound to this head" -- NOT that the
# grant is still valid (that is the Gateway's membership check against the
# verified head, §0b).
_DECISION_DOMAIN = b"puffo-authz/decision/v1\x00"

# Profile cap on grant validity span (production 7 days) and clock-skew slack.
VALIDITY_CAP_SECONDS = 7 * 24 * 3600
CLOCK_SKEW_SECONDS = 300
# Request-envelope freshness half-window (agent_key tier, §5 ±5 min).
REQUEST_FRESHNESS_SECONDS = 300
# decided_at hygiene half-window (§1 (d)): decided_at must lie within
# [t_request_sent - this, t_response_verified + this] on the GATEWAY's own clock.
DECIDED_AT_SLACK_SECONDS = 300
# Gateway CONTINUOUS-clock response deadline (§1): elapsed suspend-inclusive
# monotonic time from request send to decision verification. A response later
# than this is discarded even if its signature is valid -- the security clock is
# the Gateway's continuous clock (authz.clock), never decided_at. The clock reads
# nanoseconds (time.clock_gettime_ns), so the deadline is expressed in ns.
RESPONSE_DEADLINE_SECONDS = 5.0
RESPONSE_DEADLINE_NS = int(RESPONSE_DEADLINE_SECONDS * 1_000_000_000)


class Disposition:
    AUTHORIZED = "authorized"          # auto: may send now
    NEEDS_APPROVAL = "needs_approval"  # per_call: valid grant, awaits per-call approval


@dataclass(frozen=True)
class PeerIdentity:
    """An OS peer credential observed at THIS call (machine + account).

    STUB (Linus ruling ①): what a real SO_PEERCRED/LOCAL_PEERCRED lookup would
    return, re-resolved per request. Never to be recorded as "kernel verified".
    """
    machine_id: str
    account: str


@dataclass(frozen=True)
class AuthorizationRequest:
    grant_envelope: dict          # signed {v,type,body,sig} grant artifact
    request_id: str               # per-(grant) single-use id
    action_digest: str            # SHA-256 hex of the frozen canonical email artifact
    authz_state_digest: str       # digest of the head the caller relied on (advisory only)
    issued_at: int = 0            # request-envelope issue time (agent_key tier freshness)
    channel_binding: str = ""     # connection-level one-time challenge (echo)
    # os_account proof. STUB (Linus ruling ①): the peer identity the caller
    # observed at THIS call, NOT a kernel check. A test may override the gate's
    # resolver to model "verified peer A at connect, peer B by request time". It
    # must NEVER be recorded anywhere as "kernel credential verified".
    peer_verified: bool = False
    peer_machine_id: str = ""
    peer_account: str = ""
    # agent_key proof: agent signature over the request binding.
    agent_sig: Optional[bytes] = None


@dataclass(frozen=True)
class Decision:
    decision_id: str
    grant_id: str
    grant_version: str
    state_version: str
    authz_state_digest: str
    request_id: str
    action_digest: str
    decided_at: int
    disposition: str
    approval_mode: str            # grant's approval_mode ("auto"/"per_call")
    # RAW wire string, symmetric with approval_mode/disposition (R7): the closed
    # enum is validated ONLY by the policy guard (_check_subject_kind), never by a
    # .value assumption in the signing path -- an unknown value must mismatch, not
    # throw. See decision_policy._check_subject_kind and DELTA_R4.md (R7).
    subject_kind: str
    sig: bytes                    # service Ed25519 sig over decision_body (§4)


def request_binding(grant_id: str, request_id: str, action_digest: str,
                    issued_at: int, channel_binding: str) -> bytes:
    # What the agent signs per call (§3 request envelope, agent_key mode).
    # grant_id is bound in so an agent sig made for grant A cannot be replayed
    # against a different grant B signed by the same agent key (grant-swap).
    return canonicalize({
        "grant_id": grant_id,
        "request_id": request_id,
        "action_digest": action_digest,
        "issued_at": issued_at,
        "channel_binding": channel_binding,
    })


def decision_body(d: Decision) -> dict:
    """The canonical, signed body of a decision (everything but the sig)."""
    return {
        "decision_id": d.decision_id,
        "grant_id": d.grant_id,
        "grant_version": d.grant_version,
        "state_version": d.state_version,
        "authz_state_digest": d.authz_state_digest,
        "request_id": d.request_id,
        "action_digest": d.action_digest,
        "decided_at": d.decided_at,
        "disposition": d.disposition,
        "approval_mode": d.approval_mode,
        # raw value, no .value: signing-input must never throw on an unknown raw
        # subject_kind before the closed-set guard runs (R7).
        "subject_kind": d.subject_kind,
    }


def decision_signing_input(d: Decision) -> bytes:
    return _DECISION_DOMAIN + canonicalize(decision_body(d))


def verify_decision_sig(public_key: Ed25519PublicKey, d: Decision) -> bool:
    """True iff ``d.sig`` is the service's signature over this decision's body."""
    return _verify(public_key, decision_signing_input(d), d.sig)


class SingleUseConsumer(Protocol):
    """The single-use invariant, isolated behind one narrow atomic operation.

    ``consume_once`` returns True exactly once per ``key`` (the first caller) and
    False for every later caller. Making the check+write ONE atomic operation --
    not a lock wrapped around scattered code -- is the invariant's load-bearing
    point: a test can inject a deliberately non-atomic implementation and prove
    concurrent double-submit double-consumes, while the real implementation must
    not. Two keyspaces use this seam Gateway-side: the request consumer keys on
    ``(grant_id, request_id)`` (R8, both tiers) and the decision consumer keys on
    ``decision_id`` (R1). Jeff's ruling (2026-09-04): this is the seam hook 28
    later reworks to consume inside the same store transaction as
    ``dispatch_committed`` (§4-4) -- an INTERFACE change, not a drop-in swap.
    """

    def consume_once(self, key: str, action_digest: str) -> bool: ...


class LockedConsumer:
    """First-cut in-memory consumer: an explicit lock makes check+write atomic."""

    def __init__(self) -> None:
        self._consumed: Dict[str, str] = {}
        self._lock = threading.Lock()

    def consume_once(self, key: str, action_digest: str) -> bool:
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed[key] = action_digest
            return True


class HighWaterMark:
    """Gateway-local anti-rollback state (§4-2): the highest accepted head
    ``state_version``. It is LOCAL SAFETY STATE like the single-use consumers --
    if it cannot be read or advanced the Gateway must fail closed
    (``denied_state_unavailable``, §4.6), never silently accept an older head. A
    test injects a double whose ``get``/``raise_to`` raise to prove that red.
    """

    def __init__(self, initial: int = 0) -> None:
        self._hw = initial
        self._lock = threading.Lock()

    def get(self) -> int:
        with self._lock:
            return self._hw

    def raise_to(self, version_int: int) -> None:
        with self._lock:
            if version_int > self._hw:
                self._hw = version_int


class DecisionService(Protocol):
    def decide(self, request: AuthorizationRequest, *, now: int) -> Decision: ...

    @property
    def decision_public_key(self) -> Ed25519PublicKey: ...


class StubDecisionService:
    """In-memory cloud decision service for the vertical slice.

    It emits a SIGNED opinion for a request, binding to the current head's version
    and digest (read from the shared ``HeadState`` control plane, so the honest
    opinion matches what the Gateway independently derives from the head it
    verified). It runs NO authorization checks of its own -- membership, validity,
    scope, subject and freshness are the Gateway's job now. It only needs to be
    reachable and to sign; the Gateway does the trusting.
    """

    def __init__(self, head_state: HeadState, *,
                 decision_signing_key: Optional[Ed25519PrivateKey] = None,
                 reachable: bool = True):
        self._head_state = head_state
        self._reachable = reachable
        self._decision_signing_key = decision_signing_key or Ed25519PrivateKey.generate()

    @property
    def decision_public_key(self) -> Ed25519PublicKey:
        return self._decision_signing_key.public_key()

    def set_reachable(self, reachable: bool) -> None:
        self._reachable = reachable

    def decide(self, request: AuthorizationRequest, *, now: int) -> Decision:
        if not self._reachable:
            raise AuthorizationUnavailable("decision cloud unreachable")
        # Echo the grant's identity/mode as the cloud's opinion (untrusted; the
        # Gateway re-derives and cross-checks every field). No re-verification
        # here -- verification is the Gateway's role.
        _type, body, _sig = parse_envelope(request.grant_envelope)
        grant = parse_grant_body(body)
        disposition = (Disposition.AUTHORIZED if grant.permits_auto
                       else Disposition.NEEDS_APPROVAL)
        decision = Decision(
            decision_id=uuid.uuid4().hex,
            grant_id=grant.grant_id, grant_version=grant.grant_version,
            state_version=self._head_state.state_version,
            authz_state_digest=self._head_state.head_digest(),
            request_id=request.request_id, action_digest=request.action_digest,
            decided_at=now, disposition=disposition,
            approval_mode=grant.approval_mode.value, subject_kind=grant.subject.kind.value,
            sig=b"")
        sig = self._decision_signing_key.sign(decision_signing_input(decision))
        return replace(decision, sig=sig)


def _verify(public_key: Ed25519PublicKey, message: bytes, signature) -> bool:
    if not isinstance(signature, (bytes, bytearray)):
        return False
    try:
        public_key.verify(bytes(signature), message)
        return True
    except InvalidSignature:
        return False
