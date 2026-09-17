"""The authorization gate: the single choke point in front of a send (L5 §4/§6).

Rebuilt 2026-09-05 to the frozen seam-split ruling (Linus msg_9e866093 §0). The
old ``decide()`` did two incompatible jobs -- state sync AND local decisions --
so a real relay could silently drop §4-1/2/3. The gate now runs FOUR explicit
steps per execution, and the untrusted cloud touches only step ③:

  ① SYNC + ACCEPT the authoritative head. Fetch the user-root-signed
     ``authz_state`` head from the (untrusted) relay, verify its signature with
     the gate's OWN pinned user-root key, and enforce the high-water mark
     (§4-2): a synced ``state_version`` below the highest already accepted is
     ``denied_version_regress`` -- so a relay that WITHHOLDS a newer head and
     replays an older one cannot roll authorization back. Local safety state
     (HW / consume sets) that cannot be read fails CLOSED
     (``denied_state_unavailable``, §4.6), never open.

  ② GATEWAY-LOCAL DECISIONS on the verified grant + accepted head, in order:
     active-set MEMBERSHIP first (§0b -- revocation and supersede take effect as
     ``(grant_id,grant_version) ∉ head.active_grants``, so a hidden revocation
     is impossible: the relay cannot supply an acceptable head still listing the
     grant); validity window (with ``not_yet_valid``); validity-span cap; scope;
     subject proof + request-envelope freshness (agent_key: sig + ``issued_at``
     ±5 min + channel-binding echo). Then the request is consumed single-use on
     ``(grant_id, request_id)`` -- burned BEFORE the cloud call, so a slow or
     replayed request cannot be re-driven.

  ③ CLOUD DECISION as an untrusted second opinion, inside a Gateway MONOTONIC
     response deadline (§1). A response later than the deadline is discarded even
     if its signature is valid -- the security clock is the Gateway's monotonic
     clock, NEVER the relay-reported ``decided_at``. The decision's signature is
     authenticated, then EVERY binding field is cross-checked against the gate's
     own derivation from the ACCEPTED head (the exhaustive policy map), and
     ``decided_at`` is bounded only as a hygiene window on the Gateway's wall
     clock. Finally ``decision_id`` is consumed single-use Gateway-side.

  ④ RECORD. Only after every check passes is the success audit written -- so no
     ``authorized`` row can precede a failure (B1). Every identity/outcome field
     is the gate's OWN derivation (verified grant + accepted head); the only
     decision-sourced value recorded is ``decision_id`` (just consumed). The
     gate returns an ``Authorization`` carrying the decision plus the two
     monotonic offsets the orchestrator needs for the dispatch record (R2).

The caller only ever receives the coarse ``AuthorizationDenied`` (``str`` ==
"denied"); the rich code + detail go only to the internal authz audit (existence
oracle, §6).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from canonicalizer.jcs import digest

from .audit import AuthzAuditLog
from .clock import make_continuous_clock_ns
from .capability import (
    Grant,
    SubjectKind,
    parse_envelope,
    parse_grant_body,
    signing_input,
)
from .decision_policy import (
    ExpectedBinding,
    assert_policy_covers_decision,
    check_binding,
)
from .errors import (
    DETAIL_CHANNEL_BINDING_MISMATCH,
    DETAIL_DECIDED_AT_OUT_OF_WINDOW,
    DETAIL_DECISION_REUSED,
    DETAIL_DECISION_SIG_INVALID,
    DETAIL_INACTIVE_IN_VERIFIED_HEAD,
    DETAIL_ISSUED_AT_OUT_OF_WINDOW,
    DETAIL_NOT_YET_VALID,
    DETAIL_REQUEST_ID_REUSED,
    DETAIL_SUBJECT_IDENTITY_MISMATCH,
    DETAIL_UNTRUSTED_ISSUER,
    AuthorizationDenied,
    AuthorizationUnavailable,
    CertificateError,
    DenialReason,
    DenialSignal,
)
from .service import (
    CLOCK_SKEW_SECONDS,
    DECIDED_AT_SLACK_SECONDS,
    REQUEST_FRESHNESS_SECONDS,
    RESPONSE_DEADLINE_NS,
    VALIDITY_CAP_SECONDS,
    AuthorizationRequest,
    Decision,
    DecisionService,
    Disposition,
    HighWaterMark,
    LockedConsumer,
    PeerIdentity,
    SingleUseConsumer,
    request_binding,
    verify_decision_sig,
    _verify,
)
from .state import (
    HEAD_ARTIFACT_TYPE,
    REVOCATION_ARTIFACT_TYPE,
    Membership,
    SyncSource,
    VerifiedHead,
    parse_head_body,
    parse_revocation_body,
    parse_sync_envelope,
)


@dataclass(frozen=True)
class Authorization:
    """The gate's result on a clean allow/needs-approval. Carries the cloud
    decision plus the continuous-clock reading the moment the decision arrived
    (R2 event 1, ``mono_decision_received_ns``), so the orchestrator can complete
    the dispatch record with its own gmail-commit-start and response-complete
    readings -- all three from the ONE shared continuous clock (§1)."""

    decision: Decision
    mono_decision_received: int     # continuous-clock ns when the decision arrived (§1, R2)


class AuthorizationGate:
    def __init__(self, decision_service: DecisionService, sync_source: SyncSource,
                 audit: AuthzAuditLog, *,
                 user_root_public_key: Ed25519PublicKey, pinned_issuer_fp: str,
                 gateway_account: str,
                 now: Callable[[], int],
                 continuous_clock_ns: Optional[Callable[[], int]] = None,
                 channel_challenge: str = "",
                 peer_resolver: Optional[Callable[[AuthorizationRequest],
                                                  Optional[PeerIdentity]]] = None,
                 request_consumer: Optional[SingleUseConsumer] = None,
                 decision_consumer: Optional[SingleUseConsumer] = None,
                 high_water_mark: Optional[HighWaterMark] = None):
        assert_policy_covers_decision()  # guard field/policy drift at construction
        self._decision_service = decision_service
        self._sync_source = sync_source
        self._audit = audit
        # The gate's OWN trust anchors: the SAME user-root key verifies both the
        # grant envelope and the state head (they are the same authority, §0).
        self._user_root_public_key = user_root_public_key
        self._pinned_issuer_fp = pinned_issuer_fp
        self._gateway_account = gateway_account
        self._now = now              # wall clock (epoch seconds): validity, hygiene, audit
        # Security clock (§1): continuous (suspend-inclusive) monotonic ns. When
        # not injected, resolve the platform clock NOW and FAIL CLOSED if the
        # platform is unmapped -- never fall back to time.monotonic() (authz.clock).
        self._clock = continuous_clock_ns or make_continuous_clock_ns()
        self._channel_challenge = channel_challenge
        # STUB peer-credential resolver (ruling ①): re-resolves the OS peer per
        # request. Default reads the identity the caller observed at THIS call; a
        # test overrides it to model "verified peer A at connect, peer B by
        # request time". Never recorded as "kernel verified".
        self._peer_resolver = peer_resolver or _default_peer_resolver
        # Local safety state (§4.6). Each is consumed/read Gateway-side; a relay
        # cannot bypass it. request consumer keys on (grant_id, request_id);
        # decision consumer keys on decision_id; HW is the anti-rollback mark.
        self._request_consumer = request_consumer or LockedConsumer()
        self._decision_consumer = decision_consumer or LockedConsumer()
        self._hw = high_water_mark or HighWaterMark()

    def authorize(self, request: AuthorizationRequest, *,
                  expected_action_digest: str) -> Authorization:
        """Run the four-step flow. Return an ``Authorization`` on a clean
        allow/needs-approval; raise coarse ``denied`` otherwise.
        ``expected_action_digest`` is the digest of the frozen proposal the
        Gateway is about to send.
        """
        now = self._now()

        # ---- ① SYNC + ACCEPT the authoritative head -----------------------
        head = self._sync_and_accept(request, now)

        # ---- verify the grant with the gate's OWN anchors -----------------
        try:
            vgrant = self._verify_grant(request)
        except DenialSignal as denied:
            # Nothing trusted to decide on -> refuse, auditing the opaque peek
            # with grant_id_verified=False (identity never from the decision).
            raise self._deny(request, now, denied.reason, detail=denied.detail,
                             vgrant=None)

        # ---- ② GATEWAY-LOCAL DECISIONS ------------------------------------
        denial = self._local_decisions(request, now, head, vgrant)
        if denial is not None:
            reason, detail = denial
            raise self._deny(request, now, reason, detail=detail, vgrant=vgrant)

        # Consume the request single-use on (grant_id, request_id) -- BURNED
        # before the cloud call, so a late/replayed request cannot be re-driven.
        req_key = "%s\x00%s" % (vgrant.grant_id, request.request_id)
        try:
            consumed = self._request_consumer.consume_once(req_key, expected_action_digest)
        except Exception:  # noqa: BLE001 -- local safety state lost -> fail closed
            raise self._deny(request, now, DenialReason.STATE_UNAVAILABLE, vgrant=vgrant)
        if not consumed:
            raise self._deny(request, now, DenialReason.REPLAY,
                             detail=DETAIL_REQUEST_ID_REUSED, vgrant=vgrant)

        # ---- ③ CLOUD DECISION within the monotonic response deadline ------
        # The deadline COVERS the whole untrusted round trip AND its verification
        # (R8): request send -> decide() -> signature verify -> binding cross-check
        # -> decided_at hygiene. The endpoint clock is therefore read only AFTER
        # every one of those stages; a response that is slow to VERIFY is a slow
        # response, not a fast one. The old order read the endpoint clock right
        # after decide() and left sig/binding/hygiene outside the deadline.
        mono_sent = self._clock()
        try:
            decision = self._decision_service.decide(request, now=now)
        except AuthorizationUnavailable:
            raise self._deny(request, now, DenialReason.CLOUD_UNREACHABLE, vgrant=vgrant)
        except CertificateError as exc:
            raise self._deny(request, now, DenialReason.INVALID_ARTIFACT,
                             detail=exc.detail, vgrant=vgrant)
        except DenialSignal as denied:
            raise self._deny(request, now, denied.reason, detail=denied.detail,
                             vgrant=vgrant)
        except Exception:  # noqa: BLE001 -- fail-closed backstop, never fall open
            raise self._deny(request, now, DenialReason.INTERNAL_ERROR, vgrant=vgrant)
        # R2 event 1: the continuous-clock reading the moment the decision arrived,
        # carried on the Authorization so the dispatch record's first offset is the
        # gate's, from the same clock the deadline uses.
        mono_decision_received = self._clock()
        wall_verified = self._now()

        # Authenticate the decision's own signature before reading any field.
        if not verify_decision_sig(self._decision_service.decision_public_key, decision):
            raise self._deny(request, now, DenialReason.INVALID_ARTIFACT,
                             detail=DETAIL_DECISION_SIG_INVALID, vgrant=vgrant)

        # Cross-check EVERY binding field against the gate's own derivation from
        # the ACCEPTED head (policy map (a)/(c)). A decision bound to any other
        # head -- e.g. an old digest after HW advanced -- fails decision_head_mismatch.
        expected = self._expected_binding(request, vgrant, head, expected_action_digest)
        mismatch = check_binding(decision, expected)
        if mismatch is not None:
            raise self._deny(request, now, DenialReason.INVALID_ARTIFACT,
                             detail=mismatch, vgrant=vgrant)

        # decided_at is a HYGIENE window on the Gateway wall clock only -- never a
        # security deadline (that is the continuous-clock check below). No TTL.
        # Extracted to module level so an R8 stage-isolation test can advance the
        # continuous clock DURING this stage and prove the deadline covers it.
        if not _decided_at_in_hygiene_window(decision.decided_at, now, wall_verified):
            raise self._deny(request, now, DenialReason.INVALID_ARTIFACT,
                             detail=DETAIL_DECIDED_AT_OUT_OF_WINDOW, vgrant=vgrant)

        # Endpoint clock read AFTER sig-verify + binding + hygiene (R8): the
        # deadline covers the response through the moment it is fully verified. A
        # response later than the deadline is discarded even with a valid signature
        # -- the security clock is the Gateway continuous clock, never decided_at
        # (§1). request_id is already consumed above, so the request is dead; the
        # boundary is inclusive (``==`` passes, only strictly-greater denies).
        mono_response_verified = self._clock()
        if mono_response_verified - mono_sent > RESPONSE_DEADLINE_NS:
            raise self._deny(request, now, DenialReason.CLOUD_UNREACHABLE, vgrant=vgrant)

        # Consume decision_id single-use Gateway-side, LAST, so a decision denied
        # on a binding field above is not burned (a relay cannot bypass this).
        try:
            dconsumed = self._decision_consumer.consume_once(
                decision.decision_id, expected.action_digest)
        except Exception:  # noqa: BLE001 -- local safety state lost -> fail closed
            raise self._deny(request, now, DenialReason.STATE_UNAVAILABLE, vgrant=vgrant)
        if not dconsumed:
            raise self._deny(request, now, DenialReason.REPLAY,
                             detail=DETAIL_DECISION_REUSED, vgrant=vgrant)

        # ---- ④ RECORD the true outcome ------------------------------------
        # Every identity/outcome field is the gate's own derivation (vgrant +
        # accepted head); decision_id is the only decision-sourced value.
        self._audit.record(
            at=now, request_id=request.request_id, code=expected.disposition,
            grant_id=vgrant.grant_id, grant_id_verified=True,
            subject_kind=vgrant.subject.kind.value,
            approval_mode=vgrant.approval_mode.value, decision_id=decision.decision_id,
            state_version=head.state_version, authz_state_digest=head.digest,
            action_digest=expected.action_digest)
        return Authorization(decision=decision,
                             mono_decision_received=mono_decision_received)

    # --- ① sync + accept --------------------------------------------------

    def _sync_and_accept(self, request: AuthorizationRequest, now: int) -> VerifiedHead:
        """Fetch, verify, and accept the authoritative head, or raise coarse
        ``denied``. Enforces the high-water mark (§4-2) and fails closed if local
        safety state is unavailable (§4.6)."""
        try:
            env = self._sync_source.sync()
        except AuthorizationUnavailable:
            raise self._deny(request, now, DenialReason.CLOUD_UNREACHABLE)

        try:
            head_env, revocation_envs = parse_sync_envelope(env)
            artifact_type, body, sig = parse_envelope(head_env)
            if artifact_type != HEAD_ARTIFACT_TYPE:
                raise CertificateError("synced artifact is not an authz_state head")
            if not _verify(self._user_root_public_key,
                           signing_input(HEAD_ARTIFACT_TYPE, body), sig):
                raise CertificateError("head signature invalid")
            state_version, state_version_int, pairs = parse_head_body(body)
            # Every delivered revocation artifact must itself verify against the
            # gate's OWN user-root anchor before it is credited to the per-sync
            # revoked set (a malformed/forged one fails the whole sync closed).
            seen_revocations = self._verify_revocations(revocation_envs)
        except CertificateError as exc:
            raise self._deny(request, now, DenialReason.INVALID_ARTIFACT,
                             detail=exc.detail)

        # High-water mark is local safety state: a read/advance failure fails
        # CLOSED, never accepts an unchecked head.
        try:
            hw = self._hw.get()
        except Exception:  # noqa: BLE001
            raise self._deny(request, now, DenialReason.STATE_UNAVAILABLE)
        if state_version_int < hw:
            raise self._deny(request, now, DenialReason.VERSION_REGRESS)
        try:
            self._hw.raise_to(state_version_int)
        except Exception:  # noqa: BLE001
            raise self._deny(request, now, DenialReason.STATE_UNAVAILABLE)

        return VerifiedHead(state_version=state_version,
                            state_version_int=state_version_int,
                            active_grants=pairs, digest=digest(body),
                            seen_revocations=seen_revocations)

    def _verify_revocations(self, revocation_envs) -> frozenset:
        """Verify each delivered revocation artifact against the gate's own
        user-root key and return the set of revoked grant_ids (the per-sync
        ``seen_revocations``). Raises ``CertificateError`` on any malformed or
        badly-signed artifact -- a delivered artifact that does not verify is a
        tampering signal, so the sync fails closed rather than silently dropping
        it. Absence of an artifact is NOT an error (it yields NO_GRANT, not
        REVOKED -- that is the whole point of the split)."""
        revoked: set = set()
        for rev_env in revocation_envs:
            artifact_type, body, sig = parse_envelope(rev_env)
            if artifact_type != REVOCATION_ARTIFACT_TYPE:
                raise CertificateError("delivered artifact is not an authz_revocation")
            if not _verify(self._user_root_public_key,
                           signing_input(REVOCATION_ARTIFACT_TYPE, body), sig):
                raise CertificateError("revocation signature invalid")
            revoked.add(parse_revocation_body(body))
        return frozenset(revoked)

    # --- ② local decisions -------------------------------------------------

    def _local_decisions(self, request: AuthorizationRequest, now: int,
                         head: VerifiedHead, vgrant: Grant
                         ) -> Optional[Tuple[DenialReason, Optional[str]]]:
        """The §4 decision sequence on the verified grant + accepted head. Returns
        a (reason, detail) to deny, or None to proceed. Does NOT consume -- the
        single-use consume is the caller's step so its fail-closed wrap is explicit."""
        # (1) active-set membership FIRST (§0b): revocation/supersede/no_grant
        # land here. The revoked/no_grant split is §6 absence-attribution: a
        # SEEN revocation artifact -> denied_revoked; mere absence with no artifact
        # -> denied_no_grant (inactive_in_verified_head), never conflated.
        membership = head.membership(vgrant.grant_id, vgrant.grant_version)
        if membership == Membership.REVOKED:
            return (DenialReason.REVOKED, None)
        if membership == Membership.SUPERSEDED:
            return (DenialReason.SUPERSEDED, None)
        if membership == Membership.NO_GRANT:
            return (DenialReason.NO_GRANT, DETAIL_INACTIVE_IN_VERIFIED_HEAD)

        # (2) validity window (skew-tolerant); future valid_from -> not_yet_valid.
        if now < vgrant.valid_from - CLOCK_SKEW_SECONDS:
            return (DenialReason.EXPIRED, DETAIL_NOT_YET_VALID)
        if now > vgrant.valid_until + CLOCK_SKEW_SECONDS:
            return (DenialReason.EXPIRED, None)

        # (3) validity-span cap (profile policy).
        if vgrant.valid_until - vgrant.valid_from > VALIDITY_CAP_SECONDS:
            return (DenialReason.VALIDITY_EXCEEDS_POLICY, None)

        # (4) scope: the grant must authorize THIS Gateway's send account.
        if vgrant.scope.get("from_account") != self._gateway_account:
            return (DenialReason.SCOPE, None)

        # (5) subject proof + request-envelope freshness.
        return self._check_subject(request, now, vgrant)

    def _check_subject(self, request: AuthorizationRequest, now: int, vgrant: Grant
                       ) -> Optional[Tuple[DenialReason, Optional[str]]]:
        subject = vgrant.subject
        if subject.kind is SubjectKind.OS_ACCOUNT:
            # STUB peer credential (Linus ruling ①): the peer RE-RESOLVED at
            # request time must match the grant's subject as an IDENTITY (not a
            # bool). issued_at is NOT a protocol red in this tier -- only an
            # implementation diagnostic -- so it is unused.
            peer = self._peer_resolver(request)
            if (peer is None
                    or peer.machine_id != subject.machine_id
                    or peer.account != subject.account):
                return (DenialReason.MODE_MISMATCH, DETAIL_SUBJECT_IDENTITY_MISMATCH)
            return None

        # agent_key: a per-request agent signature over the request binding.
        if request.agent_sig is None:
            return (DenialReason.MODE_MISMATCH, None)
        try:
            agent_pub = Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(subject.agent_pubkey_hex or ""))
        except (ValueError, TypeError):
            return (DenialReason.MODE_MISMATCH, None)
        binding = request_binding(vgrant.grant_id, request.request_id,
                                  request.action_digest, request.issued_at,
                                  request.channel_binding)
        if not _verify(agent_pub, binding, request.agent_sig):
            return (DenialReason.MODE_MISMATCH, None)
        # Request-envelope freshness (agent_key tier, §5 ±5 min).
        if abs(now - request.issued_at) > REQUEST_FRESHNESS_SECONDS:
            return (DenialReason.INVALID_ARTIFACT, DETAIL_ISSUED_AT_OUT_OF_WINDOW)
        # Connection-level one-time challenge echo (fixture channel binding).
        if request.channel_binding != self._channel_challenge:
            return (DenialReason.INVALID_ARTIFACT, DETAIL_CHANNEL_BINDING_MISMATCH)
        return None

    # --- gate-internal independent derivation -----------------------------

    def _verify_grant(self, request: AuthorizationRequest) -> Grant:
        """Re-derive the authoritative grant from THIS request's envelope using the
        gate's own trust anchors. Raises ``DenialSignal(INVALID_ARTIFACT, detail)``
        if the envelope is not a well-formed, user-root-signed, issuer-pinned grant
        -- carrying the finer detail (``untrusted_issuer`` /
        ``missing_approval_mode`` / ...) so the audit is as precise as the old
        service-side check was, now that verification is the gate's job."""
        try:
            artifact_type, body, sig = parse_envelope(request.grant_envelope)
        except CertificateError as exc:
            raise DenialSignal(DenialReason.INVALID_ARTIFACT, exc.detail)
        if artifact_type != "grant":
            raise DenialSignal(DenialReason.INVALID_ARTIFACT)
        if not _verify(self._user_root_public_key, signing_input("grant", body), sig):
            raise DenialSignal(DenialReason.INVALID_ARTIFACT)
        try:
            grant = parse_grant_body(body)
        except CertificateError as exc:
            raise DenialSignal(DenialReason.INVALID_ARTIFACT, exc.detail)
        if grant.issuer_fp != self._pinned_issuer_fp:
            raise DenialSignal(DenialReason.INVALID_ARTIFACT, DETAIL_UNTRUSTED_ISSUER)
        return grant

    def _expected_binding(self, request: AuthorizationRequest, vgrant: Grant,
                          head: VerifiedHead,
                          expected_action_digest: str) -> ExpectedBinding:
        return ExpectedBinding(
            request_id=request.request_id,
            action_digest=expected_action_digest,
            authz_state_digest=head.digest,
            state_version=head.state_version,
            grant_id=vgrant.grant_id,
            grant_version=vgrant.grant_version,
            approval_mode=vgrant.approval_mode.value,
            subject_kind=vgrant.subject.kind.value,  # raw value, symmetric (R7)
            disposition=(Disposition.AUTHORIZED if vgrant.permits_auto
                         else Disposition.NEEDS_APPROVAL))

    def _deny(self, request: AuthorizationRequest, now: int, reason: DenialReason,
              *, detail: Optional[str] = None,
              vgrant: Optional[Grant] = None) -> AuthorizationDenied:
        """Audit a denial and return the coarse caller-facing exception.

        Identity comes from the gate's OWN verified grant when it has one
        (grant_id_verified=True); otherwise from an opaque, unverified peek of the
        envelope bytes (grant_id_verified=False). The decision's self-reported
        grant_id is NEVER recorded."""
        if vgrant is not None:
            grant_id: Optional[str] = vgrant.grant_id
            subject_kind: Optional[str] = vgrant.subject.kind.value
            verified = True
        else:
            grant_id, subject_kind = _peek_identifiers(request)
            verified = False
        self._audit.record(
            at=now, request_id=request.request_id, code=reason.value,
            grant_id=grant_id, grant_id_verified=verified,
            subject_kind=subject_kind, detail=detail)
        return AuthorizationDenied()


def _decided_at_in_hygiene_window(decided_at: int, request_now: int,
                                  wall_verified: int) -> bool:
    """True iff ``decided_at`` lies within the §1 (d) HYGIENE window on the Gateway
    WALL clock: ``[request_now - slack, wall_verified + slack]``. Hygiene only --
    NOT a security deadline (that is the continuous-clock response deadline) and
    NOT a decision TTL. Module-level so an R8 stage-isolation test can monkeypatch
    it to advance the continuous clock DURING this verification stage, proving the
    deadline (read after this stage) covers time spent here."""
    return (request_now - DECIDED_AT_SLACK_SECONDS
            <= decided_at
            <= wall_verified + DECIDED_AT_SLACK_SECONDS)


def _default_peer_resolver(request: AuthorizationRequest) -> Optional[PeerIdentity]:
    """Default STUB peer resolver: the peer identity the caller observed at THIS
    call, or None if no verified peer credential was presented."""
    if request.peer_verified:
        return PeerIdentity(request.peer_machine_id, request.peer_account)
    return None


def _peek_identifiers(request: AuthorizationRequest):
    """Best-effort opaque ids for a denial audit; never raises, never secret.

    Reads UNVERIFIED, attacker-controllable envelope bytes -- every value it
    returns is audited with ``grant_id_verified=False``."""
    try:
        _, body, _ = parse_envelope(request.grant_envelope)
        grant = parse_grant_body(body)
        return grant.grant_id, grant.subject.kind.value
    except Exception:  # noqa: BLE001 -- audit-only, tolerate a malformed artifact
        try:
            body = request.grant_envelope.get("body", {})
            gid = body.get("grant_id")
            return (gid if isinstance(gid, str) else None), None
        except Exception:  # noqa: BLE001
            return None, None
