"""Wire the authz gate to the existing send path (Gmail stub for the first cut).

The end-to-end vertical slice: a request is authorized, and ONLY on a clean
``authorized`` (auto) decision whose bound action digest matches the proposal
does the send flow through the proven ``SendFSM`` (write-ahead audit + gate 8
no-retry) to the injected Gmail *stub* sender. A ``needs_approval`` (per_call)
decision does NOT auto-send -- it returns ``pending_approval`` (the approval
workflow is a later slice). Nothing existing is modified.

Auto-send actor note: a verified user-signed capability grant with
``approval_mode=auto`` IS the human's cryptographic authorization -- strictly
stronger than the Option-B relay in ``gateway/send_path.py``. So driving
``fsm.confirm`` as ``Actor.HUMAN`` on a cert-authorized auto send is sound. A
first-class Gateway confirm actor is a later slice.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

from sendfsm.fsm import Actor, SendFSM
from store.proposals import ProposalStatus, ProposalStore

from .clock import make_continuous_clock_ns
from .dispatch_record import DispatchRecordLog
from .errors import AuthorizationDenied
from .gate import AuthorizationGate
from .service import AuthorizationRequest, Disposition


# Coarse codes the orchestrator adds on top of the FSM terminal status.
CODE_RECORD_UNAVAILABLE = "record_unavailable"  # cannot write the started record -> refused, zero send
CODE_OUTCOME_UNKNOWN = "outcome_unknown"        # Gmail committed but completion record unwritten


@dataclass(frozen=True)
class AuthorizedSendOutcome:
    authorized: bool
    sent: bool
    # Coarse, caller-facing code. "denied" carries NO reason (existence oracle);
    # "pending_approval" = valid grant in per_call mode, awaiting approval;
    # "record_unavailable" = refused before send (unattributable); "outcome_unknown"
    # = committed but the completion record failed; otherwise the terminal send
    # status ("sent" / "failed").
    public_code: str
    proposal_status: Optional[ProposalStatus] = None


class AuthorizedGmailSend:
    def __init__(self, gate: AuthorizationGate, fsm: SendFSM,
                 store: ProposalStore, *, now: Callable[[], int],
                 dispatch_records: DispatchRecordLog,
                 continuous_clock_ns: Optional[Callable[[], int]] = None):
        self._gate = gate
        self._fsm = fsm
        self._store = store
        self._now = now
        # R2 (§3): authz-domain provenance tying a committed send to exactly one
        # decision + request. MANDATORY -- a send that cannot be attributed does
        # not happen (Jeff fix contract 186359); never None.
        self._dispatch_records = dispatch_records
        # Same continuous security clock as the gate (§1): the two orchestrator
        # offsets must share the clock the gate's response-deadline offsets came
        # from, so all three R2 events are ordered. Fail closed on an unmapped
        # platform, never time.monotonic() (authz.clock).
        self._clock = continuous_clock_ns or make_continuous_clock_ns()

    def authorize_and_send(self, proposal_id: str,
                           request: AuthorizationRequest) -> AuthorizedSendOutcome:
        # Fetch the proposal FIRST so the digest of the bytes we are about to
        # send is an INPUT to authorization: the gate binds the decision to this
        # exact payload before it writes any success audit (B1). The digest
        # check is no longer a post-hoc compare after an "authorized" was logged.
        proposal = self._store.get(proposal_id)
        try:
            authorization = self._gate.authorize(
                request, expected_action_digest=proposal.payload_digest)
        except AuthorizationDenied as denied:
            # Coarse only. The rich reason is already in the authz audit log.
            return AuthorizedSendOutcome(
                authorized=False, sent=False, public_code=denied.public_code)

        decision = authorization.decision
        if decision.disposition == Disposition.NEEDS_APPROVAL:
            # per_call: authorized grant, but no autonomous send. No send here.
            return AuthorizedSendOutcome(
                authorized=True, sent=False, public_code="pending_approval",
                proposal_status=proposal.status)

        now = self._now()
        self._fsm.confirm(proposal_id, actor=Actor.HUMAN, now=now)

        # R2 phase 1: write the STARTED record BEFORE the Gmail commit. Event 2
        # (gmail_commit_start) is read here, right before dispatch; event 1
        # (decision_received) is the gate's, carried on the Authorization. If the
        # started record cannot be written, REFUSE before any side effect -- an
        # unattributable send does not happen (sender is never called).
        mono_gmail_commit_start = self._clock()
        try:
            self._dispatch_records.record_started(
                decision_id=decision.decision_id, request_id=request.request_id,
                proposal_id=proposal_id, action_digest=proposal.payload_digest,
                mono_decision_received_ns=authorization.mono_decision_received,
                mono_gmail_commit_start_ns=mono_gmail_commit_start)
        except Exception:  # noqa: BLE001 -- unattributable send is refused, not sent
            return AuthorizedSendOutcome(
                authorized=True, sent=False, public_code=CODE_RECORD_UNAVAILABLE,
                proposal_status=proposal.status)

        status = self._fsm.dispatch(proposal_id, now=now)

        # R2 phase 2: write the COMPLETED record AFTER the Gmail commit (event 3 +
        # terminal_status). If it fails the commit has ALREADY happened, so the
        # started record is retained (non-lossy) and the outcome is reported
        # INDETERMINATE -- never a clean "sent".
        mono_response_complete = self._clock()
        try:
            self._dispatch_records.record_completed(
                decision_id=decision.decision_id, request_id=request.request_id,
                proposal_id=proposal_id, action_digest=proposal.payload_digest,
                mono_decision_received_ns=authorization.mono_decision_received,
                mono_gmail_commit_start_ns=mono_gmail_commit_start,
                mono_response_complete_ns=mono_response_complete,
                terminal_status=status.value)
        except Exception:  # noqa: BLE001 -- committed but unrecorded -> indeterminate
            return AuthorizedSendOutcome(
                authorized=True, sent=False, public_code=CODE_OUTCOME_UNKNOWN,
                proposal_status=status)

        return AuthorizedSendOutcome(
            authorized=True, sent=status is ProposalStatus.SENT,
            public_code=status.value, proposal_status=status)
