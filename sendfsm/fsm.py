"""The send state machine (DESIGN sec 4 + gates 7 & 8).

A proposal moves PENDING -> CONFIRMED -> {SENT | FAILED | OUTCOME_UNKNOWN}, or
PENDING -> FAILED on expiry. The FSM owns the *transition rules* and delegates
everything side-effecting to injected collaborators:

  - ``store``   -- persists status (store module), enforces idempotency/expiry;
  - ``ledger``  -- records PII/token-free audit events (store module);
  - ``sender``  -- ``Callable[[str], SendResult]`` that performs the actual
    Gmail send for a proposal_id. The FSM never touches the network or the
    payload itself; the assembly layer wires a sender that fetches the payload
    and calls Gmail.

Two gates live here:

  * **gate 7 (confirm / auto-send switch has no Agent-reachable write path).**
    Approval is a control-plane operation: ``confirm`` is driven by a HUMAN, or
    by the AUTO_UNREACHABLE path *only* when the switch is in auto mode and the
    Agent is definitively unreachable. There is no ``Actor.AGENT`` and no method
    an Agent could call to approve or to change the switch. The switch mode is
    fixed at action-set establishment (actionset module) and is read-only here.

  * **gate 8 (OUTCOME_UNKNOWN => no auto-retry).** An indeterminate send is
    terminal. ``dispatch`` refuses an OUTCOME_UNKNOWN proposal, and there is no
    retry transition anywhere.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Callable, Optional, Tuple

from actionset.switch import SwitchMode
from store.ledger import AuditEvent, AuditEventType, AuditLedger
from store.proposals import ProposalStatus, ProposalStore

from .errors import (
    AgentUnreachableRequiredError,
    AlreadySettledError,
    AutoSendNotEnabledError,
    IllegalTransitionError,
    NoAutoRetryError,
)


class Actor(enum.Enum):
    """Who approved a send. Deliberately no AGENT member (gate 7)."""

    HUMAN = "human"
    AUTO_UNREACHABLE = "auto_unreachable"


class SendResultKind(enum.Enum):
    ACCEPTED = "accepted"          # provider took it -> SENT
    REJECTED = "rejected"          # provider definitively refused -> FAILED
    INDETERMINATE = "indeterminate"  # unknown -> OUTCOME_UNKNOWN, no retry


@dataclass(frozen=True)
class SendResult:
    kind: SendResultKind
    message_id_sha256: Optional[str] = None
    thread_id_sha256: Optional[str] = None
    error_code: Optional[str] = None
    egress_hosts: Tuple[str, ...] = ()


class SendFSM:
    def __init__(
        self,
        store: ProposalStore,
        ledger: AuditLedger,
        sender: Callable[[str], SendResult],
        *,
        switch_mode: SwitchMode,
    ):
        self._store = store
        self._ledger = ledger
        self._sender = sender
        self._switch_mode = switch_mode

    # --- approval (gate 7) -------------------------------------------------

    def confirm(
        self,
        proposal_id: str,
        *,
        actor: Actor,
        now: int,
        agent_reachable: Optional[bool] = None,
    ) -> None:
        """PENDING -> CONFIRMED, driven by a human or the auto-unreachable path."""
        p = self._store.get_live(proposal_id, now=now)  # refuses expired pending
        if p.status is not ProposalStatus.PENDING:
            raise IllegalTransitionError(
                "confirm requires PENDING, got %s" % p.status.value)

        if actor is Actor.AUTO_UNREACHABLE:
            if self._switch_mode is not SwitchMode.AUTO_SEND_WHEN_AGENT_UNREACHABLE:
                raise AutoSendNotEnabledError(
                    "auto-send requested but switch is confirm-then-send")
            # Auto only fires on a *definitive* unreachable signal; unknown
            # (None) or reachable (True) is not a licence to skip confirmation.
            if agent_reachable is not False:
                raise AgentUnreachableRequiredError(
                    "auto-send requires agent_reachable is False")
        # HUMAN confirm is always allowed regardless of switch mode.

        self._store.set_status(proposal_id, ProposalStatus.CONFIRMED)
        self._ledger.record(AuditEvent(
            event_type=AuditEventType.PROPOSAL_CONFIRMED,
            at=now, proposal_id=proposal_id, payload_digest=p.payload_digest,
            outcome=actor.value,
        ))

    # --- dispatch (gate 8) -------------------------------------------------

    def dispatch(self, proposal_id: str, *, now: int) -> ProposalStatus:
        """CONFIRMED -> terminal. Refuses retry of any settled proposal."""
        p = self._store.get(proposal_id)
        if p.status is ProposalStatus.OUTCOME_UNKNOWN:
            # gate 8: never re-send an indeterminate outcome.
            raise NoAutoRetryError(proposal_id)
        if p.status in (ProposalStatus.SENT, ProposalStatus.FAILED):
            raise AlreadySettledError(
                "proposal already %s" % p.status.value)
        if p.status is not ProposalStatus.CONFIRMED:
            raise IllegalTransitionError(
                "dispatch requires CONFIRMED, got %s" % p.status.value)

        self._ledger.record(AuditEvent(
            event_type=AuditEventType.SEND_ATTEMPTED,
            at=now, proposal_id=proposal_id, payload_digest=p.payload_digest,
        ))

        try:
            result = self._sender(proposal_id)
        except Exception:
            # An unexpected error mid-send leaves the true outcome unknown.
            # Fail toward OUTCOME_UNKNOWN (terminal, no retry) rather than guess.
            return self._settle_unknown(proposal_id, now, error_code="sender_raised")

        if result.kind is SendResultKind.ACCEPTED:
            self._store.set_status(proposal_id, ProposalStatus.SENT)
            self._ledger.record(AuditEvent(
                event_type=AuditEventType.SEND_SUCCEEDED,
                at=now, proposal_id=proposal_id, outcome="accepted",
                message_id_sha256=result.message_id_sha256,
                thread_id_sha256=result.thread_id_sha256,
                egress_hosts=result.egress_hosts,
            ))
            return ProposalStatus.SENT
        if result.kind is SendResultKind.REJECTED:
            self._store.set_status(proposal_id, ProposalStatus.FAILED)
            self._ledger.record(AuditEvent(
                event_type=AuditEventType.SEND_FAILED,
                at=now, proposal_id=proposal_id, outcome="rejected",
                error_code=result.error_code, egress_hosts=result.egress_hosts,
            ))
            return ProposalStatus.FAILED
        return self._settle_unknown(proposal_id, now,
                                    error_code=result.error_code,
                                    egress_hosts=result.egress_hosts)

    def _settle_unknown(self, proposal_id, now, *, error_code=None,
                        egress_hosts=()) -> ProposalStatus:
        self._store.set_status(proposal_id, ProposalStatus.OUTCOME_UNKNOWN)
        self._ledger.record(AuditEvent(
            event_type=AuditEventType.OUTCOME_UNKNOWN,
            at=now, proposal_id=proposal_id, outcome="indeterminate",
            error_code=error_code, egress_hosts=tuple(egress_hosts),
        ))
        return ProposalStatus.OUTCOME_UNKNOWN

    # --- expiry ------------------------------------------------------------

    def expire(self, proposal_id: str, *, now: int) -> ProposalStatus:
        """A PENDING proposal past its expiry becomes terminal FAILED."""
        p = self._store.get(proposal_id)
        if p.status is not ProposalStatus.PENDING:
            raise IllegalTransitionError(
                "expire requires PENDING, got %s" % p.status.value)
        if now < p.expires_at:
            raise IllegalTransitionError("proposal not yet expired")
        self._store.set_status(proposal_id, ProposalStatus.FAILED)
        self._ledger.record(AuditEvent(
            event_type=AuditEventType.PROPOSAL_EXPIRED,
            at=now, proposal_id=proposal_id, outcome="expired",
        ))
        return ProposalStatus.FAILED
