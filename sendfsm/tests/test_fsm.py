"""Send-FSM tests.

Actuated variables:
  - gate 7: approval is HUMAN or AUTO_UNREACHABLE only; auto requires the auto
    switch AND a definitive unreachable signal; there is no agent approval path;
  - gate 8: OUTCOME_UNKNOWN is terminal -- dispatch refuses it and nothing
    retries it; an indeterminate result or a sender exception both land there;
  - transition legality (confirm needs PENDING+live, dispatch needs CONFIRMED),
    idempotency (no re-dispatch of a settled proposal), and expiry.
The audit trail is asserted PII/token-free by virtue of going through
store.AuditEvent (the store suite pins that schema).
"""

import pytest

from actionset.switch import SwitchMode
from store.backend import InMemoryAppendLog, InMemoryKV
from store.ledger import AuditLedger
from store.proposals import Proposal, ProposalStatus, ProposalStore
from sendfsm.errors import (
    AgentUnreachableRequiredError,
    AlreadySettledError,
    AutoSendNotEnabledError,
    IllegalTransitionError,
    NoAutoRetryError,
)
from sendfsm.fsm import Actor, SendFSM, SendResult, SendResultKind


def _build(switch_mode=SwitchMode.CONFIRM_THEN_SEND, sender=None):
    store = ProposalStore(InMemoryKV())
    ledger = AuditLedger(InMemoryAppendLog())
    if sender is None:
        sender = lambda pid: SendResult(  # noqa: E731
            kind=SendResultKind.ACCEPTED,
            message_id_sha256="m" * 64, thread_id_sha256="t" * 64,
            egress_hosts=("gmail.googleapis.com",))
    fsm = SendFSM(store, ledger, sender, switch_mode=switch_mode)
    return store, ledger, fsm


def _seed(store, pid="p1", *, created_at=100, expires_at=400,
          status=ProposalStatus.PENDING):
    store.create(Proposal(proposal_id=pid, payload_digest="d" * 64,
                          expires_at=expires_at, created_at=created_at,
                          status=status))


def _event_types(ledger):
    return [e["event_type"] for e in ledger.entries()]


# --- gate 7: approval paths ------------------------------------------------

def test_human_confirm_from_pending():
    store, ledger, fsm = _build()
    _seed(store)
    fsm.confirm("p1", actor=Actor.HUMAN, now=200)
    assert store.get("p1").status is ProposalStatus.CONFIRMED
    assert "proposal_confirmed" in _event_types(ledger)


def test_no_agent_actor_exists():
    # gate 7: there is no Actor an Agent could present to approve a send.
    assert set(Actor.__members__) == {"HUMAN", "AUTO_UNREACHABLE"}


def test_auto_confirm_rejected_in_confirm_then_send_mode():
    store, _, fsm = _build(switch_mode=SwitchMode.CONFIRM_THEN_SEND)
    _seed(store)
    with pytest.raises(AutoSendNotEnabledError):
        fsm.confirm("p1", actor=Actor.AUTO_UNREACHABLE, now=200,
                    agent_reachable=False)


def test_auto_confirm_requires_definitive_unreachable():
    store, _, fsm = _build(
        switch_mode=SwitchMode.AUTO_SEND_WHEN_AGENT_UNREACHABLE)
    _seed(store)
    for reachable in (True, None):  # reachable, or unknown -> refused
        with pytest.raises(AgentUnreachableRequiredError):
            fsm.confirm("p1", actor=Actor.AUTO_UNREACHABLE, now=200,
                        agent_reachable=reachable)
    assert store.get("p1").status is ProposalStatus.PENDING


def test_auto_confirm_succeeds_when_unreachable_and_enabled():
    store, _, fsm = _build(
        switch_mode=SwitchMode.AUTO_SEND_WHEN_AGENT_UNREACHABLE)
    _seed(store)
    fsm.confirm("p1", actor=Actor.AUTO_UNREACHABLE, now=200, agent_reachable=False)
    assert store.get("p1").status is ProposalStatus.CONFIRMED


def test_human_confirm_allowed_even_in_auto_mode():
    store, _, fsm = _build(
        switch_mode=SwitchMode.AUTO_SEND_WHEN_AGENT_UNREACHABLE)
    _seed(store)
    fsm.confirm("p1", actor=Actor.HUMAN, now=200)
    assert store.get("p1").status is ProposalStatus.CONFIRMED


def test_confirm_refuses_expired():
    store, _, fsm = _build()
    _seed(store, created_at=100, expires_at=400)
    from store.errors import ProposalExpiredError
    with pytest.raises(ProposalExpiredError):
        fsm.confirm("p1", actor=Actor.HUMAN, now=400)


def test_confirm_refuses_non_pending():
    store, _, fsm = _build()
    _seed(store, status=ProposalStatus.CONFIRMED)
    with pytest.raises(IllegalTransitionError):
        fsm.confirm("p1", actor=Actor.HUMAN, now=200)


# --- dispatch outcomes -----------------------------------------------------

def _confirmed(store, fsm, pid="p1"):
    _seed(store, pid=pid)
    fsm.confirm(pid, actor=Actor.HUMAN, now=200)


def test_dispatch_accepted_to_sent():
    store, ledger, fsm = _build()
    _confirmed(store, fsm)
    assert fsm.dispatch("p1", now=210) is ProposalStatus.SENT
    assert store.get("p1").status is ProposalStatus.SENT
    assert _event_types(ledger)[-1] == "send_succeeded"


def test_dispatch_rejected_to_failed():
    sender = lambda pid: SendResult(kind=SendResultKind.REJECTED,  # noqa: E731
                                    error_code="invalid_recipient")
    store, ledger, fsm = _build(sender=sender)
    _confirmed(store, fsm)
    assert fsm.dispatch("p1", now=210) is ProposalStatus.FAILED
    assert _event_types(ledger)[-1] == "send_failed"
    assert ledger.entries()[-1]["error_code"] == "invalid_recipient"


def test_dispatch_indeterminate_result_to_outcome_unknown():
    sender = lambda pid: SendResult(kind=SendResultKind.INDETERMINATE,  # noqa: E731
                                    error_code="timeout")
    store, ledger, fsm = _build(sender=sender)
    _confirmed(store, fsm)
    assert fsm.dispatch("p1", now=210) is ProposalStatus.OUTCOME_UNKNOWN
    assert _event_types(ledger)[-1] == "outcome_unknown"


def test_dispatch_sender_exception_to_outcome_unknown():
    def boom(pid):
        raise RuntimeError("connection reset mid-send")
    store, ledger, fsm = _build(sender=boom)
    _confirmed(store, fsm)
    # An exception during send leaves the outcome unknown, never guessed.
    assert fsm.dispatch("p1", now=210) is ProposalStatus.OUTCOME_UNKNOWN
    assert store.get("p1").status is ProposalStatus.OUTCOME_UNKNOWN
    assert ledger.entries()[-1]["error_code"] == "sender_raised"


def test_dispatch_requires_confirmed():
    store, _, fsm = _build()
    _seed(store)  # still PENDING
    with pytest.raises(IllegalTransitionError):
        fsm.dispatch("p1", now=210)


# --- gate 8: no auto-retry -------------------------------------------------

def test_outcome_unknown_is_terminal_no_retry():
    sender = lambda pid: SendResult(kind=SendResultKind.INDETERMINATE)  # noqa: E731
    store, _, fsm = _build(sender=sender)
    _confirmed(store, fsm)
    fsm.dispatch("p1", now=210)
    assert store.get("p1").status is ProposalStatus.OUTCOME_UNKNOWN
    # Any re-dispatch is refused: gate 8.
    with pytest.raises(NoAutoRetryError):
        fsm.dispatch("p1", now=220)


def test_no_retry_transition_exists_on_fsm():
    # Structural: the FSM exposes no 'retry'/'resend' method.
    assert not [m for m in dir(SendFSM)
                if ("retry" in m.lower() or "resend" in m.lower())]


def test_sender_called_once_even_across_redispatch_attempts():
    calls = {"n": 0}

    def once(pid):
        calls["n"] += 1
        return SendResult(kind=SendResultKind.INDETERMINATE)
    store, _, fsm = _build(sender=once)
    _confirmed(store, fsm)
    fsm.dispatch("p1", now=210)
    with pytest.raises(NoAutoRetryError):
        fsm.dispatch("p1", now=220)
    assert calls["n"] == 1  # the indeterminate send was not repeated


# --- idempotency of terminal states ---------------------------------------

def test_dispatch_refuses_already_sent():
    store, _, fsm = _build()
    _confirmed(store, fsm)
    fsm.dispatch("p1", now=210)  # SENT
    with pytest.raises(AlreadySettledError):
        fsm.dispatch("p1", now=220)


def test_dispatch_refuses_already_failed():
    sender = lambda pid: SendResult(kind=SendResultKind.REJECTED,  # noqa: E731
                                    error_code="x")
    store, _, fsm = _build(sender=sender)
    _confirmed(store, fsm)
    fsm.dispatch("p1", now=210)  # FAILED
    with pytest.raises(AlreadySettledError):
        fsm.dispatch("p1", now=220)


# --- expiry ----------------------------------------------------------------

def test_expire_pending_to_failed():
    store, ledger, fsm = _build()
    _seed(store, created_at=100, expires_at=400)
    assert fsm.expire("p1", now=400) is ProposalStatus.FAILED
    assert _event_types(ledger)[-1] == "proposal_expired"


def test_expire_refuses_not_yet_expired():
    store, _, fsm = _build()
    _seed(store, created_at=100, expires_at=400)
    with pytest.raises(IllegalTransitionError):
        fsm.expire("p1", now=399)


def test_expire_refuses_non_pending():
    store, _, fsm = _build()
    _confirmed(store, fsm)  # CONFIRMED
    with pytest.raises(IllegalTransitionError):
        fsm.expire("p1", now=10_000)
