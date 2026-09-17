"""Authz dispatch record -- decision provenance for a committed send (R2, §3).

The 2026-09-05 ruling (Linus §3) requires the send to carry the decision that
authorized it, so an audit can attribute a dispatch to exactly one decision and
one request. Embedding this in the frozen FSM ledger (``store/ledger.py``) is a
0-change-baseline cross deferred to hook 28 (same-transaction, §4-4); this round
lands it as an authz-domain record.

R2 rework (Jeff fix contract 186359, Linus 186362-1 "两半结构"): the record is
MANDATORY and TWO-PHASE / append-only, so a send can never commit unrecorded and
a crash between commit and record leaves a non-lossy, indeterminate trace rather
than a silent gap:

  * ``DispatchStarted`` is written BEFORE the Gmail commit -- decision + request +
    proposal + action digest, plus the first two of the three frozen continuous-
    clock events (``mono_decision_received_ns`` from the gate, on the
    ``Authorization``; ``mono_gmail_commit_start_ns`` read by the orchestrator just
    before ``fsm.dispatch``). If it cannot be written the send is refused before
    any side effect.
  * ``DispatchCompleted`` is written AFTER the Gmail commit and adds the third
    event ``mono_response_complete_ns`` and the FSM ``terminal_status``. If it
    fails, the ``DispatchStarted`` row is retained (non-lossy): the outcome is
    reported indeterminate, never a clean ``sent``.

All three offsets come from the ONE Gateway continuous clock the gate and
orchestrator share (§1), so their order is provable; they are never the relay-
reported ``decided_at``. ``(proposal_id, request_id)`` joins the two phases (and
the FSM ledger) uniquely even when two proposals share a payload. Both schemas
are CLOSED allow-lists -- structurally incapable of holding a token, address,
subject, or body (mirrors the authz audit). hook-28 folds the completed record
into the FSM ledger transaction; this round does NOT claim cross-Gmail atomicity,
only the record's own mandatory + non-lossy property.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import List, Tuple

from store.backend import AppendLog

PHASE_STARTED = "started"
PHASE_COMPLETED = "completed"

_STARTED_FIELDS: Tuple[str, ...] = (
    "phase",                       # discriminator: "started" (a lone started == in-flight/indeterminate)
    "decision_id",                 # opaque id of the decision that authorized this dispatch
    "request_id",                  # opaque request id (join key with the FSM ledger)
    "proposal_id",                 # proposal dispatched (disambiguates same-payload proposals)
    "action_digest",               # payload digest authorized == FSM ledger action digest
    "mono_decision_received_ns",   # event 1: continuous-clock ns when the decision arrived (gate)
    "mono_gmail_commit_start_ns",  # event 2: continuous-clock ns just before the Gmail commit
)

_COMPLETED_FIELDS: Tuple[str, ...] = _STARTED_FIELDS + (
    "mono_response_complete_ns",   # event 3: continuous-clock ns after the Gmail commit returned
    "terminal_status",             # FSM terminal status string (e.g. "sent"/"failed")
)


@dataclass(frozen=True)
class DispatchStarted:
    decision_id: str
    request_id: str
    proposal_id: str
    action_digest: str
    mono_decision_received_ns: int
    mono_gmail_commit_start_ns: int
    phase: str = PHASE_STARTED

    def to_dict(self) -> dict:
        return {name: getattr(self, name) for name in _STARTED_FIELDS}


@dataclass(frozen=True)
class DispatchCompleted:
    decision_id: str
    request_id: str
    proposal_id: str
    action_digest: str
    mono_decision_received_ns: int
    mono_gmail_commit_start_ns: int
    mono_response_complete_ns: int
    terminal_status: str
    phase: str = PHASE_COMPLETED

    def to_dict(self) -> dict:
        return {name: getattr(self, name) for name in _COMPLETED_FIELDS}


def _assert_closed_schema(cls, allowed: Tuple[str, ...], probe) -> None:
    declared = frozenset(f.name for f in fields(cls))
    allow = frozenset(allowed)
    # ``phase`` is a dataclass field with a default; every OTHER allowed key is a
    # declared field. So declared fields == allowed keys exactly.
    if declared != allow:
        raise AssertionError(
            "%s fields %r drifted from closed schema %r"
            % (cls.__name__, sorted(declared), sorted(allow)))
    if frozenset(probe.to_dict()) != allow:
        raise AssertionError(
            "%s.to_dict() keys %r drifted from closed schema %r"
            % (cls.__name__, sorted(probe.to_dict()), sorted(allow)))


def _assert_closed_schemas() -> None:
    _assert_closed_schema(
        DispatchStarted, _STARTED_FIELDS,
        DispatchStarted("", "", "", "", 0, 0))
    _assert_closed_schema(
        DispatchCompleted, _COMPLETED_FIELDS,
        DispatchCompleted("", "", "", "", 0, 0, 0, ""))


class DispatchRecordLog:
    """Append-only two-phase log. ``record_started`` and ``record_completed`` each
    append one closed-schema row; a completed send has both, an interrupted send
    has only the started row. Join by ``(proposal_id, request_id)``."""

    def __init__(self, log: AppendLog):
        _assert_closed_schemas()  # guard drift at construction
        self._log = log

    def record_started(self, *, decision_id: str, request_id: str, proposal_id: str,
                       action_digest: str, mono_decision_received_ns: int,
                       mono_gmail_commit_start_ns: int) -> None:
        self._log.append(DispatchStarted(
            decision_id=decision_id, request_id=request_id, proposal_id=proposal_id,
            action_digest=action_digest,
            mono_decision_received_ns=mono_decision_received_ns,
            mono_gmail_commit_start_ns=mono_gmail_commit_start_ns).to_dict())

    def record_completed(self, *, decision_id: str, request_id: str, proposal_id: str,
                         action_digest: str, mono_decision_received_ns: int,
                         mono_gmail_commit_start_ns: int,
                         mono_response_complete_ns: int, terminal_status: str) -> None:
        self._log.append(DispatchCompleted(
            decision_id=decision_id, request_id=request_id, proposal_id=proposal_id,
            action_digest=action_digest,
            mono_decision_received_ns=mono_decision_received_ns,
            mono_gmail_commit_start_ns=mono_gmail_commit_start_ns,
            mono_response_complete_ns=mono_response_complete_ns,
            terminal_status=terminal_status).to_dict())

    def entries(self) -> List[dict]:
        return self._log.entries()

    def find(self, *, proposal_id: str, request_id: str,
             action_digest: str) -> List[dict]:
        """Records that BIND to this (proposal, request, payload). Binding IS the
        quadruple, not mere field presence (Boris 186384 / Jeff 186386): a row
        whose ``proposal_id``/``request_id``/``action_digest`` is empty or does
        not match is, for audit, equivalent to ABSENT -- it is never returned, so
        it cannot be counted as this send's record. The caller inspects ``phase``
        on the returned rows to tell a terminal ``completed`` from an
        indeterminate lone ``started`` (Jeff 186381)."""
        if not (proposal_id and request_id and action_digest):
            return []
        return [r for r in self._log.entries()
                if r.get("proposal_id") == proposal_id
                and r.get("request_id") == request_id
                and r.get("action_digest") == action_digest]
