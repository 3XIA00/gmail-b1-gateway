"""Step ④ dispatch record (R2 / §3, seam-split rebuild 2026-09-05; R2 rework).

A committed send carries the decision that authorized it, MANDATORILY and in TWO
append-only phases (Jeff fix contract 186359, Linus 186362-1 "两半结构"):

  * a STARTED row (decision_id, request_id, proposal_id, action_digest + the first
    two continuous-clock events) is written BEFORE the Gmail commit -- if it can
    not be written the send is refused with zero side effect;
  * a COMPLETED row (+ the third event + terminal_status) is written AFTER -- if
    it fails, the started row is retained and the outcome is indeterminate, never
    a clean "sent".

proposal_id + request_id is the unique join. Both schemas are CLOSED allow-lists
-- structurally incapable of holding a token/address/subject/body.
"""

from __future__ import annotations

import pytest

from authz.dispatch_record import (
    _COMPLETED_FIELDS,
    _STARTED_FIELDS,
    PHASE_COMPLETED,
    PHASE_STARTED,
    DispatchCompleted,
    DispatchRecordLog,
    DispatchStarted,
)
from store.backend import InMemoryAppendLog

from ._fixtures import (
    NOW,
    PAYLOAD_DIGEST,
    make_slice,
)


class _FailingAppendLog:
    """Raises on the ``fail_on``-th append (1-indexed), delegating the rest to an
    in-memory log: inject a started-write failure (1) or a completion-write
    failure (2) while keeping the surviving rows readable."""

    def __init__(self, fail_on: int):
        self._inner = InMemoryAppendLog()
        self._fail_on = fail_on
        self._n = 0

    def append(self, entry) -> None:
        self._n += 1
        if self._n == self._fail_on:
            raise RuntimeError("injected append failure")
        self._inner.append(entry)

    def entries(self):
        return self._inner.entries()


def _slice_with_failing_records(fail_on: int):
    slc = make_slice()
    records = DispatchRecordLog(_FailingAppendLog(fail_on))
    slc.orchestrator._dispatch_records = records
    return slc, records


# --- happy path: two ordered rows -------------------------------------------

def test_successful_send_writes_started_then_completed():
    slc = make_slice()
    req = slc.request(slc.grant_envelope(), request_id="rec-1")
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)
    assert outcome.sent is True

    records = slc.dispatch_records.entries()
    assert [r["phase"] for r in records] == [PHASE_STARTED, PHASE_COMPLETED]
    started, completed = records
    for r in (started, completed):
        assert r["request_id"] == "rec-1"
        assert r["proposal_id"] == slc.proposal_id
        assert r["action_digest"] == PAYLOAD_DIGEST
        assert r["decision_id"]                       # opaque, present
    assert completed["terminal_status"] == "sent"
    # three events, non-decreasing, all from the ONE shared continuous clock.
    assert (completed["mono_decision_received_ns"]
            <= completed["mono_gmail_commit_start_ns"]
            <= completed["mono_response_complete_ns"])
    # the started row's two events match the completed row's (same send).
    assert (started["mono_decision_received_ns"]
            == completed["mono_decision_received_ns"])
    assert (started["mono_gmail_commit_start_ns"]
            == completed["mono_gmail_commit_start_ns"])


def test_denied_send_writes_no_dispatch_record():
    slc = make_slice()
    slc.service.set_reachable(False)
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))
    assert outcome.authorized is False
    assert slc.dispatch_records.entries() == []


def test_pending_approval_writes_no_dispatch_record():
    # per_call is authorized but not dispatched -> no dispatch record.
    slc = make_slice()
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope(approval_mode="per_call")))
    assert outcome.public_code == "pending_approval"
    assert slc.dispatch_records.entries() == []


def test_dispatch_record_joins_ledger_on_proposal_and_request():
    # proposal_id + request_id + action_digest is the audit JOIN: find() returns
    # exactly the rows that bind to this send.
    slc = make_slice()
    req = slc.request(slc.grant_envelope(), request_id="join-1")
    slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    digest = slc.store.get(slc.proposal_id).payload_digest
    bound = slc.dispatch_records.find(
        proposal_id=slc.proposal_id, request_id="join-1", action_digest=digest)
    assert [r["phase"] for r in bound] == [PHASE_STARTED, PHASE_COMPLETED]
    assert bound[-1]["terminal_status"] == "sent"


def _assert_wellformed_started_half(row, *, proposal_id, request_id, action_digest):
    """A persisted 'started'/indeterminate half must carry the full quadruple
    binding + the first two continuous-clock events, and MUST NOT masquerade as a
    terminal complete record (Jeff 186381 / Linus 186389: a positive read, not
    'no complete / not sent')."""
    assert row["phase"] == PHASE_STARTED
    assert row["proposal_id"] == proposal_id
    assert row["request_id"] == request_id
    assert row["action_digest"] == action_digest
    assert row["decision_id"]                             # quadruple bound
    # the two continuous-clock events are present and numeric (real clock is int
    # ns; the fixture injects a numeric stand-in, so accept int or float here).
    assert isinstance(row["mono_decision_received_ns"], (int, float))
    assert isinstance(row["mono_gmail_commit_start_ns"], (int, float))
    # not a terminal artifact: the two completion-only keys are absent.
    assert "mono_response_complete_ns" not in row
    assert "terminal_status" not in row


# --- R2 non-lossy fault injection -------------------------------------------

def test_started_record_failure_refuses_before_send():
    # The started record cannot be written -> the send is REFUSED before any side
    # effect: an unattributable send does not happen (sender zero-call, no rows).
    slc, records = _slice_with_failing_records(fail_on=1)
    outcome = slc.orchestrator.authorize_and_send(
        slc.proposal_id, slc.request(slc.grant_envelope()))

    assert outcome.public_code == "record_unavailable"
    assert outcome.sent is False
    assert slc.sender.calls == []                    # crucially, never dispatched
    assert records.entries() == []                   # nothing recorded


def test_completion_write_failure_positively_reads_started_half():
    # Injection point #2 (completion-write fails) AFTER the Gmail commit: assert
    # POSITIVELY that the persisted started half is present (full quadruple + both
    # ns events), so a committed-but-uncompleted send is non-lossy and reported
    # outcome_unknown, never a clean sent (Jeff 186390).
    #
    # Discriminating power (corrected, Boris mutation A 186490 / Linus 186492): this
    # test does NOT by itself kill a "buffer both rows in memory, flush at
    # completion" impl -- under THIS injection that impl has already flushed the
    # started row before the failing completion write, so the row is present and the
    # test stays green. Killing that impl is the job of the after-start dispatch-
    # point test (test_after_start_crash_leaves_readable_indeterminate_half), where
    # the same impl persists zero rows. (An earlier comment here claimed this test
    # "would LOSE the half" under a memory-only impl; that wording traces to Linus's
    # 186389 pin, which overstated the point at this injection site and was self-
    # corrected in his R4 report ④ -- empirically shown false by Boris mutation A.)
    slc, records = _slice_with_failing_records(fail_on=2)
    req = slc.request(slc.grant_envelope(), request_id="cw-1")
    outcome = slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    assert outcome.public_code == "outcome_unknown"
    assert outcome.sent is False                      # not reported as a clean send
    assert slc.sender.calls == [slc.proposal_id]      # the Gmail commit DID happen
    rows = records.entries()
    assert len(rows) == 1                             # started retained, no completed
    _assert_wellformed_started_half(
        rows[0], proposal_id=slc.proposal_id, request_id="cw-1",
        action_digest=PAYLOAD_DIGEST)
    # find() classifies it as indeterminate: bound, but no terminal phase present.
    bound = records.find(proposal_id=slc.proposal_id, request_id="cw-1",
                         action_digest=PAYLOAD_DIGEST)
    assert [r["phase"] for r in bound] == [PHASE_STARTED]


def test_after_start_crash_leaves_readable_indeterminate_half(monkeypatch):
    # A TRUE after-start crash, injected THROUGH the orchestrator at the dispatch
    # point (Jeff 186484-2), not a direct record_started() call -- the crash is at
    # the real seam. The started record is persisted, then the process dies AT
    # `fsm.dispatch`. The orchestrator wraps only the two record writes in
    # try/except, so a raise from dispatch propagates == an uncaught crash.
    #
    # INJECTION POINT (Linus 186486, wording alignment): this test injects INSIDE
    # dispatch, BEFORE the sender is triggered, so `sender.calls == []` is the
    # CONSEQUENCE of this chosen point -- NOT a universal necessity. A crash
    # injected AFTER the Gmail commit already fired (also a legitimate "after-start"
    # point) would instead leave calls non-empty; the invariant that holds under
    # BOTH points is the readable indeterminate started half, asserted below.
    #
    # WHY THIS INJECTION AND NOT THE COMPOSITE (Linus 186486): a dispatch-point
    # crash is the UNIQUE single test that kills an "anchor both rows in memory,
    # flush at completion" implementation -- under it that impl persists ZERO rows
    # (red), whereas completion-write injection alone would still leave the started
    # row (green). So this pulls the write-ordering discriminating power out of the
    # three-injection composite and into one test.
    slc = make_slice()
    req = slc.request(slc.grant_envelope(), request_id="as-1")

    def _crash_at_dispatch(proposal_id, now):
        raise RuntimeError("crash at dispatch point, after the started record")
    monkeypatch.setattr(slc.orchestrator._fsm, "dispatch", _crash_at_dispatch)

    with pytest.raises(RuntimeError):
        slc.orchestrator.authorize_and_send(slc.proposal_id, req)

    # sender zero-call here BECAUSE the crash is before the sender fires (see the
    # injection-point note above); not a claim that after-start always implies it.
    assert slc.sender.calls == []
    # ...but the started half was persisted BEFORE the crash -- a positive read,
    # not merely "no complete / not sent": exactly one started row, well-formed,
    # and it cannot masquerade as a terminal complete record.
    rows = slc.dispatch_records.entries()
    assert len(rows) == 1
    _assert_wellformed_started_half(
        rows[0], proposal_id=slc.proposal_id, request_id="as-1",
        action_digest=PAYLOAD_DIGEST)
    bound = slc.dispatch_records.find(
        proposal_id=slc.proposal_id, request_id="as-1", action_digest=PAYLOAD_DIGEST)
    # find() classifies it as indeterminate: bound, but no terminal phase present.
    assert [r["phase"] for r in bound] == [PHASE_STARTED]


# --- R2 join-key binding: a record that does not bind is equivalent to absent -

@pytest.mark.parametrize("bad", [
    {"proposal_id": "not-the-proposal"},   # wrong join key
    {"proposal_id": ""},                    # missing join key
    {"request_id": ""},
    {"action_digest": ""},
])
def test_record_not_bound_to_proposal_does_not_count(bad):
    # Boris 186384 / Jeff 186386: a row persisted with a missing/wrong join key is
    # physically present but, for audit, equivalent to absent -- find() must not
    # return it, so it can never be counted as this send's record (any phase).
    slc = make_slice()
    fields = dict(decision_id="d0", request_id="rq", proposal_id=slc.proposal_id,
                  action_digest=PAYLOAD_DIGEST, mono_decision_received_ns=1,
                  mono_gmail_commit_start_ns=2)
    fields.update(bad)
    slc.dispatch_records.record_started(**fields)

    assert len(slc.dispatch_records.entries()) == 1   # physically present
    # ...but does not bind to the real (proposal, request, payload).
    assert slc.dispatch_records.find(
        proposal_id=slc.proposal_id, request_id="rq",
        action_digest=PAYLOAD_DIGEST) == []


# --- closed schema (both phases) --------------------------------------------

def test_dispatch_record_schemas_are_closed():
    started_fields = frozenset(DispatchStarted.__dataclass_fields__.keys())
    completed_fields = frozenset(DispatchCompleted.__dataclass_fields__.keys())
    assert started_fields == frozenset(_STARTED_FIELDS)
    assert completed_fields == frozenset(_COMPLETED_FIELDS)
    assert frozenset(DispatchStarted("", "", "", "", 0, 0).to_dict()) == started_fields
    assert frozenset(
        DispatchCompleted("", "", "", "", 0, 0, 0, "").to_dict()) == completed_fields
    # no free-form field exists to hold a token/address/subject/body
    for fields in (started_fields, completed_fields):
        assert "token" not in fields and "recipient" not in fields and "body" not in fields
