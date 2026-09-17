"""Proposal store + idempotency tests.

Actuated variables: idempotency dedup (one live proposal per key), expiry
visibility against an injected clock, terminal states never expiring and
keeping their idempotency claim, and persistence round-trips.
"""

import pytest
from hypothesis import given, strategies as st

from store.backend import InMemoryKV
from store.errors import (
    DuplicateIdempotencyError,
    ProposalExpiredError,
    ProposalNotFoundError,
    ProposalStateError,
)
from store.proposals import Proposal, ProposalStatus, ProposalStore


def _store():
    return ProposalStore(InMemoryKV())


def _p(pid="p1", *, created_at=100, expires_at=400, idem=None,
       status=ProposalStatus.PENDING, digest="d" * 64):
    return Proposal(proposal_id=pid, payload_digest=digest, expires_at=expires_at,
                    created_at=created_at, status=status, idempotency_key=idem)


def test_create_and_get_round_trip():
    s = _store()
    s.create(_p())
    got = s.get("p1")
    assert got == _p()


def test_get_missing_raises():
    with pytest.raises(ProposalNotFoundError):
        _store().get("nope")


def test_duplicate_proposal_id_rejected():
    s = _store()
    s.create(_p())
    with pytest.raises(ProposalStateError):
        s.create(_p())


def test_idempotency_key_dedup():
    s = _store()
    s.create(_p(pid="p1", idem="k1"))
    with pytest.raises(DuplicateIdempotencyError):
        s.create(_p(pid="p2", idem="k1"))


def test_find_by_idempotency():
    s = _store()
    s.create(_p(pid="p1", idem="k1"))
    found = s.find_by_idempotency("k1")
    assert found.proposal_id == "p1"
    assert s.find_by_idempotency("absent") is None


def test_no_idempotency_key_means_no_dedup():
    s = _store()
    s.create(_p(pid="p1", idem=None))
    s.create(_p(pid="p2", idem=None))  # both allowed
    assert s.get("p2").proposal_id == "p2"


@pytest.mark.parametrize("bad", [
    dict(created_at=100, expires_at=100),   # not after
    dict(created_at=100, expires_at=50),    # before
    dict(created_at=-1, expires_at=50),     # negative ts
])
def test_bad_timestamps_rejected(bad):
    s = _store()
    with pytest.raises(ProposalStateError):
        s.create(_p(**bad))


# --- expiry against an injected clock -------------------------------------

def test_pending_is_live_before_expiry_dead_after():
    s = _store()
    p = s.create(_p(created_at=100, expires_at=400))
    assert s.is_live(p, now=399) is True
    assert s.is_live(p, now=400) is False
    assert s.is_live(p, now=401) is False


def test_get_live_refuses_expired_pending():
    s = _store()
    s.create(_p(created_at=100, expires_at=400))
    assert s.get_live("p1", now=399).proposal_id == "p1"
    with pytest.raises(ProposalExpiredError):
        s.get_live("p1", now=400)


@pytest.mark.parametrize("terminal", [
    ProposalStatus.SENT, ProposalStatus.FAILED, ProposalStatus.OUTCOME_UNKNOWN,
])
def test_terminal_states_never_expire(terminal):
    s = _store()
    p = s.create(_p(created_at=100, expires_at=400))
    s.set_status("p1", terminal)
    settled = s.get("p1")
    assert s.is_live(settled, now=10_000) is True  # long past expiry, still live
    assert s.get_live("p1", now=10_000).status is terminal


def test_terminal_keeps_idempotency_claim():
    # A settled send must not let a retry fork a second proposal on the key.
    s = _store()
    s.create(_p(pid="p1", idem="k1"))
    s.set_status("p1", ProposalStatus.SENT)
    with pytest.raises(DuplicateIdempotencyError):
        s.create(_p(pid="p2", idem="k1"))


def test_set_status_persists():
    s = _store()
    s.create(_p())
    s.set_status("p1", ProposalStatus.CONFIRMED)
    assert s.get("p1").status is ProposalStatus.CONFIRMED


def test_backend_returns_copies_not_live_state():
    # Mutating a dict handed to the backend must not corrupt stored state.
    kv = InMemoryKV()
    s = ProposalStore(kv)
    s.create(_p())
    leaked = kv.get("p1")
    leaked["status"] = "tampered"
    assert s.get("p1").status is ProposalStatus.PENDING


# --- serialisation property ------------------------------------------------

@given(
    pid=st.text(min_size=1, max_size=20),
    created_at=st.integers(min_value=0, max_value=10**9),
    ttl=st.integers(min_value=1, max_value=10**6),
    status=st.sampled_from(list(ProposalStatus)),
)
def test_proposal_dict_round_trip(pid, created_at, ttl, status):
    p = Proposal(proposal_id=pid, payload_digest="d" * 64,
                 expires_at=created_at + ttl, created_at=created_at,
                 status=status, idempotency_key=None)
    assert Proposal.from_dict(p.to_dict()) == p


def test_from_dict_rejects_malformed():
    with pytest.raises(ProposalStateError):
        Proposal.from_dict({"proposal_id": "p1"})  # missing fields
