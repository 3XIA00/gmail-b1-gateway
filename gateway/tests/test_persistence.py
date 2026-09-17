"""On-disk persistence backend tests (ASSEMBLY_PLAN step i).

Actuated variables:
  - JSON round-trip fidelity: a value put through SqliteKV comes back byte-equal
    (int stays int, None/bool/list/nested-dict preserved); the property test
    exercises this over random JSON-native shapes.
  - backend-swap invariance: the REAL ProposalStore / AuditLedger, driven
    against the SQLite backends, exhibit the same idempotency / expiry /
    append-order / closed-schema behaviour they show on the in-memory backends
    -- i.e. moving persistence on-disk changes nothing the cores can observe.
  - durability across process restarts: closing and reopening a backend on the
    same path preserves both proposal records and audit order.
"""

import sqlite3
import threading

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gateway.persistence import SqliteAppendLog, SqliteKV
from store.errors import (
    DuplicateIdempotencyError,
    ProposalExpiredError,
)
from store.ledger import AuditEvent, AuditEventType, AuditLedger
from store.proposals import Proposal, ProposalStatus, ProposalStore


def _proposal(pid="p1", digest="d" * 64, created=100, expires=200,
              status=ProposalStatus.PENDING, idem=None):
    return Proposal(proposal_id=pid, payload_digest=digest, expires_at=expires,
                    created_at=created, status=status, idempotency_key=idem)


# --- SqliteKV round-trip / persistence ------------------------------------

def test_kv_roundtrip_preserves_json_native_types(tmp_path):
    with SqliteKV(str(tmp_path / "kv.db")) as kv:
        value = {"i": 1, "s": "x", "n": None, "b": True, "list": [1, "2", None]}
        kv.put("k", value)
        got = kv.get("k")
    assert got == value
    assert got["i"] == 1 and got["i"] is not True  # int, not coerced to bool


def test_kv_missing_key_is_none(tmp_path):
    with SqliteKV(str(tmp_path / "kv.db")) as kv:
        assert kv.get("nope") is None


def test_kv_put_overwrites(tmp_path):
    with SqliteKV(str(tmp_path / "kv.db")) as kv:
        kv.put("k", {"v": 1})
        kv.put("k", {"v": 2})
        assert kv.get("k") == {"v": 2}


def test_kv_values_returns_all_records(tmp_path):
    with SqliteKV(str(tmp_path / "kv.db")) as kv:
        kv.put("a", {"v": 1})
        kv.put("b", {"v": 2})
        vals = list(kv.values())
    assert {v["v"] for v in vals} == {1, 2}


def test_kv_persists_across_reopen(tmp_path):
    path = str(tmp_path / "kv.db")
    with SqliteKV(path) as kv:
        kv.put("k", {"v": 42})
    with SqliteKV(path) as kv2:  # fresh connection, same file
        assert kv2.get("k") == {"v": 42}


# --- SqliteAppendLog order / persistence ----------------------------------

def test_appendlog_preserves_insertion_order_and_persists(tmp_path):
    path = str(tmp_path / "audit.db")
    with SqliteAppendLog(path) as log:
        log.append({"n": 1})
        log.append({"n": 2})
        log.append({"n": 3})
        assert [e["n"] for e in log.entries()] == [1, 2, 3]
    with SqliteAppendLog(path) as log2:
        assert [e["n"] for e in log2.entries()] == [1, 2, 3]


# --- real ProposalStore over SqliteKV (backend-swap invariance) ------------

def test_proposalstore_roundtrip_over_sqlite(tmp_path):
    with SqliteKV(str(tmp_path / "p.db")) as kv:
        store = ProposalStore(kv)
        p = _proposal()
        store.create(p)
        assert store.get("p1") == p  # frozen dataclass equality by fields
        store.set_status("p1", ProposalStatus.CONFIRMED)
        assert store.get("p1").status is ProposalStatus.CONFIRMED


def test_proposalstore_idempotency_over_sqlite(tmp_path):
    with SqliteKV(str(tmp_path / "p.db")) as kv:
        store = ProposalStore(kv)
        store.create(_proposal(pid="p1", idem="key1"))
        with pytest.raises(DuplicateIdempotencyError):
            store.create(_proposal(pid="p2", idem="key1"))
        assert store.find_by_idempotency("key1").proposal_id == "p1"


def test_proposalstore_expiry_over_sqlite(tmp_path):
    with SqliteKV(str(tmp_path / "p.db")) as kv:
        store = ProposalStore(kv)
        store.create(_proposal(pid="p1", created=100, expires=200))
        assert store.is_live(store.get("p1"), now=150) is True
        assert store.is_live(store.get("p1"), now=250) is False
        with pytest.raises(ProposalExpiredError):
            store.get_live("p1", now=250)
        store.set_status("p1", ProposalStatus.SENT)
        assert store.is_live(store.get("p1"), now=250) is True  # terminal never expires


def test_kv_claim_is_atomic_put_if_absent(tmp_path):
    # The primitive create() relies on: first claim wins, later claims are no-ops
    # and never overwrite the winner's value.
    with SqliteKV(str(tmp_path / "c.db")) as kv:
        assert kv.claim("k", {"who": "first"}) is True
        assert kv.claim("k", {"who": "second"}) is False
        assert kv.get("k") == {"who": "first"}   # loser did not overwrite


def test_proposalstore_concurrent_same_key_creates_exactly_one_over_sqlite(tmp_path):
    # Boris's failure-face ①: two concurrent proposes for one idempotency key
    # must yield exactly ONE proposal (one send), not two. Drive the REAL
    # SqliteKV -- where the atomic claim lives -- with barrier-synchronised
    # threads so the create()s genuinely overlap the way the threaded proposal
    # server (ThreadingHTTPServer) runs them. A TOCTOU race is probabilistic, so
    # we replicate; the pre-fix get-then-put would let >1 thread win here.
    n = 8
    for round_ in range(25):
        with SqliteKV(str(tmp_path / ("race%d.db" % round_))) as kv:
            store = ProposalStore(kv)
            barrier = threading.Barrier(n)
            outcomes = []
            guard = threading.Lock()

            def worker(i):
                barrier.wait()  # release all threads at once to maximise overlap
                try:
                    store.create(_proposal(pid="p%d" % i, created=100,
                                           expires=200, idem="k"))
                    outcome = ("ok", i)
                except DuplicateIdempotencyError:
                    outcome = ("dup", i)
                with guard:
                    outcomes.append(outcome)

            threads = [threading.Thread(target=worker, args=(i,))
                       for i in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            winners = [i for (r, i) in outcomes if r == "ok"]
            dups = [i for (r, i) in outcomes if r == "dup"]
            assert len(winners) == 1, outcomes         # exactly one create wins
            assert len(dups) == n - 1
            win_pid = "p%d" % winners[0]
            assert store.find_by_idempotency("k").proposal_id == win_pid
            # losers were rolled back: exactly one proposal record carries the key
            live = [v for v in kv.values() if v.get("idempotency_key") == "k"]
            assert [v["proposal_id"] for v in live] == [win_pid]


def test_kv_claim_is_atomic_across_independent_connections(tmp_path):
    # Jeff 207640: the single-instance concurrency test above shares ONE SqliteKV,
    # whose threading.Lock serialises every op -- so it proves the get-then-put
    # TOCTOU races on one instance and the atomic claim closes it, but NOT the
    # storage-level cross-process guarantee, because within one instance the
    # Python lock (not SQLite) is what serialises. Here each thread opens its OWN
    # SqliteKV (its own sqlite3 connection) on the SAME file, so there is NO
    # shared in-process lock: the only thing preventing a double-claim is
    # INSERT ... ON CONFLICT(key) DO NOTHING against the PRIMARY KEY. Exactly one
    # caller wins. busy_timeout is 5000ms here (sqlite3.connect's default
    # timeout=5.0, Jeff 207695), so a loser normally BLOCKS until the winner's
    # commit lands and then returns a clean False. A loser CAN still surface
    # SQLITE_BUSY/LOCKED under lock contention -- busy_timeout does not guarantee
    # every conflict waits the full window -- and that is still a non-winner. We
    # accept it ONLY when the SQLite primary result code confirms busy/locked
    # (Jeff 207714: key on the verified code, not on message text); any other
    # code -- or no code at all -- is a real failure and must fail the test.
    # "Exactly one winner" means one storage op SUCCEEDED, not merely "at most one
    # owner", so we also assert all n threads reported.
    #
    # sqlite3.SQLITE_BUSY/SQLITE_LOCKED constants and exc.sqlite_errorcode arrived
    # in Python 3.11; use the numeric primary codes so this also runs on 3.10
    # (there sqlite_errorcode is absent -> None -> "no code" -> fail, per Jeff).
    sqlite_busy, sqlite_locked = 5, 6
    path = str(tmp_path / "xconn.db")
    SqliteKV(path).close()  # create the schema, then share NOTHING between threads
    n = 8
    barrier = threading.Barrier(n)
    outcomes = []
    guard = threading.Lock()

    def worker(i):
        kv = SqliteKV(path)  # independent connection per thread -- no shared lock
        try:
            barrier.wait()
            try:
                won = kv.claim("k", {"who": i})
                res = ("won", i) if won else ("lost", i)
            except sqlite3.OperationalError as exc:
                code = getattr(exc, "sqlite_errorcode", None)  # 3.11+; None on 3.10
                if code is not None and (code & 0xFF) in (sqlite_busy, sqlite_locked):
                    res = ("busy", i)   # verified lock contention; a degraded non-winner
                else:
                    raise               # other/absent code -> real failure, fail the test
        finally:
            kv.close()
        with guard:
            outcomes.append(res)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(outcomes) == n, outcomes            # every thread reported (no swallowed crash)
    winners = [i for (r, i) in outcomes if r == "won"]
    assert len(winners) == 1, outcomes             # exactly one storage op SUCCEEDED as winner
    non_winners = [o for o in outcomes if o[0] in ("lost", "busy")]
    assert len(non_winners) == n - 1, outcomes     # the rest are clean losers or verified busy
    with SqliteKV(path) as kv2:
        assert kv2.get("k") == {"who": winners[0]}  # winner's value persisted, not overwritten


class _ClaimCommitsThenRaises(SqliteKV):
    """Models a lost ack: the claim's write COMMITS durably, but the caller then
    sees an exception (crash/timeout after commit). create() must NOT delete its
    proposal on this path -- the commit may have landed, and deleting would leave
    the idempotency index pointing at a missing proposal (the wedge again). Same
    rule as invalidate_commit's 'raise => cannot confirm' boundary."""

    def claim(self, key, value):
        super().claim(key, value)                 # real durable commit ...
        raise RuntimeError("ack lost after commit")   # ... then the ack is lost


def test_face3_claim_commit_then_raise_keeps_proposal_over_sqlite(tmp_path):
    # Boris/Jeff/测试姬 signoff face ③: on a claim that COMMITTED and then raised,
    # create() must keep the proposal + claim (not delete), and they must survive
    # a restart reachable via the index. Jeff 207587 was explicit that the
    # injection commit BEFORE raising -- a pre-commit raise can't prove "don't
    # delete" has discriminating power. Contrast with the concurrency test above,
    # where a genuine loser (rowcount=0) IS cleaned: together they assert
    # "delete when we should / keep when we shouldn't delete" are both non-empty.
    path = str(tmp_path / "f3.db")
    with _ClaimCommitsThenRaises(path) as kv:
        store = ProposalStore(kv)
        with pytest.raises(RuntimeError):
            store.create(_proposal(pid="p1", idem="k1"))
    # a restart: the committed proposal + claim survive and stay reachable via
    # the index -- create() did not delete on the exception path.
    with SqliteKV(path) as kv2:
        store2 = ProposalStore(kv2)
        assert store2.get("p1").proposal_id == "p1"                   # proposal kept
        assert store2.find_by_idempotency("k1").proposal_id == "p1"   # index reads back


def test_proposalstore_survives_reopen(tmp_path):
    path = str(tmp_path / "p.db")
    with SqliteKV(path) as kv:
        ProposalStore(kv).create(_proposal(pid="p1", idem="key1"))
    with SqliteKV(path) as kv2:
        store = ProposalStore(kv2)
        assert store.get("p1").proposal_id == "p1"
        # the idempotency claim survives too, so a restart can't fork a send
        with pytest.raises(DuplicateIdempotencyError):
            store.create(_proposal(pid="p2", idem="key1"))


# --- real AuditLedger over SqliteAppendLog ---------------------------------

def test_auditledger_egress_and_order_over_sqlite(tmp_path):
    path = str(tmp_path / "audit.db")
    with SqliteAppendLog(path) as log:
        ledger = AuditLedger(log)
        ledger.record(AuditEvent(
            event_type=AuditEventType.SEND_SUCCEEDED, at=5, proposal_id="p1",
            egress_hosts=("a.example", "b.example")))
        ledger.record(AuditEvent(
            event_type=AuditEventType.PROPOSAL_CREATED, at=1, proposal_id="p1"))
        ents = ledger.entries()
    assert [e["event_type"] for e in ents] == ["send_succeeded", "proposal_created"]
    assert ents[0]["egress_hosts"] == ["a.example", "b.example"]  # tuple -> list, preserved
    with SqliteAppendLog(path) as log2:
        assert len(AuditLedger(log2).entries()) == 2


# --- property: JSON-native round-trip fidelity -----------------------------

_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(),
    lambda children: st.lists(children) | st.dictionaries(st.text(), children),
    max_leaves=10)


@pytest.fixture
def kv(tmp_path):
    b = SqliteKV(str(tmp_path / "prop.db"))
    yield b
    b.close()


@settings(max_examples=150,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(st.dictionaries(st.text(min_size=1), _JSON, max_size=5))
def test_kv_put_get_roundtrip_property(kv, value):
    kv.put("k", value)
    assert kv.get("k") == value


# --- durability config + delete -------------------------------------------

def test_connect_establishes_wal_and_full_durability(tmp_path):
    # The SEND_ATTEMPTED-before-wire guarantee rides on WAL + >=FULL; _connect
    # reads the settings back and refuses a silent downgrade. Assert the live
    # connection really is WAL + FULL (or stronger).
    with SqliteKV(str(tmp_path / "d.db")) as kv:
        mode = kv._conn.execute("PRAGMA journal_mode").fetchone()[0]
        sync = kv._conn.execute("PRAGMA synchronous").fetchone()[0]
    assert str(mode).lower() == "wal"
    assert int(sync) >= 2  # 2 == FULL, 3 == EXTRA


def test_kv_delete_removes_key_and_is_idempotent(tmp_path):
    with SqliteKV(str(tmp_path / "kv.db")) as kv:
        kv.put("k", {"v": 1})
        kv.delete("k")
        assert kv.get("k") is None
        kv.delete("k")  # idempotent: deleting an absent key is a no-op
        assert kv.get("k") is None
