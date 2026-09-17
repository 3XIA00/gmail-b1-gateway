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
