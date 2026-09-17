"""SealedTokenStore tests -- the concrete daemon<->store seam (task (A)).

Discipline (per 测试姬's per-branch positive-control format): every multi-branch
cell runs ALL branches, each branch is its own positive control, and the oracle
asserts the variable that switches the defect on/off -- not "the write finished".

Actuated variables:
  - load_credentials  : failure mode -> which of the FOUR buckets is raised
    (absent / keychain-outage / corrupt), plus the happy round-trip.
  - mark_ack_confirmed: all-three-fields match -> True+cleared; any mismatch ->
    False + newer record untouched.
  - clear_credentials : credentials present -> True + gone, commit + sibling
    keys survive; absent -> False.
  - save_commit       : seal fails -> NEITHER creds nor commit land (atomic);
    success -> records the RESERVED generation as given (never allocates); a
    generation at or below the barrier is refused, atomically.
  - reserve_generation: strictly > every value ever reserved AND > the barrier;
    persisted so it is never reclaimed/reused across a restart.
  - current_barrier / void_generation: the durable, monotone generation barrier
    that gates writes AND startup recovery.
  - load_commit       : returns the record WITHOUT a working DEK (a locked
    keychain must not look like an absent commit).
"""

import json

import pytest

from gateway.persistence import SqliteKV
from gateway.sealed_token_store import _STATE_KEY, SealedTokenStore
from gateway.token_store import (
    CommitInvalidated,
    CommitRecord,
    CredentialsCorrupt,
    CredentialsMissing,
    KeychainUnavailable,
)
from keystore.errors import (
    KeyBackendUnavailableError,
    KeyUnavailableError,
)
from keystore.providers import InMemoryKeyProvider

_CREDS = {"access_token": "at-xyz", "refresh_token": "rt-xyz", "expires_in": 3599}


def _db(tmp_path):
    return str(tmp_path / "token.db")


def _store(tmp_path, provider=None):
    return SealedTokenStore(_db(tmp_path), provider or InMemoryKeyProvider.generate())


def _saved(store, *, operation_id="op1", connection_id="conn1",
           result_id="res1", version=1, generation=None, credentials=None,
           ack_pending=True):
    # save_commit now RECEIVES the generation and never allocates one, so the
    # helper reserves up front (the real Connect ordering) unless a test pins an
    # explicit generation to exercise the barrier.
    if generation is None:
        generation = store.reserve_generation()
    return store.save_commit(
        operation_id=operation_id, connection_id=connection_id,
        result_id=result_id, version=version, generation=generation,
        credentials=_CREDS if credentials is None else credentials,
        ack_pending=ack_pending)


# --- fake providers to actuate each open-failure branch -------------------

class _RaisingProvider:
    def __init__(self, exc):
        self._exc = exc

    def get_dek(self):
        raise self._exc


class _ReturningProvider:
    def __init__(self, dek):
        self._dek = dek

    def get_dek(self):
        return self._dek


# --- happy round-trip ------------------------------------------------------

def test_save_then_load_round_trips_credentials(tmp_path):
    with _store(tmp_path) as s:
        rec = _saved(s)
        assert rec.generation == 1 and rec.ack_pending is True
        assert s.load_credentials() == _CREDS      # exact value round-trips
        got = s.load_commit()
        assert got == rec                          # commit persisted verbatim


def test_credentials_are_not_stored_in_clear(tmp_path):
    # The sealed bytes must not contain the token text -- confirms we actually
    # sealed rather than JSON-dumping the plaintext.
    with _store(tmp_path) as s:
        _saved(s)
    raw = SqliteKV(_db(tmp_path))
    try:
        blob = json.dumps(raw.get(_STATE_KEY))
        assert "rt-xyz" not in blob and "at-xyz" not in blob
    finally:
        raw.close()


# --- load_credentials: the FOUR buckets, each its own positive control -----

def test_load_missing_when_never_saved(tmp_path):
    with _store(tmp_path) as s:
        with pytest.raises(CredentialsMissing):
            s.load_credentials()


@pytest.mark.parametrize("provider_exc,expected", [
    (KeyUnavailableError("absent"), CredentialsMissing),        # no key material
    (KeyBackendUnavailableError("locked"), KeychainUnavailable),  # outage
])
def test_load_maps_provider_failure_to_its_bucket(tmp_path, provider_exc, expected):
    # Seal with a real key, then reopen the SAME db with a provider that fails
    # in a specific way -> the specific bucket. Running both rows proves the
    # mapping discriminates (an "always CredentialsMissing" impl fails the
    # KeychainUnavailable row, and vice versa).
    with _store(tmp_path) as s:
        _saved(s)
    with SealedTokenStore(_db(tmp_path), _RaisingProvider(provider_exc)) as s2:
        with pytest.raises(expected):
            s2.load_credentials()


def test_load_wrong_key_is_corrupt_not_missing(tmp_path):
    # Sealed with key A, opened with a different valid key B: AEAD auth fails ->
    # present-but-unopenable, never "absent".
    with _store(tmp_path) as s:
        _saved(s)
    other = InMemoryKeyProvider.generate()             # a different 32-byte key
    with SealedTokenStore(_db(tmp_path), other) as s2:
        with pytest.raises(CredentialsCorrupt):
            s2.load_credentials()


def test_load_bad_dek_material_is_corrupt(tmp_path):
    with _store(tmp_path) as s:
        _saved(s)
    with SealedTokenStore(_db(tmp_path), _ReturningProvider(b"too-short")) as s2:
        with pytest.raises(CredentialsCorrupt):
            s2.load_credentials()


def test_load_malformed_sealed_record_is_corrupt(tmp_path):
    with _store(tmp_path) as s:
        _saved(s)
        # Corrupt the stored sealed structure (drop a required field).
        row = s._kv.get(_STATE_KEY)
        del row["sealed"]["nonce"]
        s._kv.put(_STATE_KEY, row)
        with pytest.raises(CredentialsCorrupt):
            s.load_credentials()


# --- load_commit must NOT require a working DEK ----------------------------

def test_load_commit_works_without_dek_locked_keychain_is_not_absent(tmp_path):
    with _store(tmp_path) as s:
        rec = _saved(s)
    # Reopen with a provider that cannot yield the DEK at all.
    with SealedTokenStore(
            _db(tmp_path), _RaisingProvider(KeyBackendUnavailableError("locked"))) as s2:
        assert s2.load_commit() == rec             # commit is readable ...
        with pytest.raises(KeychainUnavailable):   # ... though creds are not
            s2.load_credentials()


def test_load_commit_none_when_never_saved(tmp_path):
    with _store(tmp_path) as s:
        assert s.load_commit() is None


# --- mark_ack_confirmed: all-three-fields match ----------------------------

def test_mark_ack_confirmed_matches_all_three(tmp_path):
    with _store(tmp_path) as s:
        _saved(s, operation_id="op1", result_id="res1", version=1)
        assert s.mark_ack_confirmed(
            operation_id="op1", result_id="res1", version=1) is True
        assert s.load_commit().ack_pending is False


@pytest.mark.parametrize("op,res,ver", [
    ("WRONG", "res1", 1),      # operation mismatch
    ("op1", "WRONG", 1),       # result mismatch
    ("op1", "res1", 999),      # version mismatch
])
def test_mark_ack_confirmed_mismatch_returns_false_and_leaves_pending(
        tmp_path, op, res, ver):
    # A late ACK for a superseded operation must NOT clear the newer record's
    # pending flag. Each mismatching field is its own positive control: an impl
    # that ignores that field would wrongly return True and clear the flag.
    with _store(tmp_path) as s:
        _saved(s, operation_id="op1", result_id="res1", version=1, ack_pending=True)
        assert s.mark_ack_confirmed(
            operation_id=op, result_id=res, version=ver) is False
        assert s.load_commit().ack_pending is True    # untouched


def test_mark_ack_confirmed_false_when_no_commit(tmp_path):
    with _store(tmp_path) as s:
        assert s.mark_ack_confirmed(
            operation_id="op1", result_id="res1", version=1) is False


# --- clear_credentials: scoped destruction ---------------------------------

def test_clear_removes_creds_keeps_commit_and_sibling_keys(tmp_path):
    with _store(tmp_path) as s:
        rec = _saved(s)
        # A sibling subsystem's row in the same token.db (dedup/results/etc).
        s._kv.put("dedup:cmd-1", {"result_id": "res1"})

        assert s.clear_credentials() is True
        with pytest.raises(CredentialsMissing):       # creds are gone ...
            s.load_credentials()
        assert s.load_commit() == rec                 # ... commit survives ...
        assert s._kv.get("dedup:cmd-1") == {"result_id": "res1"}  # ... siblings too


def test_clear_is_false_when_no_credentials(tmp_path):
    with _store(tmp_path) as s:
        assert s.clear_credentials() is False         # nothing present
        _saved(s)
        assert s.clear_credentials() is True
        assert s.clear_credentials() is False         # idempotent: already gone


# --- save_commit atomicity + generation ------------------------------------

def test_save_commit_seal_failure_lands_neither(tmp_path):
    # If sealing fails, NO partial state may be written: no commit appears and
    # any prior credentials/commit are untouched. Actuates both-or-neither.
    with SealedTokenStore(
            _db(tmp_path), _RaisingProvider(KeyUnavailableError("no dek"))) as s:
        with pytest.raises(KeyUnavailableError):
            _saved(s)
        assert s.load_commit() is None                # commit did not land
        with pytest.raises(CredentialsMissing):
            s.load_credentials()                      # creds did not land


def test_save_commit_records_the_reserved_generation_verbatim(tmp_path):
    # save_commit RECEIVES the reserved generation and records it as-given; it
    # must never allocate its own. Reserve 7, commit with 7 -> the record reads
    # 7 (an impl that re-allocated at commit time would read 1 and fail here).
    with _store(tmp_path) as s:
        for _ in range(6):
            s.reserve_generation()          # burn 1..6
        g = s.reserve_generation()          # == 7
        assert g == 7
        rec = _saved(s, generation=g)
        assert rec.generation == 7
        assert s.load_commit().generation == 7


# --- reserve_generation / current_barrier / void_generation ----------------

def test_reserve_generation_is_strictly_monotone(tmp_path):
    with _store(tmp_path) as s:
        assert [s.reserve_generation() for _ in range(3)] == [1, 2, 3]


def test_reserve_generation_never_reused_across_restart(tmp_path):
    # Persisted, so a restart continues the sequence rather than reissuing a
    # covered number. A fresh flow after a crash must not inherit a generation an
    # earlier barrier already covers. REAL restart: reopen from disk.
    prov = InMemoryKeyProvider.generate()
    with _reopen(tmp_path, prov) as s:
        assert s.reserve_generation() == 1
        assert s.reserve_generation() == 2
    with _reopen(tmp_path, prov) as s2:
        assert s2.reserve_generation() == 3     # not 1 -- the counter survived


def test_reserve_generation_jumps_past_a_leading_barrier(tmp_path):
    # The reserve-must-jump-barrier rule (Linus mutation-caught): if the barrier
    # leads the local counter, the next reservation must clear it, not merely
    # increment the counter -- else it would hand out a covered number and every
    # later commit would refuse forever ("silent never-connects").
    with _store(tmp_path) as s:
        s.void_generation(10)                   # barrier now 10, counter still 0
        g = s.reserve_generation()
        assert g == 11                          # max(0, 10) + 1, not 0 + 1
        # and that generation is above the barrier, so it can actually commit
        assert _saved(s, generation=g).generation == 11


def test_current_barrier_starts_at_zero_and_is_monotone(tmp_path):
    with _store(tmp_path) as s:
        assert s.current_barrier() == 0
        s.void_generation(5)
        assert s.current_barrier() == 5
        s.void_generation(3)                    # lower value must not lower it
        assert s.current_barrier() == 5
        s.void_generation(8)
        assert s.current_barrier() == 8


def test_barrier_persists_across_restart(tmp_path):
    prov = InMemoryKeyProvider.generate()
    with _reopen(tmp_path, prov) as s:
        s.void_generation(4)
    with _reopen(tmp_path, prov) as s2:
        assert s2.current_barrier() == 4        # durable, not in-memory


def test_save_commit_refuses_generation_at_or_below_barrier(tmp_path):
    # A Disconnect raises the barrier; an in-flight result reserved under an
    # earlier generation must be refused when it tries to commit. Both boundary
    # rows (== barrier and < barrier) are their own positive controls; a
    # generation strictly above the barrier still commits.
    with _store(tmp_path) as s:
        s.void_generation(5)
        with pytest.raises(CommitInvalidated):
            _saved(s, operation_id="op-eq", generation=5)    # == barrier: refused
        with pytest.raises(CommitInvalidated):
            _saved(s, operation_id="op-lt", generation=4)    # < barrier: refused
        rec = _saved(s, operation_id="op-gt", generation=6)  # > barrier: commits
        assert rec.generation == 6


def test_save_commit_refused_by_barrier_writes_nothing(tmp_path):
    # The barrier check and the write are one transaction: a refused-by-barrier
    # commit must land NEITHER creds nor commit (no partial write).
    with _store(tmp_path) as s:
        s.void_generation(5)
        with pytest.raises(CommitInvalidated):
            _saved(s, operation_id="op-old", generation=3)
        assert s.load_commit() is None
        with pytest.raises(CredentialsMissing):
            s.load_credentials()


def test_barrier_survives_clear_and_restart(tmp_path):
    # Disconnect clears creds AND raises the barrier; the barrier must outlive
    # the clear and a restart, or a restart could re-admit the very in-flight
    # refresh the Disconnect voided. REAL restart.
    prov = InMemoryKeyProvider.generate()
    with _reopen(tmp_path, prov) as s:
        g = s.reserve_generation()
        _saved(s, generation=g)
        s.void_generation(g)                    # barrier now covers this connection
        assert s.clear_credentials() is True
    with _reopen(tmp_path, prov) as s2:
        assert s2.current_barrier() == g        # barrier outlived the clear
        with pytest.raises(CommitInvalidated):  # a stale result under g is barred
            _saved(s2, operation_id="op-stale", generation=g)


def test_barrier_gates_startup_recovery_read(tmp_path):
    # Recovery reads load_commit() AND current_barrier() and refuses to recover a
    # commit whose generation the barrier covers. The store exposes both facts
    # without a DEK; this test asserts the pair a recoverer joins on -- the
    # crash-window case where the barrier landed but invalidated was never set.
    prov = InMemoryKeyProvider.generate()
    with _reopen(tmp_path, prov) as s:
        g = s.reserve_generation()
        _saved(s, generation=g)
        # Simulate the crash window: barrier raised, but the commit's own
        # invalidated bit was never flipped (Disconnect died in between).
        s.void_generation(g)
    with _reopen(tmp_path, prov) as s2:
        rec = s2.load_commit()
        assert rec is not None and rec.invalidated is False   # bit never set ...
        # ... so ONLY the barrier stands between recovery and a disconnected
        # account; recovery must gate on it.
        assert rec.generation <= s2.current_barrier()


# --- invalidate_commit: persistent cancel/Disconnect mark (Linus 205613) ----
#
# The whole point is that the mark survives a RESTART -- an in-memory cancel
# flag does not. So every "survives" assertion reopens the store from disk
# (discards the in-memory object). A mutation that keeps the flag only in
# memory would pass an in-object read and fail these reopen reads -> red.

def _reopen(tmp_path, provider):
    return SealedTokenStore(_db(tmp_path), provider)


def test_invalidate_commit_persists_across_restart(tmp_path):
    prov = InMemoryKeyProvider.generate()
    with _reopen(tmp_path, prov) as s:
        _saved(s, operation_id="op1")
        assert s.invalidate_commit(operation_id="op1") is True
    # Real restart: fresh store object, same db file.
    with _reopen(tmp_path, prov) as s2:
        assert s2.load_commit().invalidated is True


def test_fresh_commit_is_not_invalidated(tmp_path):
    with _store(tmp_path) as s:
        assert _saved(s).invalidated is False


def test_invalidate_commit_no_commit_returns_false_but_persists_mark(tmp_path):
    # Pre-commit invalidation: no commit exists yet. Return is False (no current
    # commit was hit) but the invalidation fact MUST be written -- proven by a
    # later save_commit for that operation being refused. "False != not written"
    # (Jeff 205615 / Boris 205653; the 205643 first cut's no-side-effect branch).
    with _store(tmp_path) as s:
        assert s.invalidate_commit(operation_id="op1") is False
        with pytest.raises(CommitInvalidated):
            _saved(s, operation_id="op1")


def test_invalidate_commit_wrong_operation_marks_it_and_spares_current(tmp_path):
    # A stale cancel for a superseded operation must not touch the newer commit,
    # but must still persist the stale op's invalidation (so its late in-flight
    # result can never commit). Both halves are actuated.
    with _store(tmp_path) as s:
        _saved(s, operation_id="op-current")
        assert s.invalidate_commit(operation_id="op-stale") is False
        assert s.load_commit().invalidated is False       # newer commit untouched
        with pytest.raises(CommitInvalidated):            # stale op is barred
            _saved(s, operation_id="op-stale")


def test_invalidate_commit_is_idempotent(tmp_path):
    with _store(tmp_path) as s:
        _saved(s, operation_id="op1")
        assert s.invalidate_commit(operation_id="op1") is True
        assert s.invalidate_commit(operation_id="op1") is True          # no-op, still True
        assert s.load_commit().invalidated is True


def test_invalidation_survives_clear_credentials_and_restart(tmp_path):
    # Disconnect clears the credentials AND invalidates the commit; the
    # invalidation must outlive the clear (and a restart), or a restart could
    # silently reconnect a Disconnected account.
    prov = InMemoryKeyProvider.generate()
    with _reopen(tmp_path, prov) as s:
        _saved(s, operation_id="op1")
        assert s.invalidate_commit(operation_id="op1") is True
        assert s.clear_credentials() is True
    with _reopen(tmp_path, prov) as s2:
        assert s2.load_commit().invalidated is True         # mark outlived clear
        with pytest.raises(CredentialsMissing):
            s2.load_credentials()                           # creds really gone


# --- save_commit refuses an invalidated operation, atomically (Jeff 205615) --

def test_save_commit_refused_for_invalidated_op_writes_nothing(tmp_path):
    # Pre-commit invalidation then a commit attempt for that operation: refuse,
    # and land NOTHING (no creds, no commit) -- the check and the write are one
    # transaction, so there is no partial write.
    with _store(tmp_path) as s:
        assert s.invalidate_commit(operation_id="op-bad") is False       # marks pre-commit
        with pytest.raises(CommitInvalidated):
            _saved(s, operation_id="op-bad")
        with pytest.raises(CredentialsMissing):
            s.load_credentials()                            # nothing landed
        assert s.load_commit() is None


def test_save_commit_refusal_persists_across_restart(tmp_path):
    # The whole point of persisting the mark: a restart between invalidation and
    # the stale result's commit attempt must still refuse.
    prov = InMemoryKeyProvider.generate()
    with _reopen(tmp_path, prov) as s:
        assert s.invalidate_commit(operation_id="op-bad") is False
    with _reopen(tmp_path, prov) as s2:
        with pytest.raises(CommitInvalidated):
            _saved(s2, operation_id="op-bad")


def test_a_different_operation_still_commits(tmp_path):
    # Positive control: invalidating one operation must not bar an unrelated
    # one. Without this, an "always refuse" impl would pass the refusal tests.
    with _store(tmp_path) as s:
        s.invalidate_commit(operation_id="op-bad")
        rec = _saved(s, operation_id="op-good")
        assert rec.generation == 1
        assert s.load_credentials() == _CREDS


def test_refused_old_commit_does_not_disturb_a_new_connection(tmp_path):
    # Jeff 205661: after a new operation legitimately connects, a stale old
    # result's refusal must not roll it back. At the store layer that means the
    # refused save_commit leaves the NEW op's sealed creds + commit untouched
    # (zero write). The projection is the daemon's concern -- it catches
    # CommitInvalidated and leaves the current projection alone.
    with _store(tmp_path) as s:
        s.invalidate_commit(operation_id="op-old")                       # old op barred pre-commit
        new = _saved(s, operation_id="op-new",
                     credentials={"access_token": "new-at"})
        with pytest.raises(CommitInvalidated):
            _saved(s, operation_id="op-old")                # stale result refused
        assert s.load_commit() == new                       # new commit unchanged
        assert s.load_credentials() == {"access_token": "new-at"}  # new creds intact


def test_invalidation_bars_recommit_even_after_clear(tmp_path):
    # Disconnect an operation, clear creds; the operation stays barred (its mark
    # survived the clear), while a fresh operation still connects.
    with _store(tmp_path) as s:
        _saved(s, operation_id="op1")
        s.invalidate_commit(operation_id="op1")
        s.clear_credentials()
        with pytest.raises(CommitInvalidated):
            _saved(s, operation_id="op1")                   # barred, survived clear
        assert _saved(s, operation_id="op2").operation_id == "op2"  # fresh op ok
