"""On-disk persistence backends (ASSEMBLY_PLAN step i).

Concrete SQLite implementations of the `store` module's injected seams
(`KVBackend`, `AppendLog`). The store *logic* -- proposal lifecycle,
idempotency, expiry, closed-schema audit -- is unchanged: it runs against these
exactly as it runs against the in-memory backends in unit tests. That is the
whole point of the seam, and the tests here prove the swap is behaviour-
preserving by driving the real `ProposalStore`/`AuditLedger` against SQLite.

Design decisions (the *why*):

- **Durability = WAL + `synchronous=FULL`.** This is a send gateway: the
  `SEND_ATTEMPTED` audit row must be fsync'd to disk *before* the network send,
  so a crash mid-send leaves evidence rather than a silent gap. FULL fsyncs on
  every commit (no lost transaction on power loss); the volume is low enough
  that the cost is irrelevant. Correctness over speed.
- **One connection + a lock.** The loopback HTTP server (a later step) may
  serve on multiple threads, so the connection is opened with
  `check_same_thread=False` and every access is serialised by a `Lock`. SQLite
  itself is the durability boundary; the lock only keeps the single connection's
  cursor use sane.
- **Append-only by construction.** `SqliteAppendLog` exposes only `append` and
  `entries` -- there is no update/delete method, so the audit ledger cannot be
  rewritten through this object (mirrors the closed-schema guarantee upstream).
- **Explicit `close()`.** On Windows an open SQLite file is locked, so callers
  (and tests) must close before removing the data dir. Both classes are context
  managers for that reason.
- **Values are JSON.** Both upstream `to_dict()` shapes are JSON-native
  (enum -> str, tuple -> list already applied upstream), so a JSON round-trip is
  lossless and copies inherently -- callers never share mutable state.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Callable, Iterator

# Sentinel: an `update` transform returns this to leave the row unchanged.
ABORT = object()


def _connect(db_path: str) -> sqlite3.Connection:
    # Parent dir may be a not-yet-created data-root subdir (proposals/, audit/).
    # 0700 intent per ASSEMBLY_PLAN §6 is a POSIX concern; on Windows the ACL
    # model differs, so we create the dir and leave OS-level perms to the host.
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    # Durability is load-bearing here (the SEND_ATTEMPTED row must be fsync'd
    # before the wire), and PRAGMA silently falls back to a weaker mode if the
    # filesystem can't honour it. So read the settings back and refuse rather
    # than run a gateway whose crash-evidence guarantee never actually took.
    mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
    conn.execute("PRAGMA synchronous=FULL")
    sync = conn.execute("PRAGMA synchronous").fetchone()[0]  # 2=FULL, 3=EXTRA
    if str(mode).lower() != "wal" or int(sync) < 2:
        conn.close()
        raise RuntimeError(
            "durability not established: journal_mode=%r synchronous=%r "
            "(need wal + FULL)" % (mode, sync))
    return conn


class SqliteKV:
    """A durable keyed record store for proposals (implements `KVBackend`)."""

    def __init__(self, db_path: str):
        self._lock = threading.Lock()
        self._conn = _connect(db_path)
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS kv "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            self._conn.commit()

    def get(self, key: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return None if row is None else json.loads(row[0])

    def put(self, key: str, value: dict) -> None:
        blob = json.dumps(value)
        with self._lock:
            # upsert: a proposal's status transitions overwrite the same key.
            self._conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, blob))
            self._conn.commit()

    def delete(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            self._conn.commit()

    def update(self, key: str, fn: "Callable[[dict | None], dict | object]") -> object:
        """Atomic read-modify-write of one key.

        `fn` receives the current value (a dict) or None and returns either the
        new dict to persist or the module-level `ABORT` sentinel to leave the
        row unchanged. The read, the `fn` decision, and the conditional write
        run inside one lock-held critical section on this connection with no
        other statement interleaved, so a check-then-write expressed in `fn`
        (e.g. "refuse if this operation was invalidated") cannot race a
        concurrent writer on the same store. The write itself is the usual
        WAL + `synchronous=FULL` durable commit. Returns `fn`'s return value.

        `fn` must not call back into this store (the lock is not reentrant).
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
            current = None if row is None else json.loads(row[0])
            result = fn(current)
            if result is ABORT:
                return result
            self._conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(result)))
            self._conn.commit()
            return result

    def values(self) -> Iterator[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT value FROM kv").fetchall()
        # Materialise under the lock, then yield: never hold the cursor open
        # across a caller-driven generator.
        return (json.loads(r[0]) for r in rows)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> SqliteKV:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class SqliteAppendLog:
    """A durable append-only log for audit entries (implements `AppendLog`)."""

    def __init__(self, db_path: str):
        self._lock = threading.Lock()
        self._conn = _connect(db_path)
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS audit "
                "(seq INTEGER PRIMARY KEY AUTOINCREMENT, entry TEXT NOT NULL)")
            self._conn.commit()

    def append(self, entry: dict) -> None:
        blob = json.dumps(entry)
        with self._lock:
            self._conn.execute("INSERT INTO audit (entry) VALUES (?)", (blob,))
            self._conn.commit()

    def entries(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT entry FROM audit ORDER BY seq").fetchall()
        return [json.loads(r[0]) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> SqliteAppendLog:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
