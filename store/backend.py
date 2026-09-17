"""Persistence backend seam.

The store logic (proposal lifecycle, idempotency, audit) is written against
these tiny Protocols, never against a concrete file/sqlite layout. That final
layout is a DESIGN sec 10 / assembly-layer decision (repo + transport + cross-
platform paths), so keeping it behind a seam is what makes this module
boundary-independent: the same logic runs on an in-memory backend in tests and
on the real on-disk backend once the topology is fixed.
"""

from __future__ import annotations

from typing import Dict, Iterator, List, Optional, Protocol


class KVBackend(Protocol):
    """A minimal keyed record store for proposals."""

    def get(self, key: str) -> Optional[dict]: ...
    def put(self, key: str, value: dict) -> None: ...
    def values(self) -> Iterator[dict]: ...
    # delete is idempotent (no-op on an absent key): the only caller is the
    # orphan-payload cleanup on a lost idempotency race, which must not itself
    # fail if the loser's payload was never written.
    def delete(self, key: str) -> None: ...


class AppendLog(Protocol):
    """An append-only log for audit entries."""

    def append(self, entry: dict) -> None: ...
    def entries(self) -> List[dict]: ...


class InMemoryKV:
    def __init__(self) -> None:
        self._d: Dict[str, dict] = {}

    def get(self, key: str) -> Optional[dict]:
        v = self._d.get(key)
        return dict(v) if v is not None else None  # copy: callers can't mutate state

    def put(self, key: str, value: dict) -> None:
        self._d[key] = dict(value)

    def delete(self, key: str) -> None:
        self._d.pop(key, None)  # idempotent

    def values(self) -> Iterator[dict]:
        return (dict(v) for v in self._d.values())


class InMemoryAppendLog:
    def __init__(self) -> None:
        self._log: List[dict] = []

    def append(self, entry: dict) -> None:
        self._log.append(dict(entry))

    def entries(self) -> List[dict]:
        return [dict(e) for e in self._log]
