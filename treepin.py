#!/usr/bin/env python3
"""Canonical tree pin.

Binds file CONTENT and each file's path RELATIVE TO ROOT -- never the caller's
spelling of root, the unpack directory name, or the platform checksum format.

Manifest line (exactly):  <sha256-hex><two spaces><relative-posix-path>\n
Order: by the UTF-8 bytes of the relative path.  Pin: sha256 over manifest bytes.

Usage: treepin.py <root> [--manifest] [--set full|src|py]

Authoritative source: Boris Cherny, tool-connectors thread 2026-09-04
(msg_10aa659a base + msg_ac8ccf7f: symlink/non-regular fail-closed, any-depth
tests/ exclusion for `src`, empty-set failure). The in-package copy is bound by
`full`; a verifier computes the pin with their OWN audited copy first, THEN
confirms this file's hash is in the manifest (see REVISION notes).
"""
from __future__ import annotations

import argparse, hashlib, sys
from pathlib import Path, PurePosixPath

EXCLUDED_DIRS = frozenset({"__pycache__", ".pytest_cache", ".hypothesis"})
TEST_DIR_NAME = "tests"


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if EXCLUDED_DIRS.intersection(rel.parts):
            continue
        if path.is_symlink():                       # fail closed: never a link target
            raise SystemExit(
                f"refusing to pin a tree containing a symlink: {rel.as_posix()!r} "
                "(a pin must bind the delivered bytes, not a link target)")
        if path.is_dir():
            continue
        if not path.is_file():                      # fifo/socket/device -> fail
            raise SystemExit(f"refusing to pin a non-regular entry: {rel.as_posix()!r}")
        yield rel, path


def _in_set(rel: PurePosixPath, which: str) -> bool:
    if which == "full":
        return True
    if which == "src":
        # any-depth tests/: authz/tests/, store/tests/ all excluded
        return TEST_DIR_NAME not in rel.parts[:-1]
    if which == "py":
        return rel.suffix == ".py"
    raise ValueError(which)


def manifest(root: Path, which: str) -> bytes:
    rows = []
    for rel, path in _iter_files(root):
        posix = PurePosixPath(*rel.parts)
        if any(c in str(posix) for c in "\n\r"):
            raise SystemExit(f"refusing to pin a path containing a newline: {posix!r}")
        if not _in_set(posix, which):
            continue
        rows.append((str(posix).encode("utf-8"),
                     hashlib.sha256(path.read_bytes()).hexdigest()))
    if not rows:
        raise SystemExit(
            f"set {which!r} selected no files under {root} -- refusing to emit a "
            "pin over an empty set (check the scope rules)")
    rows.sort(key=lambda r: r[0])
    return b"".join(b"%s  %s\n" % (d.encode("ascii"), p) for p, d in rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--manifest", action="store_true")
    ap.add_argument("--set", default=None, choices=["full", "src", "py"])
    args = ap.parse_args()

    root = Path(args.root).resolve(strict=True)
    if not root.is_dir():
        raise SystemExit(f"not a directory: {root}")

    if args.manifest:
        sys.stdout.buffer.write(manifest(root, args.set or "full"))
        return 0

    for which in (["full", "src", "py"] if args.set is None else [args.set]):
        print(f"{which:5} {hashlib.sha256(manifest(root, which)).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
