"""Data-root layout: the single source of truth for on-disk file locations.

Both the summoned proposal server (`gateway.entrypoint`) and the local operator
CLIs (`gateway.authorize`, `gateway.send_cli`) open the *same* files under a
shared `--data-root`, so the proposal the server froze is exactly the one the
send command later confirms. Defining the four paths here -- rather than inline
in each caller -- means the layout cannot drift between the writer and the
reader; a drift would surface as a "proposal not found" (or worse, a wrong file)
at real-send time.
"""

from __future__ import annotations

from pathlib import Path


def proposals_db(data_root: str) -> str:
    """Digest-only proposal records (written by the server, updated by send)."""
    return str(Path(data_root) / "proposals" / "proposals.db")


def payloads_db(data_root: str) -> str:
    """Frozen canonical payloads (written by the server, read by send)."""
    return str(Path(data_root) / "proposals" / "payloads.db")


def audit_db(data_root: str) -> str:
    """PII/token-free audit ledger (written by the send path)."""
    return str(Path(data_root) / "audit" / "audit.db")


def token_db(data_root: str) -> str:
    """Sealed OAuth token (written by authorize and pre-send refresh)."""
    return str(Path(data_root) / "token" / "token.db")


def client_bundle(data_root: str) -> str:
    """Daemon-bundled Google client JSON, for deployment ("one-click") authorize.

    Deployment mode reads the shared OAuth client from here instead of an
    operator-supplied `--client-secret-file`; the installer drops it in, and
    `gateway.bundle` hash-verifies it before use. Absent in POC/dev mode.
    """
    return str(Path(data_root) / "client" / "client.json")
