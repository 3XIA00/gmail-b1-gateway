"""Gateway supervisor — the closed {start, health, stop} summon channel (step v-b).

Realises two C7 observation points:

- **C7 ① (separate process).** The credential-holding Gateway runs as a *distinct
  OS process* (`python -m gateway.entrypoint`). This supervisor only spawns it,
  polls its liveness, and terminates it — it never runs in the same process as
  the OAuth credential, and never loads one itself.
- **C7 ④ (closed supervision set).** The supervision channel is *exactly*
  `{start, health, stop}` — three OS-process operations. None of them is a
  Gateway *request*, so structurally none can send an email, read the OAuth
  credential, or write the audit ledger: there is simply no method here that
  does. The supervisor imports none of the send/credential/ledger machinery.

The per-session proposal-channel bearer is minted here and handed to the child
through the *environment* (never a log line, never stdout), then returned once
from `start()` so the caller can configure the Agent process. That bearer is the
IPC capability for the closed proposal surface — a different thing from the Gmail
OAuth credential, which never leaves the child.
"""

from __future__ import annotations

import json
import os
import queue
import socket
import subprocess
import sys
import threading
from pathlib import Path
from typing import Callable, Optional

from .proposal_api import mint_session_bearer

# The repo root (…/gmail-gateway) so `python -m gateway.entrypoint` resolves the
# top-level packages regardless of the caller's cwd.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_ENTRYPOINT_MODULE = "gateway.entrypoint"
_ENV_BEARER = "GATEWAY_SESSION_BEARER"
_READY_TIMEOUT = 15.0
_STOP_TIMEOUT = 5.0


class SupervisorError(RuntimeError):
    """The Gateway could not be summoned (never reported ready, or died early)."""


def _tcp_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """True if something is accepting connections at host:port (liveness probe)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class GatewaySupervisor:
    """Spawn / poll / stop the Gateway subprocess.

    Public surface is deliberately exactly `start`, `health`, `stop` (C7 ④). The
    `popen` seam is injected so the supervision *logic* is testable without a real
    subprocess; the default spawns the real `gateway.entrypoint`.
    """

    def __init__(
        self,
        *,
        data_root,
        host: str = "127.0.0.1",
        popen: Callable = subprocess.Popen,
        bearer_factory: Callable[[], str] = mint_session_bearer,
        python: Optional[str] = None,
        cwd=None,
        ready_timeout: float = _READY_TIMEOUT,
        message_id_domain: Optional[str] = None,
    ):
        self._data_root = str(data_root)
        self._host = host
        # §2.7: the Gateway is the single Message-ID minter, so a production
        # deployment supplies the domain here and it is forwarded to the child's
        # --message-id-domain. Absent, the child refuses to propose (fail-closed).
        self._message_id_domain = message_id_domain
        self._popen = popen
        self._bearer_factory = bearer_factory
        self._python = python or sys.executable
        self._cwd = str(cwd) if cwd is not None else str(_REPO_ROOT)
        self._ready_timeout = ready_timeout
        self._proc = None
        self._port: Optional[int] = None
        self._bearer: Optional[str] = None

    def start(self) -> dict:
        """Summon the Gateway. Idempotent: a still-live child is reused, not
        re-spawned. Returns `{pid, port, bearer}` — the bearer is the caller's to
        hand to the Agent, and is passed to the child via the environment only.
        """
        if self._proc is not None and self._proc.poll() is None:
            return self._descriptor()
        bearer = self._bearer_factory()
        argv = [self._python, "-m", _ENTRYPOINT_MODULE,
                "--data-root", self._data_root, "--host", self._host]
        if self._message_id_domain:
            argv += ["--message-id-domain", self._message_id_domain]
        env = dict(os.environ)
        env[_ENV_BEARER] = bearer
        proc = self._popen(
            argv, cwd=self._cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        port = self._await_ready(proc)
        self._proc, self._port, self._bearer = proc, port, bearer
        return self._descriptor()

    def health(self) -> dict:
        """Liveness of the supervised process. Makes no Gateway *request* — only
        `poll()` (process alive) and a bare TCP connect (listener up)."""
        running = self._proc is not None and self._proc.poll() is None
        listening = bool(
            running and self._port is not None
            and _tcp_open(self._host, self._port))
        return {
            "running": running,
            "listening": listening,
            "pid": self._proc.pid if self._proc is not None else None,
            "port": self._port,
        }

    def stop(self) -> None:
        """Terminate the supervised process (graceful SIGTERM where the OS
        delivers it; hard kill as a fallback). A no-op if nothing is running.

        Contract note: this guarantees the child is TERMINATED (`health()["running"]`
        goes False), not that its listening socket is released synchronously — port
        teardown is an OS-eventual consequence that can lag the child's exit. Nothing
        in this codebase consumes an immediate port-reuse guarantee; if a production
        consumer ever does, re-adjudicate (SO_REUSEADDR / Windows exclusive-bind is
        owner backlog, deliberately not bundled into stop())."""
        proc = self._proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=_STOP_TIMEOUT)
        self._proc = self._port = self._bearer = None

    # --- internals --------------------------------------------------------

    def _await_ready(self, proc) -> int:
        line = self._read_ready_line(proc)
        if line is None:
            self._kill_quietly(proc)
            raise SupervisorError("gateway did not report ready")
        try:
            port = int(json.loads(line)["port"])
        except (ValueError, KeyError, TypeError):
            self._kill_quietly(proc)
            raise SupervisorError("gateway ready line malformed: %r" % line)
        return port

    def _read_ready_line(self, proc) -> Optional[str]:
        # readline() blocks until the child prints its one handshake line; run it
        # on a helper thread bounded by the ready deadline so a hung/dead child
        # cannot wedge start().
        result: "queue.Queue" = queue.Queue(maxsize=1)

        def reader():
            try:
                result.put(proc.stdout.readline())
            except Exception:
                result.put("")

        threading.Thread(target=reader, daemon=True).start()
        try:
            line = result.get(timeout=self._ready_timeout)
        except queue.Empty:
            return None          # timed out waiting for ready
        if not line:
            return None          # EOF: the child exited before printing ready
        return line.strip()

    @staticmethod
    def _kill_quietly(proc) -> None:
        try:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=_STOP_TIMEOUT)
        except Exception:
            pass

    def _descriptor(self) -> dict:
        return {"pid": self._proc.pid, "port": self._port, "bearer": self._bearer}
