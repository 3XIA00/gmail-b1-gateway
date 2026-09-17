"""Supervisor summon tests (ASSEMBLY_PLAN step v-b).

Two levels:

- **Supervision logic** over an injected fake `popen` (no real subprocess): the
  handshake parse, idempotent reuse, ready-timeout / early-death / malformed-line
  failure modes, stop semantics, and the C7 ④ closed-surface introspection.
- **Real summon** of the actual `gateway.entrypoint` as a distinct OS process:
  C7 ① (the child pid is not this process), the summoned surface really is the
  step-(iv) closed set, and stop() tears the listener down.

Actuated variables:
  - the child's readiness handshake -> start() returns its port, or fails closed
    (timeout / EOF / malformed) and kills the child.
  - the live/dead state of the child -> health() and idempotent-reuse switch on it.
  - the requested path/method against the summoned port -> only the closed
    proposal set answers; confirm/token routes are 404 (no supervision bypass).
"""

import inspect
import io
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from gateway import supervisor as supervisor_mod
from gateway.supervisor import GatewaySupervisor, SupervisorError, _tcp_open


# --- fakes ----------------------------------------------------------------

class _FakeStdout:
    """A stdout whose readline() yields `line` once, then EOF; or blocks until
    released (to exercise the ready-timeout path)."""

    def __init__(self, line="", *, block=False):
        self._line = line
        self._block = block
        self._released = threading.Event()
        self._done = False

    def readline(self):
        if self._block:
            self._released.wait()
            return ""
        if self._done:
            return ""
        self._done = True
        return self._line

    def release(self):
        self._released.set()


class _FakeProc:
    def __init__(self, *, ready_line="", block=False, pid=4321):
        self.stdout = _FakeStdout(ready_line, block=block)
        self.pid = pid
        self._alive = True
        self._rc = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return None if self._alive else (self._rc if self._rc is not None else 0)

    def terminate(self):
        self.terminated = True
        self._alive = False
        self._rc = 0

    def kill(self):
        self.killed = True
        self._alive = False
        self._rc = -9
        self.stdout.release()

    def wait(self, timeout=None):
        return self._rc if self._rc is not None else 0


def _fake_popen(proc):
    calls = []

    def popen(argv, **kw):
        calls.append({"argv": argv, "kw": kw})
        return proc

    popen.calls = calls
    return popen


def _sup(proc, **over):
    kw = dict(data_root="/tmp/nonexistent-data-root", popen=_fake_popen(proc),
              bearer_factory=lambda: "BEARER-XYZ", ready_timeout=0.5)
    kw.update(over)
    return GatewaySupervisor(**kw)


# --- supervision logic (fake popen) --------------------------------------

def test_start_parses_port_and_passes_bearer_via_env_only():
    proc = _FakeProc(ready_line=json.dumps({"status": "ready", "port": 54321}) + "\n")
    popen = _fake_popen(proc)
    sup = GatewaySupervisor(
        data_root="/data/root", popen=popen,
        bearer_factory=lambda: "SECRET-BEARER")
    desc = sup.start()

    assert desc == {"pid": 4321, "port": 54321, "bearer": "SECRET-BEARER"}
    call = popen.calls[0]
    # entrypoint module + data-root are on the argv; the bearer is NOT (it is a
    # secret, passed through the environment only).
    assert "gateway.entrypoint" in call["argv"]
    assert "/data/root" in call["argv"]
    assert "SECRET-BEARER" not in call["argv"]
    assert call["kw"]["env"]["GATEWAY_SESSION_BEARER"] == "SECRET-BEARER"

    h = sup.health()
    assert h["running"] is True and h["pid"] == 4321 and h["port"] == 54321


def test_start_is_idempotent_reuses_live_child():
    proc = _FakeProc(ready_line=json.dumps({"port": 7}) + "\n")
    popen = _fake_popen(proc)
    sup = GatewaySupervisor(data_root="/r", popen=popen, bearer_factory=lambda: "b")
    d1 = sup.start()
    d2 = sup.start()                      # child still alive -> reuse, no re-spawn
    assert d1 == d2
    assert len(popen.calls) == 1


def test_start_times_out_and_kills_when_never_ready():
    proc = _FakeProc(block=True)          # readline never returns a line
    sup = _sup(proc, ready_timeout=0.3)
    with pytest.raises(SupervisorError):
        sup.start()
    assert proc.killed is True
    assert sup.health()["running"] is False


def test_start_raises_and_kills_on_early_exit():
    proc = _FakeProc(ready_line="")       # immediate EOF: child died pre-ready
    sup = _sup(proc)
    with pytest.raises(SupervisorError):
        sup.start()
    assert proc.killed is True


def test_start_raises_on_malformed_ready_line():
    proc = _FakeProc(ready_line="not-json\n")
    sup = _sup(proc)
    with pytest.raises(SupervisorError):
        sup.start()
    assert proc.killed is True


def test_stop_terminates_and_clears_state():
    proc = _FakeProc(ready_line=json.dumps({"port": 9}) + "\n")
    sup = _sup(proc)
    sup.start()
    sup.stop()
    assert proc.terminated is True
    h = sup.health()
    assert h == {"running": False, "listening": False, "pid": None, "port": None}


def test_stop_before_start_is_noop():
    sup = _sup(_FakeProc())
    sup.stop()                            # nothing running -> must not raise
    assert sup.health()["running"] is False


def test_supervision_surface_is_exactly_the_closed_set():
    # C7 ④: the supervisor's entire public vocabulary is {start, health, stop}.
    sup = _sup(_FakeProc())
    public = {n for n in dir(sup)
              if not n.startswith("_") and callable(getattr(sup, n))}
    assert public == {"start", "health", "stop"}


def test_supervisor_holds_no_send_credential_or_ledger():
    # C7 ④: no supervision code path touches the send/credential/ledger machinery
    # -- the module never even references those symbols. Positive-controllable:
    # adding any of these names to supervisor.py flips this red.
    src = inspect.getsource(supervisor_mod)
    for forbidden in ("SealedTokenStore", "GmailSender", "AuditLedger",
                      "ConfirmDispatcher", "access_token", ".seal("):
        assert forbidden not in src, forbidden


# --- real summon of gateway.entrypoint -----------------------------------

def _http(port, method, path, *, bearer=None, body=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if bearer is not None:
        req.add_header("Authorization", "Bearer " + bearer)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def _await_port_closed(host, port, deadline_s=5.0):
    """Bounded poll (NO sleep) for the listening socket to close, RETURNING whether it
    did. stop()'s contract is process TERMINATION; releasing the listening socket is an
    OS-eventual consequence that can lag the child's death (notably on Windows, where
    the port may still momentarily accept). Asserting an INSTANTANEOUS close (the old
    line 254) tests OS socket-teardown timing, not stop() — a weak contract that flakes
    507/508 on 3.12.10. We instead poll until closed or the deadline and let the caller
    assert eventual close (not a relaxed skip). Each _tcp_open carries its own connect
    timeout, so the loop is bounded without a sleep."""
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        if _tcp_open(host, port, timeout=0.25) is False:
            return True
    return False


_PARAMS = {
    "account_handle": "me@example.com",
    "to": ["alice@example.com"],
    "subject": "Hi",
    "body": {"format": "text", "content": "hello alice"},
}


def test_summons_distinct_process_serving_the_closed_set(tmp_path):
    # A production sender needs a Message-ID domain (§2.7 single-minter); supply
    # one so propose is a valid 200. The no-domain refusal is its own test below.
    sup = GatewaySupervisor(
        data_root=str(tmp_path), message_id_domain="gateway.test")  # real Popen
    desc = sup.start()
    try:
        h = sup.health()
        assert h["running"] is True and h["listening"] is True
        # C7 ①: the credential-holding Gateway is a *separate* process.
        assert desc["pid"] != os.getpid()
        assert h["pid"] == desc["pid"]

        port, bearer = desc["port"], desc["bearer"]
        # The summoned surface really is the step-(iv) closed set.
        s, b = _http(port, "POST", "/proposal", bearer=bearer, body=_PARAMS)
        assert s == 200
        pid = b["proposal_id"]
        s2, b2 = _http(port, "GET", "/proposal/" + pid, bearer=bearer)
        assert s2 == 200 and b2["status"] == "pending"

        # No supervision bypass: confirm/token/unknown routes are uniform 404,
        # and an unauthenticated request is indistinguishable from an unknown one.
        for m, p in (("POST", "/proposal/%s/confirm" % pid), ("GET", "/token"),
                     ("GET", "/secret-admin")):
            s3, b3 = _http(port, m, p, bearer=bearer,
                           body=({} if m == "POST" else None))
            assert s3 == 404 and b3 == {"error": "not_found"}, (m, p, s3, b3)
        s4, b4 = _http(port, "POST", "/proposal", body=_PARAMS)   # no bearer
        assert s4 == 404 and b4 == {"error": "not_found"}
    finally:
        sup.stop()

    # After stop: the PROCESS is gone (stop()'s actual contract — the decisive leg),
    # and the listening socket closes EVENTUALLY (bounded poll, not an instantaneous
    # assert — the OS may lag the child's death; see _await_port_closed).
    assert sup.health()["running"] is False
    assert _await_port_closed("127.0.0.1", desc["port"]) is True


def test_production_entry_refuses_propose_without_a_message_id_domain(tmp_path):
    # §2.7 single-minter fail-closed at the REAL production entry (Jeff 205699):
    # a Gateway spawned with no Message-ID domain must REFUSE to propose rather
    # than freeze/send an ID-less mail. Asserted end-to-end through the spawned
    # process: the closed surface is still up (a valid bearer, served route), but
    # the propose is rejected with the uniform coarse code and nothing is minted.
    sup = GatewaySupervisor(data_root=str(tmp_path))   # no message_id_domain
    desc = sup.start()
    try:
        port, bearer = desc["port"], desc["bearer"]
        s, b = _http(port, "POST", "/proposal", bearer=bearer, body=_PARAMS)
        assert s == 400 and b == {"error": "invalid_payload"}, (s, b)
    finally:
        sup.stop()


def test_restart_spawns_a_fresh_process(tmp_path):
    sup = GatewaySupervisor(data_root=str(tmp_path))
    p1 = sup.start()["pid"]
    sup.stop()
    p2 = sup.start()["pid"]
    try:
        assert p1 != p2
        assert sup.health()["running"] is True
    finally:
        sup.stop()
