"""Token revocation tests (RFC 7009) -- §2.8 Disconnect remote-revoke leg.

Actuated variable: HTTP status / exception type -> RevokeOutcome + a coarse,
sanitized reason.
  2xx            -> CONFIRMED (RFC 7009: also covers an already-invalid token)
  4xx            -> FAILED (provider answered and definitively refused)
  5xx/3xx        -> UNKNOWN (nothing usable came back; retryable)
  timeout        -> UNKNOWN reason=timeout  (NOT proof it was not processed)
  transport      -> UNKNOWN reason=transport
  egress blocked -> UNKNOWN reason=egress_blocked (call never left machine)
The reason is a pure function of status-or-type, never a response body /
exception text (which could echo the token) -- §8 sanitization / M1. The three
outcomes map onto Disconnect's five-row table (confirmed / failed / unknown)
and are never merged into a single boolean.

Enum names/values match the daemon's ``ops.RevokeOutcome`` verbatim; the
``make_disconnect_revoker`` adapter translates onto an injected target enum by
NAME so ``disconnect_gmail``'s ``outcome is RevokeOutcome.CONFIRMED`` holds.
"""

import asyncio
import enum
import socket
from urllib.error import URLError

import pytest

from gateway.egress import EgressGuardedClient
from gateway.oauth_listener import OAUTH_ALLOW_HOSTS
from gateway.token_revoke import (
    REVOKE_HOST,
    RevokeOutcome,
    TokenRevoker,
    make_disconnect_revoker,
)
from oauth import DEFAULT_REVOKE_ENDPOINT, build_revoke_token_request


class FakeTransport:
    """Injected wire seam: records calls, returns a canned (status, body) or raises."""

    def __init__(self, *, result=None, exc=None):
        self._result = result
        self._exc = exc
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if self._exc is not None:
            raise self._exc
        return self._result


def _revoker(transport, *, endpoint=DEFAULT_REVOKE_ENDPOINT):
    return TokenRevoker(
        EgressGuardedClient(OAUTH_ALLOW_HOSTS, transport=transport),
        revoke_endpoint=endpoint)


# --- pure builder (RFC 7009: token only, no client auth) ------------------

def test_build_request_carries_only_token():
    req = build_revoke_token_request(token="rt-123")
    assert req.endpoint == DEFAULT_REVOKE_ENDPOINT
    assert req.body == {"token": "rt-123"}          # no client_id, no secret
    assert set(req.body) == {"token"}


def test_build_request_rejects_empty_token():
    with pytest.raises(ValueError):
        build_revoke_token_request(token="")


# --- outcome classification -----------------------------------------------

@pytest.mark.parametrize("status", [200, 204])
def test_2xx_is_confirmed(status):
    r = _revoker(FakeTransport(result=(status, b""))).revoke("rt")
    assert r.outcome is RevokeOutcome.CONFIRMED
    assert r.egress_hosts == (REVOKE_HOST,)


@pytest.mark.parametrize("status,reason", [
    (400, "rejected_400"), (401, "rejected_401"), (403, "rejected_403"),
])
def test_4xx_is_failed(status, reason):
    r = _revoker(FakeTransport(result=(status, b'{"error":"x"}'))).revoke("rt")
    assert r.outcome is RevokeOutcome.FAILED and r.reason == reason
    assert r.egress_hosts == (REVOKE_HOST,)


@pytest.mark.parametrize("status,reason", [
    (500, "server_500"), (503, "server_503"), (302, "server_302"),
])
def test_5xx_and_3xx_are_unknown(status, reason):
    r = _revoker(FakeTransport(result=(status, b""))).revoke("rt")
    assert r.outcome is RevokeOutcome.UNKNOWN and r.reason == reason


def test_timeout_is_unknown_never_failed_or_confirmed():
    r = _revoker(FakeTransport(exc=socket.timeout())).revoke("rt")
    assert r.outcome is RevokeOutcome.UNKNOWN
    assert r.reason == "timeout" and r.egress_hosts == (REVOKE_HOST,)


def test_transport_error_is_unknown_and_message_dropped():
    r = _revoker(FakeTransport(exc=URLError("boom at 10.0.0.1"))).revoke("rt")
    assert r.outcome is RevokeOutcome.UNKNOWN and r.reason == "transport"
    assert "boom" not in (r.reason or "") and "10.0.0.1" not in (r.reason or "")


def test_connection_refused_is_unknown():
    r = _revoker(FakeTransport(exc=ConnectionRefusedError("refused"))).revoke("rt")
    assert r.outcome is RevokeOutcome.UNKNOWN and r.reason == "transport"


# --- egress guard (positive zero-cloud-touch control) ---------------------

def test_non_allowlisted_endpoint_is_blocked_before_the_wire():
    t = FakeTransport(result=(200, b""))
    r = _revoker(t, endpoint="https://evil.example/revoke").revoke("rt")
    assert r.outcome is RevokeOutcome.UNKNOWN
    assert r.reason == "egress_blocked" and r.egress_hosts == ("evil.example",)
    assert t.calls == []                             # never reached the wire


def test_plaintext_scheme_is_blocked():
    t = FakeTransport(result=(200, b""))
    r = _revoker(t, endpoint="http://oauth2.googleapis.com/revoke").revoke("rt")
    assert r.outcome is RevokeOutcome.UNKNOWN and r.reason == "egress_blocked"
    assert t.calls == []


def test_revoker_refuses_non_oauth_allowlist():
    with pytest.raises(ValueError):
        TokenRevoker(EgressGuardedClient(frozenset({"gmail.googleapis.com"})))


# --- request shape on the wire + sanitization -----------------------------

def test_wire_body_is_urlencoded_token_only():
    t = FakeTransport(result=(200, b""))
    _revoker(t).revoke("supertok")
    method, url, headers, body = t.calls[0]
    assert method == "POST" and url == DEFAULT_REVOKE_ENDPOINT
    assert headers["Content-Type"] == "application/x-www-form-urlencoded"
    assert body == b"token=supertok"                 # only the token, no secret


def test_reason_never_leaks_response_body_or_token():
    t = FakeTransport(result=(400, b'{"error":"bad token supertok"}'))
    r = _revoker(t).revoke("supertok")
    blob = "%r %s" % (r, r.reason)
    assert "supertok" not in blob and "bad token" not in blob


# --- Disconnect adapter: (credentials) -> awaitable (RevokeOutcome, str) ---
#
# A stand-in for the daemon's ops.RevokeOutcome: a DISTINCT enum with the same
# member names. The adapter must return a member of THIS enum (selected by
# name), because disconnect_gmail does `outcome is RevokeOutcome.CONFIRMED`
# against its own enum -- returning our own member would silently fail that
# identity check. Distinct identities here actuate that translation.

class DaemonOutcome(enum.Enum):
    CONFIRMED = "confirmed"
    FAILED = "failed"
    UNKNOWN = "unknown"


def _run(coro):
    return asyncio.run(coro)


def test_adapter_revokes_refresh_token_not_access_token():
    # Prefer refresh_token: revoking it kills the whole grant. Access-only
    # revocation would leave the refresh token live -> a silent half-disconnect.
    t = FakeTransport(result=(200, b""))
    revoke = make_disconnect_revoker(_revoker(t), outcome_enum=DaemonOutcome)
    outcome, evidence = _run(
        revoke({"refresh_token": "rt-live", "access_token": "at-live"}))
    assert outcome is DaemonOutcome.CONFIRMED       # daemon's member, by identity
    assert t.calls[0][3] == b"token=rt-live"        # the refresh token, not access
    assert "rt-live" not in evidence                # evidence never echoes the token


def test_adapter_falls_back_to_access_token_when_no_refresh():
    t = FakeTransport(result=(200, b""))
    revoke = make_disconnect_revoker(_revoker(t), outcome_enum=DaemonOutcome)
    outcome, _ = _run(revoke({"access_token": "at-only"}))
    assert outcome is DaemonOutcome.CONFIRMED
    assert t.calls[0][3] == b"token=at-only"


def test_adapter_maps_failed_by_name_to_target_enum():
    t = FakeTransport(result=(400, b'{"error":"x"}'))
    revoke = make_disconnect_revoker(_revoker(t), outcome_enum=DaemonOutcome)
    outcome, evidence = _run(revoke({"refresh_token": "rt"}))
    assert outcome is DaemonOutcome.FAILED          # translated, not our own enum
    assert outcome is not RevokeOutcome.FAILED      # positive control on the remap
    assert evidence == "rejected_400"


def test_adapter_maps_unknown_by_name_to_target_enum():
    t = FakeTransport(exc=socket.timeout())
    revoke = make_disconnect_revoker(_revoker(t), outcome_enum=DaemonOutcome)
    outcome, evidence = _run(revoke({"refresh_token": "rt"}))
    assert outcome is DaemonOutcome.UNKNOWN
    assert evidence == "timeout"


def test_adapter_no_token_is_unknown_never_confirmed_and_no_wire_call():
    # An empty record is not a revocation: must be UNKNOWN, and nothing may
    # leave the machine.
    t = FakeTransport(result=(200, b""))
    revoke = make_disconnect_revoker(_revoker(t), outcome_enum=DaemonOutcome)
    outcome, evidence = _run(revoke({}))
    assert outcome is DaemonOutcome.UNKNOWN
    assert evidence == "no_token_in_record"
    assert t.calls == []                             # never hit the wire


def test_adapter_defaults_to_own_enum_when_no_target_given():
    t = FakeTransport(result=(200, b""))
    revoke = make_disconnect_revoker(_revoker(t))     # no outcome_enum
    outcome, _ = _run(revoke({"refresh_token": "rt"}))
    assert outcome is RevokeOutcome.CONFIRMED
