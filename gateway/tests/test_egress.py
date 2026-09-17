"""Egress allow-list enforcement tests (ASSEMBLY_PLAN step ii, gate 3).

Actuated variable: the host of the outbound URL. A host on the injected
allow-list reaches the transport; any other host -- or a non-HTTPS scheme --
is refused fail-closed *before* the transport is touched, and the offending
host is carried on the error for `egress_hosts` recording.
"""

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gateway.egress import EgressBlockedError, EgressGuardedClient, HttpResponse


class _RecordingTransport:
    def __init__(self, status=200, body=b"ok"):
        self.status = status
        self.body = body
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        return self.status, self.body


def test_allowed_host_reaches_transport():
    t = _RecordingTransport(status=200, body=b"hi")
    c = EgressGuardedClient({"gmail.googleapis.com"}, transport=t)
    resp = c.post("https://gmail.googleapis.com/x", headers={"A": "b"}, body=b"z")
    assert isinstance(resp, HttpResponse)
    assert resp.status == 200 and resp.body == b"hi"
    assert resp.host == "gmail.googleapis.com"
    assert t.calls == [("POST", "https://gmail.googleapis.com/x", {"A": "b"}, b"z")]


def test_disallowed_host_refused_and_transport_untouched():
    t = _RecordingTransport()
    c = EgressGuardedClient({"gmail.googleapis.com"}, transport=t)
    with pytest.raises(EgressBlockedError) as ei:
        c.post("https://evil.example/x", headers={}, body=b"")
    assert ei.value.host == "evil.example"
    assert ei.value.reason == "host_not_allowed"
    assert t.calls == []  # fail-closed happens before any network touch


def test_non_https_scheme_refused():
    t = _RecordingTransport()
    c = EgressGuardedClient({"gmail.googleapis.com"}, transport=t)
    with pytest.raises(EgressBlockedError) as ei:
        c.post("http://gmail.googleapis.com/x", headers={}, body=b"")
    assert ei.value.reason == "scheme_not_https"
    assert t.calls == []


def test_blocked_error_carries_host_for_recording():
    c = EgressGuardedClient({"gmail.googleapis.com"}, transport=_RecordingTransport())
    with pytest.raises(EgressBlockedError) as ei:
        c.post("https://oauth2.googleapis.com/token", headers={}, body=b"")
    # the attempted (blocked) host is recoverable so the caller can log it
    assert ei.value.host == "oauth2.googleapis.com"


def test_allow_list_is_exposed_and_frozen():
    c = EgressGuardedClient(["gmail.googleapis.com"], transport=_RecordingTransport())
    assert c.allow_hosts == frozenset({"gmail.googleapis.com"})


@given(host=st.text(alphabet="abcdefghijklmnopqrstuvwxyz.-", min_size=1, max_size=30))
def test_only_allowlisted_host_passes_property(host):
    allow = {"gmail.googleapis.com"}
    t = _RecordingTransport()
    c = EgressGuardedClient(allow, transport=t)
    url = "https://%s/path" % host
    if host in allow:
        c.post(url, headers={}, body=b"")
    else:
        with pytest.raises(EgressBlockedError):
            c.post(url, headers={}, body=b"")
        assert t.calls == []


def test_allow_list_is_case_normalised():
    # urlsplit lower-cases the URL host, so a mixed-case allow-list entry must
    # be normalised too or it would silently fail closed on a legitimate host.
    t = _RecordingTransport(status=200, body=b"ok")
    c = EgressGuardedClient({"Gmail.GoogleAPIs.com"}, transport=t)
    assert c.allow_hosts == frozenset({"gmail.googleapis.com"})
    resp = c.post("https://gmail.googleapis.com/x", headers={}, body=b"")
    assert resp.status == 200 and len(t.calls) == 1


def test_transport_survives_broken_error_body_read(monkeypatch):
    # urllib_transport must still return the HTTP status when reading the error
    # body raises -- the status is the signal the sender classifies on.
    import urllib.error

    from gateway import egress

    class _BrokenBody(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("https://x/y", 503, "boom", {}, None)

        def read(self, *a):
            raise IOError("body read failed")

    class _Opener:
        def open(self, *a, **k):
            raise _BrokenBody()

    monkeypatch.setattr(egress.urllib.request, "build_opener", lambda *a: _Opener())
    status, body = egress.urllib_transport("POST", "https://x/y", {}, b"")
    assert status == 503 and body == b""
