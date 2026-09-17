"""Egress-enforcing HTTP client (ASSEMBLY_PLAN step ii; gate 3 / DESIGN §8.1).

A thin client that enforces the §8.1 host **allow-list**, fail-closed, on every
outbound call, and records the host actually contacted so an audit event can
carry a positive `egress_hosts` observable rather than merely "no cloud call was
seen" ([[feedback_zero_is_a_search_hypothesis]]). The allow-list is passed in at
construction, so the same client serves the send path (`{gmail.googleapis.com}`)
and, later, the OAuth exchange (`{oauth2.googleapis.com}`) with a different list.

The wire call itself is an injected `transport` seam, so all of the guard logic
is exercised without a network; the default `urllib_transport` is a minimal
stdlib client used only on the operator's own machine.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit

# (method, url, headers, body) -> (status, body_bytes). A 4xx/5xx is a normal
# return with its status; only genuine transport failures (timeout, connection,
# DNS) raise -- the caller maps those to a coarse, sanitized category (M1).
Transport = Callable[..., tuple[int, bytes]]


class EgressBlockedError(Exception):
    """A call to a non-allow-listed host (or non-HTTPS URL) was refused.

    Carries the offending host so the caller can still record it in
    `egress_hosts`: a blocked attempt is a positive zero-cloud-touch artifact,
    not a silent skip.
    """

    def __init__(self, host: str | None, reason: str):
        super().__init__("egress refused to %r (%s)" % (host, reason))
        self.host = host or ""
        self.reason = reason


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    host: str


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A redirect to another host would silently bypass the allow-list, so we
    # never follow one; the 3xx surfaces as-is for the caller to treat as a
    # non-success (indeterminate) outcome.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urllib_transport(method, url, headers, body, *, timeout: float = 30.0):
    """Minimal stdlib HTTPS transport. Live-machine only; tests inject a fake."""
    req = urllib.request.Request(
        url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        # A real HTTP response, not a transport failure: return its status so
        # the caller classifies it. Connection/timeout errors are deliberately
        # NOT caught here -- they propagate to the sender's type-based mapping.
        try:
            err_body = e.read()
        except OSError:
            # The status is the load-bearing signal (the sender classifies on
            # it); a broken error-body read must not mask it or crash the send.
            err_body = b""
        return e.code, err_body


class EgressGuardedClient:
    """Refuses any request whose host is not in the injected allow-list."""

    def __init__(self, allow_hosts, *, transport: Transport | None = None):
        # Normalise to lower case: urlsplit().hostname is already lower-cased,
        # so an allow-list entry with any upper-case letters would never match
        # and would silently fail closed on a host that should be permitted.
        self._allow = frozenset(h.lower() for h in allow_hosts)
        self._transport = transport or urllib_transport

    @property
    def allow_hosts(self) -> frozenset:
        return self._allow

    def post(self, url: str, *, headers: Mapping[str, str], body: bytes) -> HttpResponse:
        parts = urlsplit(url)
        host = parts.hostname
        # https-only: a bearer token rides in the Authorization header, so a
        # plaintext scheme is refused before the transport is ever touched.
        if parts.scheme != "https":
            raise EgressBlockedError(host, "scheme_not_https")
        if host not in self._allow:
            raise EgressBlockedError(host, "host_not_allowed")
        status, resp_body = self._transport("POST", url, headers, body)
        return HttpResponse(status=status, body=resp_body, host=host)
