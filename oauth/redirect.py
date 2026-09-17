"""Loopback redirect validation (DESIGN sec 3, release gate 2).

The authorization code comes back to a redirect URI the Gateway controls.
v1 accepts *only* an RFC 8252 loopback redirect: the code never leaves the
user's machine, and there is no Web-app / hosted callback that a remote party
could point at. Anything that is not loopback is refused here, fail-closed —
we do not "fix up" a suspicious URI, we reject it.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .errors import LoopbackRequiredError

# RFC 8252 sec 7.3: the loopback interface. IPv4, IPv6, and the "localhost"
# name (resolved locally). This is an allow-list, not a deny-list: a host that
# is not one of these is rejected, so a new spelling of "not loopback" cannot
# slip through by being un-enumerated.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def validate_loopback_redirect(redirect_uri: str) -> None:
    """Raise ``LoopbackRequiredError`` unless *redirect_uri* is loopback.

    Requires: ``http`` scheme (loopback does not use TLS per RFC 8252),
    a loopback host, and an explicit port (the Gateway binds an ephemeral
    port and must know which one). No userinfo, no wildcard host.
    """
    parts = urlsplit(redirect_uri)
    if parts.scheme != "http":
        raise LoopbackRequiredError(
            "redirect must use http on loopback, got scheme %r" % parts.scheme)
    if parts.username or parts.password:
        raise LoopbackRequiredError("redirect must not carry userinfo")
    host = parts.hostname  # lower-cased, brackets stripped for IPv6
    if host not in _LOOPBACK_HOSTS:
        raise LoopbackRequiredError("redirect host %r is not loopback" % host)
    if parts.port is None:
        raise LoopbackRequiredError("redirect must pin an explicit loopback port")
