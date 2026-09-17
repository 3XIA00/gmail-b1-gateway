"""OAuth loopback listener + token exchange (ASSEMBLY_PLAN step iii).

Wraps the pure `oauth` core (PKCE / state / authorize / callback / token
exchange) with the three side effects it deliberately excludes: a 127.0.0.1
listener that receives the RFC 8252 loopback redirect, a browser open, and the
egress-guarded HTTPS token exchange. The result is a `TokenResult`; **sealing
and persistence stay downstream** (keystore + `gateway.persistence`), so this
object's boundary is exactly "run the browser consent flow and return tokens".

Security posture:
- **Loopback only.** The server binds `127.0.0.1` on an ephemeral port; the
  redirect URI is `http://127.0.0.1:<port>/…`, which the core's
  `AuthorizationRequest` re-validates as loopback (gate 2).
- **CSRF + forged-callback.** `extract_authorization_code` checks `state`
  before the code, so a forged callback is rejected before its code is trusted.
- **No secret-in-logs.** The callback query string carries the authorization
  code, so the handler's request logging is silenced (the stdlib default prints
  the path — and thus the code — to stderr). `TokenResult.__repr__` redacts the
  tokens, so they cannot leak through a log line or traceback.
- **Egress-guarded exchange.** The token POST goes through an injected
  `EgressGuardedClient` whose allow-list must be `OAUTH_ALLOW_HOSTS`
  (`{oauth2.googleapis.com}`) — gate 3.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable
from urllib.parse import parse_qsl, urlencode, urlsplit

from oauth import (
    DEFAULT_AUTH_ENDPOINT,
    DEFAULT_TOKEN_ENDPOINT,
    V1_ALLOWED_SCOPES,
    AuthorizationRequest,
    build_authorization_url,
    build_token_exchange_request,
    extract_authorization_code,
    generate_pkce_pair,
    generate_state,
)
from oauth.errors import OAuthError

from .egress import EgressGuardedClient

# gate 3 allow-list for the token exchange (see gateway.gmail_sender for send).
OAUTH_ALLOW_HOSTS = frozenset({"oauth2.googleapis.com"})


def _is_loopback(host: str) -> bool:
    """True only for a host that resolves to the local machine (gate 2)."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback  # 127.0.0.0/8, ::1
    except ValueError:
        return False


class OAuthTimeoutError(OAuthError):
    """No loopback callback arrived within the allotted time."""


class OAuthExchangeError(OAuthError):
    """The provider refused the token exchange, or returned no access token."""


@dataclass(frozen=True)
class TokenResult:
    access_token: str
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    token_type: str | None = None
    received_at: int | None = None

    @classmethod
    def from_response(cls, body: bytes) -> TokenResult:
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise OAuthExchangeError("token response was not valid JSON")
        if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
            raise OAuthExchangeError("token response missing access_token")
        exp = data.get("expires_in")
        return cls(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_in=exp if isinstance(exp, int) and not isinstance(exp, bool) else None,
            scope=data.get("scope"),
            token_type=data.get("token_type"))

    def __repr__(self) -> str:
        # Tokens must never surface in a log line, repr, or traceback.
        return (
            "TokenResult(access_token=<redacted>, refresh_token=%s, "
            "expires_in=%r, scope=%r, token_type=%r, received_at=%r)" % (
                "<redacted>" if self.refresh_token else None,
                self.expires_in, self.scope, self.token_type, self.received_at))


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 (stdlib naming)
        parts = urlsplit(self.path)
        if parts.path != self.server.callback_path:
            self.send_response(404)
            self.end_headers()
            return
        # Take the FIRST value per key: a forged callback that appends a second
        # `code=`/`state=` must not override the first pair the flow will check.
        captured: dict = {}
        for key, value in parse_qsl(parts.query):
            captured.setdefault(key, value)
        self.server.captured = captured
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(
            b"<html><body>Authorization received. You can close this window."
            b"</body></html>")
        self.server.done.set()

    def log_message(self, *args):
        # Silence the default stderr log -- the request path carries the
        # authorization code, which must not be written anywhere.
        return


class _LoopbackServer(HTTPServer):
    def __init__(self, host: str, callback_path: str):
        # The callback query string carries the authorization code, so the
        # listener must never bind a routable interface. Guard at the bind point
        # itself, so no construction path can expose it (gate 2, defence-in-depth).
        if not _is_loopback(host):
            raise ValueError("loopback listener refuses non-loopback host %r" % host)
        super().__init__((host, 0), _CallbackHandler)  # port 0 -> ephemeral
        self.callback_path = callback_path
        self.captured: dict | None = None
        self.done = threading.Event()

    @property
    def port(self) -> int:
        return self.server_address[1]


class LoopbackOAuthFlow:
    """Run the browser consent flow on a loopback listener; return tokens."""

    def __init__(
        self,
        *,
        client_id: str,
        egress_client: EgressGuardedClient,
        client_secret: str | None = None,
        scopes: frozenset = V1_ALLOWED_SCOPES,
        browser_opener: Callable[[str], object] | None = None,
        host: str = "127.0.0.1",
        callback_path: str = "/oauth2/callback",
        auth_endpoint: str = DEFAULT_AUTH_ENDPOINT,
        token_endpoint: str = DEFAULT_TOKEN_ENDPOINT,
        timeout: float = 300.0,
        on_redirect_uri: Callable[[str], object] | None = None,
        now: Callable[[], int] | None = None,
    ):
        # The token exchange must be pinned to the OAuth host (gate 3): reject an
        # egress client scoped to anything else rather than discover it at send.
        if egress_client.allow_hosts != OAUTH_ALLOW_HOSTS:
            raise ValueError(
                "OAuth flow requires an egress client scoped to %s, got %s"
                % (set(OAUTH_ALLOW_HOSTS), set(egress_client.allow_hosts)))
        # Fail fast at construction, not only at the run() bind.
        if not _is_loopback(host):
            raise ValueError("OAuth flow refuses non-loopback host %r" % host)
        self._client_id = client_id
        self._egress = egress_client
        self._client_secret = client_secret
        self._scopes = scopes
        self._open = browser_opener or webbrowser.open
        self._host = host
        self._callback_path = callback_path
        self._auth_endpoint = auth_endpoint
        self._token_endpoint = token_endpoint
        self._timeout = timeout
        # Optional observer of the bound redirect_uri (with the ephemeral port),
        # fired once the loopback is up and before the browser opens, so a caller
        # can surface it for a human to verify. The uri is non-secret (loopback
        # host + port + fixed callback path); the CLI wires this to stdout.
        self._on_redirect_uri = on_redirect_uri
        self._now = now or (lambda: int(time.time()))

    def run(self) -> TokenResult:
        pkce = generate_pkce_pair()
        state = generate_state()
        server = _LoopbackServer(self._host, self._callback_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            redirect_uri = "http://%s:%d%s" % (
                self._host, server.port, self._callback_path)
            if self._on_redirect_uri is not None:
                self._on_redirect_uri(redirect_uri)
            request = AuthorizationRequest(
                client_id=self._client_id, redirect_uri=redirect_uri,
                state=state, code_challenge=pkce.challenge, scopes=self._scopes)
            auth_url = build_authorization_url(
                request, auth_endpoint=self._auth_endpoint)

            self._open(auth_url)
            if not server.done.wait(self._timeout):
                raise OAuthTimeoutError(
                    "no OAuth callback within %ss" % self._timeout)

            code = extract_authorization_code(
                server.captured or {}, expected_state=state)
            return self._exchange(code, pkce.verifier, redirect_uri)
        finally:
            server.shutdown()
            server.server_close()

    def _exchange(self, code, verifier, redirect_uri) -> TokenResult:
        request = build_token_exchange_request(
            code=code, code_verifier=verifier, client_id=self._client_id,
            redirect_uri=redirect_uri, client_secret=self._client_secret,
            token_endpoint=self._token_endpoint)
        body = urlencode(request.body).encode("utf-8")
        resp = self._egress.post(
            request.endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body)
        if not (200 <= resp.status < 300):
            # Surface the provider's short `error` code (safe) or the status --
            # never the raw body / error_description (§8 sanitization).
            raise OAuthExchangeError(
                "token exchange failed: %s" % self._safe_error(resp))
        parsed = TokenResult.from_response(resp.body)
        # Capture the token endpoint response boundary itself. Deriving this
        # later from the seal/file timestamp would silently extend validity if
        # downstream persistence were ever delayed.
        return TokenResult(
            access_token=parsed.access_token,
            refresh_token=parsed.refresh_token,
            expires_in=parsed.expires_in,
            scope=parsed.scope,
            token_type=parsed.token_type,
            received_at=self._now(),
        )

    @staticmethod
    def _safe_error(resp) -> str:
        try:
            data = json.loads(resp.body.decode("utf-8"))
            err = data.get("error") if isinstance(data, dict) else None
        except (ValueError, UnicodeDecodeError):
            err = None
        return err if isinstance(err, str) else ("HTTP %d" % resp.status)
