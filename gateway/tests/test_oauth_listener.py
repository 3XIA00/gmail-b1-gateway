"""OAuth loopback listener tests (ASSEMBLY_PLAN step iii).

These drive the REAL loopback server on 127.0.0.1 (ephemeral port) in-process:
a fake `browser_opener` stands in for the user's browser by firing an HTTP GET
at the redirect URI (as Google would), and a fake egress transport stands in
for the token endpoint. So the socket listener, the callback capture, the PKCE
binding, and the exchange wiring are all exercised without a browser or network.

Actuated variables:
  - callback `state` -> forged/mismatched callback is rejected before its code
    is trusted; `error=` -> AuthorizationError; no code -> MissingCodeError.
  - the code_verifier sent at exchange S256-hashes to the code_challenge shown
    in the auth URL (end-to-end PKCE binding).
  - exchange HTTP status -> a sanitized OAuthExchangeError (provider `error`
    code only, never the body / error_description).
"""

import threading
import urllib.error
import urllib.request

import pytest
from urllib.parse import parse_qs, urlencode, urlsplit

from oauth import code_challenge
from oauth.errors import AuthorizationError, MissingCodeError, StateMismatchError
from gateway.egress import EgressGuardedClient
from gateway.oauth_listener import (
    OAUTH_ALLOW_HOSTS,
    LoopbackOAuthFlow,
    OAuthExchangeError,
    OAuthTimeoutError,
    TokenResult,
)

_TOKEN_JSON = (
    b'{"access_token":"ya29.tok","refresh_token":"1//refresh",'
    b'"expires_in":3599,"scope":"https://www.googleapis.com/auth/gmail.send",'
    b'"token_type":"Bearer"}')


def _egress(status=200, body=_TOKEN_JSON):
    calls = []

    def transport(method, url, headers, b):
        calls.append((method, url, dict(headers), b))
        return status, body

    return EgressGuardedClient(OAUTH_ALLOW_HOSTS, transport=transport), calls


def _make_opener(code="auth-code-xyz", state_override=None, extra=None):
    """A fake browser: on open(auth_url), GET the redirect URI like Google."""
    cap = {}

    def opener(auth_url):
        q = parse_qs(urlsplit(auth_url).query)
        redirect_uri = q["redirect_uri"][0]
        state = state_override if state_override is not None else q["state"][0]
        cap["auth_url"] = auth_url
        cap["redirect_uri"] = redirect_uri
        params = {"state": state}
        if code is not None:
            params["code"] = code
        if extra:
            params.update(extra)
        url = redirect_uri + "?" + urlencode(params)
        urllib.request.urlopen(url, timeout=5).read()

    return opener, cap


def _flow(client, opener, **kw):
    return LoopbackOAuthFlow(
        client_id="cid.apps.googleusercontent.com", egress_client=client,
        browser_opener=opener, timeout=5, **kw)


# --- happy path -----------------------------------------------------------

def test_happy_flow_returns_tokens():
    client, calls = _egress()
    opener, cap = _make_opener(code="auth-code-xyz")
    result = _flow(client, opener).run()

    assert result.access_token == "ya29.tok"
    assert result.refresh_token == "1//refresh"
    assert result.expires_in == 3599
    assert result.scope.endswith("gmail.send")
    assert result.token_type == "Bearer"
    assert isinstance(result.received_at, int)

    q = parse_qs(urlsplit(cap["auth_url"]).query)
    assert q["scope"][0] == "https://www.googleapis.com/auth/gmail.send"
    assert q["code_challenge_method"][0] == "S256"
    assert q["access_type"][0] == "offline" and q["prompt"][0] == "consent"
    assert q["redirect_uri"][0].startswith("http://127.0.0.1:")

    method, url, _, body = calls[0]
    assert method == "POST" and url == "https://oauth2.googleapis.com/token"
    form = parse_qs(body.decode("utf-8"))
    assert form["grant_type"][0] == "authorization_code"
    assert form["code"][0] == "auth-code-xyz"
    assert form["redirect_uri"][0] == cap["redirect_uri"]
    # end-to-end PKCE binding: verifier sent at exchange hashes to the shown challenge
    assert code_challenge(form["code_verifier"][0]) == q["code_challenge"][0]


def test_on_redirect_uri_observer_fires_with_bound_uri_before_browser():
    # The CLI prints this so a human can verify the loopback redirect against the
    # consent page; it must carry the real ephemeral port and fire before the
    # browser opens (i.e. before the operator is looking at the consent screen).
    client, _ = _egress()
    events = []
    base_opener, cap = _make_opener()

    def opener(auth_url):
        events.append("browser")
        base_opener(auth_url)

    _flow(client, opener,
          on_redirect_uri=lambda uri: events.append(("redirect", uri))).run()

    redirects = [e for e in events if isinstance(e, tuple)]
    assert len(redirects) == 1                      # fired exactly once
    (_, uri), = redirects
    assert uri == cap["redirect_uri"]               # the very uri the browser used
    assert uri.startswith("http://127.0.0.1:") and uri.endswith("/oauth2/callback")
    assert events.index(("redirect", uri)) < events.index("browser")  # before browser


def test_client_secret_included_only_when_given():
    client, calls = _egress()
    opener, _ = _make_opener()
    _flow(client, opener, client_secret="shh").run()
    form = parse_qs(calls[0][3].decode("utf-8"))
    assert form["client_secret"][0] == "shh"


def test_token_received_at_is_captured_at_exchange_response():
    client, _ = _egress()
    opener, _ = _make_opener()
    result = _flow(client, opener, now=lambda: 123456).run()
    assert result.received_at == 123456


# --- callback validation --------------------------------------------------

def test_state_mismatch_rejected_before_exchange():
    client, calls = _egress()
    opener, _ = _make_opener(state_override="tampered-state")
    with pytest.raises(StateMismatchError):
        _flow(client, opener).run()
    assert calls == []  # never reached the token endpoint


def test_provider_error_in_callback():
    client, _ = _egress()
    opener, _ = _make_opener(code=None, extra={"error": "access_denied"})
    with pytest.raises(AuthorizationError):
        _flow(client, opener).run()


def test_missing_code_in_callback():
    client, _ = _egress()
    opener, _ = _make_opener(code=None)
    with pytest.raises(MissingCodeError):
        _flow(client, opener).run()


# --- exchange failures (sanitized) ----------------------------------------

def test_exchange_failure_surfaces_error_code_not_body():
    client, _ = _egress(
        status=400,
        body=b'{"error":"invalid_grant","error_description":"bad code for user@x"}')
    opener, _ = _make_opener()
    with pytest.raises(OAuthExchangeError) as ei:
        _flow(client, opener).run()
    msg = str(ei.value)
    assert "invalid_grant" in msg          # short provider code is safe to show
    assert "error_description" not in msg   # body/description is dropped
    assert "user@x" not in msg


def test_exchange_missing_access_token():
    client, _ = _egress(status=200, body=b'{"scope":"x"}')
    opener, _ = _make_opener()
    with pytest.raises(OAuthExchangeError):
        _flow(client, opener).run()


def test_timeout_when_no_callback():
    client, _ = _egress()
    flow = LoopbackOAuthFlow(
        client_id="c", egress_client=client,
        browser_opener=lambda url: None, timeout=0.3)  # never hits callback
    with pytest.raises(OAuthTimeoutError):
        flow.run()


# --- sanitization + surface -----------------------------------------------

def test_token_result_repr_redacts_tokens():
    r = TokenResult(access_token="ya29.SECRET", refresh_token="1//SECRETREF",
                    expires_in=10, scope="s", token_type="Bearer")
    s = repr(r)
    assert "ya29.SECRET" not in s and "1//SECRETREF" not in s
    assert "<redacted>" in s


def test_only_callback_path_is_served():
    from gateway.oauth_listener import _LoopbackServer
    server = _LoopbackServer("127.0.0.1", "/oauth2/callback")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % server.port
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(base + "/nope", timeout=5)
        assert ei.value.code == 404
        urllib.request.urlopen(base + "/oauth2/callback?code=c&state=s", timeout=5).read()
        assert server.captured == {"code": "c", "state": "s"}
    finally:
        server.shutdown()
        server.server_close()


# --- hardening: take-first / loopback-only / oauth-scoped egress ----------

def test_callback_captures_first_value_per_key():
    from gateway.oauth_listener import _LoopbackServer
    server = _LoopbackServer("127.0.0.1", "/oauth2/callback")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = "http://127.0.0.1:%d" % server.port
        # a forged second code=/state= must not override the first pair
        urllib.request.urlopen(
            base + "/oauth2/callback?code=first&state=s1&code=evil&state=s2",
            timeout=5).read()
        assert server.captured == {"code": "first", "state": "s1"}
    finally:
        server.shutdown()
        server.server_close()


def test_loopback_server_refuses_non_loopback_host():
    from gateway.oauth_listener import _LoopbackServer
    with pytest.raises(ValueError):
        _LoopbackServer("0.0.0.0", "/oauth2/callback")


def test_flow_rejects_egress_not_scoped_to_oauth_host():
    bad = EgressGuardedClient(
        {"gmail.googleapis.com"}, transport=lambda *a, **k: (200, b"{}"))
    with pytest.raises(ValueError):
        LoopbackOAuthFlow(client_id="c", egress_client=bad)


def test_flow_rejects_non_loopback_host():
    client, _ = _egress()
    with pytest.raises(ValueError):
        LoopbackOAuthFlow(client_id="c", egress_client=client, host="0.0.0.0")
