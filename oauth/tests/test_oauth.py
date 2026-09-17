"""OAuth (loopback + PKCE) tests.

Actuated variables:
  - PKCE (RFC 7636): a verifier is 43-128 unreserved chars; the S256 challenge
    is the deterministic base64url(sha256(verifier)); we pin the RFC Appendix-B
    known-answer vector and property-test derivation over random verifiers.
  - gate 1: the authorization scope is exactly the v1 allow-list; an extra or
    unknown scope is refused, not trimmed.
  - gate 2: only a loopback redirect is accepted; non-loopback host, non-http
    scheme, userinfo, or a missing port each fail closed.
  - CSRF: the callback's state must match the issued state (constant-time);
    state is checked before code/error so a forged callback is rejected first.
  - the token-exchange request is pure construction — verifier + loopback are
    re-validated, and no secret is emitted unless explicitly supplied.
"""

import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from oauth.authorize import (
    AuthorizationRequest,
    build_authorization_url,
)
from oauth.callback import extract_authorization_code
from oauth.errors import (
    AuthorizationError,
    LoopbackRequiredError,
    MissingCodeError,
    PKCEError,
    ScopeViolationError,
    StateMismatchError,
)
from oauth.pkce import (
    code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
    validate_code_verifier,
)
from oauth.redirect import validate_loopback_redirect
from oauth.state import generate_state, state_matches
from oauth.token_request import build_token_exchange_request

GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"
LOOPBACK = "http://127.0.0.1:8731"

# RFC 7636 charset, for generating well-formed verifiers in property tests.
_UNRESERVED = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~",
    min_size=43, max_size=128)


# --- PKCE ------------------------------------------------------------------

def test_pkce_rfc7636_appendix_b_known_answer():
    # The RFC's own worked example: pins our S256 derivation to the spec.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_generated_verifier_is_well_formed():
    v = generate_code_verifier()
    validate_code_verifier(v)  # does not raise
    assert 43 <= len(v) <= 128


def test_generate_pkce_pair_is_matched():
    pair = generate_pkce_pair()
    assert pair.challenge == code_challenge(pair.verifier)
    assert pair.method == "S256"
    assert pair.challenge != pair.verifier  # challenge is the digest, not the key


def test_generated_verifiers_are_unique():
    assert len({generate_code_verifier() for _ in range(200)}) == 200


@pytest.mark.parametrize("bad", [
    "short", "", "a" * 42, "a" * 129, "has spaces here " * 3,
    "contains+slash/and=pad" + "a" * 30,
])
def test_validate_code_verifier_rejects_malformed(bad):
    with pytest.raises(PKCEError):
        validate_code_verifier(bad)


@settings(max_examples=200)
@given(_UNRESERVED)
def test_code_challenge_is_deterministic_and_correct(verifier):
    ch1 = code_challenge(verifier)
    ch2 = code_challenge(verifier)
    assert ch1 == ch2  # deterministic
    # matches an independent recomputation of base64url(sha256(verifier))
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    assert ch1 == expected
    assert len(ch1) == 43  # 32-byte digest -> 43 base64url chars, no padding
    assert "=" not in ch1


# --- state (CSRF) ----------------------------------------------------------

def test_generate_state_is_nonempty_and_unique():
    states = {generate_state() for _ in range(200)}
    assert len(states) == 200
    assert all(states)


def test_state_matches_only_on_equality():
    s = generate_state()
    assert state_matches(s, s) is True
    assert state_matches(s, s + "x") is False


@pytest.mark.parametrize("expected,received", [
    ("", "abc"), ("abc", ""), ("", ""),
])
def test_state_never_matches_empty(expected, received):
    assert state_matches(expected, received) is False


# --- redirect (gate 2, fail-closed) ----------------------------------------

@pytest.mark.parametrize("uri", [
    "http://127.0.0.1:8080",
    "http://localhost:51999",
    "http://[::1]:9000",
])
def test_loopback_redirect_accepted(uri):
    validate_loopback_redirect(uri)  # does not raise


@pytest.mark.parametrize("uri", [
    "https://127.0.0.1:8080",          # loopback uses http, not https
    "http://evil.example.com:80",      # remote host
    "http://169.254.169.254:80",       # link-local metadata, not loopback
    "http://127.0.0.1",                # no explicit port
    "http://user:pass@127.0.0.1:80",   # userinfo present
    "https://accounts.google.com",     # hosted callback
    "ftp://127.0.0.1:21",              # wrong scheme
    "http://127.0.0.1.evil.com:80",    # host is not loopback
])
def test_non_loopback_redirect_rejected(uri):
    with pytest.raises(LoopbackRequiredError):
        validate_loopback_redirect(uri)


# --- authorization request (gate 1 scope + gate 2 redirect) ----------------

def _auth_request(scopes=frozenset({GMAIL_SEND}), redirect=LOOPBACK):
    return AuthorizationRequest(
        client_id="cid.apps.googleusercontent.com",
        redirect_uri=redirect,
        state="state-token",
        code_challenge="challenge-value",
        scopes=scopes,
    )


def test_authorization_request_accepts_v1_scope():
    req = _auth_request()  # does not raise
    assert req.scopes == frozenset({GMAIL_SEND})


def test_authorization_request_rejects_extra_scope():
    with pytest.raises(ScopeViolationError):
        _auth_request(scopes=frozenset({
            GMAIL_SEND, "https://www.googleapis.com/auth/gmail.readonly"}))


def test_authorization_request_rejects_unknown_scope():
    with pytest.raises(ScopeViolationError):
        _auth_request(scopes=frozenset({"https://mail.google.com/"}))


def test_authorization_request_rejects_empty_scope():
    with pytest.raises(ScopeViolationError):
        _auth_request(scopes=frozenset())


def test_authorization_request_rejects_non_loopback_redirect():
    with pytest.raises(LoopbackRequiredError):
        _auth_request(redirect="https://example.com/cb")


def test_build_authorization_url_carries_pkce_and_params():
    req = _auth_request()
    url = build_authorization_url(req)
    parts = urlsplit(url)
    q = parse_qs(parts.query)
    assert parts.scheme == "https" and parts.netloc == "accounts.google.com"
    assert q["response_type"] == ["code"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["code_challenge"] == ["challenge-value"]
    assert q["state"] == ["state-token"]
    assert q["scope"] == [GMAIL_SEND]
    assert q["redirect_uri"] == [LOOPBACK]
    assert q["access_type"] == ["offline"]  # ask for a refresh token


def test_build_authorization_url_honors_injected_endpoint():
    url = build_authorization_url(_auth_request(),
                                  auth_endpoint="https://auth.test/authorize")
    assert url.startswith("https://auth.test/authorize?")


# --- callback validation ---------------------------------------------------

def test_callback_returns_code_on_match():
    code = extract_authorization_code(
        {"state": "s1", "code": "auth-code-xyz"}, expected_state="s1")
    assert code == "auth-code-xyz"


def test_callback_rejects_state_mismatch():
    with pytest.raises(StateMismatchError):
        extract_authorization_code(
            {"state": "forged", "code": "auth-code-xyz"}, expected_state="s1")


def test_callback_state_checked_before_code_is_trusted():
    # A forged callback carrying a valid-looking code is still rejected.
    with pytest.raises(StateMismatchError):
        extract_authorization_code(
            {"state": "", "code": "attacker-code"}, expected_state="s1")


def test_callback_surfaces_provider_error():
    with pytest.raises(AuthorizationError) as exc:
        extract_authorization_code(
            {"state": "s1", "error": "access_denied"}, expected_state="s1")
    assert exc.value.provider_error == "access_denied"


def test_callback_missing_code_and_error():
    with pytest.raises(MissingCodeError):
        extract_authorization_code({"state": "s1"}, expected_state="s1")


# --- token exchange request (pure construction) ----------------------------

def _verifier():
    return generate_code_verifier()


def test_token_request_builds_authorization_code_grant():
    v = _verifier()
    req = build_token_exchange_request(
        code="auth-code", code_verifier=v,
        client_id="cid", redirect_uri=LOOPBACK)
    assert req.endpoint == "https://oauth2.googleapis.com/token"
    assert req.body["grant_type"] == "authorization_code"
    assert req.body["code"] == "auth-code"
    assert req.body["code_verifier"] == v
    assert req.body["redirect_uri"] == LOOPBACK
    assert "client_secret" not in req.body  # public client, none supplied


def test_token_request_includes_secret_only_when_given():
    req = build_token_exchange_request(
        code="c", code_verifier=_verifier(), client_id="cid",
        redirect_uri=LOOPBACK, client_secret="desktop-public-secret")
    assert req.body["client_secret"] == "desktop-public-secret"


def test_token_request_rejects_bad_verifier():
    with pytest.raises(PKCEError):
        build_token_exchange_request(
            code="c", code_verifier="tooshort", client_id="cid",
            redirect_uri=LOOPBACK)


def test_token_request_rejects_non_loopback_redirect():
    with pytest.raises(LoopbackRequiredError):
        build_token_exchange_request(
            code="c", code_verifier=_verifier(), client_id="cid",
            redirect_uri="https://example.com/cb")


def test_token_request_rejects_empty_code():
    with pytest.raises(ValueError):
        build_token_exchange_request(
            code="", code_verifier=_verifier(), client_id="cid",
            redirect_uri=LOOPBACK)


def test_token_request_honors_injected_endpoint():
    req = build_token_exchange_request(
        code="c", code_verifier=_verifier(), client_id="cid",
        redirect_uri=LOOPBACK, token_endpoint="https://token.test/t")
    assert req.endpoint == "https://token.test/t"


def test_refresh_request_builds_refresh_grant_without_secret():
    from oauth import build_refresh_token_request

    req = build_refresh_token_request(refresh_token="1//refresh", client_id="cid")
    assert req.endpoint == "https://oauth2.googleapis.com/token"
    assert req.body == {
        "grant_type": "refresh_token",
        "refresh_token": "1//refresh",
        "client_id": "cid",
    }


def test_refresh_request_includes_public_desktop_secret_when_given():
    from oauth import build_refresh_token_request

    req = build_refresh_token_request(
        refresh_token="1//refresh", client_id="cid",
        client_secret="desktop-public-secret")
    assert req.body["client_secret"] == "desktop-public-secret"


@pytest.mark.parametrize("refresh_token,client_id", [("", "cid"), ("r", "")])
def test_refresh_request_rejects_missing_required_input(refresh_token, client_id):
    from oauth import build_refresh_token_request

    with pytest.raises(ValueError):
        build_refresh_token_request(
            refresh_token=refresh_token, client_id=client_id)
