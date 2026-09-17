"""Token endpoint request construction (authorization-code and refresh grants).

Assembles the POST body for exchanging the authorization code for tokens. It
does NOT send the request and it does NOT store the result — the assembly
layer performs the HTTPS call and hands the returned tokens to the keystore.
Keeping this pure means the token-bearing network round-trip lives at the
boundary, and this module can be tested without a secret or a socket.

PKCE binding: the ``code_verifier`` is included here (and only here); the
redirect URI is re-validated as loopback so a tampered value cannot widen the
exchange. ``client_secret`` is optional — an installed/Desktop client's secret
is not a confidentiality boundary (PKCE is), and a pure public client omits it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .pkce import validate_code_verifier
from .redirect import validate_loopback_redirect

DEFAULT_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"


@dataclass(frozen=True)
class TokenExchangeRequest:
    """Where to POST and the form body to POST — nothing is sent here."""

    endpoint: str
    body: dict[str, str]


@dataclass(frozen=True)
class RefreshTokenRequest:
    """Where to POST a refresh grant — nothing is sent here."""

    endpoint: str
    body: dict[str, str]


def build_token_exchange_request(
    *,
    code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
    client_secret: str | None = None,
    token_endpoint: str = DEFAULT_TOKEN_ENDPOINT,
) -> TokenExchangeRequest:
    """Build the ``authorization_code`` exchange request.

    Re-validates the redirect (loopback) and the PKCE verifier before building
    the body, so an invalid input fails here rather than at the provider.
    """
    if not code:
        raise ValueError("authorization code is required")
    validate_code_verifier(code_verifier)
    validate_loopback_redirect(redirect_uri)
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if client_secret is not None:
        body["client_secret"] = client_secret
    return TokenExchangeRequest(endpoint=token_endpoint, body=body)


def build_refresh_token_request(
    *,
    refresh_token: str,
    client_id: str,
    client_secret: str | None = None,
    token_endpoint: str = DEFAULT_TOKEN_ENDPOINT,
) -> RefreshTokenRequest:
    """Build an OAuth 2.0 ``refresh_token`` grant request."""
    if not refresh_token:
        raise ValueError("refresh token is required")
    if not client_id:
        raise ValueError("client id is required")
    body = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
    }
    if client_secret is not None:
        body["client_secret"] = client_secret
    return RefreshTokenRequest(endpoint=token_endpoint, body=body)
