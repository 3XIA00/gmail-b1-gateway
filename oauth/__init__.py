"""Loopback + PKCE authorization flow (boundary-independent core).

Pure logic for the OAuth authorization-code + PKCE flow: verifier/challenge
derivation, CSRF state, loopback-redirect validation, authorization-URL
assembly, callback validation, and token-exchange request construction. No
sockets, no browser, no token storage — those live in the assembly layer,
which wires a loopback listener + HTTPS client around this core.

Public API:
  - PKCE:        generate_pkce_pair, generate_code_verifier, code_challenge,
                 validate_code_verifier, PKCEPair, CODE_CHALLENGE_METHOD
  - state:       generate_state, state_matches
  - authorize:   AuthorizationRequest, build_authorization_url,
                 V1_ALLOWED_SCOPES, DEFAULT_AUTH_ENDPOINT
  - callback:    extract_authorization_code
  - exchange:    build_token_exchange_request, TokenExchangeRequest,
                 DEFAULT_TOKEN_ENDPOINT
  - revoke:      build_revoke_token_request, RevokeTokenRequest,
                 DEFAULT_REVOKE_ENDPOINT
  - redirect:    validate_loopback_redirect
  - errors:      OAuthError and its subclasses.
"""

from __future__ import annotations

from .authorize import (
    DEFAULT_AUTH_ENDPOINT,
    V1_ALLOWED_SCOPES,
    AuthorizationRequest,
    build_authorization_url,
)
from .callback import extract_authorization_code
from .errors import (
    AuthorizationError,
    LoopbackRequiredError,
    MissingCodeError,
    OAuthError,
    PKCEError,
    ScopeViolationError,
    StateMismatchError,
)
from .pkce import (
    CODE_CHALLENGE_METHOD,
    PKCEPair,
    code_challenge,
    generate_code_verifier,
    generate_pkce_pair,
    validate_code_verifier,
)
from .redirect import validate_loopback_redirect
from .state import generate_state, state_matches
from .revoke_request import (
    DEFAULT_REVOKE_ENDPOINT,
    RevokeTokenRequest,
    build_revoke_token_request,
)
from .token_request import (
    DEFAULT_TOKEN_ENDPOINT,
    RefreshTokenRequest,
    TokenExchangeRequest,
    build_refresh_token_request,
    build_token_exchange_request,
)

__all__ = [
    "generate_pkce_pair",
    "generate_code_verifier",
    "code_challenge",
    "validate_code_verifier",
    "PKCEPair",
    "CODE_CHALLENGE_METHOD",
    "generate_state",
    "state_matches",
    "AuthorizationRequest",
    "build_authorization_url",
    "V1_ALLOWED_SCOPES",
    "DEFAULT_AUTH_ENDPOINT",
    "extract_authorization_code",
    "build_token_exchange_request",
    "build_refresh_token_request",
    "build_revoke_token_request",
    "TokenExchangeRequest",
    "RefreshTokenRequest",
    "RevokeTokenRequest",
    "DEFAULT_TOKEN_ENDPOINT",
    "DEFAULT_REVOKE_ENDPOINT",
    "validate_loopback_redirect",
    "OAuthError",
    "LoopbackRequiredError",
    "ScopeViolationError",
    "PKCEError",
    "StateMismatchError",
    "MissingCodeError",
    "AuthorizationError",
]
