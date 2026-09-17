"""Authorization-request construction (DESIGN sec 3, gates 1 & 2).

Builds the URL the user opens in their browser to grant access. This is pure
string assembly + validation — no browser is launched here (that is the
assembly layer). Two invariants are enforced at construction time so a bad
request can never reach the provider:

  - gate 1: the requested scope is exactly the v1 allow-list
    (``gmail.send`` only). Extra or unknown scopes are refused, not trimmed.
  - gate 2: the redirect URI is loopback (delegated to ``redirect``).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlencode

from .errors import ScopeViolationError
from .pkce import CODE_CHALLENGE_METHOD
from .redirect import validate_loopback_redirect

# gate 1 — v1 sends mail and nothing else. Allow-list, so any scope not named
# here (read, modify, full-mailbox) is rejected rather than silently allowed.
V1_ALLOWED_SCOPES = frozenset({"https://www.googleapis.com/auth/gmail.send"})

DEFAULT_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"


def _validate_scopes(scopes: frozenset[str]) -> None:
    extra = scopes - V1_ALLOWED_SCOPES
    if extra:
        raise ScopeViolationError(
            "scopes outside the v1 allow-list: %s" % sorted(extra))
    if not scopes:
        raise ScopeViolationError("at least one scope is required")


@dataclass(frozen=True)
class AuthorizationRequest:
    """The fully-validated inputs to an authorization URL."""

    client_id: str
    redirect_uri: str
    state: str
    code_challenge: str
    scopes: frozenset[str]

    def __post_init__(self) -> None:
        validate_loopback_redirect(self.redirect_uri)
        _validate_scopes(self.scopes)


def build_authorization_url(
    request: AuthorizationRequest,
    *,
    auth_endpoint: str = DEFAULT_AUTH_ENDPOINT,
) -> str:
    """Assemble the browser authorization URL for *request*.

    ``access_type=offline`` + ``prompt=consent`` so the exchange yields a
    refresh token (the Gateway must send without re-prompting each time),
    ``code_challenge_method=S256`` for PKCE, and a scope string that is
    already allow-list-validated by ``AuthorizationRequest``.
    """
    params = {
        "client_id": request.client_id,
        "redirect_uri": request.redirect_uri,
        "response_type": "code",
        "scope": " ".join(sorted(request.scopes)),
        "state": request.state,
        "code_challenge": request.code_challenge,
        "code_challenge_method": CODE_CHALLENGE_METHOD,
        "access_type": "offline",
        "prompt": "consent",
    }
    return "%s?%s" % (auth_endpoint, urlencode(params))
