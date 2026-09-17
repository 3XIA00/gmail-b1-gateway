"""OAuth (loopback + PKCE) error types.

Every failure here is fail-closed: the caller gets an exception, never a
partially-validated grant that a later step might treat as trusted.
"""

from __future__ import annotations


class OAuthError(Exception):
    """Base for the loopback/PKCE authorization flow."""


class LoopbackRequiredError(OAuthError):
    """Redirect URI is not a loopback address (gate 2 — fail closed)."""

    code = "loopback_required"


class ScopeViolationError(OAuthError):
    """Requested scope is outside the v1 allow-list (gate 1)."""

    code = "scope_not_allowed"


class PKCEError(ValueError):
    """A code_verifier that is malformed per RFC 7636."""

    code = "pkce_invalid"


class StateMismatchError(OAuthError):
    """Callback state did not match the value we issued (CSRF guard)."""

    code = "state_mismatch"


class MissingCodeError(OAuthError):
    """Callback carried neither an authorization code nor an error."""

    code = "authorization_code_missing"


class AuthorizationError(OAuthError):
    """The provider returned an explicit ``error=`` on the callback."""

    code = "authorization_denied"

    def __init__(self, provider_error: str) -> None:
        super().__init__("authorization failed: %s" % provider_error)
        self.provider_error = provider_error
