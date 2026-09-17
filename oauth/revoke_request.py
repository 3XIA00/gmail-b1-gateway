"""OAuth 2.0 token revocation request construction (RFC 7009).

Assembles the POST body for revoking a token at the provider's revocation
endpoint. Like the other builders here it does NOT send the request and does
NOT touch storage -- the assembly layer performs the HTTPS call, so this module
can be tested without a socket.

RFC 7009 §2.1: the request carries only the ``token``; a public client
authenticates with nothing, so **no client secret and no client_id** are sent.
That is exactly what lets Disconnect's remote-revoke leg run under the B1
cloud-only-secret model and during a cloud outage. ``token_type_hint`` is
deliberately omitted: it is optional, and an omitted/mismatched hint only makes
the server try both token tables (RFC 7009 §2.1), so the minimal body is the
safe one.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"


@dataclass(frozen=True)
class RevokeTokenRequest:
    """Where to POST a revocation and the form body -- nothing is sent here."""

    endpoint: str
    body: dict[str, str]


def build_revoke_token_request(
    *,
    token: str,
    revoke_endpoint: str = DEFAULT_REVOKE_ENDPOINT,
) -> RevokeTokenRequest:
    """Build an RFC 7009 token-revocation request (token only, no client auth)."""
    if not token:
        raise ValueError("token is required")
    return RevokeTokenRequest(endpoint=revoke_endpoint, body={"token": token})
