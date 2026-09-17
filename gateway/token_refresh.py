"""Gateway-internal OAuth access-token refresh.

Refresh happens before the send FSM makes its single Gmail call. It never
rebuilds a proposal, never changes human approval, and never retries a Gmail
send. Token endpoint traffic uses its own strict egress allow-list.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from urllib.error import URLError
from urllib.parse import urlencode

from oauth import V1_ALLOWED_SCOPES, build_refresh_token_request
from oauth.errors import OAuthError

from .egress import EgressBlockedError, EgressGuardedClient
from .oauth_listener import OAUTH_ALLOW_HOSTS, TokenResult
from .send_path import SealedTokenStore


class ReauthorizationRequiredError(OAuthError):
    """The sealed credential cannot be refreshed without user authorization."""


class TokenRefreshError(OAuthError):
    """The provider refused refresh or returned an unusable response."""


class RefreshingTokenProvider:
    """Return a fresh bearer, refreshing once under a per-connection lock."""

    def __init__(
        self,
        store: SealedTokenStore,
        client: EgressGuardedClient,
        *,
        now: Callable[[], int],
        refresh_skew_seconds: int = 60,
    ):
        if client.allow_hosts != OAUTH_ALLOW_HOSTS:
            raise ValueError("refresh requires OAuth-only egress allow-list")
        if refresh_skew_seconds < 0:
            raise ValueError("refresh skew must be non-negative")
        self._store = store
        self._client = client
        self._now = now
        self._skew = refresh_skew_seconds
        self._lock = threading.Lock()

    def access_token(self) -> str:
        with self._lock:
            record = self._store.token_record()
            expires_at = record.get("expires_at")
            if (isinstance(expires_at, int) and not isinstance(expires_at, bool)
                    and self._now() < expires_at - self._skew):
                return record["access_token"]
            return self._refresh(record)

    def _refresh(self, record: dict) -> str:
        refresh_token = record.get("refresh_token")
        client_id = record.get("client_id")
        client_secret = record.get("client_secret")
        if not isinstance(refresh_token, str) or not isinstance(client_id, str):
            # Pre-refresh-schema records intentionally fail closed. One new
            # authorize stores all refresh inputs inside the sealed record.
            raise ReauthorizationRequiredError("authorization must be renewed")
        if client_secret is not None and not isinstance(client_secret, str):
            raise ReauthorizationRequiredError("authorization must be renewed")

        request = build_refresh_token_request(
            refresh_token=refresh_token,
            client_id=client_id,
            client_secret=client_secret,
        )
        try:
            response = self._client.post(
                request.endpoint,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=urlencode(request.body).encode("utf-8"),
            )
        except (EgressBlockedError, TimeoutError, URLError, OSError):
            raise TokenRefreshError("token refresh transport failed")
        if not 200 <= response.status < 300:
            if response.status == 400:
                raise ReauthorizationRequiredError("authorization is no longer valid")
            raise TokenRefreshError("token refresh failed")
        try:
            result = TokenResult.from_response(response.body)
        except OAuthError:
            raise TokenRefreshError("token refresh response was unusable")

        if result.scope is not None:
            granted = frozenset(result.scope.split())
            if granted != V1_ALLOWED_SCOPES:
                raise TokenRefreshError("refreshed scope did not match gmail.send")

        refreshed_at = self._now()
        expires_at = (
            refreshed_at + result.expires_in
            if result.expires_in is not None else None
        )
        self._store.replace_access_token(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            issued_at=refreshed_at,
            expires_at=expires_at,
            scope=result.scope,
        )
        return result.access_token
