"""Local-direct OAuth 2.0 token revocation (RFC 7009) -- Disconnect's remote leg.

Posts ONLY the token to the provider's revocation endpoint. RFC 7009 requires
no client authentication, so this leg carries no client secret and works during
a cloud outage (B1: the secret is cloud-only; revoke is local-direct). It rides
the same OAuth-only egress allow-list as exchange/refresh.

Scope of this object is deliberately narrow:
  - It builds + sends the revoke call and classifies the outcome into three
    states (CONFIRMED / FAILED / UNKNOWN), returning that discriminant. It never
    raises for a network or status outcome, because the caller (Disconnect) must
    present the local-clear fact and the remote-revoke result as TWO separate
    facts and never merge them into one boolean -- merging is exactly how "only
    did half but signalled handoff-safe" happens.
  - It does NOT read, own, or clear the credential. The caller reads the token
    value into memory first, so "revoke then clear" is not an ordering red-line;
    the value is already in hand and the store can be cleared in either order.
  - A timeout is NOT proof the server did not process the revocation (the
    response may be lost), so it maps to UNKNOWN -- never to failed and never to
    confirmed.

The three outcome names/values match the daemon's ``ops.RevokeOutcome``
verbatim, and this library never imports the daemon: it stays self-contained
and separately testable. The daemon injects ``make_disconnect_revoker`` as its
remote-revoke leg, translating this enum onto its own by NAME (see the adapter)
-- at merge time that translation collapses to a single import, not a value
remap, because the names already coincide.
"""

from __future__ import annotations

import asyncio
import enum
from dataclasses import dataclass
from urllib.error import URLError
from urllib.parse import urlencode

from oauth import DEFAULT_REVOKE_ENDPOINT, build_revoke_token_request

from .egress import EgressBlockedError, EgressGuardedClient, HttpResponse
from .oauth_listener import OAUTH_ALLOW_HOSTS

REVOKE_HOST = "oauth2.googleapis.com"


class RevokeOutcome(enum.Enum):
    CONFIRMED = "confirmed"    # provider acknowledged (2xx)
    FAILED = "failed"          # provider answered, and refused (definitive 4xx)
    UNKNOWN = "unknown"        # timeout/transport/5xx: genuinely unknown


@dataclass(frozen=True)
class RevokeResult:
    outcome: RevokeOutcome
    # A coarse, sanitized code -- the HTTP status or a fixed category, NEVER a
    # response body or exception message, either of which could echo the token
    # (§8 sanitization / M1). Present for diagnostics only.
    reason: str | None = None
    egress_hosts: tuple[str, ...] = ()


class TokenRevoker:
    """Revoke a token at the provider. Instances are the callable Disconnect
    injects for its remote-revoke leg (``revoker.revoke(token)``)."""

    def __init__(
        self,
        client: EgressGuardedClient,
        *,
        revoke_endpoint: str = DEFAULT_REVOKE_ENDPOINT,
    ):
        # Same invariant as refresh: revoke must ride the OAuth-only allow-list,
        # never the send-path (gmail.googleapis.com) list.
        if client.allow_hosts != OAUTH_ALLOW_HOSTS:
            raise ValueError("revoke requires OAuth-only egress allow-list")
        self._client = client
        self._endpoint = revoke_endpoint

    def revoke(self, token: str) -> RevokeResult:
        request = build_revoke_token_request(
            token=token, revoke_endpoint=self._endpoint)
        try:
            response = self._client.post(
                request.endpoint,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=urlencode(request.body).encode("utf-8"),
            )
        except EgressBlockedError as e:
            # The call never left the machine: definitely not confirmed at the
            # provider, but the provider never saw it -> not a rejection either.
            return RevokeResult(
                RevokeOutcome.UNKNOWN, reason="egress_blocked",
                egress_hosts=(e.host,) if e.host else ())
        except TimeoutError:
            return RevokeResult(
                RevokeOutcome.UNKNOWN, reason="timeout",
                egress_hosts=(REVOKE_HOST,))
        except (URLError, OSError):
            return RevokeResult(
                RevokeOutcome.UNKNOWN, reason="transport",
                egress_hosts=(REVOKE_HOST,))
        return self._classify(response)

    def _classify(self, response: HttpResponse) -> RevokeResult:
        egress = (response.host,)
        if 200 <= response.status < 300:
            # RFC 7009 §2.2: 200 also covers an already-invalid token.
            return RevokeResult(RevokeOutcome.CONFIRMED, egress_hosts=egress)
        if 400 <= response.status < 500:
            # Definitive refusal. Code is the STATUS only; the body may echo the
            # token and is dropped entirely (sanitization / M1).
            return RevokeResult(
                RevokeOutcome.FAILED,
                reason="rejected_%d" % response.status, egress_hosts=egress)
        # 5xx / 3xx (unfollowed redirect): outcome genuinely unknown -> the
        # caller may retry; it is NOT a refusal and NOT a success.
        return RevokeResult(
            RevokeOutcome.UNKNOWN,
            reason="server_%d" % response.status, egress_hosts=egress)


def make_disconnect_revoker(revoker, *, outcome_enum=RevokeOutcome):
    """Adapt a (sync) :class:`TokenRevoker` into Disconnect's injected leg.

    Disconnect (``ops.disconnect_gmail``) expects an async callable
    ``(credentials: dict) -> tuple[RevokeOutcome, str]``. This wraps the
    synchronous revoker for that seam:

    - It runs the blocking revoke in a worker thread so it never stalls the
      daemon's event loop.
    - It revokes the ``refresh_token`` when present -- revoking the refresh
      token invalidates the whole grant, whereas revoking only the access token
      leaves the refresh token live. It falls back to ``access_token`` if that
      is all the record carries.
    - It returns the *daemon's* ``RevokeOutcome`` (passed in as ``outcome_enum``,
      defaulting to this module's own for standalone tests) selected by NAME.
      The names coincide (CONFIRMED/FAILED/UNKNOWN), so this is a rename, not a
      value remap: ``disconnect_gmail`` does ``outcome is RevokeOutcome.CONFIRMED``
      against its own enum, so the member it receives must be *its* member.
    - The evidence string is the revoker's sanitized reason (never a body or
      token), or "" when there is nothing to add.
    """

    async def _revoke(credentials: dict) -> tuple:
        token = credentials.get("refresh_token") or credentials.get("access_token")
        if not token:
            # No token to revoke: cannot confirm anything happened at Google.
            # UNKNOWN, never CONFIRMED -- a missing token is not a revocation.
            return outcome_enum["UNKNOWN"], "no_token_in_record"
        result = await asyncio.to_thread(revoker.revoke, token)
        return outcome_enum[result.outcome.name], result.reason or ""

    return _revoke
