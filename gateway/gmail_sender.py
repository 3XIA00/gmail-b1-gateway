"""Gmail send `sender` for the send FSM (ASSEMBLY_PLAN step ii).

Turns an *approved canonical payload* into a Gmail `users.messages.send` call
behind the egress allow-list, and maps the outcome to the `sendfsm.SendResult`
the FSM already routes. The FSM owns the state transitions; this object is the
concrete `Callable[[proposal_id], SendResult]` it was designed to receive.

**Failure classification (Chris M1 / 测试姬).** Every failure code emitted here
is derived from the HTTP **status** or the exception **type** only -- never a
response body, exception message, or traceback, any of which could carry a
recipient address / PII / token and would violate §8 sanitization. Transport
errors are caught and *returned* as INDETERMINATE (the FSM's bare-except
backstop is reserved for a genuine wiring bug that *raises*), giving the audit
seat a "timeout vs. transport vs. wiring" discriminant with no PII leak.

**Content fidelity (gate 7b) scope.** This object sends exactly the canonical
payload handed to it, and `build_raw_message` is a pure function of that payload
(no Date / boundary; the Message-ID is not minted here but read verbatim from the
canonical), so the bytes sent are deterministic. The Message-ID (§2.7) is minted
once upstream at propose time and frozen into the canonical, so it is inside the
digested/authorized bytes; the send layer only renders it, never regenerates it
(retry re-reads the same frozen canonical and re-emits identical bytes). Binding
that payload to the *confirmed* `payload_digest` lives where the payload store
and confirm do (steps iv/v); hence the payload is an injected `payload_provider`
seam rather than a reach into the store here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
from email.message import EmailMessage
from typing import Callable, Optional, Tuple
from urllib.error import URLError

from canonicalizer.payload import (
    AttachmentsNotSupportedError,
    PayloadSchemaError,
    enforce_v1_send_policy,
)
from oauth.errors import OAuthError
from sendfsm.fsm import SendResult, SendResultKind

from .egress import EgressBlockedError, EgressGuardedClient, HttpResponse

GMAIL_HOST = "gmail.googleapis.com"
GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build_raw_message(canonical: dict) -> bytes:
    """Render an approved v1 canonical payload into RFC 5322 bytes.

    Deterministic for a given payload, so the bytes sent are a pure function of
    the approved content -- support for "what was shown is what is sent". `From`
    is deliberately omitted: Gmail stamps the authenticated account, which is the
    source of truth for which mailbox actually sends.

    The Message-ID (§2.7) is emitted verbatim from ``canonical["message_id"]``
    when present -- it was minted once upstream and frozen into this canonical
    before the digest/authorize step, so rendering it here (rather than minting)
    keeps the sent header equal to the authorized, frozen ID. A canonical without
    the field (schema/gate tests, legacy paths) renders no Message-ID, unchanged.
    """
    msg = EmailMessage()
    msg["To"] = ", ".join(canonical["to"])
    if canonical["cc"]:
        msg["Cc"] = ", ".join(canonical["cc"])
    if canonical["bcc"]:
        msg["Bcc"] = ", ".join(canonical["bcc"])
    msg["Subject"] = canonical["subject"]
    if canonical.get("message_id"):
        msg["Message-ID"] = canonical["message_id"]
    msg.set_content(canonical["body"]["content"])
    return msg.as_bytes()


def _raw_b64(canonical: dict) -> str:
    return base64.urlsafe_b64encode(build_raw_message(canonical)).decode("ascii")


class GmailSender:
    """Concrete FSM `sender`: approved payload -> Gmail send -> SendResult."""

    def __init__(
        self,
        client: EgressGuardedClient,
        *,
        payload_provider: Callable[[str], dict],
        token_provider: Callable[[], str],
        url: str = GMAIL_SEND_URL,
    ):
        self._client = client
        self._payload_provider = payload_provider  # proposal_id -> canonical dict
        self._token_provider = token_provider      # () -> access token
        self._url = url

    def __call__(self, proposal_id: str) -> SendResult:
        canonical = self._payload_provider(proposal_id)

        # Last-line fail-closed: never send anything outside the v1 policy, even
        # if a bad payload somehow reached the store. Definitely-not-sent ->
        # REJECTED (the code is fixed, not the schema message, per sanitization).
        try:
            enforce_v1_send_policy(canonical)
        except (AttachmentsNotSupportedError, PayloadSchemaError):
            return SendResult(kind=SendResultKind.REJECTED, error_code="policy_blocked")

        body = json.dumps({"raw": _raw_b64(canonical)}).encode("utf-8")
        try:
            access_token = self._token_provider()
        except OAuthError:
            # Refresh/reauthorization failed before Gmail was contacted, so the
            # message is definitely not sent. Keep the error coarse and free of
            # provider bodies / credentials.
            return SendResult(
                kind=SendResultKind.REJECTED,
                error_code="authorization_required",
            )
        headers = {
            "Authorization": "Bearer %s" % access_token,
            "Content-Type": "application/json",
        }

        try:
            resp = self._client.post(self._url, headers=headers, body=body)
        except EgressBlockedError as e:
            # A blocked host is a positive zero-cloud-touch artifact -> record it.
            return SendResult(
                kind=SendResultKind.REJECTED, error_code="egress_blocked",
                egress_hosts=(e.host,) if e.host else ())
        except socket.timeout:
            return SendResult(
                kind=SendResultKind.INDETERMINATE, error_code="TIMEOUT",
                egress_hosts=(GMAIL_HOST,))
        except (URLError, OSError):
            return SendResult(
                kind=SendResultKind.INDETERMINATE, error_code="TRANSPORT",
                egress_hosts=(GMAIL_HOST,))

        return self._classify(resp)

    def _classify(self, resp: HttpResponse) -> SendResult:
        egress = (resp.host,)
        if 200 <= resp.status < 300:
            mid, tid = self._parse_ids(resp.body)
            return SendResult(
                kind=SendResultKind.ACCEPTED,
                message_id_sha256=_sha256_hex(mid) if mid else None,
                thread_id_sha256=_sha256_hex(tid) if tid else None,
                egress_hosts=egress)
        if 400 <= resp.status < 500:
            # Definitive client-side refusal: not sent, no retry. Code is the
            # STATUS only -- the response body may echo an address and is dropped.
            return SendResult(
                kind=SendResultKind.REJECTED,
                error_code="rejected_%d" % resp.status, egress_hosts=egress)
        # 5xx / 3xx / anything else: true outcome unknown -> OUTCOME_UNKNOWN, no retry.
        return SendResult(
            kind=SendResultKind.INDETERMINATE,
            error_code="server_%d" % resp.status, egress_hosts=egress)

    @staticmethod
    def _parse_ids(body: bytes) -> Tuple[Optional[str], Optional[str]]:
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None, None
        if not isinstance(data, dict):
            return None, None
        mid, tid = data.get("id"), data.get("threadId")
        return (mid if isinstance(mid, str) else None,
                tid if isinstance(tid, str) else None)
