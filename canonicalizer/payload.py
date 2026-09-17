"""PrepareEmail -> canonical payload normalization, digest, and the v1
send-time attachment policy gate.

DIGEST DOMAIN (DESIGN.md v0.1 sec 5.1 / 8.5):
    account_handle, to, cc, bcc, subject, body{format, content},
    attachments[]. ``idempotency_key`` is a dedup key, NOT part of the
    approved-content digest (sec 6), so it is accepted on input but
    excluded from the canonical payload.

CLOSED SCHEMA (supports sec 3 release gate 4 -- parameter-level closed
action set, no raw MIME / arbitrary header / URL / pass-through):
    build_canonical_payload rejects any field outside the fixed schema
    rather than silently dropping it, so an injected field fails closed
    instead of riding along invisibly.

V1 SEND POLICY:
    v1 sends only a text body with an empty attachment slot. The digest
    domain still models a populated attachment slot (golden vector B) for
    forward compatibility, but enforce_v1_send_policy rejects a non-empty
    slot before any proposal is created or Gmail is called.
"""

from __future__ import annotations

from .jcs import digest as _jcs_digest

_TOP_LEVEL_KEYS = frozenset(
    {"account_handle", "to", "cc", "bcc", "subject", "body", "attachments"}
)
# idempotency_key is accepted on input but excluded from the digest.
#
# message_id is deliberately NOT in the input allow-list: it is a Gateway-minted
# value injected via the `message_id=` keyword (§2.7), never something the Agent
# may supply. An Agent-supplied `message_id` field therefore fails closed through
# reject-unknown, exactly like any other out-of-schema field. It still enters the
# canonical (and thus the digest) when the Gateway injects it -- so the approved,
# authorized bytes bind the exact ID that is sent, and changing that frozen ID
# invalidates the authorization (Jeff 205545/205645).
_TOP_LEVEL_ALLOWED = _TOP_LEVEL_KEYS | {"idempotency_key"}
_BODY_KEYS = frozenset({"format", "content"})
_ATTACHMENT_KEYS = frozenset(
    {"name", "media_type", "content_ref", "sha256", "size"}
)


class PayloadSchemaError(ValueError):
    """Input is outside the closed PrepareEmail schema."""


class AttachmentsNotSupportedError(Exception):
    """v1 refuses a non-empty attachment slot before proposal / Gmail."""

    code = "attachments_not_supported_in_v1"

    def __init__(self, message: str = "attachments_not_supported_in_v1"):
        super().__init__(message)


def _reject_unknown(name: str, keys, allowed) -> None:
    unknown = set(keys) - set(allowed)
    if unknown:
        raise PayloadSchemaError(
            "%s has unsupported field(s) %s; the action set is closed"
            % (name, sorted(unknown))
        )


def _require(name: str, mapping, key):
    if key not in mapping:
        raise PayloadSchemaError("%s is missing required field %r" % (name, key))
    return mapping[key]


def _str_list(name: str, value) -> list:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PayloadSchemaError("%s must be a list of strings" % name)
    return list(value)


def _normalize_attachment(index: int, a) -> dict:
    where = "attachments[%d]" % index
    if not isinstance(a, dict):
        raise PayloadSchemaError("%s must be an object" % where)
    _reject_unknown(where, a.keys(), _ATTACHMENT_KEYS)
    for k in ("name", "media_type", "content_ref", "sha256"):
        v = _require(where, a, k)
        if not isinstance(v, str):
            raise PayloadSchemaError("%s.%s must be a string" % (where, k))
    size = _require(where, a, "size")
    # bool is a subtype of int; reject it explicitly so True/False cannot
    # masquerade as a size.
    if isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise PayloadSchemaError("%s.size must be a non-negative integer" % where)
    return {
        "content_ref": a["content_ref"],
        "media_type": a["media_type"],
        "name": a["name"],
        "sha256": a["sha256"],
        "size": size,
    }


def build_canonical_payload(prepare, *, message_id: str | None = None) -> dict:
    """Normalize a PrepareEmail-shaped input into the canonical payload
    whose JCS digest the user approves.

    - cc / bcc / attachments omitted or empty normalize to [].
    - body normalizes to exactly {format, content}.
    - idempotency_key (if present) is excluded from the digest domain.
    - Any field outside the closed schema is rejected (fail closed).
    - message_id (§2.7): a Gateway-minted RFC 5322 Message-ID, injected via this
      keyword (never read from `prepare`, so an Agent cannot supply or override
      it). When given it becomes part of the canonical -- and hence of the digest
      the user approves and the cloud authorizes -- so the sent header binds to
      the authorized bytes. Optional so callers that do not send (schema/gate
      tests, the frozen golden vectors) are unchanged.
    """
    if not isinstance(prepare, dict):
        raise PayloadSchemaError("prepare must be an object")
    _reject_unknown("prepare", prepare.keys(), _TOP_LEVEL_ALLOWED)
    if message_id is not None and (
        not isinstance(message_id, str) or not message_id
    ):
        # Gateway-minted, so this is a wiring bug, not Agent input -- but validate
        # rather than freeze a malformed ID into the authorized bytes.
        raise PayloadSchemaError("message_id must be a non-empty string")

    account_handle = _require("prepare", prepare, "account_handle")
    if not isinstance(account_handle, str):
        raise PayloadSchemaError("account_handle must be a string")

    subject = _require("prepare", prepare, "subject")
    if not isinstance(subject, str):
        raise PayloadSchemaError("subject must be a string")

    body = _require("prepare", prepare, "body")
    if not isinstance(body, dict):
        raise PayloadSchemaError("body must be an object")
    _reject_unknown("body", body.keys(), _BODY_KEYS)
    body_format = _require("body", body, "format")
    body_content = _require("body", body, "content")
    if not isinstance(body_format, str) or not isinstance(body_content, str):
        raise PayloadSchemaError("body.format and body.content must be strings")

    to = _str_list("to", _require("prepare", prepare, "to"))
    cc = _str_list("cc", prepare["cc"]) if prepare.get("cc") else []
    bcc = _str_list("bcc", prepare["bcc"]) if prepare.get("bcc") else []

    attachments_in = prepare.get("attachments") or []
    if not isinstance(attachments_in, list):
        raise PayloadSchemaError("attachments must be a list")
    attachments = [
        _normalize_attachment(i, a) for i, a in enumerate(attachments_in)
    ]

    canonical = {
        "account_handle": account_handle,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "subject": subject,
        "body": {"format": body_format, "content": body_content},
        "attachments": attachments,
    }
    if message_id is not None:
        canonical["message_id"] = message_id
    return canonical


def payload_digest(prepare, *, message_id: str | None = None) -> str:
    """Lowercase-hex SHA-256 of the JCS bytes of the canonical payload."""
    return _jcs_digest(build_canonical_payload(prepare, message_id=message_id))


def enforce_v1_send_policy(canonical) -> None:
    """Fail closed before proposal / Gmail if the payload is outside v1.

    v1 sends only a text body with no attachments. Raises rather than
    silently degrading (no dropping the attachment and sending the rest).
    """
    if canonical["attachments"]:
        raise AttachmentsNotSupportedError()
    if canonical["body"]["format"] != "text":
        raise PayloadSchemaError("v1 supports only text bodies")
