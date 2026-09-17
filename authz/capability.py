"""Signed artifact envelope + grant.body model + fail-closed parser (L5 §1/§2).

Artifact envelope (§1):

    {"v":1, "type":"grant|revocation|authz_state|approval", "body":{...}, "sig":"..."}

    sig = Ed25519(user_root_sk, domain_tag(type) || JCS(body))
    domain_tag = b"puffo-authz/" + type + b"/v1\\0"

Domain separation means a grant signature can never be replayed as, say, a
revocation signature. The signature covers the body's JCS bytes exactly as
received; unknown fields are refused, so there is nothing unsigned to smuggle.

grant.body fail-closed parsing (§2, property-not-enumeration):
  * ``tool``/``action`` are a closed enum ("gmail"/"send"); anything else fails.
  * ``scope`` is a closed schema (only ``from_account``); unknown keys fail.
  * ``approval_mode`` is REQUIRED. ABSENT -> CertificateError with detail
    ``missing_approval_mode`` (schema violation, never auto, never silently
    per_call). Present-but-unknown -> CertificateError.
  * unknown ``subject.kind`` fails.
These express the boundary, so a novel bad value fails closed.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Tuple

from canonicalizer.jcs import canonicalize

from .errors import DETAIL_MISSING_APPROVAL_MODE, CertificateError

_DOMAIN_PREFIX = b"puffo-authz/"


def domain_tag(artifact_type: str) -> bytes:
    return _DOMAIN_PREFIX + artifact_type.encode("utf-8") + b"/v1\x00"


def signing_input(artifact_type: str, body: dict) -> bytes:
    """The exact bytes signed for an artifact of ``artifact_type``."""
    return domain_tag(artifact_type) + canonicalize(body)


class SubjectKind(enum.Enum):
    OS_ACCOUNT = "os_account"  # "all my agents": kernel-verified OS peer credential
    AGENT_KEY = "agent_key"    # a specific agent: per-request agent signature


class ApprovalMode(enum.Enum):
    AUTO = "auto"
    PER_CALL = "per_call"


@dataclass(frozen=True)
class Subject:
    kind: SubjectKind
    # os_account:
    machine_id: Optional[str] = None
    account: Optional[str] = None
    # agent_key:
    agent_pubkey_hex: Optional[str] = None
    agent_slug: Optional[str] = None


@dataclass(frozen=True)
class Grant:
    grant_id: str
    grant_version: str          # canonical decimal string
    grant_version_int: int
    issuer_fp: str
    subject: Subject
    tool: str
    action: str
    scope: dict
    approval_mode: ApprovalMode
    valid_from: int             # epoch seconds
    valid_until: int            # epoch seconds
    state_version: str          # canonical decimal string

    @property
    def permits_auto(self) -> bool:
        return self.approval_mode is ApprovalMode.AUTO


# --- envelope --------------------------------------------------------------

def parse_envelope(env: dict) -> Tuple[str, dict, bytes]:
    """(type, body, sig_bytes) from a signed artifact envelope; fail closed."""
    if not isinstance(env, dict):
        raise CertificateError("artifact envelope must be an object")
    unknown = set(env) - {"v", "type", "body", "sig"}
    if unknown:  # closed envelope: nothing unsigned may ride alongside {v,type,body,sig}
        raise CertificateError("unknown envelope keys: %s" % sorted(unknown))
    if env.get("v") != 1:
        raise CertificateError("unsupported artifact version")
    artifact_type = env.get("type")
    if not isinstance(artifact_type, str) or not artifact_type:
        raise CertificateError("artifact type must be a non-empty string")
    body = env.get("body")
    if not isinstance(body, dict):
        raise CertificateError("artifact body must be an object")
    sig_hex = env.get("sig")
    if not isinstance(sig_hex, str):
        raise CertificateError("artifact sig must be a hex string")
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        raise CertificateError("artifact sig is not valid hex")
    return artifact_type, body, sig


# --- grant.body ------------------------------------------------------------

# Canonical, non-negative decimal: ASCII digits, no leading zeros (except "0"
# itself), no sign/whitespace/unicode digits. str.isdigit() is deliberately NOT
# used -- it accepts unicode digit forms and leading zeros, both of which break
# a byte-canonical version comparison.
_CANONICAL_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
# grant_id is a 128-bit id as 32 lowercase hex chars (§2).
_GRANT_ID_HEX = re.compile(r"^[0-9a-f]{32}$")


def _require_str(d: dict, key: str) -> str:
    v = d.get(key)
    if not isinstance(v, str) or not v:
        raise CertificateError("grant field %r must be a non-empty string" % key)
    return v


def _require_grant_id(d: dict) -> str:
    s = _require_str(d, "grant_id")
    if not _GRANT_ID_HEX.match(s):
        raise CertificateError("grant_id must be 32 lowercase hex chars (128-bit)")
    return s


def _require_decimal_str(d: dict, key: str) -> Tuple[str, int]:
    s = _require_str(d, key)
    if not _CANONICAL_DECIMAL.match(s):
        raise CertificateError("grant field %r must be a canonical decimal string" % key)
    return s, int(s)


# Closed grant.body schema (§2): every key that may appear, top-level. Unknown
# keys fail closed so nothing unmodelled rides inside the signed body.
_GRANT_BODY_KEYS = frozenset({
    "grant_id", "grant_version", "state_version", "issuer_fp", "subject",
    "tool", "action", "scope", "approval_mode", "valid_from", "valid_until",
})


def parse_grant_body(body: dict) -> Grant:
    """Parse a grant.body dict per §2, failing closed on anything ill-formed."""
    unknown = set(body) - _GRANT_BODY_KEYS
    if unknown:
        raise CertificateError("unknown grant.body keys: %s" % sorted(unknown))
    grant_id = _require_grant_id(body)
    grant_version, grant_version_int = _require_decimal_str(body, "grant_version")
    issuer_fp = _require_str(body, "issuer_fp")
    state_version, _ = _require_decimal_str(body, "state_version")

    tool = _require_str(body, "tool")
    action = _require_str(body, "action")
    if tool != "gmail" or action != "send":
        raise CertificateError("tool/action outside the closed enum")

    scope = _parse_scope(body.get("scope"))
    subject = _parse_subject(body.get("subject"))
    approval_mode = _parse_approval_mode(body)
    valid_from = _parse_rfc3339(body, "valid_from")
    valid_until = _parse_rfc3339(body, "valid_until")
    if valid_until <= valid_from:
        raise CertificateError("valid_until must be after valid_from")

    return Grant(
        grant_id=grant_id, grant_version=grant_version,
        grant_version_int=grant_version_int, issuer_fp=issuer_fp,
        subject=subject, tool=tool, action=action, scope=scope,
        approval_mode=approval_mode, valid_from=valid_from,
        valid_until=valid_until, state_version=state_version)


def _parse_scope(scope) -> dict:
    if not isinstance(scope, dict):
        raise CertificateError("scope must be an object")
    if not isinstance(scope.get("from_account"), str) or not scope["from_account"]:
        raise CertificateError("scope.from_account is required")
    unknown = set(scope) - {"from_account"}
    if unknown:  # closed schema: refuse unknown scope keys
        raise CertificateError("unknown scope keys: %s" % sorted(unknown))
    return dict(scope)


# Closed per-kind subject schemas (§2): the keys allowed alongside "kind".
_SUBJECT_KEYS = {
    SubjectKind.OS_ACCOUNT: frozenset({"kind", "machine_id", "account"}),
    SubjectKind.AGENT_KEY: frozenset({"kind", "agent_pubkey", "agent_slug"}),
}


def _parse_subject(s) -> Subject:
    if not isinstance(s, dict):
        raise CertificateError("subject must be an object")
    try:
        kind = SubjectKind(s.get("kind"))
    except ValueError:
        raise CertificateError("unknown subject.kind %r" % (s.get("kind"),))
    unknown = set(s) - _SUBJECT_KEYS[kind]
    if unknown:  # closed schema: os_account keys can't smuggle into agent_key or vice versa
        raise CertificateError("unknown subject keys for %s: %s"
                               % (kind.value, sorted(unknown)))
    if kind is SubjectKind.OS_ACCOUNT:
        return Subject(kind=kind,
                       machine_id=_require_str(s, "machine_id"),
                       account=_require_str(s, "account"))
    return Subject(kind=kind,
                   agent_pubkey_hex=_require_str(s, "agent_pubkey"),
                   agent_slug=_require_str(s, "agent_slug"))


def _parse_approval_mode(body: dict) -> ApprovalMode:
    if "approval_mode" not in body:
        # REQUIRED field absent -> schema violation, tagged for the audit.
        raise CertificateError("approval_mode is required",
                               detail=DETAIL_MISSING_APPROVAL_MODE)
    try:
        return ApprovalMode(body.get("approval_mode"))
    except ValueError:
        raise CertificateError("unknown approval_mode %r" % (body.get("approval_mode"),))


def _parse_rfc3339(body: dict, key: str) -> int:
    s = _require_str(body, key)
    t = s[:-1] + "+00:00" if s.endswith("Z") else s  # Python 3.10 fromisoformat has no 'Z'
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        raise CertificateError("%s is not RFC3339" % key)
    if dt.tzinfo is None:
        raise CertificateError("%s must be timezone-aware" % key)
    return int(dt.timestamp())
