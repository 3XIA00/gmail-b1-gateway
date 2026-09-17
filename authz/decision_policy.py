"""Exhaustive per-field binding policy for a signed ``Decision`` (L5 §4).

Policy map sealed 2026-09-05 by the three-reviewer gate (Jeff Dean / Boris
Cherny / 测试姬) after R1/R6/R7: a validly-signed decision relayed by the
UNTRUSTED cloud can have ANY of its fields swapped, and the gate previously
verified only 2 of the 11 binding fields. The fix is not a per-field patch but a
single rule enforced structurally:

    Every field of ``Decision`` must fall into EXACTLY one trust class, and the
    map's field set must equal ``Decision``'s field set -- so a NEW field is red
    (unclassified) by default instead of silently unverified. The defect class
    that produced R1/R6/R7 is precisely "someone added a field and nobody added
    the check"; ``assert_policy_covers_decision`` makes that impossible to ship.

Trust classes (Jeff msg_af679352):
  (a) Gateway INDEPENDENTLY derives the value (from the user-root-signed grant
      envelope in THIS request + the authoritative head the Gateway holds) and
      compares it exactly. The decision's self-reported value is never trusted.
  (b) Gateway-LOCAL single-use consume (a state operation, not a comparison).
  (c) Closed enumeration AND consistent with the independently-verified grant /
      the Gateway's own locally-derived result.
  (d) Verified against a protocol-defined time rule.
  (e) Explicitly a non-authorization input the execution path NEVER reads
      (guarded by a poison-value projection-invariance test; see tests).

``sig`` is not a bound *claim* -- it authenticates the whole body and is checked
by ``verify_decision_sig`` before this map runs; it is named the authenticator,
not classified (a)-(e).
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Callable, Optional, Tuple

from .capability import ApprovalMode, SubjectKind
from .errors import (
    DETAIL_ACTION_DIGEST_MISMATCH,
    DETAIL_DECISION_APPROVAL_MODE_MISMATCH,
    DETAIL_DECISION_DISPOSITION_MISMATCH,
    DETAIL_DECISION_GRANT_ID_MISMATCH,
    DETAIL_DECISION_GRANT_VERSION_MISMATCH,
    DETAIL_DECISION_HEAD_MISMATCH,
    DETAIL_DECISION_REQUEST_MISMATCH,
    DETAIL_DECISION_SUBJECT_KIND_MISMATCH,
    DETAIL_DECISION_VERSION_MISMATCH,
)
from .service import Decision, Disposition

CLASS_A = "a"  # independently derived + exact compare
CLASS_B = "b"  # Gateway-local atomic consume
CLASS_C = "c"  # closed enum + consistent with verified grant / local result
CLASS_D = "d"  # protocol-defined time rule
CLASS_E = "e"  # non-authorization input, never read on the execution path

# The one field authenticated (not classified): the whole-body signature.
AUTHENTICATOR_FIELD = "sig"

_APPROVAL_MODES = frozenset(m.value for m in ApprovalMode)
# Raw enum VALUES (strings): subject_kind is a raw wire string like approval_mode
# /disposition (R7), so the closed-set guard compares strings, and an unknown raw
# value simply mismatches instead of throwing in the signing path.
_SUBJECT_KINDS = frozenset(k.value for k in SubjectKind)
_DISPOSITIONS = frozenset({Disposition.AUTHORIZED, Disposition.NEEDS_APPROVAL})


@dataclass(frozen=True)
class ExpectedBinding:
    """What the Gateway INDEPENDENTLY derives for a request -- the trusted side of
    every (a)/(c) comparison. Built from the verified grant + the held head, never
    from the decision.
    """
    request_id: str
    action_digest: str
    authz_state_digest: str
    state_version: str
    grant_id: str
    grant_version: str
    approval_mode: str
    subject_kind: str            # raw enum value, symmetric with approval_mode (R7)
    disposition: str


def _cmp(field: str, detail: str) -> Callable[[Decision, ExpectedBinding], Optional[str]]:
    """(a) exact-comparison check: decision.<field> must equal the Gateway's own
    independently-derived value, else ``detail``."""
    def check(decision: Decision, expected: ExpectedBinding) -> Optional[str]:
        if getattr(decision, field) != getattr(expected, field):
            return detail
        return None
    return check


def _check_approval_mode(decision: Decision, expected: ExpectedBinding) -> Optional[str]:
    # (c) closed enum AND == the verified grant's mode; the relay does not get to
    # decide auto-vs-per_call (R7).
    if decision.approval_mode not in _APPROVAL_MODES:
        return DETAIL_DECISION_APPROVAL_MODE_MISMATCH
    if decision.approval_mode != expected.approval_mode:
        return DETAIL_DECISION_APPROVAL_MODE_MISMATCH
    return None


def _check_subject_kind(decision: Decision, expected: ExpectedBinding) -> Optional[str]:
    if decision.subject_kind not in _SUBJECT_KINDS:
        return DETAIL_DECISION_SUBJECT_KIND_MISMATCH
    if decision.subject_kind != expected.subject_kind:
        return DETAIL_DECISION_SUBJECT_KIND_MISMATCH
    return None


def _check_disposition(decision: Decision, expected: ExpectedBinding) -> Optional[str]:
    # (c) closed enum AND == the disposition the Gateway itself derived from the
    # verified grant's approval_mode. A replay cannot isolate this from
    # approval_mode (the service signs them consistent), but the guard is here so
    # the field is never merely "used, never compared".
    if decision.disposition not in _DISPOSITIONS:
        return DETAIL_DECISION_DISPOSITION_MISMATCH
    if decision.disposition != expected.disposition:
        return DETAIL_DECISION_DISPOSITION_MISMATCH
    return None


@dataclass(frozen=True)
class FieldPolicy:
    field: str
    cls: str
    # (a)/(c) carry a value check; (b)/(d)/(e) carry None (handled by the gate,
    # pending a ruling, or asserted unused by a poison test).
    check: Optional[Callable[[Decision, ExpectedBinding], Optional[str]]]


# Order matters only for WHICH detail a multi-field mismatch reports first; every
# field is still covered. (a) then (b) then (c) then (d)/(e).
_POLICY: Tuple[FieldPolicy, ...] = (
    FieldPolicy("request_id", CLASS_A, _cmp("request_id", DETAIL_DECISION_REQUEST_MISMATCH)),
    FieldPolicy("action_digest", CLASS_A, _cmp("action_digest", DETAIL_ACTION_DIGEST_MISMATCH)),
    FieldPolicy("authz_state_digest", CLASS_A, _cmp("authz_state_digest", DETAIL_DECISION_HEAD_MISMATCH)),
    FieldPolicy("grant_id", CLASS_A, _cmp("grant_id", DETAIL_DECISION_GRANT_ID_MISMATCH)),
    FieldPolicy("grant_version", CLASS_A, _cmp("grant_version", DETAIL_DECISION_GRANT_VERSION_MISMATCH)),
    FieldPolicy("state_version", CLASS_A, _cmp("state_version", DETAIL_DECISION_VERSION_MISMATCH)),
    # (b): the gate consumes decision_id single-use on its OWN side (a relay
    # cannot bypass it, unlike the service-internal consume). gate.py owns this.
    FieldPolicy("decision_id", CLASS_B, None),
    FieldPolicy("approval_mode", CLASS_C, _check_approval_mode),
    FieldPolicy("subject_kind", CLASS_C, _check_subject_kind),
    FieldPolicy("disposition", CLASS_C, _check_disposition),
    # (d): decided_at is enforced by the GATE as a HYGIENE window on the Gateway
    # wall clock (§1: [t_request_sent-5min, t_response_verified+5min]) -- NEVER a
    # security deadline (that is the Gateway monotonic response deadline) and NOT
    # a decision TTL. check_binding carries None because the rule needs the
    # request-send/verify wall times the gate holds, not a field-equality compare.
    FieldPolicy("decided_at", CLASS_D, None),
    # (e): none this round. Adding an (e) member requires registering a
    # poison-value projection-invariance test (see tests) or the (e) regression
    # assertion fails.
)


def check_binding(decision: Decision, expected: ExpectedBinding) -> Optional[str]:
    """Run every (a)/(c) field check in policy order; return the first mismatch
    detail, or None if all comparison-bound fields match. (b) consume and (d)
    time rule are enforced by the gate, not here.
    """
    for policy in _POLICY:
        if policy.check is None:
            continue
        detail = policy.check(decision, expected)
        if detail is not None:
            return detail
    return None


def fields_in_class(cls: str) -> Tuple[str, ...]:
    return tuple(p.field for p in _POLICY if p.cls == cls)


def assert_policy_covers_decision() -> None:
    """The policy map's field set + the authenticator MUST equal Decision's field
    set. A new Decision field that is neither classified nor named the
    authenticator fails here -- the R1/R6/R7 defect ("added a field, forgot the
    check") cannot ship. Mirrors audit._assert_closed_schema.
    """
    mapped = frozenset(p.field for p in _POLICY)
    if AUTHENTICATOR_FIELD in mapped:
        raise AssertionError(
            "the authenticator field %r must not be classified (a)-(e)"
            % AUTHENTICATOR_FIELD)
    covered = mapped | {AUTHENTICATOR_FIELD}
    decision_fields = frozenset(f.name for f in fields(Decision))
    if covered != decision_fields:
        raise AssertionError(
            "decision policy map %r + authenticator %r does not cover Decision "
            "fields %r -- classify a new field (a)-(e) or name it the authenticator"
            % (sorted(mapped), AUTHENTICATOR_FIELD, sorted(decision_fields)))
