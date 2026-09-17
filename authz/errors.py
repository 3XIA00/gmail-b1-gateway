"""Authorization errors and the internal failure-reason taxonomy (L5 v0.5.1 §6).

Two-tier BY CONSTRUCTION (existence-oracle rule, §6):

  * ``DenialReason`` + a ``detail`` string are the INTERNAL audit codes. They
    ride on ``DenialSignal``, the exception the service raises to the gate. The
    gate records them to the audit and then raises the caller-facing exception.
    ``DenialSignal`` never crosses the gate to a caller.
  * ``AuthorizationDenied`` is the caller-facing failure. It is STRUCTURALLY
    incapable of carrying a reason: it holds no fine state at all, so its
    ``str()``, ``repr()``, ``args``, and ``__dict__`` are the single coarse
    token ``"denied"`` (and nothing else). Even an accidental
    ``log.error(exc)`` / ``repr(exc)`` / ``vars(exc)`` cannot leak which check
    failed -- the guarantee is a property of the type, not a discipline.

Reason values are the exact ``denied_*`` strings from the L5 §6 audit-code set.
"""

from __future__ import annotations

import enum
from typing import Optional


class DenialReason(enum.Enum):
    """Internal, audit-only reason a request was refused. NEVER shown to a caller."""

    INVALID_ARTIFACT = "denied_invalid_artifact"          # bad sig / malformed / missing field
    CLOUD_UNREACHABLE = "denied_cloud_unreachable"        # revocation cloud unreachable -> fail closed
    REVOKED = "denied_revoked"                            # a revocation artifact for this grant_id was seen THIS sync (§6 ①)
    NO_GRANT = "denied_no_grant"                          # grant_id not in the verified head and NO revocation artifact seen (§6 ③)
    EXPIRED = "denied_expired"                            # now past valid_until (+skew)
    SUPERSEDED = "denied_superseded"                      # grant_version below the active version
    VALIDITY_EXCEEDS_POLICY = "denied_validity_exceeds_policy"  # validity span over profile cap
    MODE_MISMATCH = "denied_mode_mismatch"                # proof mechanism/identity != subject
    SCOPE = "denied_scope"                                # grant scope != this send's account (§2/§6)
    REPLAY = "denied_replay"                              # request_id already consumed (single-use)
    VERSION_REGRESS = "denied_version_regress"            # synced head state_version below high-water mark (§4-2)
    STATE_UNAVAILABLE = "denied_state_unavailable"        # local safety state lost/corrupt -> fail closed (§4.6)
    INTERNAL_ERROR = "denied_internal"                    # unexpected error -> fail closed, never fail open


# Detail strings (L5 §6): a finer note under a reason. Internal/audit-only.
DETAIL_MISSING_APPROVAL_MODE = "missing_approval_mode"
DETAIL_UNTRUSTED_ISSUER = "untrusted_issuer"
DETAIL_DECISION_REUSED = "decision_reused"
DETAIL_DECISION_HEAD_MISMATCH = "decision_head_mismatch"  # authz_state_digest binding violation (L5 v0.5.2 §4/§6)
DETAIL_ACTION_DIGEST_MISMATCH = "action_digest_mismatch"  # decision-to-payload binding violation (Linus ruling B1)
DETAIL_DECISION_SIG_INVALID = "decision_sig_invalid"      # decision signature/MAC missing or invalid (§4)
DETAIL_SUBJECT_IDENTITY_MISMATCH = "subject_identity_mismatch"  # os_account peer identity != grant.subject (ruling ①)
DETAIL_INACTIVE_IN_VERIFIED_HEAD = "inactive_in_verified_head"  # §6 ③: grant absent from verified head, no revocation artifact (denied_no_grant)

# Per-field binding-mismatch details (policy map sealed 2026-09-05, R1/R6/R7):
# every one names the exact Decision field whose value did not match the
# Gateway's OWN independent derivation from the verified grant + held head. A
# relay that swaps any binding field of a validly-signed decision lands here.
DETAIL_DECISION_REQUEST_MISMATCH = "decision_request_mismatch"        # R1: decision.request_id != this request
DETAIL_DECISION_GRANT_ID_MISMATCH = "decision_grant_id_mismatch"      # R6: decision.grant_id != verified grant
DETAIL_DECISION_GRANT_VERSION_MISMATCH = "decision_grant_version_mismatch"  # R6: grant_version swap
DETAIL_DECISION_VERSION_MISMATCH = "decision_version_mismatch"  # R3/§4: state_version != accepted head (Linus 2026-09-05)
DETAIL_DECISION_APPROVAL_MODE_MISMATCH = "decision_approval_mode_mismatch"  # R7: approval_mode != verified grant
DETAIL_DECISION_SUBJECT_KIND_MISMATCH = "decision_subject_kind_mismatch"    # R7: subject_kind != verified grant
DETAIL_DECISION_DISPOSITION_MISMATCH = "decision_disposition_mismatch"      # disposition != locally-derived result

# Request-map + freshness details (L5 §5, Linus ruling 2026-09-05 §1/§2):
DETAIL_NOT_YET_VALID = "not_yet_valid"                    # #6: valid_from is in the future (under denied_expired)
DETAIL_REQUEST_ID_REUSED = "request_id_reused"           # R8: (grant_id,request_id) already consumed (replay axis)
DETAIL_ISSUED_AT_OUT_OF_WINDOW = "issued_at_out_of_window"  # R8: request issued_at outside ±5min (agent_key tier)
DETAIL_CHANNEL_BINDING_MISMATCH = "channel_binding_mismatch"  # R8: connection challenge echo mismatch (fixture)
DETAIL_DECIDED_AT_OUT_OF_WINDOW = "decided_at_out_of_window"  # (d): decision.decided_at outside the hygiene window


class AuthorizationError(Exception):
    """Base for all authorization-layer errors."""


class CertificateError(AuthorizationError):
    """A grant artifact could not be parsed into a well-formed value (fail closed).

    Carries an optional ``detail`` (e.g. ``missing_approval_mode``) that the
    service surfaces under ``denied_invalid_artifact`` in the audit log.
    """

    def __init__(self, message: str, *, detail: Optional[str] = None):
        super().__init__(message)
        self.detail = detail


class AuthorizationUnavailable(AuthorizationError):
    """The authorization service could not reach the revocation cloud/stub.

    Not "no" but "cannot decide". Under Q2=B the Gateway fails CLOSED, so the
    gate maps this to a coarse ``denied`` with the ``CLOUD_UNREACHABLE`` reason.
    """


class DenialSignal(AuthorizationError):
    """INTERNAL service->gate refusal carrying the fine reason + detail.

    Raised by the authorization service, caught by the gate, which copies the
    reason/detail into the audit and then raises a coarse ``AuthorizationDenied``
    to the caller. This type never reaches a caller.
    """

    def __init__(self, reason: DenialReason, detail: Optional[str] = None):
        if not isinstance(reason, DenialReason):
            raise TypeError("reason must be a DenialReason")
        super().__init__(reason.value)
        self.reason = reason
        self.detail = detail


class AuthorizationDenied(AuthorizationError):
    """Caller-facing refusal. Coarse ``denied`` and NOTHING else, by construction.

    Carries no reason/detail state -- ``str``, ``repr``, ``args`` and
    ``__dict__`` expose only the coarse token, so the fine code cannot leak
    through any exception surface a caller might log.
    """

    PUBLIC_CODE = "denied"

    def __init__(self):
        # str(self) == "denied", args == ("denied",), __dict__ == {}.
        super().__init__(self.PUBLIC_CODE)

    @property
    def public_code(self) -> str:
        return self.PUBLIC_CODE
