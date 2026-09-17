"""Authoritative state head: the user-root-signed active-grant set (L5 §4/§4.5).

The 2026-09-05 ruling (Linus msg_9e866093 §0/§0b) makes the authorization
authority the **user-root-signed state head**, not the cloud's signed decision.
Revocation and supersede take effect through **active-set membership**:

    a grant authorizes only if ``(grant_id, grant_version) ∈ head.active_grants``

so a malicious relay that hides a revocation simply cannot supply an acceptable
head that still lists the revoked grant. The mechanism is Gateway-side and
lease-independent (§0b: promoted to the §4 decision sequence).

This module holds:

  * ``VerifiedHead`` -- a parsed, digest-bearing head the Gateway has verified;
  * head body canonical form + fail-closed parser (artifact type ``authz_state``);
  * ``HeadState`` -- the operator/test CONTROL PLANE: ``revoke``/``supersede``
    mutate the active set, bump ``state_version`` monotonically, and re-sign a
    NEW head with the user-root key (so a real signature-verifiable head, not a
    frozen constant -- 测试姬/Boris's "fixture must be advanceable" red line);
  * ``SyncSource`` / ``StubSyncSource`` -- the UNTRUSTED relay that ships the
    signed head to the Gateway each execution. It can be made unreachable, and
    it can WITHHOLD the newest head (returning an older pinned one) so the
    §4.5 T_fresh withholding gap can be exercised as an explicit negative
    (deferred: no time bound closes it this cut).

Nothing here is trusted by the Gateway on faith: the Gateway re-verifies the
head signature against its own pinned user-root key and enforces a high-water
mark before accepting a head.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Protocol, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from canonicalizer.jcs import digest

from .capability import signing_input
from .errors import AuthorizationUnavailable, CertificateError

HEAD_ARTIFACT_TYPE = "authz_state"
REVOCATION_ARTIFACT_TYPE = "authz_revocation"

_CANONICAL_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_GRANT_ID_HEX = re.compile(r"^[0-9a-f]{32}$")

# Closed head.body schema: nothing unmodelled may ride inside the signed head.
_HEAD_BODY_KEYS = frozenset({"state_version", "active_grants"})
_ACTIVE_ENTRY_KEYS = frozenset({"grant_id", "grant_version"})
# Closed revocation.body schema.
_REVOCATION_BODY_KEYS = frozenset({"grant_id", "state_version"})
# Closed sync-wrapper schema (the relay ships head + any revocation artifacts).
_SYNC_ENVELOPE_KEYS = frozenset({"head", "revocations"})


@dataclass(frozen=True)
class VerifiedHead:
    """A head the Gateway has verified (signature + schema). ``digest`` is over
    the canonical head body -- the SAME value the decision must bind to (R3).

    ``seen_revocations`` is the PER-SYNC set of grant_ids for which a valid,
    user-root-signed revocation artifact accompanied this head. It is NOT a
    persistent table (cross-restart revocation memory is deferred): it exists
    only for the attribution split below (§6)."""

    state_version: str            # canonical decimal string
    state_version_int: int
    active_grants: FrozenSet[Tuple[str, str]]   # {(grant_id, grant_version)}
    digest: str
    seen_revocations: FrozenSet[str] = frozenset()   # grant_ids revoked THIS sync

    def membership(self, grant_id: str, grant_version: str) -> "Membership":
        """Classify a (grant_id, grant_version), with §6 absence-attribution:

          ① a revocation artifact for grant_id was SEEN this sync -> REVOKED
             (checked FIRST: a revocation wins even over a head that still lists
             the grant -- a relay inconsistency must fail closed, never allow);
          ② exact (grant_id, grant_version) present            -> ACTIVE;
          ③ grant_id present at a DIFFERENT version            -> SUPERSEDED;
          ④ otherwise (absent, no revocation artifact seen)    -> NO_GRANT.

        The revoked/no_grant split is the point of the per-sync ``seen_revocations``
        set: mere ABSENCE from the head is NOT evidence of revocation -- only a
        delivered revocation artifact is. A relay that DROPS the revocation
        artifact downgrades the outcome to NO_GRANT, it cannot upgrade absence to
        a false ACTIVE (both still deny)."""
        if grant_id in self.seen_revocations:
            return Membership.REVOKED
        if (grant_id, grant_version) in self.active_grants:
            return Membership.ACTIVE
        if any(gid == grant_id for gid, _ in self.active_grants):
            return Membership.SUPERSEDED
        return Membership.NO_GRANT


class Membership:
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"
    NO_GRANT = "no_grant"


# --- head body canonical form + parser ------------------------------------

def head_body(state_version: str, active_grants: List[Tuple[str, str]]) -> dict:
    """Canonical head body. ``active_grants`` is emitted as a list sorted by
    (grant_id, grant_version) so the digest is order-independent of the caller."""
    entries = sorted(set(active_grants))
    return {
        "state_version": state_version,
        "active_grants": [
            {"grant_id": gid, "grant_version": gver} for gid, gver in entries
        ],
    }


def parse_head_body(body: dict) -> Tuple[str, int, FrozenSet[Tuple[str, str]]]:
    """Parse an authz_state head body, failing closed on anything ill-formed."""
    if not isinstance(body, dict):
        raise CertificateError("head body must be an object")
    unknown = set(body) - _HEAD_BODY_KEYS
    if unknown:
        raise CertificateError("unknown head.body keys: %s" % sorted(unknown))
    sv = body.get("state_version")
    if not isinstance(sv, str) or not _CANONICAL_DECIMAL.match(sv):
        raise CertificateError("head state_version must be a canonical decimal string")
    active = body.get("active_grants")
    if not isinstance(active, list):
        raise CertificateError("head active_grants must be a list")
    pairs: set[Tuple[str, str]] = set()
    for entry in active:
        if not isinstance(entry, dict):
            raise CertificateError("active_grants entry must be an object")
        if set(entry) != _ACTIVE_ENTRY_KEYS:
            raise CertificateError("active_grants entry keys must be exactly %s"
                                   % sorted(_ACTIVE_ENTRY_KEYS))
        gid = entry.get("grant_id")
        gver = entry.get("grant_version")
        if not isinstance(gid, str) or not _GRANT_ID_HEX.match(gid):
            raise CertificateError("active_grants grant_id must be 32 lowercase hex")
        if not isinstance(gver, str) or not _CANONICAL_DECIMAL.match(gver):
            raise CertificateError("active_grants grant_version must be canonical decimal")
        pairs.add((gid, gver))
    return sv, int(sv), frozenset(pairs)


def revocation_body(grant_id: str, state_version: str) -> dict:
    """Canonical revocation-artifact body: which grant, at which state_version."""
    return {"grant_id": grant_id, "state_version": state_version}


def parse_revocation_body(body: dict) -> str:
    """Parse an authz_revocation body, failing closed; returns grant_id."""
    if not isinstance(body, dict):
        raise CertificateError("revocation body must be an object")
    if set(body) != _REVOCATION_BODY_KEYS:
        raise CertificateError("revocation body keys must be exactly %s"
                               % sorted(_REVOCATION_BODY_KEYS))
    gid = body.get("grant_id")
    sv = body.get("state_version")
    if not isinstance(gid, str) or not _GRANT_ID_HEX.match(gid):
        raise CertificateError("revocation grant_id must be 32 lowercase hex")
    if not isinstance(sv, str) or not _CANONICAL_DECIMAL.match(sv):
        raise CertificateError("revocation state_version must be canonical decimal")
    return gid


def sync_envelope(head_env: dict, revocation_envs: List[dict]) -> dict:
    """The relay's per-sync payload: the signed head plus any revocation
    artifacts delivered alongside it. A CLOSED wrapper -- the head envelope stays
    the closed {v,type,body,sig} artifact, so revocation artifacts cannot smuggle
    unsigned bytes into the head."""
    return {"head": head_env, "revocations": list(revocation_envs)}


def parse_sync_envelope(env: dict) -> Tuple[dict, List[dict]]:
    """Split the sync wrapper into (head_env, [revocation_env, ...]); fail closed."""
    if not isinstance(env, dict):
        raise CertificateError("sync envelope must be an object")
    unknown = set(env) - _SYNC_ENVELOPE_KEYS
    if unknown:
        raise CertificateError("unknown sync envelope keys: %s" % sorted(unknown))
    head_env = env.get("head")
    if not isinstance(head_env, dict):
        raise CertificateError("sync envelope head must be an object")
    revocations = env.get("revocations", [])
    if not isinstance(revocations, list):
        raise CertificateError("sync envelope revocations must be a list")
    return head_env, revocations


# --- sync source (untrusted relay) ----------------------------------------

class SyncSource(Protocol):
    """The relay that ships the signed authz_state head to the Gateway.

    UNTRUSTED: it may be unreachable or WITHHOLD the newest head. It cannot forge
    (the head is user-root-signed and the Gateway re-verifies). ``sync`` returns
    a signed head envelope ``{v,type,body,sig}`` or raises
    ``AuthorizationUnavailable`` when the state cannot be fetched (§4-1)."""

    def sync(self) -> dict: ...


class HeadState:
    """Operator/test control plane over the authoritative head.

    ``revoke``/``supersede`` mutate the active set, bump ``state_version`` by 1
    (monotonic), and cause the next ``signed_head`` to re-sign a genuinely new,
    verifiable head with the user-root key. This is the "advanceable fixture"
    the reviewers required: the head is not a frozen constant, so the digest
    provably changes on a revocation."""

    def __init__(self, user_priv: Ed25519PrivateKey,
                 active_grants: Dict[str, str], *, state_version_int: int = 1):
        self._user_priv = user_priv
        self._active: Dict[str, str] = dict(active_grants)  # grant_id -> grant_version
        self._version_int = state_version_int
        # Revocation ledger: grant_id -> state_version_int AT which it was revoked.
        # A revocation is positive evidence (a signed artifact), distinct from mere
        # absence from ``_active`` -- that distinction is the §6 revoked/no_grant split.
        self._revocations: Dict[str, int] = {}

    @property
    def state_version(self) -> str:
        return str(self._version_int)

    def revoke(self, grant_id: str) -> None:
        self._active.pop(grant_id, None)
        self._version_int += 1
        self._revocations[grant_id] = self._version_int

    def supersede(self, grant_id: str, new_version: int) -> None:
        self._active[grant_id] = str(new_version)
        self._version_int += 1

    def add(self, grant_id: str, grant_version: str) -> None:
        self._active[grant_id] = grant_version
        self._version_int += 1
        self._revocations.pop(grant_id, None)  # re-granted: no longer revoked

    def signed_head(self) -> dict:
        body = head_body(str(self._version_int),
                         [(gid, ver) for gid, ver in self._active.items()])
        sig = self._user_priv.sign(signing_input(HEAD_ARTIFACT_TYPE, body))
        return {"v": 1, "type": HEAD_ARTIFACT_TYPE, "body": body, "sig": sig.hex()}

    def signed_revocation(self, grant_id: str, state_version_int: int) -> dict:
        body = revocation_body(grant_id, str(state_version_int))
        sig = self._user_priv.sign(signing_input(REVOCATION_ARTIFACT_TYPE, body))
        return {"v": 1, "type": REVOCATION_ARTIFACT_TYPE, "body": body, "sig": sig.hex()}

    def signed_revocations(self) -> List[dict]:
        """User-root-signed revocation artifacts for every grant revoked so far."""
        return [self.signed_revocation(gid, ver)
                for gid, ver in sorted(self._revocations.items())]

    def head_digest(self) -> str:
        """Digest of the CURRENT head body (for the decision service to bind to;
        the Gateway derives its own from the head it independently verified)."""
        body = head_body(str(self._version_int),
                         [(gid, ver) for gid, ver in self._active.items()])
        return digest(body)


class StubSyncSource:
    """In-memory relay over a ``HeadState``. Can be made unreachable or made to
    WITHHOLD the newest head (returning a pinned older one) for the §4.5 T_fresh
    withholding negative (deferred: lease-off has no time bound to close it)."""

    def __init__(self, head_state: HeadState, *, reachable: bool = True):
        self._head_state = head_state
        self._reachable = reachable
        self._withheld: Optional[dict] = None
        self._include_revocations = True

    def set_reachable(self, reachable: bool) -> None:
        self._reachable = reachable

    def pin_and_withhold(self) -> None:
        """Freeze the CURRENT signed head and keep returning it even after the
        control plane advances -- models a relay replaying an older head."""
        self._withheld = self._head_state.signed_head()

    def withhold_revocations(self) -> None:
        """Deliver the (advanced) head but DROP the revocation artifacts -- models
        a relay that hides the positive revocation evidence. The head still omits
        the revoked grant, so the outcome is NO_GRANT, not REVOKED (§6 red B)."""
        self._include_revocations = False

    def resume(self) -> None:
        self._withheld = None
        self._include_revocations = True

    def sync(self) -> dict:
        if not self._reachable:
            raise AuthorizationUnavailable("authz state relay unreachable")
        head_env = (self._withheld if self._withheld is not None
                    else self._head_state.signed_head())
        revocations = (self._head_state.signed_revocations()
                       if self._include_revocations else [])
        return sync_envelope(head_env, revocations)
