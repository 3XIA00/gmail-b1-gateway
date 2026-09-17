# PUF-367 authz — round-3 four-axis delta + D0/D1 provenance (2026-09-05)

Change log for the four hardening axes folded onto the seam-split package after
the reviewers converged (Linus 186258/186261, Jeff 186259/186262, Boris 186118/
186137/186172/186211-1, 测试姬 186151/186267). Authority order for every item
below: **L5 v0.5.2 full text (`3840d7bd…`) + the R1–R8/P1 frozen contract > the
`76564ec0…` digest/membership/KAT delta extract**; the extract is a note for the
digest/membership/KAT segments only, never the implementation basis. The old
extract `b1a4ac7c…` is VOIDED and was not used.

## Change log (per area — no count gap)

1. **Axis 1 — continuous-clock seam (§1).** NEW `authz/clock.py`: allow-list
   platform dispatch (Darwin `CLOCK_MONOTONIC_RAW` / Linux `CLOCK_BOOTTIME`),
   **fail-closed at startup** on any unmapped platform or missing constant, never
   `time.monotonic()`. `gate.py`/`orchestrator.py` take an injectable
   `continuous_clock_ns`; the deadline is expressed in ns (`RESPONSE_DEADLINE_NS`).
   The `now − kern.boottime` cross-check is diagnostic-only, off the startup +
   authorize paths (Boris caveat). Tests `test_authz_clock.py` are NON-timing
   (monkeypatch `time`, capture `clock_id`, assert RAISES on unmapped) + the
   request-map deadline tests inject scripted ns values.

2. **Axis 2 — membership absence-attribution (§6).** `state.py`
   `VerifiedHead.membership()` now returns REVOKED / ACTIVE / SUPERSEDED /
   **NO_GRANT** with the §6 priority (revocation checked FIRST). NEW closed
   `authz_revocation` artifact + `{head, revocations}` sync envelope; `seen_
   revocations` is a **per-sync set**, not a persistent table (cross-restart table
   stays deferred — the extract's old "permanent append-only" wording is NOT
   implemented). Two separated reds (delivered→`denied_revoked`; withheld + head
   drops grant→`denied_no_grant`+`inactive_in_verified_head`), each with a
   **pre-run sync-set self-assertion** (fixture-leak defense). Carried additions:
   the **supersede tuple-granularity** unit (leg②: `(G,old)`∉ ∧ `(G,new)`∈; not an
   isolation vector) and the revocation-wins-over-listed-grant unit.

3. **Axis 3 — digest KAT (§4/R3).** NEW `test_authz_digest_kat.py`.
   `authz_state_digest = SHA-256(JCS(head.body))`, one byte domain, no projection.
   Independent stdlib-json oracle; paired B0/B1 fixtures; function-level +
   Gateway-level preimage reds. The Gateway red follows "只投递并签 B1，B0 离线算
   D0 不投递": only B1 is signed/delivered, D0 is injected as a test constant onto
   an otherwise byte-honest decision (no same-version double head). Five green legs
   pinned by the positive control (digest=D1→authorized); the red moves only the
   digest (D0)→`decision_head_mismatch`.

4. **R1–R8/P1 main-fix face — 照冻结合同无变更 (no change per frozen contract).**
   The seam-split package (R1/R2/R3/R6/R7/R8/R9/§4-2/§4.6/R4/R5/P1 + the policy
   map + `assert_policy_covers_decision`) is UNCHANGED this round except where an
   axis above touches it (the clock injection in gate/orchestrator, the NO_GRANT
   branch in `_local_decisions`, the sync-envelope parse in `_sync_and_accept`).
   The R7 decision field set (`approval_mode`/`subject_kind`/`disposition`) and
   `Decision.allowed_fields == policy-map.keys` remain as already built — the
   extract's 8-field JSON is a first-cut subset and was NOT used to narrow them.

## D0/D1 provenance (declare on every change — Boris 186172 / Jeff 186170)

The KAT constants are TEST-SIDE known answers, derived by an INDEPENDENT oracle
(stdlib `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`
→ SHA-256), NOT by `canonicalizer.jcs` (the code under test) and NOT read back
from the Gateway. For these ASCII-only, integer-free bodies that stdlib
canonicalization equals RFC 8785 JCS, so it is a valid independent oracle.

- **B0** = head body `{state_version:"1", active_grants:[G@1]}` where
  `G = 00112233445566778899aabbccddeeff`.
- **B1** = B0 plus ONE unrelated grant `G_other = ffffffffffffffffffffffffffffffff`
  at version `1`; byte-identical to B0 in `state_version` and the G entry.
- **D0** = `b1240c7258634087220e7f0f4c573d3884544553743eb32b6bdbeec2fb757ca8`
- **D1** = `f4e41db13d116396d8de0dc2fda17f619f358e794cf0c3103818178b0bbbf250`

`test_kat_constants_self_consistent` proves the pinned constants match the
independent oracle; `test_production_digest_matches_kat` is the positive control
that the code under test equals them. **Lifecycle (Boris `dc8929a7`):** if B0/B1
change, the constants MUST be re-derived independently (never backfilled via the
digest function under test — that degrades the oracle to `f(x)==f(x)`), and the
change flagged here separately from ordinary edits.

## Two-stage delivery + binding rule

- **msg-1 (fixture-only manifest):** the exact complete B0/B1 JSON instances,
  with NO expected bytes / D0 / D1 / back-derivable constants. It commits the
  exact B0/B1 bytes before the package reveals the expected digests.
- **msg-2 (full package):** this tree, with the tree-pin values published in the
  message. The in-package B0/B1 (`head_body(...)` in `test_authz_digest_kat.py`)
  are BYTE-IDENTICAL to msg-1. If they ever differ, the delivery is VOID and must
  reopen — never a silent rebind.
- The salted blind-order commit-then-reveal is the reviewers' 3-seat forensic
  process; my part is only to deliver the manifest + package and guarantee
  msg-1 instance == in-package instance.

## NOT ACCEPTED

Submitted for the blocking R1–R8 + P1 re-verification. The prior NOT-ACCEPTED
stands until the reviewers clear it; nothing here is self-accepted.
