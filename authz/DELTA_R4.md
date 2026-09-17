# PUF-367 authz — round-4 fix delta (R2/R5/R7/R8) — 2026-09-05

Fix contract: Jeff `msg_69e104cb` (seq 186359), three-seat countersign Linus
186362 / Jeff 186363 / Boris 186365. Authority: `authz-protocol-l5.md` SHA-256
`3840d7bdafd91617faced391c06ccd08123ed4fa1477c2f4ff3061f55de7a99e` full text;
this delta does not replace it. **Only R2/R5/R7/R8 change; nothing else.**

Runtime fingerprint (this build, row 1): Windows 11 Home China 10.0.26200
(`platform.platform()=Windows-10-10.0.26200-SP0`) · **AMD64 / x86_64**
(`platform.machine()=AMD64`, `architecture=('64bit','WindowsPE')`) · CPython
**3.10.11** (tags/v3.10.11:7d4cc5a, MSC v.1929 64 bit AMD64) · interpreter
`%LOCALAPPDATA%\Programs\Python\Python310\python.exe` (= `C:\Users\<local-account>
\AppData\Local\Programs\Python\Python310\python.exe`; stock python.org per-user
install; the account segment is elided as not load-bearing / to avoid disclosing a
host account name — exact-literal cross-confirm via 测试姬 on operator authority if
the readback demands it, Jeff 186484-1 / Linus 186486-4). Row 2 (deployment /
reviewers' independent second runtime): macOS **26.5** · arm64 · CPython **3.14.5**
(Homebrew python@3.14), base executable `/opt/homebrew/Cellar/python@3.14/3.14.5/
Frameworks/Python.framework/Versions/3.14/bin/python3.14` (reviewer-supplied, run
there — Jeff 186484 / Linus 186486).

## R7 — closed enum truly fail-closed

Root cause: `Decision.subject_kind` was a `SubjectKind` **enum** while
`approval_mode`/`disposition` were already raw `str`. `decision_body` serialized
`d.subject_kind.value`; that runs inside `verify_decision_sig` (signing-input),
which the gate calls BEFORE the closed-set guard. A malicious relay supplying a
raw `subject_kind="alien"` threw a bare `AttributeError` — no coarse denied, no
audit (an availability hole + audit gap).

Fix (express the boundary uniformly, not patch the one throw):
`Decision.subject_kind` and `ExpectedBinding.subject_kind` become raw `str`,
symmetric with `approval_mode`/`disposition`. `decision_body` serializes the raw
value (no `.value`), so signing-input never throws on any raw value.
`_SUBJECT_KINDS` becomes the frozenset of enum *values*; `_check_subject_kind`
(the closed-set guard already present) is now the single validation point —
unknown value → `decision_subject_kind_mismatch`, never an exception.
`StubDecisionService`/`_expected_binding` emit `subject.kind.value`.

Tests: for a **validly-signed** decision with an unknown raw value in each of
`subject_kind`/`approval_mode`/`disposition` → coarse `denied` +
`decision_*_mismatch` audit + sender zero-call + NO bare exception. Plus
wrong-type/bad-signature keep their existing schema/signature attribution.
Per Linus 186362-2 / Jeff 186363-②: the existing `*_mismatch` detail
intentionally covers BOTH "in-enum-but-mismatched" and "unknown-not-in-enum";
no new code (future distinction → doc-batch registration).

## R8 — deadline covers response verified/complete

Root cause: the gate sampled `mono_verified` immediately after `decide()`
returned and ran the deadline check BEFORE signature verify / binding / decided_at
hygiene. Time spent in those stages was outside the deadline.

Fix: keep `mono_sent` at cloud-request send; read `mono_decision_received` right
after `decide()` returns (R2 event 1); run sig-verify → binding → decided_at
hygiene; THEN read `mono_response_verified` and apply the deadline
(`> RESPONSE_DEADLINE_NS` → `denied_cloud_unreachable`, request_id already dead,
sender zero-call; boundary `==` passes), all BEFORE the decision-id consume /
dispatch. The decided_at hygiene check is extracted to module-level
`_decided_at_in_hygiene_window(...)` so a test can advance the clock during that
stage. suspend-inclusive clock mapping unchanged (Darwin RAW / Linux BOOTTIME /
unknown fail-closed); `decided_at` stays a wall-clock hygiene window, no TTL.

Tests: advancing the continuous clock past the deadline DURING sig-verify,
DURING binding, and DURING hygiene (monkeypatching each stage) each go red→green;
plus the round-trip-timeout control and the normal positive control. R4a adds the
exact-boundary case (Linus 186486-6): `elapsed == RESPONSE_DEADLINE_NS`
authorizes (strict `>`), pinning the inclusive edge so a `>=` regression is caught.

## R2 — dispatch record mandatory + two-phase + correct three events

Root cause: `dispatch_records` was `Optional=None` (send succeeded with no
record); the record was written AFTER `fsm.dispatch` (append failure → sent but
unrecorded); event names `mono_request_sent/decision_verified/dispatch_committed`
did not match the frozen three events.

Fix:
1. Exactly three events `mono_decision_received_ns` / `mono_gmail_commit_start_ns`
   / `mono_response_complete_ns`, all from the ONE Gateway continuous clock
   shared by gate + orchestrator (order provable). `decision_received` is the
   gate's post-`decide()` reading carried on `Authorization`.
2. `DispatchRecordLog` is a REQUIRED dependency of `AuthorizedGmailSend` (no
   `None`). Two-phase, append-only (Linus 186362-1 "两半结构"): `record_started`
   (decision_received + gmail_commit_start) is written BEFORE `fsm.dispatch`;
   `record_completed` (+ response_complete + terminal_status) AFTER. Two closed
   schemas (`DispatchStarted`, `DispatchCompleted`), each drift-guarded; joined by
   `(proposal_id, request_id)`.
3. If the started-record write fails → refuse before any send (`fsm` untouched,
   sender zero-call, `record_unavailable`). If the completion write fails after
   the Gmail commit started → the started record is retained (non-lossy,
   indeterminate); the outcome is `outcome_unknown`, never a clean `sent`.
4. hook-28 same-transaction fold into the FSM ledger stays deferred; this round
   does NOT claim cross-Gmail atomicity — only the record's own mandatory/
   non-lossy property.

Reviewer refinements folded in (all ruled 非扩项 / executable expansions of
R2-1/R2-3, not new scope — Jeff 186381/186386/186390, Boris 186384, Linus 186389):
  * **explicit phase/state** (Jeff 186381): `DispatchStarted` carries a `phase`
    discriminator and LACKS `mono_response_complete_ns`/`terminal_status`, so a
    started/indeterminate half can never masquerade as a terminal complete record;
    only the completed artifact carries all three events.
  * **join-key binding = the quadruple** (Boris 186384 / Jeff 186386): a new
    `DispatchRecordLog.find(proposal_id, request_id, action_digest)` returns only
    rows that BIND; a row with any join key empty/mismatched is, for audit,
    equivalent to absent (never counted as the send's record), any phase.
  * **positive started-half read** (Linus 186389 / Jeff 186390): the after-start
    and completion-write injection tests POSITIVELY read the persisted started
    half (quadruple + `mono_decision_received_ns` + `mono_gmail_commit_start_ns`),
    not merely "no complete / not sent" — mechanically forcing the started half to
    be persisted BEFORE the sender is called.
  * **after-start = real dispatch-point injection** (R4a, Jeff 186484-2 / Linus
    186486): the after-start test now injects a crash THROUGH the orchestrator by
    making `fsm.dispatch` raise (the orchestrator wraps only the two record writes,
    so the raise propagates as an uncaught crash) — not a direct `record_started()`
    call. Injection point = INSIDE dispatch, before the sender fires, so
    `sender.calls == []` is the CONSEQUENCE of this point, NOT a universal necessity
    (a post-commit crash injection would leave calls non-empty; both legitimate —
    the invariant under both is the readable indeterminate started half). Rationale
    (Linus 186486): a dispatch-point crash is the UNIQUE single test that kills an
    "anchor both rows in memory, flush at completion" impl (zero rows here ⇒ red;
    completion-write injection alone leaves it green), pulling write-ordering
    discriminating power out of the three-injection composite into one test.

Fault-injection / binding tests: before-start (refuse, zero send), completion-
write (outcome_unknown + positive started-half read), after-start (real
dispatch-point crash injection ⇒ readable indeterminate half + sender zero-call),
and the join-key negative control (present-but-unbindable ⇒ absent, 4 cases).

## R5 — reproducible dependencies + fingerprint

`requirements.txt` locks every external dependency with the PyPI-published
sha256 of every wheel/sdist pip may select on either declared runtime, so
`pip install --require-hashes -r requirements.txt` installs a byte-identical set
or fails closed. Two runtime rows (Windows/AMD64/py3.10.11 + macOS/arm64/
py3.14.5) each carry OS version, architecture, interpreter path, continuous-clock
mapping (win32 UNMAPPED → fail-closed; darwin → CLOCK_MONOTONIC_RAW), and the
resolved dependency set.

**Closure correction (flagged):** the fix contract 186359 named **7** transitive
(`cffi/iniconfig/packaging/pluggy/pycparser/Pygments/sortedcontainers`). The true
closure is **11** — those 7 unconditional plus **4 marker-gated, row-1 only**,
surfaced by the `--require-hashes` boundary check (pip refused the lock until each
was pinned), not by reading a list:

  * `typing-extensions` — cryptography, `; python_full_version < "3.11"`
  * `exceptiongroup`    — pytest + hypothesis, `; python_version < "3.11"`
  * `tomli`             — pytest, `; python_version < "3.11"`
  * `colorama`          — pytest, `; sys_platform == "win32"`

Markers are copied verbatim from the parents' `requires_dist`, so ONE file is
correct on both runtimes (all four evaluate False on macOS/py3.14 and drop out).
Total external = 3 direct + 11 transitive = 14.

Both wheel sets are boundary-verified from this build: `pip download
--require-hashes -r requirements.txt` (row 1, Windows/py3.10) → EXIT 0, and the
same with `--platform macosx_11_0_arm64 --python-version 314 --abi cp314
--only-binary=:all:` (row 2 wheels) → EXIT 0. Real marker drop-out on py3.14 was
CONFIRMED on the deployment host by Jeff 186484: a clean macOS venv
`pip install --require-hashes` → EXIT 0 with the 4 row-1 markers explicitly
non-matching and dropping out, 10 packages resolved, `pip check` green. The 4
marker-gated transitives are thereby ruled real-closure-completion, NOT scope
drift (Jeff 186484 final / Linus 186486-5).

## Test counts (this build, row 1)

`python -m pytest authz/ -q` → **166 passed** (R4: 165; R4a +1 R8 exact-boundary):
+3 R7 valid-sig/unknown-enum E2E, +3 R8 stage-isolation + 1 control + 1 exact-
boundary (R4a), and the R2 two-phase set (before-start / completion-write positive-
read / after-start real dispatch-point injection / 4-case join-key negative
control) replacing the old single-phase dispatch tests.
`python -m pytest -q` (full) → **508 passed** (R4: 507; R4a +1).

## R4a — delivery-evidence shape closures (2026-09-05)

Implementation behavior was ruled fully green at R4 (Jeff 186484 second-layer +
Linus 186486 spec-authority re-verify: pins reproduce, macOS 507/507 + authz
165/165 + gateway 173/173, independent R2/R7/R8 counter-probes pass). R4a closes
the two DELIVERY-EVIDENCE SHAPES they flagged — no implementation-behavior change:
  1. **R5 fingerprint rows** now carry OS/version/arch/interpreter-exact-path for
     both runtimes (row 1 normalized `%LOCALAPPDATA%` with the account segment
     elided + limitation stated; row 2 reviewer-supplied Homebrew base executable).
  2. **R2 after-start test** rewritten from a direct `record_started()` call to a
     real orchestrator dispatch-point crash injection (see the R2 refinement bullet
     above), with the injection point stated so `sender.calls == []` reads as a
     consequence of the point, not a universal necessity. Folded into the same
     condition (Jeff 186491): the completion-write test's comment claiming a
     "memory-only impl … would LOSE the half here" is CORRECTED — Boris's mutation A
     (186490) empirically showed that impl stays green under the completion-write
     injection (it flushes the started row before the failing completion write); the
     after-start dispatch-point test is what kills it. Per Linus 186492 the wording
     traced to his own 186389 pin (self-corrected in R4 report ④), not a transcription
     error; the corrected comment states the accurate discriminating power.
Plus the non-blocking R8 exact-boundary case (Linus 186486-6). Contract remained
R2/R5/R7/R8 only; nothing else changed.

## NOT ACCEPTED

Submitted for the R1–R8+P1 re-verification. Nothing self-accepted. Frozen
baseline contracts unchanged; R2 same-transaction fold (hook 28) still deferred.
