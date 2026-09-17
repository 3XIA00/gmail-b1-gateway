# PUF-367 authz vertical slice — seam-split rebuild + 4-axis fold (2026-09-05, round 3)

> **Round-3 addendum (four frozen axes).** After the seam-split rebuild, the
> reviewers converged on four hardening axes, now folded in: **(1)** the §1
> security clock is a fail-closed **continuous-clock seam** (`clock.py`), never
> `time.monotonic`; **(2)** membership **absence attribution** splits
> `denied_revoked` (delivered revocation) from `denied_no_grant` (withheld
> artifact / dropped grant); **(3)** the digest binding is an **independent-oracle
> KAT** proving `active_grants` is inside `SHA-256(JCS(head.body))`; **(4)** the
> delivery carries D0/D1 provenance + a change log (below). See the per-axis
> sections and the R3/R9/§6/§1 findings rows.

Runnable, tested implementation of the user-signed capability authorization the
Gateway runs before every Gmail send. Rebuilt to the **frozen ruling** (Linus
msg_9e866093 §0–§8) after the sealed policy-map revision was **NOT ACCEPTED**:
the reviewers' core finding was that the previous `decide()` seam architecturally
**conflated "state sync" with "local decision"**, so swapping the stub for a real
relay would silently drop §4-1/2/3. This round splits that seam. **Stub sync +
stub decision service + Gmail stub sender + Ed25519 fixture keys + an advanceable
user-root-signed head — no real Gmail, OAuth, network, or send.**

Baseline modules (canonicalizer / store / sendfsm / actionset + the other package
trees) stay **byte-unchanged**; all authz changes live in `authz/`, plus the P1
fix in `gateway/proposal_api.py` and payload-root `requirements.txt`.

## The seam split (§0) — four steps per execution, cloud touches only ③

The old `decide()` did two incompatible jobs at once. It is now:

| step | who | what |
|---|---|---|
| ① **sync + accept** | Gateway ← untrusted relay | fetch the user-root-signed `authz_state` head, verify its sig against the **pinned user-root key**, enforce the **high-water mark** (anti-rollback, §4-2), accept + advance HW. Local safety state unreadable ⇒ **fail closed** (`denied_state_unavailable`, §4.6). |
| ② **local decisions** | Gateway | on the verified grant + accepted head, in order: **active-set membership** (§0b, revocation/supersede) → validity (+`not_yet_valid`) → validity-span cap → scope → subject proof + request-envelope freshness → consume `(grant_id, request_id)` single-use (burned **before** the cloud call). |
| ③ **cloud decision** | untrusted relay | a signed second opinion, inside a **monotonic response deadline** (§1). Late ⇒ discarded even if validly signed. Then: authenticate sig → policy-map cross-check against the **accepted head** → `decided_at` hygiene window → consume `decision_id`. |
| ④ **record** | Gateway | success audit (identity from the gate's own derivation) + the R2 dispatch record. |

**Why the split is the fix, not "add ifs":** the authority is now the
user-root-signed head (`authz.state`), not the cloud's decision. A real relay
dropped into `SyncSource`/`DecisionService` **cannot** bypass §4-1/2/3 because
those checks run on the Gateway against the head it independently verified — the
seam makes "trusted state" and "untrusted opinion" different objects.

## Active-set membership (§0b) — revocation & supersede that a relay can't hide

A grant authorizes only if `(grant_id, grant_version) ∈ head.active_grants`. The
membership check is ordered so **absence is attributed, not collapsed** (§6):

1. `grant_id` in the **per-sync `seen_revocations`** set (a user-root-signed
   `authz_revocation` artifact was delivered this sync) ⇒ `REVOKED` ⇒
   `denied_revoked`. Checked **first** so a relay that both delivers a revocation
   and leaves the grant in the head still fails closed to `denied_revoked`.
2. exact pair in `active_grants` ⇒ `ACTIVE`.
3. `grant_id` present at another version ⇒ `SUPERSEDED` ⇒ `denied_superseded`.
4. `grant_id` absent with **no** revocation artifact seen ⇒ `NO_GRANT` ⇒
   `denied_no_grant` + detail `inactive_in_verified_head`.

The §6 distinction between (1) and (4) is the point: a **delivered** revocation
attributes to `denied_revoked`; a **withheld** revocation whose head simply drops
the grant attributes to `denied_no_grant` — the Gateway never guesses "must have
been revoked" from absence alone. `seen_revocations` is a **per-sync set**, not a
persistent table (a relay cannot make an old revocation stick or vanish across
syncs; each sync re-establishes it from the delivered artifacts). Revocations
ride a closed sync envelope `{head, revocations:[…]}` — the head envelope schema
is closed, so revocation artifacts cannot be smuggled inside it.

Revocation/supersede take effect when the operator re-signs a **new head**
(monotonic `state_version` +1, changed `active_grants`, changed digest). A
malicious relay cannot supply an *acceptable* head that still lists a revoked
grant, so R9's revoke **and** supersede both disappear via one mechanism. The
head is a genuinely re-signed artifact (`HeadState`), not a frozen constant —
"revoke ⇒ digest changes" is a necessary-but-not-sufficient red line, tested.

## The security clock is the Gateway's continuous clock (§1)

- **Response deadline** = Gateway **continuous-clock** elapsed time (`clock.py`).
  Timeout ⇒ `denied_cloud_unreachable` fail-closed; a late response is discarded
  even with a valid sig; the `request_id` is already consumed, so it is dead.
- The security clock is **suspend-inclusive monotonic**, NOT `time.monotonic()`.
  `time.monotonic()` freezes across suspend on macOS/Linux, so a machine that
  sleeps between "request sent" and "decision verified" would under-count exactly
  the gap an attacker exploits (Jeff: 不要用 `time.monotonic()` 冒充合规连续钟).
  The seam dispatches by platform on an **allow-list**: Darwin →
  `clock_gettime_ns(CLOCK_MONOTONIC_RAW)`, Linux → `CLOCK_BOOTTIME`. Any
  unmapped platform (incl. `win32`) or a mapped one whose interpreter lacks the
  constant **fails closed at startup** — it never falls back to `time.monotonic`.
  `now − kern.boottime` cross-checks ride the distrusted wall clock, so they are
  **release/diagnostic evidence only** and are off the startup + authorize paths
  (Boris caveat).
- **`decided_at`** is **never** a security clock (it is the adversary's domain).
  It is only a **hygiene window** on the Gateway wall clock
  `[t_request_sent−5min, t_response_verified+5min]`; outside ⇒
  `denied_invalid_artifact` + `decided_at_out_of_window`. **No decision TTL.**

Deadline tests inject a **scripted** continuous clock (ns values), so the
assertion moves the exact variable it tests — never a real sleep (a false-green
on faster interpreters). Clock-seam tests are **non-timing**: they monkeypatch
`time` and capture the dispatched `clock_id`, and assert the seam RAISES (returns
no callable) on unmapped platforms — proving strict fail-closed, no sleeping.

## Policy map — every `Decision` field, exactly one class (preserved)

The exhaustive per-field cross-check (`authz.decision_policy`) is retained: the
Gateway independently derives every binding field from the verified grant + the
**accepted head** and compares field-by-field, and a structural assertion forces
every `Decision` field to be classified — a new field is red by default.

| class | meaning | fields |
|---|---|---|
| (a) | Gateway derives + compares exactly | `request_id`, `action_digest`, `authz_state_digest`, `grant_id`, `grant_version`, `state_version` |
| (b) | Gateway-local atomic single-use consume | `decision_id` |
| (c) | closed enum + consistent with verified grant / local result | `approval_mode`, `subject_kind`, `disposition` |
| (d) | protocol time rule (gate-enforced hygiene window, §1) | `decided_at` |
| (e) | non-authorization input, never read on the execution path | *(none this round)* |
| — | authenticator (not classified) | `sig` |

## The digest binding is a known-answer test (§4/R3)

`authz_state_digest = SHA-256(JCS(head.body))` — one byte domain, the same
canonical byte string the head signature covers, no projection (Jeff 186163).
`test_authz_digest_kat.py` pins this with a **known-answer test** whose oracle is
**independent of the code under test**:

- **paired fixtures** `B0`/`B1`, byte-identical except `B1` adds ONE unrelated
  grant `G_other` to `active_grants` (the referenced grant + `state_version` are
  byte-identical — the "green legs");
- **D0/D1** are derived test-side by a **stdlib-json oracle** (`json.dumps(
  sort_keys, separators=(",",":"), ensure_ascii=False)` → SHA-256), NOT by
  `canonicalizer.jcs` and NOT read back from the Gateway. `test_kat_constants_
  self_consistent` proves the pinned constants match that oracle;
  `test_production_digest_matches_kat` is the positive control that the code under
  test equals it. If `B0`/`B1` change, **re-derive D0/D1 independently** (never
  backfill via the digest function under test — that degrades the oracle to
  `f(x)==f(x)`).

Two-level preimage proof that `active_grants` is inside the digest:

- **function level** — `B0`/`B1` differ only in `active_grants`, yet `D0 ≠ D1`;
- **Gateway level** — a re-signed head red: the gate **syncs** head `B1` (digest
  `D1`) but the cloud decision is bound to the **old** head `B0` (digest `D0`),
  same `state_version`, grant active in both, valid signature. The only field that
  can disagree with the gate's own derivation is `authz_state_digest`, so it is
  `denied_invalid_artifact` + `decision_head_mismatch` and nothing else. A
  positive control (decision bound to `B1`) pins the five other legs green, so the
  red moves **only** the digest.

## What's here

| file | role |
|------|------|
| `state.py` | **NEW** — the authoritative head: `VerifiedHead` + `membership()` (REVOKED/ACTIVE/SUPERSEDED/NO_GRANT), closed head-body schema + fail-closed parser, the closed `authz_revocation` artifact + `{head, revocations}` sync envelope, `HeadState` (operator control plane: `revoke`/`supersede`/`add`, monotonic re-sign, signed-revocation emission), `SyncSource`/`StubSyncSource` (untrusted relay; unreachable + withhold head + withhold revocations) |
| `clock.py` | **NEW** — the §1 continuous (suspend-inclusive monotonic) security-clock seam: allow-list platform dispatch (Darwin `CLOCK_MONOTONIC_RAW` / Linux `CLOCK_BOOTTIME`), **fail-closed at startup** on unmapped platform / missing constant, never `time.monotonic`; diagnostic boottime cross-check kept off the startup + authorize paths |
| `service.py` | **rewritten** — `StubDecisionService` is the demoted **untrusted** cloud opinion (no validity/scope/subject/revoke — those are the Gateway's now); keeps `Decision` + sig, request binding, the `SingleUseConsumer` seam + `LockedConsumer`, and **`HighWaterMark`** (anti-rollback safety state) |
| `gate.py` | **rewritten** — the four-step flow: sync+accept (HW, fail-closed) → verify grant → local decisions → monotonic-deadline cloud decision → policy-map cross-check + `decided_at` window → consume → audit; returns an `Authorization` carrying monotonic offsets for R2 |
| `decision_policy.py` | the exhaustive per-field policy map + `assert_policy_covers_decision` *(state_version detail renamed; decided_at now gate-enforced)* |
| `dispatch_record.py` | **NEW** — R2 authz-domain dispatch record `{decision_id, request_id, proposal_id, action_digest, 3 monotonic offsets}`, closed token-free schema |
| `orchestrator.py` | fetches the proposal first (B1), passes `payload_digest`; writes the R2 dispatch record after dispatch |
| `errors.py` | `DenialSignal` (internal) vs `AuthorizationDenied` (coarse by construction); **+ `denied_version_regress`, `denied_state_unavailable`** and details `not_yet_valid` / `request_id_reused` / `issued_at_out_of_window` / `channel_binding_mismatch` / `decided_at_out_of_window` |
| `audit.py` | closed token-free schema *(unchanged; values now from the gate's derivation + accepted head)* |
| `capability.py` | signed envelope + grant.body parser; closed schemas *(unchanged)* |
| `gateway/proposal_api.py` | **P1 fix** — `ProposalServer.server_bind` skips `socket.getfqdn` |
| `treepin.py` / `requirements.txt` (payload root) | tree pin generator / locked deps + runtime declaration (R5) |

## Findings → resolution (frozen contract)

| # | finding | resolution | red→green test(s) |
|---|---|---|---|
| §0 | `decide()` conflates sync + local decision | seam split: `state.py` authority + `StubDecisionService` demoted; Gateway runs all local decisions | whole `test_authz_state_sync.py` + behaviors |
| R1 | `decision_id` single-use must be Gateway-side | class (b), consumed last, Gateway-side | `test_gateway_consumes_decision_id_second_feed_is_replay` |
| R2 | send must carry the decision | `dispatch_record.py`; orchestrator writes it post-dispatch (join `proposal_id`+`request_id`) | `test_authz_dispatch_record.py` |
| R3 | `state_version`+`authz_state_digest` from the SAME verified head | both derived from the accepted head; version-wrong→`decision_version_mismatch`, digest-wrong→`decision_head_mismatch`; `authz_state_digest=SHA-256(JCS(head.body))` pinned by an **independent-oracle KAT** (`active_grants` inside the preimage, fn + Gateway level) | `test_state_digest_mismatch_is_refused_red`, `test_authz_digest_kat.py` (5 legs), policy-map unit |
| R6 | `grant_id`/`grant_version` bound; identity from gate | class (a); audit identity from `vgrant`, never the decision | `test_relay_swaps_grant_id_is_denied_and_never_verified` |
| R7 | `approval_mode`/`subject_kind`/`disposition` bound | class (c) | `test_relay_swaps_approval_mode_to_auto_is_denied_no_send` |
| R8 | request map: `(grant_id,request_id)` consume + freshness | Gateway consume (replay axis `request_id_reused`); agent_key `issued_at`±5min + channel echo | `test_authz_request_map.py`, `test_replayed_request_is_rejected` |
| R9 | revoke **and** supersede | active-set membership (§0b) | `test_revocation_changes_digest_and_denies_membership`, `test_supersede_denies_old_version_via_membership` |
| §6 | absence attribution: revoked vs never-granted must not collapse | ordered membership: delivered revocation artifact→`denied_revoked`; withheld artifact + head drops grant→`denied_no_grant`+`inactive_in_verified_head`; `seen_revocations` a per-sync set, revocation checked first. Each separated red **self-asserts its sync set** pre-run (deliver has G's revocation, withhold does not) — a fixture-leak defense (Boris 186211-1/Jeff 186212) | `test_membership_revoked_when_revocation_artifact_seen`, `test_red_a_revocation_artifact_delivered_is_denied_revoked`, `test_red_b_revocation_artifact_withheld_is_denied_no_grant`, `test_membership_revocation_wins_even_if_head_still_lists_grant` |
| leg② | supersede is tuple-granular, not id-granular (carried, not an isolation vector) | membership keys on `(grant_id, grant_version)`; a version bump alone flips old→`SUPERSEDED` / new→`ACTIVE`, so a stale version can't pass as active on an advanced head (Linus 186258 / 测试姬 186151) | `test_membership_is_tuple_granular_not_id_granular`, `test_supersede_denies_old_version_via_membership` |
| §4-2 | anti-rollback | high-water mark; synced version < HW ⇒ `denied_version_regress` | `test_synced_head_below_high_water_is_version_regress` |
| §4.6 | local safety state lost ⇒ fail closed | `denied_state_unavailable` on HW/consumer failure | `test_*_failure_fails_closed` (×3) |
| §1 | continuous-clock deadline; `decided_at` hygiene only; no `time.monotonic` | `clock.py` allow-list dispatch (Darwin `CLOCK_MONOTONIC_RAW` / Linux `CLOCK_BOOTTIME`), fail-closed at startup on unmapped platform / missing constant; scripted-ns deadline; wall-clock hygiene window | `test_authz_clock.py` (non-timing dispatch + fail-closed), `test_authz_request_map.py::test_response_*`, `test_security_clock_is_monotonic_not_decided_at` |
| R4 | outage not one-shot | continuous deny, no cache | `test_repeated_outage_is_continuously_denied_no_cache` |
| R5 | deps + runtime declared | `requirements.txt`: `requires-python >=3.10,<3.15`, exact pins | declaration |
| P1 | py3.14/macOS `getfqdn` bind stall | `server_bind` override skips `getfqdn` | `test_server_bind_never_calls_getfqdn` (non-timing) |
| structural | new `Decision` field could go unverified | `assert_policy_covers_decision` | `test_policy_map_covers_every_decision_field` |

## Reproduce

From the payload root (`gmail-gateway/`; `PYTHONPATH` = payload root). External
deps are locked in `requirements.txt`.

```
python -m pytest authz/ -q      # this slice — needs only cryptography + pytest
python -m pytest -q             # whole payload regression — also needs hypothesis
```

## Actual output (self-reported 2026-09-05, Windows, CPython 3.10.11, pytest 9.0.3)

```
$ python -m pytest authz/ -q
150 passed              # 128 seam-split + 12 clock seam + 4 membership-isolation
                        #   + 1 supersede tuple-granularity + 5 digest KAT

$ python -m pytest -q
492 passed              # baseline unchanged + authz + P1 counterfactual
```

No xfail: the prior `decided_at` xfail is retired — the rule is now enforced as
the §1 hygiene window (`test_stale_decided_at_is_refused_by_hygiene_window`).

## Two-part provenance

**(1) Tree pin — which bytes.** `treepin.py` at the payload root: each manifest
line `<sha256-hex><two spaces><relative-posix-path>`, ordered by UTF-8 path
bytes; pin = `sha256` over manifest bytes. Root-independent; fail-closed on
symlink / non-regular / newline-in-path / empty set. `full` = whole payload;
`src` excludes any-depth `tests/`; `py` = `*.py`. `treepin.py` is itself in
`full`. **The three pin values + the `treepin.py` sha are published in the
delivery message, not here** (this file is inside `full`).

Verifier trust-root order: compute the pin with **your own** audited `treepin.py`
over the unpacked payload first; then confirm the in-package `treepin.py` hash
appears in `full`. The in-package script is a regression convenience, not
independent attribution evidence.

**(2) Runtime fingerprint — who executes.** Every field is either a declared
value or an explicit `未声明`; **no third-party backfill**.

| field | value |
|---|---|
| OS family | Windows (self-reported) |
| OS specific version | Windows 11 Home China 10.0.26200 (self-reported) |
| arch | 未声明 |
| implementation | CPython (self-reported, not inferred from "Python") |
| exact version | 3.10.11 (self-reported) |
| deps + lock | `cryptography==50.0.0`, `pytest==9.0.3`, `hypothesis==6.165.10` (exact pins) |
| deployment-host interpreter | macOS Homebrew CPython 3.14.5 (borrowed, doc-tier) — **3.14 bring-up smoke: 未声明** |

Each evidence row above is **self-reported**; none is independently reproduced in
this delivery. R5 clean-env reproduce on 3.14 is the verifier's to run.

## Known deviations / pending

1. **R2 same-transaction fold is deferred to hook 28.** The dispatch record lives
   in the authz domain now; embedding it in `store/ledger.py` + `sendfsm/fsm.py`
   (same store transaction as `dispatch_committed`, §4-4) would edit the frozen
   0-change baseline. **Interface change, not a drop-in swap.** The
   `consume_once` seam and the new Gateway-side consumers are shaped for it.
2. **§4.5 T_fresh withholding gap is lease-off.** `StubSyncSource.pin_and_withhold`
   models a relay hiding a newer head; with no freshness lease there is no *time*
   bound that closes it — but the **high-water mark** closes the rollback case
   (a withheld older head below HW is `denied_version_regress`). The pure
   never-saw-the-newer-head case remains open (deferred, no time bound this cut).
3. **os_account peer resolution is a STUB, not a kernel check.** Re-resolved per
   request via an injectable resolver; never recorded as "kernel verified".
4. **Cert-authorized auto-send drives `fsm.confirm` as `Actor.HUMAN`.** A verified
   `approval_mode=auto` grant is the human's cryptographic authorization; a
   first-class Gateway confirm actor is booked to hook 28.
5. **NOT self-accepted.** This is submitted for the blocking R1–R9 + P1
   re-verification (Tester/Boris re-run the three verification tables); the prior
   NOT-ACCEPTED stands until they clear it.

## Deferred (NOT in this cut, per schema §7)

Freshness lease / real challenge-echo transport, real OAuth, the `per_call`
approval workflow, timing-side-channel quantification, real kernel peer
credentials, and the hook-28 same-transaction consume↔dispatch + first-class
confirm actor.
