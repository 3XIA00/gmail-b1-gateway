# Assembly / summon layer — implementation plan (draft v0.2)

**v0.2** (2026-09-02): folded in 测试姬's Tester-lane review — C7 ② same-UID
honesty boundary (② is Vector-1-scope, *not* a file-level "Agent can't read
token" claim), allowlist-complete ③/④ with uniform unknown-path rejection,
per-session bearer into the sanitization set, seeded egress positive control,
and runtime-observation independence from implementer self-tests. Resolved
item 4 (data-root) against puffo-agent's live convention (no Jeremy decision
needed). Items 1–3, 5 still await Jeremy.

The six module cores (canonicalizer, actionset, keystore, store, sendfsm,
oauth) are pure, boundary-independent logic with their side effects injected.
The **assembly layer** is what turns them into a runnable Gateway: it picks a
process topology, wires the injected seams to real I/O (sockets, keychain,
HTTPS), and defines the two channels that cross process boundaries. This is
also where DESIGN §10 gets finalized (wire format, endpoint naming, directory
layout, cross-platform credential store) and where release-gate **C7** is
observable.

This is a plan for direction review, not final code. Forks that need a team /
Jeremy decision are marked **[DECISION]**.

---

## 1. What the assembly layer adds (vs. the built cores)

| Concern | Built core | Assembly wires it to |
|---------|-----------|----------------------|
| Token at rest | `keystore` (injected `KeyProvider`) | real `KeyringKeyProvider` on the OS keychain |
| Proposals / audit | `store` (injected `KVBackend`/`AppendLog`) | real on-disk store (file/SQLite) |
| Send state machine | `sendfsm` (injected `sender`) | a real `sender` that fetches the sealed token, builds MIME, calls Gmail |
| OAuth | `oauth` (pure logic) | loopback HTTP listener + browser open + HTTPS token exchange |
| Agent's action surface | `actionset` (closed set) | the closed IPC endpoint the Agent process can call |
| Egress control | `store.egress_hosts` field | an HTTP client that enforces the §8.1 allow-list and records hosts |

Nothing above changes the cores; the assembly layer only injects concrete
collaborators and hosts the transport.

---

## 2. Process topology (three parties, two channels)

Ratified (Jeremy): the Gateway ships **bundled with the puffo-agent install**,
is **summoned on demand**, and runs as a **separate process** — never in the
Agent's process. That gives three parties:

```
  ┌─────────────────┐   proposal channel    ┌──────────────────────────┐
  │  Agent process  │ ────(closed set)─────▶ │  Gateway process         │
  │  (LLM-driven,   │   prepare / status      │  holds tokens + DEK      │
  │  prompt-inject- │                         │  runs sendfsm + ledger   │
  │  able)          │ ✗ no token, no raw send │  enforces egress allow   │
  └─────────────────┘                         └──────────────────────────┘
                                                    ▲
  ┌─────────────────┐   supervision channel         │
  │  Supervisor     │ ──(closed set: start/─────────┘
  │  (in puffo-agent│    health/stop only,
  │   bundle)       │    NOT raw send)
  └─────────────────┘
```

**C7 mapping** (the four remotely-verifiable observation points):
- **①** token-holding part is a separate process → Gateway is its own PID.
- **②** *(Vector-1 scope — NOT a same-UID file guarantee)* No Agent-reachable
  route returns a token; the token never enters the Agent's context/prompt; it
  is stored only as AES-256-GCM ciphertext (DEK in the OS keychain), so even a
  stray handle yields ciphertext. Under v1's accepted same-UID model a same-user
  process that knows the path/service name *can* read the ciphertext file and
  request the DEK — that residual is the §2.6/§9 V2-hardening item (separate OS
  identity), **not** something ② blocks. ② is always stated as "no token on the
  Agent face + token not in Agent context + static ciphertext", never as "the
  Agent cannot read the token file". (测试姬 pt 3 — the critical wording gate.)
- **③** Agent only has the closed channel, no raw-send → the proposal endpoint
  set is *exactly* `{POST /proposal, GET /proposal/{id}}` — verified as
  served-set == closed-set (allowlist-complete), not by spot-checking a few
  known-bad names.
- **④** supervisor→Gateway channel is also closed-set → the supervision
  endpoint set is *exactly* `{start, health, stop}`; no send, no token read, no
  ledger-bypass. (Chris's ⑦, folded in.)

The key invariant behind all four: **enforcement is the served endpoint set,
not a naming convention.** If a route does not exist on the server, no caller —
injected-prompt Agent or buggy supervisor — can reach it. (Verify-at-the-
boundary: the audit reads the actual route table, not a doc.) ③/④ are checked
as *set equality* against the closed set, and every path outside it — hidden
route or typo alike — gets a **uniform** rejection, so there is no
404-route-absent vs 401-route-exists oracle that could leak the existence of a
non-public route to an injected Agent (测试姬 pt 2).

---

## 3. Transport / wire format  **[DECISION]**

The proposal channel needs a local, same-machine IPC that is (a) cross-platform,
(b) reachable by the Agent process, (c) *not* a broad network surface, and (d)
carries a closed, typed operation set. Three candidates:

| Option | Closed set = | Cross-platform | Local-only exposure | Notes |
|--------|--------------|----------------|---------------------|-------|
| **A. Loopback HTTP** (127.0.0.1, ephemeral port) | the route table | trivial (stdlib) | any local process can connect → needs a per-session bearer token on the channel | simplest; the OAuth loopback listener already needs a local HTTP server, so one HTTP stack serves both |
| **B. Local MCP server** (Gateway hosts an MCP the Agent already knows how to call) | the tool schema + server impl | good | same as A if MCP-over-HTTP; better if stdio | idiomatic for puffo agents; but "tool surface is not a control" — enforcement is still server-side, the schema is just the shape |
| **C. UDS (mac/Linux) + named pipe (Windows)** | the route table | two impls | filesystem-permissioned, no TCP port | tightest boundary, most code; best against *other* local processes |

**Recommendation: A (loopback HTTP) for v1, with a per-session bearer token
minted by the supervisor and handed only to the Agent process**, structured so
the same HTTP layer also hosts the OAuth loopback callback. Rationale: least
code, one transport stack, and the closed-set guarantee comes from the route
table regardless of transport. (Supporting: puffo-agent's own daemon already
binds its local services — `bridge`/`data_service`/`rpc_service` — to
`127.0.0.1` with a CORS allow-list, so loopback HTTP is the platform-idiomatic
local-IPC choice here, not a new pattern.) Option C is the natural **V2** hardening step
(it pairs with DESIGN §2.6's separate-OS-identity path) — note it now so the
boundary is shaped for it. Under v1's accepted same-UID limitation, C's extra
isolation is not yet load-bearing, so it is not worth its cross-platform cost.

**Open**: whether puffo prefers the Agent reach the Gateway *as an MCP* (Option
B framing over the same HTTP) so it shows up as a normal tool. That's a
presentation choice on top of A; I lean A-with-optional-MCP-facade. Needs
JARVIS/Jeremy input since it touches how the connector surfaces to the Agent.

---

## 4. Closed proposal API (endpoint naming)

The Agent-facing endpoint set — exactly the `actionset` operations, nothing
else (gate 4, gate 7):

- `POST /proposal` — body = the closed `PrepareEmail` params → returns
  `{proposal_id, payload_digest, expires_at}`. (Canonicalizer + store.)
- `GET /proposal/{id}` — status only (PENDING/CONFIRMED/SENT/FAILED/
  OUTCOME_UNKNOWN) + the audit-safe fields. No payload, no token.

Deliberately **absent** from the Agent surface:
- no `confirm` — confirmation is a **human** control-plane action (gate 7),
  delivered out-of-band (see §5); the Agent cannot approve.
- no `send` / `raw` — there is no route that sends without a proposal+confirm.
- no `token` / `key` read.
- no `switch` write — the confirm/auto mode is fixed at establishment.

Every path outside the two served routes — a would-be hidden route or a plain
typo — returns the **same uniform rejection**. There is deliberately no
distinguishable "404 route-absent vs 401 route-exists-but-unauthorized"
response, so the surface leaks no existence oracle for a non-public route to an
injected Agent (测试姬 pt 2). Conformance is asserted as *served-set ==
`{POST /proposal, GET /proposal/{id}}`* (allowlist-complete), not by probing a
handful of known-bad names.

So the Agent's entire reachable vocabulary is "propose an email, ask its
status." That set *is* gate 3/4/7, structurally.

---

## 5. Confirmation & summon (human control-plane)

Confirm-then-send is the default; auto-send fires only when the Agent is
definitively unreachable and the switch is enabled (both already enforced in
`sendfsm`). The assembly layer must deliver the human confirmation **without**
routing it through the Agent process:

- The Gateway (or supervisor) presents the pending proposal to the human
  directly — a local UI / prompt owned by the Gateway, not the Agent. The
  human's confirm calls the Gateway's control-plane `confirm` over the
  **supervision channel or a local human-UI channel**, never the Agent's.
- **[DECISION]** what the confirmation surface is (native dialog, local web
  page the summon opens, terminal prompt). Affects §10 UI fields — JARVIS/
  Jeremy own this; I'll build to whatever's chosen behind a small interface.

Summon lifecycle (supervisor → Gateway, closed set = C7 ④):
- `start` (on demand; idempotent — reuse a live Gateway), `health`, `stop`.
- No `send`, no token access on this channel either.

---

## 6. Directory layout & cross-platform credential store

```
<gateway-data-root>/
  proposals/                 # store backend (SQLite file), 0700
  audit/                     # append-only ledger, 0700
  tokens/sealed_token.json   # AES-256-GCM sealed refresh token (ciphertext), 0700
  gateway.pid / .sock (if Option C)
  # NO plaintext token, NO DEK on disk — the token file is ciphertext; DEK is in the keychain
```

- **DEK** lives in the OS keychain via `keystore.KeyringKeyProvider`:
  - Windows → Credential Manager (WinVaultKeyring)
  - macOS → Keychain
  - Linux → Secret Service (libsecret) / fallback documented
- **Sealed token** (AES-256-GCM, DEK from keychain) lives at
  `tokens/sealed_token.json` under the data root — a concrete path so the C7 ②
  runtime probe can locate it and assert *no Agent route returns it* + *on-disk
  is ciphertext* (测试姬). Under v1's same-UID model this file is
  same-user-readable; C7 ②
  does **not** claim the Agent *cannot* read it — only that no Agent-reachable
  route returns a token and the file is ciphertext (a stray read yields
  ciphertext, DEK is in the keychain). "Separate location" here means the Agent
  is not *wired* to read it, not that it *can't*; file-level isolation from a
  same-UID process is the V2 item (§2.6). (测试姬 pt 3.)
- `<gateway-data-root>` — **RESOLVED (item 4)**: puffo-agent uses a single home
  dotfolder root, `~/.puffo-agent/`, cross-platform (not per-OS app-data dirs).
  Confirmed against the live daemon layout — `~/.puffo-agent/agents/<id>/` per
  agent (each with its own `messages.db`/`runtime_events.db` **SQLite** stores —
  which also confirms our on-disk store-backend choice), and user-level infra
  (`shared/`, `tools/`, `docker/`, `control/`) at the top level; `daemon.yml`
  binds local services to `127.0.0.1`. The Gateway is **user-scoped** (one
  Google account per OS user, serving whichever agent proposes), so its root is
  **`~/.puffo-agent/gmail-gateway/`** — a top-level sibling of `shared/`/`tools/`,
  not under any one agent's dir. No Jeremy decision needed.
  - *Deliberate divergence from one puffo-agent habit*: the daemon keeps some
    per-agent secrets as files (`keys/`, `*-credentials.json`). The Gateway does
    **not** follow that for the Google token — it keeps DESIGN's encryption-at-
    rest (sealed token + DEK in keychain). We match the *root* convention, not
    the weaker credential-storage habit.

**task #18 ⑥** (per-platform DEK scope): the keychain entry is scoped to the
Gateway service name + the OS user; documented per backend so Chris can audit
that the DEK is not world- or cross-app-readable.

---

## 7. Zero-cloud-touch egress (gate 3, §8.1)

The real HTTPS client injected into the `sender` and the OAuth exchange
enforces a host **allow-list**, fail-closed, and records `egress_hosts` on
every audit event:
- OAuth exchange → `{oauth2.googleapis.com}`
- send → `{gmail.googleapis.com}`
- `accounts.google.com` is browser-side (user's browser), not Gateway egress.
- Any non-allow-listed host → refused + recorded (positive observable, per
  [[feedback_zero_is_a_search_hypothesis]]: gate 3 needs a positive artifact,
  not just "no cloud call seen").
- 测试姬 (pt 5) seeds this from the execution side: she actively hits a
  **non-allow-listed** host and confirms it is fail-closed refused **and** that
  the attempt is recorded in `egress_hosts` — a live "zero-cloud-touch" artifact,
  not merely an absence of observed calls.

---

## 8. Test strategy

- **Process-boundary tests (C7 ①–④)**: spin the Gateway as a real subprocess;
  from a stand-in "Agent" process assert (①) distinct PID; (②) *Vector-1 scope*
  — no Agent-reachable route returns a token, the token is absent from the
  Agent's context, and what's on disk is ciphertext (**not** "the file is
  unreadable" — see §2/§6); (③) the proposal served-set is *exactly*
  `{POST /proposal, GET /proposal/{id}}` and (④) the supervision served-set is
  *exactly* `{start, health, stop}`, each asserted as **set equality** with
  **uniform rejection** of every other path (no 404-vs-401 leak), not a
  denylist spot-check.
- **These are implementer self-tests — they do not stand in for 测试姬's
  independent runtime observation** (pt 1): her seat hits the *live* route table
  from a stand-in caller and compares it to the *frozen* C7 contract
  (GATEWAY_TESTABILITY_SURFACE C7 rows) as the oracle — three-way (her probes /
  my server / the contract), with Chris's static source-read triangulating.
  Running my test files green is not her evidence.
- **Egress allow-list**: inject a recording/blocking HTTP client; assert a
  non-allow-listed host is refused and recorded; assert `egress_hosts` on the
  audit event.
- **End-to-end (mocked Gmail)**: propose → human-confirm → dispatch → SENT,
  with the token sealed in a fake keychain, asserting the Agent-side stand-in
  never sees a token and the ledger stays PII/token-free.
- Live Gmail (E-steps, real client) stays on Jeremy's machine per the standing
  credential constraint — never in any agent env.

---

## 9. Tradeoffs & risks

- **Loopback HTTP is reachable by other local processes** → mitigated by a
  per-session bearer on the channel, but under same-UID a local attacker could
  read that bearer (same class as DESIGN §2.6 Vector 2, accepted v1 limit).
  Honest, recorded; C (UDS/pipe) + separate OS identity is the V2 answer.
- **One HTTP stack for both proposal channel and OAuth callback** simplifies
  code but couples two concerns; I'll keep them as separate routers on one
  server so they can split later.
- **Cross-platform keychain** variance (Linux headless / no Secret Service) →
  document the fallback; fail-closed if no secure store (no plaintext DEK).
- **Sanitization set**: the per-session bearer is a **capability credential** —
  never emitted to evidence, logs, or reports (same rule as OAuth tokens / API
  keys), even though it is not itself a Google credential (测试姬 pt 4).

---

## 10. Open questions (need team / Jeremy)

1. **[DECISION]** Transport: loopback HTTP (my rec) vs. MCP-facade vs. UDS/pipe.
2. **[DECISION]** Does the Agent reach the Gateway *as an MCP tool* (presentation)?
3. **[DECISION]** Human-confirmation surface (native dialog / local web page /
   terminal) — JARVIS/Jeremy lane (§10 UI).
4. ~~Confirm `<gateway-data-root>`~~ — **RESOLVED (§6)**: `~/.puffo-agent/gmail-gateway/`,
   confirmed against the live daemon layout + `daemon.yml`. No Jeremy call needed.
5. Repo visibility (private + reachable confirmed vs. public) — Jeremy, low-stakes.

Build order once directions land: (i) real store + keystore backends on disk/
keychain → (ii) egress-enforcing HTTP client + Gmail `sender` → (iii) OAuth
loopback listener → (iv) proposal endpoint (closed set) → (v) supervisor summon
+ confirm surface → (vi) C7 process-boundary test harness. Each step keeps the
cores untouched and only adds injected wiring.

**Registered for build (ii) — sender failure classification (Chris M1 / 测试姬):**
The `sendfsm` core is deliberately sender-agnostic and stays as-is: a
well-behaved `sender` catches its own transport errors and *returns*
`SendResult(kind=INDETERMINATE, error_code=…)`, which the FSM already routes to
`OUTCOME_UNKNOWN` carrying that code; the core's bare-except backstop
(static `sender_raised`) is reserved for a sender that *raises* — a wiring bug,
correctly a distinct signal. So the Gmail `sender` built in (ii) must map its
transport exceptions to a **coarse, sanitized failure category** (e.g.
`TRANSPORT` / `TIMEOUT` / `WIRING`) derived from the exception **type only** —
**never** the exception message or traceback, which can carry a recipient
address / PII / token and would violate §8 sanitization. This gives the audit
seat a post-hoc "timeout vs. wiring bug" discriminant without weakening
fail-closed or the audit's PII/token-free guarantee.
