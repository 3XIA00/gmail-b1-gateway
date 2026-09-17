# Gateway assembly layer

The concrete process/IO wiring around the boundary-independent cores. The
cores (`canonicalizer`, `actionset`, `keystore`, `store`, `sendfsm`, `oauth`)
are pure logic with side effects injected; this package supplies those side
effects. It is built out over ASSEMBLY_PLAN steps (i)–(vi).

## Landed

**Step (i) — on-disk persistence** (`persistence.py`):

| Class | Implements (store seam) | Backs |
|-------|-------------------------|-------|
| `SqliteKV` | `KVBackend` | proposals + idempotency index |
| `SqliteAppendLog` | `AppendLog` | closed-schema audit ledger |

Design decisions (the *why*):

- **Durability = WAL + `synchronous=FULL`.** This is a send gateway: the
  `SEND_ATTEMPTED` audit row must be fsync'd *before* the network send, so a
  crash mid-send leaves evidence, never a silent gap. Volume is low; the cost
  is irrelevant.
- **Append-only by construction.** `SqliteAppendLog` exposes only `append` /
  `entries` — no update or delete — so the ledger cannot be rewritten through
  it, mirroring the upstream closed-schema guarantee.
- **One connection + lock, explicit `close()`.** The later loopback HTTP server
  may be multithreaded (`check_same_thread=False` + a `Lock`); an open SQLite
  file is locked on Windows, so both classes are context managers.
- **Values are JSON.** Both upstream `to_dict()` shapes are already JSON-native
  (enum→str, tuple→list), so the round-trip is lossless and copies inherently.

The backends take an injected `db_path`; the data-root wiring
(`~/.puffo-agent/gmail-gateway/` → `proposals/`, `audit/`) is finalized when the
summon/entrypoint lands (step v/vi).

**Step (ii) — egress-guarded HTTP client + Gmail sender** (`egress.py`,
`gmail_sender.py`):

| Class / fn | Role |
|------------|------|
| `EgressGuardedClient` | refuses any host outside the injected allow-list (and any non-HTTPS URL) fail-closed, records the host contacted (gate 3 / §8.1) |
| `GmailSender` | the concrete `sendfsm` `sender`: approved canonical payload → `users.messages.send` → `SendResult` |
| `build_raw_message` | canonical payload → deterministic RFC 5322 bytes |

Design decisions (the *why*):

- **Egress is a generic guard, allow-list injected.** One client serves the
  send path (`{gmail.googleapis.com}`) and, later, the OAuth exchange
  (`{oauth2.googleapis.com}`). A blocked host is *recorded* (a positive
  zero-cloud-touch artifact), not silently skipped. Redirects are never
  followed (an off-host redirect would bypass the allow-list). The wire call is
  an injected `transport` seam, so all guard logic is tested without a network.
- **Failure codes from status / type only (M1).** `2xx`→ACCEPTED, `4xx`→REJECTED
  (definitely not sent), `5xx`/`3xx`/timeout/transport→INDETERMINATE (outcome
  unknown, no retry). The code is a pure function of the HTTP **status** or the
  exception **type** — never a response body / exception message / traceback,
  which could carry a recipient address, PII, or token (§8 sanitization).
  Transport errors are *caught and returned* as INDETERMINATE; the FSM's
  bare-except backstop stays reserved for a genuine wiring bug that raises.
- **Deterministic, faithful MIME (gate 7b).** `build_raw_message` is a pure
  function of the payload (no Date / Message-ID / boundary), so what is shown is
  byte-identical to what is sent. `From` is omitted — Gmail stamps the
  authenticated account. A last-line `enforce_v1_send_policy` guard fails closed
  before the wire if a non-v1 payload ever reaches the sender.

The `payload_provider` / `token_provider` are injected seams; binding the
payload to the *confirmed* digest lives in steps (iv)/(v).

**Step (iii) — OAuth loopback listener + token exchange** (`oauth_listener.py`):

| Class / fn | Role |
|------------|------|
| `LoopbackOAuthFlow` | runs the browser consent flow on a 127.0.0.1 ephemeral-port listener; returns a `TokenResult` |
| `TokenResult` | the exchange result; `__repr__` redacts both tokens |

Design decisions (the *why*):

- **Wraps the pure `oauth` core with only its three excluded side effects** — a
  loopback socket, a browser open, and the egress-guarded HTTPS token POST.
  Sealing/persistence stay downstream, so the boundary is exactly "run consent,
  return tokens".
- **Forged-callback + CSRF.** The core's `extract_authorization_code` checks
  `state` before the code, so a mismatched callback is rejected before its code
  is trusted (and before any exchange). The redirect URI is re-validated as
  loopback by `AuthorizationRequest` (gate 2).
- **No secret-in-logs.** The callback query string carries the authorization
  code, so the handler's default stderr request-logging is silenced, and
  `TokenResult.__repr__` redacts the tokens — neither can leak via a log line or
  traceback (§8). The token exchange goes through the injected
  `EgressGuardedClient` pinned to `{oauth2.googleapis.com}` (gate 3); a non-2xx
  surfaces the provider's short `error` code only, never the body.

**Step (iv) — closed Agent-facing proposal endpoint** (`proposal_api.py`):

| Class / fn | Role |
|------------|------|
| `ProposalService` | transport-independent propose / status / payload-load over the injected stores + clock |
| `ProposalServer` / `_ProposalHandler` | loopback HTTP wrapping the service; per-session bearer; served-set == closed-set |
| `mint_session_bearer` | fresh per-session capability token (supervisor mints it, step v) |

Design decisions (the *why*):

- **The Agent's entire vocabulary is "propose an email, ask its status."** The
  served routes are *exactly* `{POST /proposal, GET /proposal/{id}}`. No
  confirm, send/raw, token/key, or switch route exists — so gates 3/4/7 are
  structural: a route that is not served cannot be reached by any caller, an
  injected-prompt Agent included. `propose` runs the closed `actionset`
  projection, so an out-of-schema field / non-empty attachment slot fails closed
  *before* anything is persisted.
- **Uniform rejection — no route-existence oracle** (测试姬 pt 2). Every
  unserved path/method **and** every request without the valid session bearer
  gets one identical 404. There is deliberately no 404-route-absent vs
  401-route-exists distinction, so an injected Agent cannot probe for a
  non-public route. (A 400 for a malformed body is only reachable *after* the
  bearer check, i.e. only by the legitimate token-holder.)
- **Content is frozen off the audit/proposal records.** The canonical payload
  (recipients/subject/body = PII) is stored in a *separate* content store, never
  in the digest-only `Proposal` record or the token/PII-free ledger; no Agent
  route returns it. `get_status` exposes only digest + status + timestamps. The
  stored canonical's digest is asserted equal to the digest handed to the Agent
  (gate 7b byte-fidelity groundwork); the content store is the sender's
  `payload_provider` seam for step (v).
- **Bearer is a capability credential** — constant-time (`hmac.compare_digest`),
  never logged (request log silenced; the body carries PII), never echoed.

**Step (v, part) — confirm + dispatch send path** (`send_path.py`, + the
`POST /proposal/{id}/confirm` route in `proposal_api.py`):

| Class / fn | Role |
|------------|------|
| `SealedTokenStore` | OAuth token at rest (keystore AEAD ciphertext); the sender's `token_provider` seam — never on any Agent route (C7 ②) |
| `RefreshingTokenProvider` | Returns the current access token or refreshes it before expiry through an OAuth-only egress client; never sends or rebuilds a proposal |
| `ConfirmDispatcher` | Agent-relay confirm (Option B): `fsm.confirm(HUMAN)` on the relay, then `fsm.dispatch` through `GmailSender` |

Design decisions (the *why*):

- **Option B / gate-7 relaxed-for-POC.** Under the Agent-relay confirm, the
  Gateway marks the approval `Actor.HUMAN` on the strength of the Agent's relay,
  so it **cannot** cryptographically distinguish a genuine human confirmation
  from a forged one (gate 7(a) approval-authenticity, not in effect), nor
  guarantee the human saw the exact sent bytes (gate 7(b) content-fidelity /
  WYSIWYS, not in effect). Accepted for POC by Jeremy at
  `msg_bea7d785…`, to be tightened before broader use (Option A, the first-class
  Gateway-identity confirm surface). This is documented in DESIGN §2.6/§9 and
  carried as a load-bearing comment in `send_path.py`. **Mounting the confirm
  route is opt-in** (`ProposalServer(confirm=…)`) — omit it and the Agent
  surface is the pure step-(iv) closed set with no confirm route at all.
- **Token stays ciphertext, off every Agent route (C7 ②).** `SealedTokenStore`
  seals the token via the keystore AEAD (DEK in the OS keychain); `access_token`
  is a Gateway-internal seam handed only to `GmailSender`. No Agent-facing
  endpoint returns a token; what's at rest is ciphertext; open fails closed with
  no plaintext fallback on tamper / missing DEK / missing record.
- **Refresh changes credentials, not authority or content.** The authorization
  response timestamp and `expires_in` are sealed as an absolute expiry. Before
  Gmail is contacted, the token provider refreshes within a 60-second skew,
  serializes concurrent callers for the connection, and atomically re-seals the
  new access token while preserving the refresh token when Google does not
  rotate it. Refresh uses only `oauth2.googleapis.com`; scope changes fail
  closed. It neither seeds nor edits a proposal and does not retry a Gmail 401.
  A pre-refresh-schema record requires one new authorization to acquire the
  sealed expiry/client metadata; later sends refresh without user interaction.
- **No second send.** `confirm_and_dispatch` raises the FSM/store transition
  errors unchanged; a settled proposal (or an OUTCOME_UNKNOWN one — gate 8)
  cannot be re-dispatched, so a re-issued confirm is a 409, never a second wire
  call.

`test_token_refresh.py` and the CLI integration tests cover fresh-token reuse,
pre-expiry refresh, refresh-token preservation, exact-scope rejection,
single-flight concurrency, the legacy-record reauthorization boundary, and the
critical negative case: refresh failure makes zero Gmail calls.

**Step (v-b) — supervisor summon** (`supervisor.py`, `entrypoint.py`):

| Class / fn | Role |
|------------|------|
| `GatewaySupervisor` | the closed `{start, health, stop}` summon channel over the Gateway subprocess (C7 ①/④) |
| `gateway.entrypoint` | the summoned process: assembles the closed proposal set over the on-disk backends and reports its port |

Design decisions (the *why*):

- **The Gateway is summoned as a distinct OS process (C7 ①).** `GatewaySupervisor`
  spawns `python -m gateway.entrypoint`, so the credential-holding Gateway never
  shares a process with the supervisor (or, later, the Agent). The child reports
  only its ephemeral port on stdout; the per-session proposal bearer is minted by
  the supervisor and passed *in* via the environment — never a log line or the
  handshake — then returned once to the caller to configure the Agent.
- **The supervision channel is a closed OS-level set (C7 ④).** `{start, health,
  stop}` are spawn / poll+TCP-liveness / terminate — none is a Gateway *request*,
  so structurally none can send, read the credential, or write the ledger; the
  module references none of that machinery (a source-scan test positive-controls
  the claim). `start` is idempotent (a live child is reused) and fails closed —
  killing the child — on a ready-timeout, an early exit, or a malformed handshake.
- **Fail-closed bring-up.** The entrypoint refuses to start without a bearer, and
  a hard `stop()` on Windows (TerminateProcess, no signal handler) loses no
  committed audit row because the SQLite backends run WAL + `synchronous=FULL`.

## Tests

115 tests. Persistence (14, `test_persistence.py`) drives the **real**
`ProposalStore` / `AuditLedger` against the SQLite backends (idempotency /
expiry / append-order / closed-schema unchanged), plus reopen-persistence, a
hypothesis JSON round-trip, a WAL+FULL durability read-back, and idempotent
delete. Step (ii) (29, `test_egress.py` + `test_gmail_sender.py`)
covers allow-list fail-closed (incl. a hypothesis host property, case-normalised
matching, and a broken-error-body-read guard), the full
status/type→`SendResult` table with sanitized codes, deterministic/faithful MIME,
and **real `SendFSM` integration** driving a proposal to SENT / OUTCOME_UNKNOWN
with a token-free ledger. Step (iii) (14, `test_oauth_listener.py`) drives the
**real** in-process loopback server (a fake browser GETs the redirect as Google
would; a fake egress transport stands in for the token endpoint): happy flow
with **end-to-end PKCE binding** (the exchanged verifier S256-hashes to the shown
challenge), state-mismatch / provider-error / missing-code rejection, sanitized
exchange-failure, timeout, token-redacting repr, callback-path isolation,
first-value-per-key callback capture, a loopback-only bind guard, an
OAuth-host-scoped egress assertion, and an injected `on_redirect_uri` observer
firing with the bound loopback+ephemeral-port redirect before the browser opens
(the CLI prints it for consent-page verification). Count is now 15.
Step (iv) (13, `test_proposal_api.py`) covers the service (closed-schema
fail-closed-before-write, v1 attachment reject, idempotent replay, audit-safe
status with no PII, content freeze, orphan-payload cleanup on a lost idempotency
race) and the **real** loopback HTTP boundary:
propose/status round-trip, wrong/absent bearer indistinguishable from an unknown
route (identical 404 + body), served-set == closed-set (a method×path probe grid
all 404 even *with* the bearer, including exotic verbs TRACE/FOOBAR — the
no-route-oracle property holds on the method axis, not just the path), and
400-not-404 for a malformed body. Step (v)
(13, `test_send_path.py`) covers `SealedTokenStore` (ciphertext-at-rest
round-trip + fail-closed on tamper / missing DEK / missing record) and the
confirm→dispatch path over the **real** `SendFSM` + `GmailSender` with a fake
egress transport: propose → relayed-confirm → SENT with a token/PII-free ledger
and the token absent from the Agent surface, 5xx → OUTCOME_UNKNOWN with no
second send (gate 8), double-confirm 409, the confirm route 404ing when the
dispatcher is not mounted, and the L3(a) end-to-end missing-DEK-at-dispatch path
(the sealed token cannot be opened → the sender raises → ledger
`send_attempted → outcome_unknown` with no wire call and no second send). Step
(v-b) (11, `test_supervisor.py`) drives the supervisor: the handshake parse /
idempotent reuse / ready-timeout / early-death / malformed-line fail-closed and
the C7 ④ closed-surface introspection over an injected fake process, then a
**real** summon of `gateway.entrypoint` as a distinct OS process (C7 ①: child
pid ≠ this process) that serves the step-(iv) closed set and 404s every
confirm/token/unknown route, with `stop()` tearing the listener down. Step
(v-c) — the operator CLI (13, `test_paths.py` + `test_authorize.py` +
`test_send_cli.py`) — covers the shared data-root layout (writer/reader resolve
one path; `build_server` sources it from the same module), `authorize` sealing a
retrievable token with a token-free summary + idempotent DEK provision + the
real factory wiring a stdout redirect_uri print, and
`send` driving the **real** confirm→dispatch over the on-disk backends with a
fake egress: SENT with the bearer absent from the return value, a 5xx →
OUTCOME_UNKNOWN, no second send on a settled id (calls stay 1), an unknown id
failing closed before any wire call, and `main` requiring an explicit
`--proposal`. The local end-to-end seed scaffold (6, `test_seed_proposal.py` —
`gateway.seed_proposal`, a POC helper, **not** a product verb) pins that a
seeded proposal is exactly what `send` dispatches (seed → real send path → SENT,
frozen record PENDING with the returned digest) and that the reused
`ProposalService.propose` still fails closed through the seed (an unknown field
or a non-text body is refused with nothing written to either store).

```
python -m pytest gateway/tests -q
```

Requires Python 3.10+, `hypothesis` (tests). Standard-library only
(`sqlite3`, `urllib`, `email`).
