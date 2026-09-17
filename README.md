# Gmail Gateway

In-house Gmail connector for Puffo agents. A **user-local** Gateway holds all
Google credentials and performs `gmail.send`; the Puffo cloud never touches a
token. An Agent can only *propose* an email through a closed action set — it
never sees a token and cannot send directly. v1 is send-only, text body.

Canonical spec: **DESIGN.md v0.1** (sha256 `45925f6d…`, held by the planner).
Implementation plan: [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md).

## Module map (boundary-independent cores)

Each module is pure logic with its side effects injected, so it is identical
whether the Gateway ships as a standalone binary or a daemon subprocess. The
process/transport **assembly layer** ([`gateway/`](gateway/)) that wires them
together is being built out over ASSEMBLY_PLAN steps (i)–(vi); it is where §10 —
wire format, endpoint naming, directory layout, cross-platform credential store
— gets finalized. Steps (i)–(iv) (on-disk SQLite persistence; egress-guarded
HTTP client + Gmail sender; OAuth loopback listener + token exchange; the closed
Agent-facing proposal endpoint) have landed, along with step (v) — the confirm +
dispatch send path (Agent-relay confirm / Option B, the accepted, documented
gate-7 POC relaxation) and the supervisor summon (`GatewaySupervisor` +
`gateway.entrypoint`: the closed `{start, health, stop}` channel that spawns the
Gateway as a distinct OS process). The C7 process-boundary test harness is the
remaining assembly slice.

| Module | Responsibility | Key gates | Tests |
|--------|----------------|-----------|-------|
| `canonicalizer` | RFC 8785 JCS + SHA-256 payload digest | parameter-level closed schema (gate 4) | 19 |
| `actionset` | The closed set of Agent actions; confirm/auto switch | gate 4, gate 7 | 27 |
| `keystore` | Envelope AEAD (AES-256-GCM) for tokens at rest; DEK in OS keychain | fail-closed, no plaintext fallback (gate 6) | 31 |
| `store` | Proposals + idempotency + closed-schema audit ledger | audit schema PII/token-free by construction | 26 |
| `sendfsm` | Send state machine: confirm-then-send / auto / outcome_unknown | gate 7, gate 8 | 21 |
| `oauth` | Loopback + PKCE authorization (pure; no sockets/browser) | gate 1 (scope), gate 2 (loopback) | 45 |

**169 core tests + 115 assembly (`gateway/`) = 284 total.** These are
implementer-declared; independent verification (static source review + runtime
observation) is triangulated separately.

## Run

```
python -m pytest -q          # whole suite
python -m pytest oauth/tests -q   # one module
```

Requires Python 3.10+, `cryptography`, `keyring`, `hypothesis`.

## Operator CLI

Two local verbs, run on the operator's own machine (`python -m gateway <verb>`;
the `gmail-gateway` name is not yet packaged as a console script):

```
python -m gateway authorize --data-root <dir> --client-secret-file <google.json>
python -m gateway send --proposal <proposal_id> --data-root <dir>
```

- `authorize` runs one real loopback OAuth and seals the token locally; it prints
  the bound `redirect_uri` (loopback + ephemeral port + `/oauth2/callback` — the
  port is chosen fresh per run, so verify the redirect by structure, not a fixed
  number) and a token-free summary, and never touches proposal/send logic.
- `send` confirms + dispatches one **explicit** already-approved `proposal_id`
  (no "send the latest" default) over the real egress-guarded client; exit 0 iff
  the provider accepted. Neither verb prints a token or payload.

The Agent-facing way to *create* a proposal is `POST /proposal` on the running
Gateway; the operator verb set stays exactly `{authorize, send}`. For a local
end-to-end smoke (authorize → seed → send) without standing up the HTTP server,
a POC scaffold — **not a product verb** — freezes one proposal by reusing the
same closed `ProposalService.propose` path verbatim:

```
python -m gateway.seed_proposal --data-root <dir> --account-handle <acct> \
    --to <TEST-addr> --subject <s> --body <text>
```

It adds no field and no bypass (input outside the closed schema fails closed
exactly as on the Agent route), performs no send, and holds no token.

## Security model (v1)

- **Vector 1 (prompt injection drives the Agent):** blocked — the token is
  never in the Agent's LLM context; the Agent reaches Gmail only through the
  closed proposal interface (`actionset`), which cannot express a raw send.
- **Vector 2 (a malicious same-OS-user process reads the token files):** not
  blocked under a shared UID in v1 — an honestly-recorded limitation
  (DESIGN §2.6). OS-level hardening (separate service identity) is deferred to
  V2; the module boundaries are already shaped to allow it.
