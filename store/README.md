# Gmail Gateway store (proposals · idempotency · audit)

The Gateway's local persistence layer. Three cohesive concerns, all written
against an injected backend seam so the concrete on-disk layout stays a DESIGN
sec 10 / assembly-layer decision:

- `proposals.py` — proposal lifecycle records + idempotency dedup + expiry.
- `ledger.py` — the append-only audit ledger with a **closed, PII/token-free
  schema** (DESIGN sec 7).
- `backend.py` — the `KVBackend` / `AppendLog` Protocols + in-memory impls.

## Scope

**In scope:** persisting proposals, enforcing one live proposal per idempotency
key, answering "is this proposal still live?" against an injected clock, and an
audit trail that cannot carry sensitive content.

**Out of scope:** state *transition rules* (the send FSM owns those — this store
persists whatever status the FSM writes), the crypto for tokens at rest (that is
the `keystore` module), OAuth, and transport. No token or email content ever
enters this module.

## Design decisions

1. **Backend behind a seam (boundary-independent).** All logic runs against
   `KVBackend` / `AppendLog` Protocols; `InMemoryKV` / `InMemoryAppendLog` back
   the tests. The real file/sqlite backend and its cross-platform paths are the
   §10 assembly decision, so the module is identical whether the Gateway ends up
   a standalone binary or a daemon subprocess.

2. **Audit schema is a closed allow-list, by construction (Chris code-time ②).**
   `AuditEvent` is a fixed dataclass whose fields are exactly `_ALLOWED_FIELDS`
   — every one a hash, id, host, code, timestamp, or enum. There is no
   free-form `extra`/`detail`/`body` field, so there is nowhere to put a token,
   address, subject, or body even by accident. `record` accepts **only** the
   typed `AuditEvent` (never a raw dict), closing the last path to append an
   arbitrary payload. `test_audit_schema_is_the_closed_allow_list` pins the
   field set, so adding a field is a conscious edit at the exact review point
   where "does this carry PII/token?" gets asked. This is the
   property-not-enumeration form of the control — express the boundary, don't
   chase a deny-list of bad values.

3. **Idempotency claim is taken up front and outlives the send.** `create`
   writes the `idem:<key>` index before the proposal, so a concurrent duplicate
   can't slip between check and write; and terminal states (`SENT` / `FAILED` /
   `OUTCOME_UNKNOWN`) keep the claim, so a retry after a settled send cannot
   fork a second proposal on the same key.

4. **Expiry is evaluated against an injected clock, and terminal states never
   expire.** `is_live`/`get_live` take `now` as a parameter (deterministic in
   tests). A pending proposal past `expires_at` is refused; a settled one stays
   readable forever (its outcome is a permanent audit fact).

5. **Backends hand out copies.** `get`/`values`/`entries` return fresh dicts so
   a caller mutating a returned record cannot corrupt stored state
   (`test_backend_returns_copies_not_live_state`, `test_entries_are_copies`).

## Run

```
cd gmail-gateway
python -m pytest store/tests -q
```

26 tests: create/get round-trips, idempotency dedup (incl. claim surviving a
terminal send), timestamp validation, expiry against an injected clock, terminal
states never expiring, status persistence, copy-not-alias backend semantics, a
hypothesis serialisation round-trip, and the audit ledger (closed-schema pin,
no-free-form-field, typed-only append, append-only read-back).

## Depends on

Nothing outside the standard library. Repo-independent: no import of the other
Gateway modules.
