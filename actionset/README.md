# Gmail Gateway action-set projection (v1)

The Agent-facing action set. Implements the two release gates that live at
the action boundary in **DESIGN.md v0.1 §3**, on top of the already-accepted
M2 canonicalizer (`canonicalizer.payload`):

- **gate 4** — parameter-level *closed* action set, and
- **gate 7** — the confirm / auto-send switch has no Agent-reachable write
  path.

## Scope

**In scope (this module):**
- `catalog.py` — the closed Agent action allow-list.
- `prepare.py` — `PrepareEmail` → `PrepareEmailResult{proposal_id,
  payload_digest, expires_at}`, projected through the M2 closed schema.
- `switch.py` — `ActionSet` + `SwitchMode`; the switch as an
  establishment-time, read-only value.

**Out of scope (adjacent Gateway pieces):** OAuth loopback listener,
encrypted token store, proposal/idempotency store, send state machine, Gmail
transport. Per DESIGN §10 the repo/transport and endpoint names are
undecided; this module is a self-contained drop-in.

## Design decisions

1. **Projection, not expansion (Chris code-time ①).** The *only* path from
   Agent input to email content is M2 `build_canonical_payload`'s closed
   schema. `prepare_email` adds no header dict, no `extra_params`, no
   pass-through slot; an injected field fails closed inside the
   canonicalizer. `test_prepare_has_no_header_or_extra_params_slot` and the
   `test_any_unknown_field_fails_closed` property actuate this.

2. **Digest cannot diverge from the accepted one.** `prepare_email` digests
   the exact canonical it just validated, so its `payload_digest` is
   byte-identical to `canonicalizer.payload.payload_digest(params)`
   (`test_digest_is_identical_to_canonicalizer`). The projection layer
   introduces no second serializer.

3. **Action set is an allow-list, not a deny-list (gate 4, action level).**
   `AGENT_ACTIONS` is a frozenset; `require_agent_action` refuses anything
   outside it. v1 = exactly `{PrepareEmail}`. There is deliberately **no**
   send/dispatch action (confirm-then-send: an Agent builds a proposal and
   never dispatches it) and **no** switch-write action. Widening the surface
   is a reviewable diff to this set, not a runtime parameter.

4. **Switch has no Agent-reachable write path (gate 7).** `ActionSet` is a
   frozen dataclass: `switch_mode` is fixed at establishment and cannot be
   reassigned, and `project` only ever dispatches catalog actions — none of
   which writes the switch. Changing the mode means an operator
   *re-establishes* the action set (a new instance), i.e. it "takes effect on
   the next action-set establishment" (DESIGN §4), never via an Agent call.
   The AUTO_SEND mode's own "only when the Agent is unreachable" semantics
   are enforced downstream in the send FSM; this module carries the mode
   read-only.

5. **Clock and id are injected, not computed.** `now` and
   `proposal_id_factory` are parameters, so the projection is a pure function
   of its inputs — deterministic in tests, and the clock/id source is the
   caller's single auditable choice (inject-not-compute).

## Result carries no content

`PrepareEmailResult` is `{proposal_id, payload_digest, expires_at}` only — no
body, recipients, or send handle leak back to the Agent
(`test_result_is_immutable_and_carries_no_content`).

## Run

```
cd gmail-gateway
python -m pytest actionset/tests -q
```

27 tests (gate-4 closed-set + no-bypass, gate-7 no-write-path, digest
equivalence, injected-clock boundaries), incl. two hypothesis properties
(any non-`PrepareEmail` action refused; any unknown content field fails
closed).

## Depends on

`canonicalizer` (M2, accepted 2026-08-31). Import path assumes both packages
share the `gmail-gateway/` root, matching the M2 run instructions.
