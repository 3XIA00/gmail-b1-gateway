# Gmail Gateway send FSM

The send state machine (DESIGN sec 4 + release gates 7 & 8). It owns the
*transition rules* for a proposal and delegates every side effect to injected
collaborators — so it holds no network, no payload, and no token.

```
PENDING ──confirm──▶ CONFIRMED ──dispatch──▶ SENT
   │                                   ├────▶ FAILED
   │                                   └────▶ OUTCOME_UNKNOWN   (terminal, no retry)
   └──expire──▶ FAILED
```

## Collaborators (all injected)

- `store: ProposalStore` — persists status, enforces idempotency + expiry.
- `ledger: AuditLedger` — records PII/token-free audit events.
- `sender: Callable[[str], SendResult]` — performs the actual Gmail send for a
  proposal_id. The assembly layer wires a sender that fetches the payload and
  calls Gmail; the FSM never sees the payload or a token.
- `switch_mode: SwitchMode` — read-only, fixed at action-set establishment.

## Design decisions

1. **Gate 7 — the switch has no Agent-reachable write path.** Approval is a
   control-plane operation via `confirm`, and the only approvers are
   `Actor.HUMAN` or `Actor.AUTO_UNREACHABLE`. There is deliberately **no**
   `Actor.AGENT` (`test_no_agent_actor_exists`) and no method that changes the
   switch. Auto-approval fires only when the switch is
   `AUTO_SEND_WHEN_AGENT_UNREACHABLE` **and** the reachability signal is a
   definitive `False` — an unknown (`None`) or reachable (`True`) state is
   refused (`test_auto_confirm_requires_definitive_unreachable`). Human confirm
   is always allowed. The reachability signal is injected, not computed here.

2. **Gate 8 — OUTCOME_UNKNOWN is terminal, never retried.** An indeterminate
   result *or* any exception raised mid-send both settle to `OUTCOME_UNKNOWN`
   (`test_dispatch_indeterminate_result_...`, `test_dispatch_sender_exception_...`):
   when we cannot know whether the provider accepted the message, we do not
   guess and we do not resend. `dispatch` refuses an `OUTCOME_UNKNOWN` proposal
   (`NoAutoRetryError`), there is no `retry`/`resend` method on the FSM
   (`test_no_retry_transition_exists_on_fsm`), and the sender is proven to run
   at most once across re-dispatch attempts
   (`test_sender_called_once_even_across_redispatch_attempts`).

3. **Fail toward unknown, not toward a duplicate.** The dispatch path catches
   *any* sender exception and settles `OUTCOME_UNKNOWN` rather than letting the
   error propagate into an ambiguous state that a caller might retry. Definite
   provider rejection is the separate `FAILED` outcome (distinguishable in the
   audit trail), also terminal in v1 (no retry).

4. **Idempotency at the terminal boundary.** A proposal already `SENT` or
   `FAILED` cannot be re-dispatched (`AlreadySettledError`); combined with the
   store's idempotency-key claim, one logical send maps to one provider call.

5. **Transition rules live here; persistence lives in the store.** The FSM is
   the single owner of "what state may follow what"; the store only records the
   status the FSM writes. This keeps the two modules from disagreeing about the
   machine.

## Run

```
cd gmail-gateway
python -m pytest sendfsm/tests -q
```

21 tests: approval paths (human / auto-only-when-enabled-and-unreachable /
expired / non-pending), the four dispatch outcomes (accepted → SENT, rejected →
FAILED, indeterminate → OUTCOME_UNKNOWN, sender-exception → OUTCOME_UNKNOWN),
gate-8 no-retry (incl. sender-called-once and no-retry-method), terminal-state
idempotency, and expiry.

## Depends on

`store` (proposal records + audit ledger) and `actionset` (the `SwitchMode`
enum only). No network, no crypto, no token.
