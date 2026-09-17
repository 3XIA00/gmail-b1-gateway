# Gmail Gateway payload canonicalizer (M2)

Implements the RFC 8785 (JCS) canonicalization + SHA-256 digest that the
Gmail Gateway confirm-then-send flow pins in **DESIGN.md v0.1 §5.1 / §8.5**.
This is the M2 piece: the deterministic function the user's approval is a
digest *of*, and the cross-implementation acceptance target.

## Scope

**In scope (this module):**
- `jcs.py` — real RFC 8785 JCS serializer over the payload's value domain.
- `payload.py` — `PrepareEmail` → canonical payload normalization,
  `payload_digest`, and the v1 send-time attachment gate.
- Golden-vector reproduction + property/boundary tests.

**Out of scope (adjacent Gateway pieces, not this deliverable):** OAuth
loopback listener, encrypted token store, proposal store, idempotency
ledger, send state machine, Gmail transport. Per DESIGN.md §10 the target
repo/transport and endpoint names are undecided; this module is a
self-contained drop-in for whatever the Gateway repo turns out to be.

## Design decisions

1. **Real JCS, not `json.dumps(sort_keys=True)`.** DESIGN.md §8.5 forbids a
   generic key-sorting serializer in production; it only agrees with JCS on
   the two frozen fixtures by accident (they lack non-ASCII keys,
   non-integer numbers, and special control chars). This impl sorts object
   members by **UTF-16 code unit** (via UTF-16-BE byte comparison), applies
   JCS string escaping, and emits all non-ASCII as raw UTF-8.
   `test_object_key_order_is_utf16_not_codepoint` actuates the exact
   divergence (U+FFFF vs U+10000) that separates the two.

2. **Number domain = integers only, fail closed.** The canonical payload's
   only number is an attachment `size` (non-negative integer). Full JCS
   non-integer output is the ECMAScript shortest-round-trip double
   algorithm; a half-correct version is worse than none, so non-integer and
   unsafe-range numbers are **rejected**, not served.

3. **Digest excludes `idempotency_key`.** It is a dedup key (§6), not part
   of the approved-content digest. Accepted on input, excluded from the
   canonical payload.

4. **Closed schema (supports §3 release gate 4).** `build_canonical_payload`
   **rejects** any field outside the fixed schema rather than silently
   dropping it, so an injected `raw_mime` / arbitrary header fails closed
   instead of riding along invisibly. There is no raw-MIME / arbitrary-URL /
   pass-through slot in the schema.

5. **Digest domain vs v1 send policy are separate layers.** The digest
   domain models a *populated* attachment slot (golden vector B) for
   forward compatibility; `enforce_v1_send_policy` rejects a non-empty slot
   before any proposal/Gmail call (`attachments_not_supported_in_v1`),
   without silently degrading to a body-only send.

Gate (7) (confirm / auto-send switch has no Agent-reachable write path) is
the action-set projection layer, not this module — the canonicalizer is a
pure function over content and neither exposes nor mutates the switch.

## Golden-vector results (self-verification)

| Vector | JCS bytes | SHA-256 | Reproduced |
|---|---|---|---|
| A (empty slot, ASCII) | 208 | `4fd1ec7e…cc38c7a` | ✅ |
| B (populated slot, Unicode incl. U+1F600) | 388 | `8a041087…382c26b` | ✅ |

Vector B's three Unicode fields are built from DESIGN.md's **code-point
sequences**, not copied glyphs, so editor NFC/NFD normalization cannot alter
the scalars under test.

## Independence / clean-room

This implementation derives **only** from DESIGN.md v0.1. It does **not**
use, and has not seen, the Glimmer r2 canonicalizer 测试姬 disclosed
holding — clean-room is intact on the implementation side.

Acceptance is a **separate seat** (测试姬, §8.4/§8.5): she constructs the
A/B inputs independently from DESIGN.md code points, runs *this* real JCS
impl, and compares to the **frozen golden values** (always the oracle —
never this repo's fixtures or any serializer's output). The three-way
non-same-source (implementation / independent inputs / frozen values) is
Chris's to audit.

## Run

```
cd gmail-gateway
python -m pytest -q
```

Full suite = **19 tests**: `tests/test_properties.py` (**16**
property/boundary tests) + `tests/test_golden_vectors.py` (**3**
golden-vector reproductions). `test_golden_vectors.py` was held out of the
initial delivery bundle during the acceptance-independence window — it
embeds this module's own A/B code-point construction, which had to stay
out of the Tester's pre-acceptance path. It is included now that
executor-seat acceptance (测试姬) and QA audit (Chris) are complete.
Running only `test_properties.py` reports `16 passed`; the full 19
requires both test files.

## Portability

The deliverable contract is the **byte-exact JCS output + digest**, which is
language-invariant by design. This Python module is the reference impl; if
§10 fixes the Gateway in another language, it ports and must reproduce the
same frozen vectors A/B.
