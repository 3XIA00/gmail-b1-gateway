# Gmail Gateway OAuth (loopback + PKCE)

The authorization core (DESIGN sec 3, release gates 1 & 2). Pure logic for the
authorization-code + PKCE flow — **no sockets, no browser, no token storage**.
The assembly layer wraps a loopback listener and an HTTPS client around this
core; keeping the I/O at the boundary is what lets every rule below be tested
without a network or a secret.

```
generate_pkce_pair ─┐
generate_state ─────┤
                    ▼
        AuthorizationRequest ──build_authorization_url──▶ (browser opens URL)
        (validates: gate 1 scope, gate 2 loopback)                  │
                    ┌───────────────────────────────────────────────┘
                    ▼   loopback listener receives the redirect (assembly)
        extract_authorization_code(params, expected_state)
        (state checked first, constant-time; then error; then code)
                    ▼
        build_token_exchange_request(code, code_verifier, ...)
        (re-validates verifier + loopback; returns endpoint+body, sends nothing)
                    ▼   assembly POSTs it, hands tokens to the keystore

        build_refresh_token_request(refresh_token, client_id, ...)
        (returns the OAuth refresh endpoint+body; sends nothing)
```

## Design decisions

1. **PKCE is the real client authenticator (RFC 7636).** The Gateway is a
   public client — it cannot keep a `client_secret` secret — so a fresh
   high-entropy `code_verifier` binds the code to this flow; only its S256
   `code_challenge` travels in the authorization request. We pin the RFC
   Appendix-B known-answer vector and property-test the derivation over random
   verifiers, so the challenge is provably `base64url(sha256(verifier))`.

2. **Gate 2 — loopback only, fail-closed.** The redirect must be `http` on a
   loopback host (`127.0.0.1` / `::1` / `localhost`) with an explicit port.
   The host check is an **allow-list**, so a new spelling of "not loopback"
   (a link-local metadata address, a `127.0.0.1.evil.com` look-alike, a hosted
   HTTPS callback) is refused by default rather than needing to be enumerated.
   We validate at request time *and* again at token exchange — a tampered
   redirect cannot widen the flow.

3. **Gate 1 — scope allow-list.** v1 asks for exactly
   `gmail.send` and nothing else. Any extra or unknown scope is *rejected*, not
   trimmed, so a read/modify/full-mailbox scope can never be requested by
   accident.

4. **State is a CSRF binding, checked first.** A random `state` is issued per
   request and the callback must echo it (constant-time compare). The callback
   validator checks state **before** it looks at the code or an error param, so
   a forged callback carrying an attacker-chosen code is rejected before that
   code is ever trusted.

5. **Pure construction, no egress.** `build_authorization_url`,
   `build_token_exchange_request`, and `build_refresh_token_request` only
   assemble strings/params. The token
   round-trip — the one network call that carries the code and returns tokens —
   lives in the assembly layer, next to the keystore that seals the result.
   `client_secret` is optional and omitted unless explicitly supplied: an
   installed/Desktop client's secret is not a confidentiality boundary (PKCE
   is). No real client credentials or tokens ever live in this module.

## Run

```
cd gmail-gateway
python -m pytest oauth/tests -q
```

45 tests: PKCE (RFC known-answer, well-formedness, uniqueness, deterministic
S256 property test, malformed rejection), state (uniqueness, constant-time
match, empty-never-matches), loopback redirect (accept/reject table),
authorization request (scope allow-list + loopback + URL params), callback
validation (match / state-mismatch / forged-code / provider-error /
missing-code), and token-exchange construction (grant body, secret-only-when-
given, verifier + loopback re-validation, empty-code, injected endpoints).

## Depends on

Standard library + `hypothesis` (tests only). No network, no crypto beyond
`hashlib`/`secrets`, no token. Boundary-independent: identical whether the
Gateway ships as a standalone binary or a daemon subprocess.
