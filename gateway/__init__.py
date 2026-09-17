"""Assembly layer: the process/IO wiring around the boundary-independent cores.

The module packages (`canonicalizer`, `actionset`, `keystore`, `store`,
`sendfsm`, `oauth`) are pure logic with their side effects injected. This
package holds the concrete side effects -- on-disk persistence, and later the
loopback transport, egress-enforcing HTTP client, OAuth listener, proposal
endpoint, and supervisor summon. Building it out is ASSEMBLY_PLAN steps (i)-(vi);
step (i) (persistence) lands here first.
"""
