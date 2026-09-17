"""User-signed capability authorization layer (PUF-367 first cut).

The Gateway consults this layer before every Gmail send. A send is permitted
only by a *user-signed capability certificate* (the user's cryptographic grant
of a specific tool/action to an account or a named agent) plus a fresh,
single-use authorization decision bound to *this* request.

First-cut scope (Jeff's 6-point cut): local stub authorization service (no real
cloud), five behaviours -- allow->send, revoke->reject, cloud-unreachable->
reject (fail closed), missing-approval-field->no-auto-send, replay->reject --
demonstrated end to end through a Gmail *stub* sender wired to the existing
SendFSM. Real Gmail/OAuth, the T+8 refresh wall, and production deploy are
explicitly deferred.

Existence-oracle rule (load-bearing): the caller/agent only ever learns the
coarse verdict ``denied``. The rich failure reason (revoked / expired /
cloud-unreachable / ...) is recorded ONLY in the internal authz audit log, so a
caller cannot use fine-grained rejections to probe hidden state.
"""
