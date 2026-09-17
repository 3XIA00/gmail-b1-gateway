"""Local deep-link trigger for one-click authorize (`puffo://authorize`).

The daemon registers a `puffo://` URL scheme (installer / c2 concern). When the
user clicks "Connect Gmail" in the Puffo UI, the OS hands the daemon a
`puffo://authorize` URI; this module is the *handler* for that hand-off. Its whole
job is to gate the existing loopback+PKCE authorize behind an explicit,
device-local human confirmation -- the deep-link by itself must grant nothing.

Security contract (each clause is a unit-testable invariant):

- **The deep-link grants nothing on its own.** `handle_authorize_trigger` runs
  `authorize` *only if* `confirm()` returns True. A negative or absent
  confirmation performs zero side effect: no browser opens, no loopback binds, no
  token is minted. This is the half this repo can enforce, and its test proves
  confirm-negative => no-effect.
- **`confirm` MUST be a device-local human affirmation.** The caller (the daemon /
  c2 UI) MUST bind `confirm` to a device-local human-affirmation source that is
  not satisfiable by any inbound network message, agent message, or channel
  event. This handler cannot verify the *authenticity* of the confirm source --
  that acceptance criterion lives at the c2/UI layer and MUST travel in the c2
  hand-off (parallel to the bundled client's hash trust-root). A green unit test
  here does NOT prove the wiring is human-only; do not treat `confirm` as an
  ordinary injectable callback.
- **The deep-link carries no authority.** Nothing from the URI is passed into
  `authorize`: the client is always the hash-verified bundled client and the
  redirect is always the gateway's own freshly-bound loopback. So a crafted
  `puffo://authorize?redirect_uri=...&code=...&client_id=...` cannot inject
  anything -- at most it pops the same confirmation dialog.
- **Malformed input fails closed.** A URI whose scheme/action is not
  `puffo://authorize` is rejected (raising `TriggerError`) before any
  confirmation is opened.
"""

from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit

_SCHEME = "puffo"
_ACTION = "authorize"


class TriggerError(Exception):
    """The deep-link URI is not a well-formed `puffo://authorize` trigger."""


def _is_authorize_uri(uri: str) -> bool:
    if not isinstance(uri, str):
        return False
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    # `puffo://authorize` -> scheme 'puffo', host/netloc 'authorize'. Accept the
    # authority-form and the (rarer) `puffo:authorize` path-form; nothing else.
    action = parts.netloc or parts.path.lstrip("/")
    return parts.scheme == _SCHEME and action == _ACTION


def handle_authorize_trigger(
    uri: str,
    *,
    confirm: Callable[[], bool],
    authorize: Callable[[], None],
) -> bool:
    """Gate `authorize` behind a device-local confirmation for a deep-link.

    Returns True iff the user confirmed and `authorize` ran; False if the
    confirmation was declined/absent (with no side effect). Raises `TriggerError`
    for a malformed URI, *before* any confirmation is opened. Nothing from `uri`
    is passed into `authorize` -- the URI carries no authority (see module docs).
    """
    if not _is_authorize_uri(uri):
        raise TriggerError("not a puffo://authorize trigger")
    if not confirm():
        return False        # declined/absent confirmation => zero side effect
    authorize()
    return True
