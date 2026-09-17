"""Callback validation — turn a loopback redirect hit into a trusted code.

The assembly layer's loopback listener receives the browser redirect and hands
us the query parameters. We refuse anything ambiguous:

  - an explicit provider ``error=`` -> AuthorizationError (user denied, etc.);
  - a ``state`` that does not match what we issued -> StateMismatchError
    (constant-time; a forged callback is rejected before the code is trusted);
  - neither code nor error -> MissingCodeError.

Only when state matches *and* a code is present do we return the code. This is
pure validation; no token exchange happens here.
"""

from __future__ import annotations

from collections.abc import Mapping

from .errors import AuthorizationError, MissingCodeError, StateMismatchError
from .state import state_matches


def extract_authorization_code(
    params: Mapping[str, str],
    *,
    expected_state: str,
) -> str:
    """Validate callback *params* against *expected_state*; return the code.

    State is checked before anything else so a mismatched (possibly forged)
    callback is rejected regardless of what else it carries.
    """
    if not state_matches(expected_state, params.get("state", "")):
        raise StateMismatchError("callback state did not match the issued state")
    provider_error = params.get("error")
    if provider_error:
        raise AuthorizationError(provider_error)
    code = params.get("code")
    if not code:
        raise MissingCodeError("callback carried no authorization code")
    return code
