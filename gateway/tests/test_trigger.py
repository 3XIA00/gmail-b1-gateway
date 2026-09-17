"""Deep-link authorize-trigger tests (`puffo://authorize`, axis d).

Actuates the enforceable half of the trigger's security contract:
  - confirm-negative/absent => `authorize` never runs, zero side effect;
  - confirm-positive => `authorize` runs exactly once;
  - nothing from the URI reaches `authorize` (a crafted code/redirect_uri/
    client_id changes nothing) -- the deep-link carries no authority;
  - a malformed / wrong-scheme URI fails closed with `TriggerError`, *before*
    any confirmation is opened.

The OTHER half -- that `confirm` is bound to a device-local human affirmation not
satisfiable by any network/agent/channel event -- is a c2/UI acceptance
criterion and is deliberately NOT testable here (see module docstring). A green
test proves confirm-negative => no-effect, not human-only wiring.
"""

import pytest

from gateway.trigger import TriggerError, handle_authorize_trigger


class _Spy:
    """Records calls (and any args) so we can assert what ran and how often."""

    def __init__(self, returns=None):
        self.calls = []
        self._returns = returns

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._returns


def test_confirm_positive_runs_authorize_once():
    confirm = _Spy(returns=True)
    authorize = _Spy()
    assert handle_authorize_trigger(
        "puffo://authorize", confirm=confirm, authorize=authorize) is True
    assert len(authorize.calls) == 1


@pytest.mark.parametrize("verdict", [False, None, 0, ""])
def test_confirm_negative_or_absent_runs_nothing(verdict):
    confirm = _Spy(returns=verdict)
    authorize = _Spy()
    assert handle_authorize_trigger(
        "puffo://authorize", confirm=confirm, authorize=authorize) is False
    assert authorize.calls == []          # zero side effect


def test_uri_carries_no_authority():
    # A crafted redirect_uri/code/client_id must not reach authorize: it takes
    # no args, and the handler passes none. Behaviour is identical to a clean URI.
    confirm = _Spy(returns=True)
    authorize = _Spy()
    crafted = ("puffo://authorize?redirect_uri=http://evil/steal"
               "&code=attacker-code&client_id=attacker.apps")
    assert handle_authorize_trigger(
        crafted, confirm=confirm, authorize=authorize) is True
    assert authorize.calls == [((), {})]  # called with nothing from the URI


@pytest.mark.parametrize("uri", [
    "http://authorize",             # wrong scheme
    "puffo://send",                 # wrong action
    "puffo://authorize-extra",      # not an exact action match
    "https://accounts.google.com/o/oauth2/auth",
    "not a uri at all",
    "puffo://",                     # no action
    "",
])
def test_malformed_uri_fails_closed_before_confirm(uri):
    confirm = _Spy(returns=True)
    authorize = _Spy()
    with pytest.raises(TriggerError):
        handle_authorize_trigger(uri, confirm=confirm, authorize=authorize)
    assert confirm.calls == []            # rejected before opening a confirmation
    assert authorize.calls == []


def test_path_form_scheme_is_accepted():
    # `puffo:authorize` (path form, no authority) is a valid trigger too.
    confirm = _Spy(returns=True)
    authorize = _Spy()
    assert handle_authorize_trigger(
        "puffo:authorize", confirm=confirm, authorize=authorize) is True
    assert len(authorize.calls) == 1
