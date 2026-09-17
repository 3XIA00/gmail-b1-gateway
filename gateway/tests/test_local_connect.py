"""Local-build "Connect Gmail" button wiring tests (POC).

Actuates the non-GUI logic of `gateway.local_connect` -- everything the button
does except render:
  - `load_local_config`: required keys, default vs explicit bundle path, and
    fail-closed on missing/malformed config;
  - `build_authorize_callback` / `connect_once`: the client is hash-verified and
    `run_authorize` runs ONLY after a positive confirm; a declined confirm reads
    nothing and runs nothing; a bundle-verify failure fails closed before authorize.

The tkinter shell (`run_gui`) is deliberately not tested here (needs a display);
its logic lives in `connect_once`, which is fully covered with injected fakes so
no real Google / no browser is touched.
"""

import json

import pytest

from gateway import paths
from gateway.bundle import BundleError
from gateway.local_connect import (
    LocalConnectConfig,
    LocalConnectConfigError,
    build_authorize_callback,
    connect_once,
    load_local_config,
    main,
)

_SUMMARY = {
    "scope": "https://www.googleapis.com/auth/gmail.send",
    "expires_in": 3599,
    "has_refresh_token": True,
    "token_db": "DR/token/token.db",
}


def _cfg() -> LocalConnectConfig:
    return LocalConnectConfig(
        data_root="DR", client_bundle="DR/client/client.json",
        expected_sha256="a" * 64)


class _Loader:
    """Fake load_bundled_client: records (path, pin), returns creds or raises."""

    def __init__(self, returns=("CID.apps", "SEC"), raises=None):
        self.calls = []
        self._returns = returns
        self._raises = raises

    def __call__(self, bundle_path, expected_sha256):
        self.calls.append((bundle_path, expected_sha256))
        if self._raises is not None:
            raise self._raises
        return self._returns


class _Authorizer:
    """Fake run_authorize: records kwargs, returns a token-free summary."""

    def __init__(self, summary=None):
        self.calls = []
        self._summary = summary if summary is not None else _SUMMARY

    def __call__(self, *, data_root, client_id, client_secret, timeout):
        self.calls.append(dict(
            data_root=data_root, client_id=client_id,
            client_secret=client_secret, timeout=timeout))
        return self._summary


# --- load_local_config --------------------------------------------------------

def test_load_config_defaults_bundle(tmp_path):
    p = tmp_path / "local_connect.json"
    p.write_text(json.dumps({"data_root": "DR", "expected_sha256": "b" * 64}))
    cfg = load_local_config(str(p))
    assert cfg.data_root == "DR"
    assert cfg.expected_sha256 == "b" * 64
    assert cfg.client_bundle == paths.client_bundle("DR")


def test_load_config_explicit_bundle(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({
        "data_root": "DR", "expected_sha256": "b" * 64,
        "client_bundle": "/custom/client.json"}))
    assert load_local_config(str(p)).client_bundle == "/custom/client.json"


def test_load_config_missing_file(tmp_path):
    with pytest.raises(LocalConnectConfigError, match="not found"):
        load_local_config(str(tmp_path / "nope.json"))


def test_load_config_invalid_json(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{ not json")
    with pytest.raises(LocalConnectConfigError, match="unreadable"):
        load_local_config(str(p))


@pytest.mark.parametrize("obj, match", [
    ([], "JSON object"),
    ({"expected_sha256": "b" * 64}, "data_root"),
    ({"data_root": "", "expected_sha256": "b" * 64}, "data_root"),
    ({"data_root": "DR"}, "expected_sha256"),
    ({"data_root": "DR", "expected_sha256": ""}, "expected_sha256"),
    ({"data_root": "DR", "expected_sha256": "b" * 64, "client_bundle": 5}, "client_bundle"),
])
def test_load_config_rejects_bad_shapes(tmp_path, obj, match):
    p = tmp_path / "c.json"
    p.write_text(json.dumps(obj))
    with pytest.raises(LocalConnectConfigError, match=match):
        load_local_config(str(p))


# --- build_authorize_callback -------------------------------------------------

def test_build_callback_wires_bundle_pin_and_creds():
    loader = _Loader(returns=("CID", "SEC"))
    authz = _Authorizer()
    cb = build_authorize_callback(
        _cfg(), loader=loader, authorizer=authz, timeout=42.0)
    summary = cb()
    # verified against the config's exact bundle path + pin ...
    assert loader.calls == [("DR/client/client.json", "a" * 64)]
    # ... and the parsed creds flow into run_authorize with the data-root.
    assert authz.calls == [dict(
        data_root="DR", client_id="CID", client_secret="SEC", timeout=42.0)]
    assert summary == _SUMMARY


# --- connect_once (the button's real wiring: in-process confirm -> authorize) --

def test_connect_once_confirmed_verifies_then_authorizes_once():
    loader = _Loader(returns=("CID", "SEC"))
    authz = _Authorizer()
    summary = connect_once(
        _cfg(), confirm=lambda: True, loader=loader, authorizer=authz)
    assert summary == _SUMMARY
    assert loader.calls == [("DR/client/client.json", "a" * 64)]
    assert len(authz.calls) == 1


@pytest.mark.parametrize("verdict", [False, None, 0, ""])
def test_connect_once_declined_reads_nothing_runs_nothing(verdict):
    loader = _Loader()
    authz = _Authorizer()
    summary = connect_once(
        _cfg(), confirm=lambda: verdict, loader=loader, authorizer=authz)
    assert summary is None
    # On decline the client file is never even read, and authorize never runs.
    assert loader.calls == []
    assert authz.calls == []


def test_connect_once_bundle_failure_fails_closed_before_authorize():
    loader = _Loader(raises=BundleError("hash does not match"))
    authz = _Authorizer()
    with pytest.raises(BundleError):
        connect_once(_cfg(), confirm=lambda: True, loader=loader, authorizer=authz)
    assert authz.calls == []  # verify failed -> no browser, no authorize


# --- main() config-error path (no GUI launched) -------------------------------

def test_main_bad_config_returns_2_no_gui(tmp_path, capsys):
    rc = main(["--config", str(tmp_path / "missing.json")])
    assert rc == 2
    assert "local_connect" in capsys.readouterr().err
