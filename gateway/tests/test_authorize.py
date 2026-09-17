"""`gmail-gateway authorize` wiring tests (ASSEMBLY_PLAN step v-c, command A).

The real command runs a browser + live token endpoint, so these drive the
*wiring* with a fake flow and an in-memory DEK, actuating:
  - the returned token is sealed and re-openable with the same DEK (round-trip
    through SealedTokenStore over the on-disk token.db);
  - what is at rest is ciphertext, and the command's summary is token-free;
  - client creds are read from the Google client-secret JSON (both the Desktop
    `{"installed": {...}}` shape and a bare object);
  - the DEK is provisioned iff absent, never overwritten.
"""

import json

import pytest

from keystore.aead import AEADCipher
from keystore.providers import InMemoryKeyProvider, KeyringKeyProvider
from gateway import paths
from gateway.authorize import (
    _announce_redirect_uri,
    _default_flow_factory,
    _ensure_dek,
    _read_client_credentials,
    run_authorize,
)
from gateway.oauth_listener import TokenResult
from gateway.persistence import SqliteKV
from gateway.send_path import SealedTokenStore

_ACCESS = "ya29.SECRET-ACCESS-TOKEN"
_REFRESH = "1//SECRET-REFRESH"
_DEK = bytes(range(32))
_SCOPE = "https://www.googleapis.com/auth/gmail.send"


class _FakeFlow:
    def __init__(self, client_id, client_secret, timeout):
        self.seen = (client_id, client_secret, timeout)

    def run(self):
        return TokenResult(access_token=_ACCESS, refresh_token=_REFRESH,
                           expires_in=3599, scope=_SCOPE, token_type="Bearer")


def test_run_authorize_seals_retrievable_token_and_summary_is_token_free(tmp_path):
    seen = {}

    def factory(cid, secret, timeout):
        flow = _FakeFlow(cid, secret, timeout)
        seen["args"] = flow.seen
        return flow

    summary = run_authorize(
        data_root=str(tmp_path), client_id="cid.apps", client_secret="shh",
        timeout=42.0, flow_factory=factory, key_provider=InMemoryKeyProvider(_DEK),
        now=lambda: 1000)

    # the flow got the creds + timeout it was handed
    assert seen["args"] == ("cid.apps", "shh", 42.0)
    # summary carries no secret material
    dumped = json.dumps(summary)
    assert _ACCESS not in dumped and _REFRESH not in dumped
    assert summary["scope"].endswith("gmail.send")
    assert summary["has_refresh_token"] is True

    # the token is really sealed on disk and re-openable with the same DEK...
    with SqliteKV(paths.token_db(str(tmp_path))) as kv:
        store = SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), kv)
        assert store.access_token() == _ACCESS
        record = store.token_record()
        assert record["refresh_token"] == _REFRESH
        assert record["issued_at"] == 1000
        assert record["expires_at"] == 4599
        assert record["client_id"] == "cid.apps"
        assert record["client_secret"] == "shh"
        assert record["scope"] == _SCOPE
        # ...and what is at rest is ciphertext, not the plaintext token
        assert _ACCESS not in json.dumps(kv.get("sealed_token"))
        assert _REFRESH not in json.dumps(kv.get("sealed_token"))


def test_read_client_credentials_installed_and_bare(tmp_path):
    p1 = tmp_path / "desktop.json"
    p1.write_text(json.dumps(
        {"installed": {"client_id": "abc.apps", "client_secret": "shh"}}))
    assert _read_client_credentials(str(p1)) == ("abc.apps", "shh")

    p2 = tmp_path / "bare.json"
    p2.write_text(json.dumps({"client_id": "xyz.apps"}))
    assert _read_client_credentials(str(p2)) == ("xyz.apps", None)


def test_read_client_credentials_rejects_missing_client_id(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"installed": {"client_secret": "only-secret"}}))
    with pytest.raises(ValueError):
        _read_client_credentials(str(p))


def test_default_flow_factory_wires_redirect_uri_print(capsys):
    # The real factory hands the flow a redirect_uri observer that prints to
    # stdout (non-secret: loopback + ephemeral port + fixed path), so 测试姬's
    # checklist can verify the live redirect. No network on construction.
    flow = _default_flow_factory("cid.apps", "secret", 5.0)
    assert flow._on_redirect_uri is _announce_redirect_uri

    _announce_redirect_uri("http://127.0.0.1:54321/oauth2/callback")
    out = capsys.readouterr().out
    assert "redirect_uri: http://127.0.0.1:54321/oauth2/callback" in out


def test_ensure_dek_provisions_when_absent_and_is_idempotent():
    store = {}

    class _FakeKeyring:
        def get_password(self, service, username):
            return store.get((service, username))

        def set_password(self, service, username, password):
            store[(service, username)] = password

    prov = KeyringKeyProvider("gmail-gateway", "dek-test", backend=_FakeKeyring())
    _ensure_dek(prov)               # absent -> provisions
    dek = prov.get_dek()
    assert len(dek) == 32
    _ensure_dek(prov)               # present -> no overwrite, no raise
    assert prov.get_dek() == dek    # same key preserved
