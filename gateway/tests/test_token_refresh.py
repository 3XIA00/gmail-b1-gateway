"""Automatic refresh is local, single-flight, and never sends mail itself."""

import threading
import time

import pytest

from gateway.egress import EgressGuardedClient
from gateway.send_path import SealedTokenStore
from gateway.token_refresh import (
    ReauthorizationRequiredError,
    RefreshingTokenProvider,
    TokenRefreshError,
)
from keystore.aead import AEADCipher
from keystore.providers import InMemoryKeyProvider
from store.backend import InMemoryKV

_DEK = bytes(range(32))
_SCOPE = "https://www.googleapis.com/auth/gmail.send"


def _store(**over):
    values = {
        "access_token": "old",
        "refresh_token": "1//refresh",
        "issued_at": 100,
        "expires_at": 200,
        "client_id": "cid.apps",
        "client_secret": "desktop-public-secret",
        "scope": _SCOPE,
    }
    values.update(over)
    store = SealedTokenStore(
        AEADCipher(InMemoryKeyProvider(_DEK)), InMemoryKV())
    store.store(**values)
    return store


def test_fresh_token_never_calls_refresh_endpoint():
    def transport(*args, **kwargs):
        raise AssertionError("refresh endpoint must not be called")

    provider = RefreshingTokenProvider(
        _store(expires_at=1000),
        EgressGuardedClient({"oauth2.googleapis.com"}, transport=transport),
        now=lambda: 500)
    assert provider.access_token() == "old"


def test_expired_token_refreshes_and_preserves_refresh_token():
    calls = []

    def transport(method, url, headers, body, *, timeout=30.0):
        calls.append((url, body))
        return 200, (b'{"access_token":"fresh","expires_in":3599,'
                     b'"scope":"https://www.googleapis.com/auth/gmail.send"}')

    store = _store()
    provider = RefreshingTokenProvider(
        store,
        EgressGuardedClient({"oauth2.googleapis.com"}, transport=transport),
        now=lambda: 500)
    assert provider.access_token() == "fresh"
    assert len(calls) == 1
    assert store.token_record()["refresh_token"] == "1//refresh"
    assert store.token_record()["expires_at"] == 4099
    raw = store._backend.get("sealed_token")
    assert raw["write_origin"] == "refresh"
    assert raw["written_at"] == 500


def test_authorize_and_refresh_writes_are_forensically_distinguishable():
    store = _store()
    assert store._backend.get("sealed_token")["write_origin"] == "authorize"

    provider = RefreshingTokenProvider(
        store,
        EgressGuardedClient(
            {"oauth2.googleapis.com"},
            transport=lambda *a, **k: (
                200, b'{"access_token":"fresh","expires_in":3599}')),
        now=lambda: 500)
    assert provider.access_token() == "fresh"
    assert store._backend.get("sealed_token")["write_origin"] == "refresh"


def test_pre_refresh_schema_record_requires_one_reauthorization():
    with pytest.raises(ReauthorizationRequiredError):
        RefreshingTokenProvider(
            _store(expires_at=None, client_id=None),
            EgressGuardedClient({"oauth2.googleapis.com"},
                                transport=lambda *a, **k: None),
            now=lambda: 500).access_token()


def test_scope_change_fails_closed():
    def transport(*args, **kwargs):
        return 200, (b'{"access_token":"fresh","expires_in":3599,'
                     b'"scope":"https://www.googleapis.com/auth/gmail.readonly"}')

    with pytest.raises(TokenRefreshError):
        RefreshingTokenProvider(
            _store(),
            EgressGuardedClient({"oauth2.googleapis.com"}, transport=transport),
            now=lambda: 500).access_token()


def test_concurrent_callers_share_one_refresh():
    calls = []

    def transport(*args, **kwargs):
        calls.append(1)
        time.sleep(0.02)
        return 200, b'{"access_token":"fresh","expires_in":3599}'

    provider = RefreshingTokenProvider(
        _store(),
        EgressGuardedClient({"oauth2.googleapis.com"}, transport=transport),
        now=lambda: 500)
    results = []
    threads = [threading.Thread(target=lambda: results.append(provider.access_token()))
               for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == ["fresh"] * 5
    assert calls == [1]
