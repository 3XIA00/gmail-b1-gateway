"""`gmail-gateway send --proposal <id>` wiring tests (step v-c, command B).

Drives the real send-path assembly over ON-DISK backends (a token is sealed and
a proposal is frozen in one connection set, then `run_send` opens a fresh set --
the cross-process handoff the WAL-durable stores exist for), with a fake egress
transport standing in for Gmail. Actuated variables:
  - a live, approved proposal -> confirm+dispatch reaches SENT with exactly one
    wire call, and the bearer never appears in the return value / stdout;
  - re-running send on a settled proposal cannot fork a second send (calls == 1);
  - an unknown proposal_id fails closed before any wire call;
  - `main` requires an explicit --proposal (no implicit "latest").
"""

import pytest

from keystore.aead import AEADCipher
from keystore.providers import InMemoryKeyProvider
from sendfsm.errors import AlreadySettledError, IllegalTransitionError
from store.errors import ProposalNotFoundError
from store.proposals import ProposalStore
from gateway import paths
from gateway.persistence import SqliteKV
from gateway.proposal_api import ProposalService
from gateway.send_cli import main, run_send
from gateway.send_path import SealedTokenStore

_ACCESS = "ya29.SECRET-ACCESS-TOKEN"
_DEK = bytes(range(32))


def _params(**over):
    p = {
        "account_handle": "me@example.com",
        "to": ["alice@example.com"],
        "subject": "Hi",
        "body": {"format": "text", "content": "hello alice"},
    }
    p.update(over)
    return p


def _seed(data_root: str) -> str:
    """Seal a token and freeze one pending proposal; return its id."""
    with SqliteKV(paths.token_db(data_root)) as tk:
        SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), tk).store(
            access_token=_ACCESS, refresh_token="1//REFRESH",
            issued_at=900, expires_at=1500,
            client_id="cid.apps", client_secret="public-desktop-secret",
            scope="https://www.googleapis.com/auth/gmail.send")
    proposals_kv = SqliteKV(paths.proposals_db(data_root))
    payloads_kv = SqliteKV(paths.payloads_db(data_root))
    try:
        service = ProposalService(
            proposals=ProposalStore(proposals_kv), payloads=payloads_kv,
            now=lambda: 1000, ttl_seconds=3600,
            proposal_id_factory=lambda: "prop-1")
        return service.propose(_params())["proposal_id"]
    finally:
        proposals_kv.close()
        payloads_kv.close()


def _ok_transport(calls):
    def transport(method, url, headers, body, *, timeout=30.0):
        calls.append({"method": method, "url": url, "headers": dict(headers)})
        return 200, b'{"id":"MID","threadId":"TID"}'
    return transport


def test_run_send_dispatches_over_real_path_token_hidden(tmp_path):
    pid = _seed(str(tmp_path))
    calls = []
    status = run_send(
        data_root=str(tmp_path), proposal_id=pid,
        transport=_ok_transport(calls), key_provider=InMemoryKeyProvider(_DEK),
        now=lambda: 1000)

    assert status == "sent"
    assert len(calls) == 1
    assert calls[0]["url"] == (
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send")
    # the sender presented the bearer to Gmail, but it is not in our return value
    assert calls[0]["headers"]["Authorization"] == "Bearer " + _ACCESS
    assert _ACCESS not in status


def test_run_send_twice_cannot_fork_a_second_send(tmp_path):
    pid = _seed(str(tmp_path))
    calls = []
    kp = InMemoryKeyProvider(_DEK)
    assert run_send(data_root=str(tmp_path), proposal_id=pid,
                    transport=_ok_transport(calls), key_provider=kp,
                    now=lambda: 1000) == "sent"
    # a second send on the settled proposal is refused before any wire call
    with pytest.raises((AlreadySettledError, IllegalTransitionError)):
        run_send(data_root=str(tmp_path), proposal_id=pid,
                 transport=_ok_transport(calls), key_provider=kp,
                 now=lambda: 1000)
    assert len(calls) == 1


def test_run_send_unknown_proposal_fails_closed_no_wire_call(tmp_path):
    _seed(str(tmp_path))
    calls = []
    with pytest.raises(ProposalNotFoundError):
        run_send(data_root=str(tmp_path), proposal_id="does-not-exist",
                 transport=_ok_transport(calls), key_provider=InMemoryKeyProvider(_DEK),
                 now=lambda: 1000)
    assert calls == []


def test_run_send_indeterminate_settles_unknown(tmp_path):
    pid = _seed(str(tmp_path))
    calls = []

    def transport(method, url, headers, body, *, timeout=30.0):
        calls.append(1)
        return 503, b"upstream unavailable"

    status = run_send(
        data_root=str(tmp_path), proposal_id=pid, transport=transport,
        key_provider=InMemoryKeyProvider(_DEK), now=lambda: 1000)
    assert status == "outcome_unknown"
    assert len(calls) == 1


def test_run_send_refreshes_expired_token_before_single_gmail_call(tmp_path):
    pid = _seed(str(tmp_path))
    calls = []

    def transport(method, url, headers, body, *, timeout=30.0):
        calls.append({"url": url, "headers": dict(headers), "body": body})
        if url == "https://oauth2.googleapis.com/token":
            return 200, (b'{"access_token":"ya29.FRESH","expires_in":3599,'
                         b'"scope":"https://www.googleapis.com/auth/gmail.send"}')
        return 200, b'{"id":"MID","threadId":"TID"}'

    status = run_send(
        data_root=str(tmp_path), proposal_id=pid, transport=transport,
        key_provider=InMemoryKeyProvider(_DEK), now=lambda: 2000)

    assert status == "sent"
    assert [c["url"] for c in calls] == [
        "https://oauth2.googleapis.com/token",
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
    ]
    assert calls[1]["headers"]["Authorization"] == "Bearer ya29.FRESH"
    assert b"1%2F%2FREFRESH" in calls[0]["body"]
    with SqliteKV(paths.token_db(str(tmp_path))) as tk:
        record = SealedTokenStore(
            AEADCipher(InMemoryKeyProvider(_DEK)), tk).token_record()
    assert record["access_token"] == "ya29.FRESH"
    assert record["refresh_token"] == "1//REFRESH"
    assert record["issued_at"] == 2000
    assert record["expires_at"] == 5599


def test_run_send_refresh_failure_never_calls_gmail(tmp_path):
    pid = _seed(str(tmp_path))
    calls = []

    def transport(method, url, headers, body, *, timeout=30.0):
        calls.append(url)
        assert url == "https://oauth2.googleapis.com/token"
        return 400, b'{"error":"invalid_grant"}'

    status = run_send(
        data_root=str(tmp_path), proposal_id=pid, transport=transport,
        key_provider=InMemoryKeyProvider(_DEK), now=lambda: 2000)
    assert status == "failed"
    assert calls == ["https://oauth2.googleapis.com/token"]


def test_main_requires_explicit_proposal(tmp_path):
    # argparse exits (code 2) when the required --proposal is absent: no implicit
    # "send the latest" path exists.
    with pytest.raises(SystemExit):
        main(["--data-root", str(tmp_path)])
