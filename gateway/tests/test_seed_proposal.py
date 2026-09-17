"""`gateway.seed_proposal` — local POC seed for the end-to-end send (not a verb).

Drives the seed over ON-DISK backends and pins the two properties that matter:
  - a seeded proposal is exactly the one `send` later confirms — seeding then
    running the real send path dispatches over the wire, and the frozen record
    round-trips PENDING with the returned digest;
  - the seed reuses the closed gate-4 schema + v1 policy verbatim — an unknown
    field or a non-text body fails closed here just as on the Agent route, with
    nothing written to either store.
"""

import argparse
import re

import pytest

from canonicalizer.payload import PayloadSchemaError
from keystore.aead import AEADCipher
from keystore.providers import InMemoryKeyProvider
from store.proposals import ProposalStatus, ProposalStore
from gateway import paths
from gateway.persistence import SqliteKV
from gateway.seed_proposal import _params_from_args, main, run_seed
from gateway.send_cli import run_send
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


def _seal_token(data_root: str) -> None:
    with SqliteKV(paths.token_db(data_root)) as tk:
        SealedTokenStore(AEADCipher(InMemoryKeyProvider(_DEK)), tk).store(
            access_token=_ACCESS, refresh_token="1//REFRESH",
            issued_at=900, expires_at=4500,
            client_id="cid.apps", client_secret="desktop-public-secret",
            scope="https://www.googleapis.com/auth/gmail.send")


def test_seeded_proposal_is_exactly_what_send_dispatches(tmp_path):
    result = run_seed(data_root=str(tmp_path), params=_params(), now=lambda: 1000)
    assert set(result) == {"proposal_id", "payload_digest", "expires_at"}
    assert result["expires_at"] == 1000 + 3600  # default ttl mirrors entrypoint

    # frozen PENDING in the shared store, with the returned digest on the record
    proposals_kv = SqliteKV(paths.proposals_db(str(tmp_path)))
    try:
        rec = ProposalStore(proposals_kv).get(result["proposal_id"])
        assert rec.status == ProposalStatus.PENDING
        assert rec.payload_digest == result["payload_digest"]
    finally:
        proposals_kv.close()

    # the REAL send path (fresh connection set) confirms + dispatches that very
    # proposal over the wire — the seed->send cross-process handoff end to end.
    _seal_token(str(tmp_path))
    calls = []

    def transport(method, url, headers, body, *, timeout=30.0):
        calls.append(url)
        return 200, b'{"id":"MID","threadId":"TID"}'

    status = run_send(
        data_root=str(tmp_path), proposal_id=result["proposal_id"],
        transport=transport, key_provider=InMemoryKeyProvider(_DEK),
        now=lambda: 1000)
    assert status == "sent"
    assert calls == [
        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"]


def test_seed_reuses_closed_schema_unknown_field_fails_closed(tmp_path):
    # An unmodelled field is refused by the reused gate before any store write.
    with pytest.raises(PayloadSchemaError):
        run_seed(data_root=str(tmp_path),
                 params=_params(headers={"X-Injected": "1"}), now=lambda: 1000)

    for db in (paths.proposals_db, paths.payloads_db):
        kv = SqliteKV(db(str(tmp_path)))
        try:
            assert list(kv.values()) == []   # nothing frozen — fail closed
        finally:
            kv.close()


def test_seed_reuses_v1_policy_non_text_body_fails_closed(tmp_path):
    # v1 sends only a text body; an html body is refused through the seed too.
    with pytest.raises(PayloadSchemaError):
        run_seed(
            data_root=str(tmp_path),
            params=_params(body={"format": "html", "content": "<b>no</b>"}),
            now=lambda: 1000)


def test_params_from_args_fixes_text_body_and_omits_empty_cc_bcc():
    ns = argparse.Namespace(
        account_handle="a", to=["x@y"], subject="s", body="b", cc=[], bcc=[])
    assert _params_from_args(ns) == {
        "account_handle": "a", "to": ["x@y"], "subject": "s",
        "body": {"format": "text", "content": "b"}}

    ns2 = argparse.Namespace(
        account_handle="a", to=["x@y"], subject="s", body="b",
        cc=["c@d"], bcc=["e@f"])
    mapped = _params_from_args(ns2)
    assert mapped["cc"] == ["c@d"] and mapped["bcc"] == ["e@f"]


def test_main_seeds_and_prints_send_hint(tmp_path, capsys):
    rc = main(["--data-root", str(tmp_path), "--account-handle", "me@example.com",
               "--to", "alice@example.com", "--subject", "Hi", "--body", "hello"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "python -m gateway send --proposal" in out

    m = re.search(r"proposal_id:\s+(\S+)", out)
    assert m, out
    proposals_kv = SqliteKV(paths.proposals_db(str(tmp_path)))
    try:
        assert ProposalStore(proposals_kv).get(m.group(1)).status == \
            ProposalStatus.PENDING
    finally:
        proposals_kv.close()


def test_main_requires_recipient(tmp_path):
    # argparse exits when the required --to is absent (no empty-recipient seed).
    with pytest.raises(SystemExit):
        main(["--data-root", str(tmp_path), "--account-handle", "me@example.com",
              "--subject", "Hi", "--body", "hello"])
