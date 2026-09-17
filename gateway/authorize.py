"""`gmail-gateway authorize` -- one-time real OAuth, seal the token locally.

Runs the loopback consent flow (`gateway.oauth_listener`) against real Google,
then seals the returned token at rest (keystore AEAD, DEK in the OS keychain)
under the shared data-root. It does exactly this one thing: it never touches the
proposal / confirm / send surface, and it never prints a token -- success is a
scope + location line, so an operator can confirm the grant is `gmail.send`-only
without a credential ever reaching a terminal, log, or evidence file.

Design decisions (the *why*):

- **Client creds come from the Google client-secret JSON file, not argv.** A
  secret passed on the command line leaks into shell history and the process
  table; read it from the file Google hands you (`--client-secret-file`) so it
  stays on disk. The Desktop-app format nests under `"installed"`; a bare
  `{client_id, client_secret}` object is accepted too.
- **DEK provisioned iff absent.** The keychain DEK is created on first authorize
  and never overwritten (`KeyringKeyProvider.provision` refuses), so
  re-authorizing re-seals under the same key rather than orphaning earlier
  sealed data.
- **Everything side-effecting is injected** (flow factory, key provider), so the
  wiring is unit-tested with a fake flow + in-memory key while `main` builds the
  real loopback flow + OS keychain.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Callable

from keystore.aead import AEADCipher
from keystore.errors import KeyMaterialError, KeyUnavailableError
from keystore.providers import KeyProvider, KeyringKeyProvider
from oauth.errors import OAuthError

from . import paths
from .egress import EgressGuardedClient
from .oauth_listener import OAUTH_ALLOW_HOSTS, LoopbackOAuthFlow, TokenResult
from .persistence import SqliteKV
from .send_path import SealedTokenStore

# One keychain DEK entry per install; authorize and send must agree on it so the
# token sealed by one is openable by the other.
_KEYRING_SERVICE = "gmail-gateway"
_KEYRING_DEK_USER = "dek-v1"


def _read_client_credentials(path: str) -> tuple[str, str | None]:
    """(client_id, client_secret) from a Google client-secret JSON file.

    Accepts the Desktop-app shape (`{"installed": {...}}`) and a bare object.
    The client_secret is optional (loopback + PKCE does not strictly require it),
    but Google issues one for Desktop clients and the exchange includes it.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and isinstance(data.get("installed"), dict):
        data = data["installed"]
    if not isinstance(data, dict) or not isinstance(data.get("client_id"), str):
        raise ValueError("client-secret file has no client_id")
    secret = data.get("client_secret")
    return data["client_id"], secret if isinstance(secret, str) else None


def _announce_redirect_uri(redirect_uri: str) -> None:
    # Non-secret (loopback host + ephemeral port + fixed callback path). Printed
    # so the operator can verify it against the consent-page redirect before
    # approving; the port is chosen fresh per run, so there is no fixed value to
    # publish ahead of time. Flush so it lands before the browser-wait blocks.
    sys.stdout.write("redirect_uri: %s\n" % redirect_uri)
    sys.stdout.flush()


def _default_flow_factory(client_id: str, client_secret: str | None,
                          timeout: float) -> LoopbackOAuthFlow:
    # Real loopback flow over a real egress client pinned to the OAuth host
    # (EgressGuardedClient defaults to the live urllib transport).
    egress = EgressGuardedClient(OAUTH_ALLOW_HOSTS)
    return LoopbackOAuthFlow(
        client_id=client_id, egress_client=egress,
        client_secret=client_secret, timeout=timeout,
        on_redirect_uri=_announce_redirect_uri)


def _ensure_dek(provider: KeyProvider) -> None:
    """Provision the keychain DEK iff absent; never overwrite an existing key."""
    try:
        provider.get_dek()
        return
    except KeyUnavailableError:
        pass
    provision = getattr(provider, "provision", None)
    if provision is None:
        raise KeyUnavailableError("key provider has no DEK and cannot provision one")
    provision()


def run_authorize(
    *,
    data_root: str,
    client_id: str,
    client_secret: str | None,
    timeout: float = 300.0,
    flow_factory: Callable[[str, str | None, float], object] | None = None,
    key_provider: KeyProvider | None = None,
    now: Callable[[], int] | None = None,
) -> dict:
    """Run the consent flow and seal the token. Returns a token-free summary."""
    factory = flow_factory or _default_flow_factory
    provider = key_provider or KeyringKeyProvider(_KEYRING_SERVICE, _KEYRING_DEK_USER)

    result: TokenResult = factory(client_id, client_secret, timeout).run()
    issued_at = (
        result.received_at
        if result.received_at is not None
        else (now or (lambda: int(time.time())))()
    )
    expires_at = (
        issued_at + result.expires_in if result.expires_in is not None else None
    )

    _ensure_dek(provider)
    backend = SqliteKV(paths.token_db(data_root))
    try:
        SealedTokenStore(AEADCipher(provider), backend).store(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            issued_at=issued_at,
            expires_at=expires_at,
            client_id=client_id,
            # Desktop-app client_secret is public-by-design; sealing it avoids
            # needless exposure but PKCE, not this string, is the auth boundary.
            client_secret=client_secret,
            scope=result.scope)
    finally:
        backend.close()

    # Token-free summary. `scope` lets the operator confirm gmail.send-only.
    return {
        "scope": result.scope,
        "expires_in": result.expires_in,
        "has_refresh_token": result.refresh_token is not None,
        "token_db": paths.token_db(data_root),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gmail-gateway authorize")
    parser.add_argument("--data-root", required=True)
    # POC/dev vs deployment: exactly one client source. `--client-secret-file`
    # is the operator-supplied Google JSON (no pin); `--bundled` is the daemon
    # deployment client under the data-root, gated by a pinned content hash.
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--client-secret-file")
    source.add_argument("--bundled", action="store_true")
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args(argv)

    try:
        if args.bundled:
            # Deployment path: hash-verify the bundled client (fail-closed before
            # any side effect) and parse the verified bytes. `EXPECTED_CLIENT_SHA256`
            # is None until c2 pins it, so an unpinned build refuses to authorize.
            from .bundle import EXPECTED_CLIENT_SHA256, BundleError, load_bundled_client
            try:
                client_id, client_secret = load_bundled_client(
                    paths.client_bundle(args.data_root), EXPECTED_CLIENT_SHA256)
            except BundleError as exc:
                sys.stderr.write("authorize: bundled client: %s\n" % exc)
                return 2
        else:
            client_id, client_secret = _read_client_credentials(args.client_secret_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        sys.stderr.write("authorize: cannot read client-secret file: %s\n" % exc)
        return 2

    try:
        summary = run_authorize(
            data_root=args.data_root, client_id=client_id,
            client_secret=client_secret, timeout=args.timeout)
    except (KeyMaterialError, KeyUnavailableError) as exc:
        sys.stderr.write("authorize: keychain error: %s\n" % exc)
        return 3
    except OAuthError as exc:
        # Already sanitized upstream (short provider error code / timeout only).
        sys.stderr.write("authorize: %s\n" % exc)
        return 1
    except Exception as exc:  # noqa: BLE001 -- top-level sanitizing boundary
        # Never surface a message that could carry a token/secret: type only.
        sys.stderr.write("authorize: failed: %s\n" % type(exc).__name__)
        return 1

    sys.stdout.write(
        "authorized: scope=%s expires_in=%s refresh_token=%s\n"
        "token sealed at %s\n" % (
            summary["scope"], summary["expires_in"],
            "yes" if summary["has_refresh_token"] else "no",
            summary["token_db"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
