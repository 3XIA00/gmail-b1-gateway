r"""Local build: a real "Connect Gmail" button that runs one real authorization.

POC per Jeremy 2026-09-03: before porting one-click authorize into the daemon,
first ship a *local* build with a real clickable button that runs one real Gmail
authorization on the operator's own machine, using the operator's own existing
(test) Google client. This module is that button.

It adds NO new security surface: the button is the ONLY trigger -- there is no
socket, no HTTP listener, and no `puffo://` URL-scheme handler. Clicking calls
`confirm()` (a native OS dialog) and, only on a positive confirm, verifies the
bundled client (`bundle.load_bundled_client`, hash-pinned, fail-closed) and runs
the real loopback + PKCE consent (`authorize.run_authorize`). It never touches
the proposal / send surface and never prints or stores a token.

Design decisions (the *why*):

- **The in-process button is the only trigger (A2.2 "by construction").** The
  daemon deployment will eventually gate `puffo://authorize` deep-links through
  `gateway.trigger`; this local POC deliberately does NOT reuse that URI entry,
  register any URL-scheme handler, or open any socket. Reusing a URI/IPC entry
  would add a trigger surface an outside process/message could poke; keeping the
  only path `button -> confirm -> authorize` makes "the trigger is a device-local
  human click" true structurally, not just by policy. (Per the signed local-build
  acceptance checklist section 0; the same confirm-gate guarantee `trigger.py`
  enforces is replicated inline here without the URI layer.)
- **The confirm is a native OS dialog = device-local human affirmation (A2.2).**
  A `tkinter` messagebox on the operator's own screen cannot be satisfied by any
  channel/agent/network message. A declined confirm does nothing at all -- the
  client file is not even read and no browser opens.
- **The pin is injected from a LOCAL config, not the module constant.**
  `bundle.EXPECTED_CLIENT_SHA256` stays `None` (deployment still fails closed
  until c2 pins it). The POC's pin comes from a config file the operator fills in
  on their own machine, passed straight to `load_bundled_client` -- the DI seam
  the bundle loader was designed for. Neither the client JSON nor the pin ever
  lives in this repo or in any agent.
- **Wiring is one testable function (`connect_once`); the GUI is a thin shell.**
  `connect_once` is the whole confirm->verify->authorize path and is unit-tested
  with fakes (no display, no real Google). `run_gui` only supplies the native
  `confirm` dialog and renders the token-free summary.

Operator setup (all on your own machine -- nothing here enters the repo/agents):

  1. Put your Google Desktop client JSON somewhere local, e.g.
     `<data-root>\client\client.json` (the default bundle path). Use the WHOLE
     file including client_secret (the pin is over its raw bytes).
  2. Compute its raw-bytes SHA-256 (this is the pin):
       PowerShell:  (Get-FileHash -Algorithm SHA256 .\client.json).Hash.ToLower()
       certutil:    certutil -hashfile .\client.json SHA256
       or:  python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" client.json
  3. Create `local_connect.json` (kept out of git) next to where you run it:
       {
         "data_root": "C:\\path\\to\\poc-data",
         "expected_sha256": "<the 64-hex digest from step 2>"
       }
     ("client_bundle" is optional; it defaults to <data_root>/client/client.json.)
  4. Run:  python -m gateway.local_connect --config local_connect.json
     Click "Connect Gmail" -> confirm -> your browser opens Google's consent page.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Callable, Optional

from oauth.errors import OAuthError

from . import paths
from .authorize import run_authorize
from .bundle import BundleError, load_bundled_client


class LocalConnectConfigError(Exception):
    """The local POC config file is missing or malformed."""


@dataclass(frozen=True)
class LocalConnectConfig:
    data_root: str
    client_bundle: str
    expected_sha256: str


def load_local_config(path: str) -> LocalConnectConfig:
    """Parse the operator's local POC config JSON.

    Requires `data_root` and `expected_sha256` (both non-empty strings);
    `client_bundle` is optional and defaults to `paths.client_bundle(data_root)`.
    Deliberately does NOT validate the pin's *shape* -- that is
    `bundle._validate_expected`'s single responsibility, and duplicating the hex
    check here would be a second place to keep in sync. A malformed pin simply
    fails closed inside `load_bundled_client` at click time.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise LocalConnectConfigError(
            "config not found: %s -- create it (see module docstring)" % path)
    except (OSError, ValueError) as exc:
        raise LocalConnectConfigError("config unreadable: %s" % type(exc).__name__)

    if not isinstance(raw, dict):
        raise LocalConnectConfigError("config must be a JSON object")
    data_root = raw.get("data_root")
    pin = raw.get("expected_sha256")
    if not isinstance(data_root, str) or not data_root:
        raise LocalConnectConfigError(
            "config: 'data_root' (non-empty string) is required")
    if not isinstance(pin, str) or not pin:
        raise LocalConnectConfigError(
            "config: 'expected_sha256' (non-empty string) is required")
    bundle = raw.get("client_bundle")
    if bundle is None:
        bundle = paths.client_bundle(data_root)
    elif not isinstance(bundle, str) or not bundle:
        raise LocalConnectConfigError(
            "config: 'client_bundle' must be a non-empty string if given")
    return LocalConnectConfig(
        data_root=data_root, client_bundle=bundle, expected_sha256=pin)


def build_authorize_callback(
    config: LocalConnectConfig,
    *,
    loader: Callable[[str, Optional[str]], tuple] = load_bundled_client,
    authorizer: Callable[..., dict] = run_authorize,
    timeout: float = 300.0,
) -> Callable[[], dict]:
    """A zero-arg callback: hash-verify the bundled client, then run real authorize.

    Zero-arg by design (A2.2): nothing from any caller/URI can steer it -- the
    client is always the config's bundle verified against the config's pin, and
    the redirect is always the gateway's own loopback. `loader`/`authorizer` are
    injected so tests drive the wiring without real Google.
    """
    def _authorize() -> dict:
        client_id, client_secret = loader(config.client_bundle, config.expected_sha256)
        return authorizer(
            data_root=config.data_root,
            client_id=client_id,
            client_secret=client_secret,
            timeout=timeout,
        )
    return _authorize


def connect_once(
    config: LocalConnectConfig,
    *,
    confirm: Callable[[], bool],
    loader: Callable[[str, Optional[str]], tuple] = load_bundled_client,
    authorizer: Callable[..., dict] = run_authorize,
    timeout: float = 300.0,
) -> Optional[dict]:
    """Confirm-gate, then verify-and-authorize once. In-process; no URI/socket.

    Returns the token-free summary dict if the operator confirmed and authorize
    ran, or `None` if the confirmation was declined -- with zero side effect: on a
    decline the client file is not read and no browser opens. This inlines the
    confirm-before-authorize guarantee `trigger.handle_authorize_trigger` gives,
    without the URI entry, so the button is the only trigger surface.
    """
    if not confirm():
        return None
    authorize_cb = build_authorize_callback(
        config, loader=loader, authorizer=authorizer, timeout=timeout)
    return authorize_cb()


def run_gui(config: LocalConnectConfig) -> None:  # pragma: no cover - needs a display
    """The thin tkinter shell: one window, one "Connect Gmail" button.

    Not unit-tested (rendering needs a display); all of its non-GUI logic is in
    `connect_once`, which is. The authorize wait blocks the main thread while the
    browser consent is open -- acceptable for a POC (the operator is in the
    browser, not this window); threading it off is a later polish, not a
    correctness issue.
    """
    import tkinter as tk
    from tkinter import messagebox

    root = tk.Tk()
    root.title("Puffo - Connect Gmail")
    root.minsize(360, 140)

    status = tk.StringVar(
        value="Click to connect your Gmail (bundled test client).")

    def _confirm() -> bool:
        # Device-local human affirmation (A2.2 + A2.4 informed): a native dialog on
        # the operator's own screen, naming the scope + account being connected.
        return bool(messagebox.askyesno(
            "Connect Gmail",
            "Connect your Gmail account to Puffo?\n\n"
            "This opens Google's consent page in your browser and requests "
            "gmail.send access (send-only) for the bundled test client."))

    def _on_click() -> None:
        button.config(state="disabled")
        status.set("Verifying client + opening your browser for Google consent...")
        root.update_idletasks()  # force one repaint before the blocking wait
        try:
            summary = connect_once(config, confirm=_confirm)
        except BundleError as exc:
            messagebox.showerror("Connect Gmail", "Client check failed: %s" % exc)
            status.set("Failed: the bundled client did not verify.")
        except OAuthError as exc:
            # Already sanitized upstream (short provider code / timeout only).
            messagebox.showerror("Connect Gmail", "Authorization failed: %s" % exc)
            status.set("Failed during Google consent.")
        except Exception as exc:  # noqa: BLE001 - sanitizing boundary: type only
            # Never surface a message that could carry a token/secret.
            messagebox.showerror(
                "Connect Gmail", "Authorization failed: %s" % type(exc).__name__)
            status.set("Failed.")
        else:
            if summary is not None:
                messagebox.showinfo(
                    "Connect Gmail",
                    "Connected. Token sealed locally.\n\n"
                    "scope=%s\nexpires_in=%s\nrefresh_token=%s\nsealed at %s" % (
                        summary.get("scope"), summary.get("expires_in"),
                        "yes" if summary.get("has_refresh_token") else "no",
                        summary.get("token_db")))
                status.set("Connected. Token sealed locally.")
            else:
                status.set("Cancelled - no browser opened, nothing sealed.")
        finally:
            button.config(state="normal")

    tk.Label(root, textvariable=status, wraplength=340, justify="left").pack(
        padx=16, pady=(16, 8))
    button = tk.Button(root, text="Connect Gmail", command=_on_click, width=20)
    button.pack(padx=16, pady=(0, 16))
    root.mainloop()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gateway.local_connect")
    parser.add_argument(
        "--config", default="local_connect.json",
        help="local POC config JSON (kept out of git; see module docstring)")
    args = parser.parse_args(argv)
    try:
        config = load_local_config(args.config)
    except LocalConnectConfigError as exc:
        sys.stderr.write("local_connect: %s\n" % exc)
        return 2
    run_gui(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
