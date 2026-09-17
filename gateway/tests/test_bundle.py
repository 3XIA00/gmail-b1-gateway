"""Bundled-client loader tests (deployment "one-click authorize", axis c1).

Actuates the runtime supply-chain contract of `gateway.bundle`:
  - a bundle whose raw bytes match the pin loads (Desktop `{"installed": {...}}`
    and bare shapes; secret present and absent);
  - ANY single-byte mutation -- explicitly including the text-mode-hazard bytes
    0x1A / 0x0A and an LF->CRLF newline rewrite -- fails closed, because the pin
    is over the raw bytes read in binary with no transcoding;
  - an absent/empty/malformed/all-zero pin is refused *before* the file is
    opened (the deployment guard), so a misconfig cannot mint under an unset pin;
  - at the `authorize.main` level, deployment mode with an unusable/mismatched
    pin returns non-zero and seals no token (fail-closed before any side effect).
"""

import hashlib
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gateway import paths
from gateway.bundle import (
    EXPECTED_CLIENT_SHA256,
    BundleError,
    load_bundled_client,
)

_INSTALLED = {
    "installed": {
        "client_id": "1234.apps.googleusercontent.com",
        "client_secret": "GOCSPX-example",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": ["http://localhost"],
    }
}


def _write_bundle(dir_path, obj) -> tuple[str, str]:
    """Write `obj` as JSON bytes; return (path, sha256-of-raw-bytes hex)."""
    raw = json.dumps(obj).encode("utf-8")
    p = dir_path / "client.json"
    p.write_bytes(raw)
    return str(p), hashlib.sha256(raw).hexdigest()


def test_loads_installed_shape_with_matching_pin(tmp_path):
    path, pin = _write_bundle(tmp_path, _INSTALLED)
    assert load_bundled_client(path, pin) == (
        "1234.apps.googleusercontent.com", "GOCSPX-example")


def test_loads_bare_object_and_secretless_branch(tmp_path):
    path, pin = _write_bundle(tmp_path, {"client_id": "xyz.apps"})
    # No client_secret -> None, mirroring _read_client_credentials.
    assert load_bundled_client(path, pin) == ("xyz.apps", None)


def test_uppercase_pin_is_accepted_case_insensitively(tmp_path):
    path, pin = _write_bundle(tmp_path, _INSTALLED)
    assert load_bundled_client(path, pin.upper())[0].endswith(".com")


@pytest.mark.parametrize("bad_pin", [
    None,
    "",
    "   ",
    "testfake",
    "REPLACE_ME",
    "deadbeef",                 # too short
    "g" * 64,                   # right length, non-hex
    "a" * 63,                   # one short
    "a" * 65,                   # one long
    "0" * 64,                   # all-zero unset sentinel
])
def test_unusable_pin_fails_before_reading_file(tmp_path, bad_pin):
    # Point at a NONEXISTENT path: if the guard runs first (as it must), the
    # error is about the *hash*, not an unreadable file -- proving no file I/O
    # happened before the pin was validated.
    missing = str(tmp_path / "does-not-exist.json")
    with pytest.raises(BundleError, match="hash"):
        load_bundled_client(missing, bad_pin)


def test_mismatched_pin_fails_closed(tmp_path):
    path, _ = _write_bundle(tmp_path, _INSTALLED)
    other = hashlib.sha256(b"a different client").hexdigest()
    with pytest.raises(BundleError, match="does not match"):
        load_bundled_client(path, other)


@pytest.mark.parametrize("mutation", [
    b"\x1a",   # text-mode read-EOF hazard (keystore precedent)
    b"\x0a",   # LF, transcodes to CRLF under Windows text mode
    b"\x00",   # NUL
    b"x",      # ordinary byte
])
def test_appended_hazard_byte_fails_closed(tmp_path, mutation):
    raw = json.dumps(_INSTALLED).encode("utf-8")
    pin = hashlib.sha256(raw).hexdigest()
    p = tmp_path / "client.json"
    p.write_bytes(raw + mutation)          # one extra byte -> different digest
    with pytest.raises(BundleError, match="does not match"):
        load_bundled_client(str(p), pin)


def test_lf_to_crlf_rewrite_fails_closed(tmp_path):
    # Pin an LF-newline body; a CRLF-rewritten copy is a *different* byte
    # sequence and must fail -- proving no newline normalization in the hash.
    raw_lf = b'{\n"client_id": "id.apps"\n}'
    pin = hashlib.sha256(raw_lf).hexdigest()
    p = tmp_path / "client.json"
    p.write_bytes(raw_lf.replace(b"\n", b"\r\n"))
    with pytest.raises(BundleError, match="does not match"):
        load_bundled_client(str(p), pin)
    # Sanity: the untouched LF bytes DO match the same pin.
    p.write_bytes(raw_lf)
    assert load_bundled_client(str(p), pin) == ("id.apps", None)


# tmp_path is reused across examples on purpose: each example rewrites the file
# before loading, so the fixture carries no state between examples.
@settings(max_examples=60, deadline=None,
          suppress_health_check=[HealthCheck.function_scoped_fixture])
@given(data=st.data())
def test_any_single_byte_mutation_fails_closed(tmp_path, data):
    raw = json.dumps(_INSTALLED).encode("utf-8")
    pin = hashlib.sha256(raw).hexdigest()
    idx = data.draw(st.integers(min_value=0, max_value=len(raw) - 1))
    delta = data.draw(st.integers(min_value=1, max_value=255))
    mutated = bytearray(raw)
    mutated[idx] = (mutated[idx] + delta) % 256   # guaranteed different byte
    p = tmp_path / "client.json"
    p.write_bytes(bytes(mutated))
    # Either the digest differs (mismatch) or the JSON is now unparseable; both
    # are BundleError, both fail closed. Never returns creds for mutated bytes.
    with pytest.raises(BundleError):
        load_bundled_client(str(p), pin)


def test_valid_json_but_no_client_id_fails_closed(tmp_path):
    path, pin = _write_bundle(tmp_path, {"installed": {"client_secret": "only"}})
    with pytest.raises(BundleError, match="client_id"):
        load_bundled_client(path, pin)


def test_module_pin_is_unset_so_deployment_refuses_by_default():
    # The shipped constant is None until c2 sets it; deployment authorize must
    # fail closed until a real pin is configured.
    assert EXPECTED_CLIENT_SHA256 is None


# --- authorize.main deployment path: fail-closed, no side effect --------------

def _no_token_sealed(data_root: str) -> bool:
    import os
    return not os.path.exists(paths.token_db(data_root))


def test_main_bundled_with_unset_pin_fails_closed(tmp_path, capsys):
    from gateway import authorize
    # Default module pin is None -> guard refuses before opening/creating anything.
    rc = authorize.main(["--data-root", str(tmp_path), "--bundled"])
    assert rc == 2
    assert _no_token_sealed(str(tmp_path))          # never reached run_authorize
    assert "bundled client" in capsys.readouterr().err


def test_main_bundled_with_mismatched_pin_fails_closed(tmp_path, capsys, monkeypatch):
    from gateway import authorize, bundle
    # A real-shaped pin, but the on-disk bundle does not match it.
    bundle_path = tmp_path / "client" / "client.json"
    bundle_path.parent.mkdir(parents=True)
    bundle_path.write_bytes(json.dumps(_INSTALLED).encode("utf-8"))
    monkeypatch.setattr(bundle, "EXPECTED_CLIENT_SHA256",
                        hashlib.sha256(b"not the bundle").hexdigest())
    rc = authorize.main(["--data-root", str(tmp_path), "--bundled"])
    assert rc == 2
    assert _no_token_sealed(str(tmp_path))
    assert "does not match" in capsys.readouterr().err


def test_main_rejects_both_sources_at_once(tmp_path):
    from gateway import authorize
    # --client-secret-file and --bundled are mutually exclusive.
    with pytest.raises(SystemExit):
        authorize.main([
            "--data-root", str(tmp_path),
            "--client-secret-file", "x.json", "--bundled"])
