"""Sanitization CONTRAST test (Boris's addition).

A sanitizer test only proves something if the UNSANITIZED value would actually
have leaked. So we build an exception carrying a real (fake, throwaway) token in
its message -- the exact shape an OAuth failure produces -- and:

  1. first assert the RAW ``str(exc)`` DOES contain the token (the leak is real);
  2. then assert ``sanitize_error(exc)`` does NOT, and is just the type name.

The tokens below are obviously fake, one-time throwaway strings: never real
credentials.
"""

from __future__ import annotations

from authz.sanitize import sanitize_error

# Clearly-fake throwaway secrets, only to prove the sanitizer removes them.
_FAKE_REFRESH = "1//0gFAKE-refresh-token-DO-NOT-USE-throwaway"
_FAKE_ACCESS = "ya29.FAKEfake-access-token-DO-NOT-USE-throwaway"


class FakeOAuthHTTPError(Exception):
    """Stands in for an HTTPError whose str() is the raw provider response body."""


def _token_bearing_exception() -> FakeOAuthHTTPError:
    body = (
        '{"error":"invalid_grant","error_description":"Token has been expired '
        'or revoked.","refresh_token":"%s","access_token":"%s"}'
        % (_FAKE_REFRESH, _FAKE_ACCESS)
    )
    url = "https://oauth.example/callback#access_token=%s&token_type=Bearer" % _FAKE_ACCESS
    return FakeOAuthHTTPError(body + " " + url)


def test_unsanitized_exception_leaks_the_token():
    exc = _token_bearing_exception()
    raw = str(exc)
    # Precondition of the contrast: WITHOUT sanitization the token is exposed.
    assert _FAKE_REFRESH in raw
    assert _FAKE_ACCESS in raw


def test_sanitized_exception_drops_the_token():
    exc = _token_bearing_exception()
    safe = sanitize_error(exc)
    assert _FAKE_REFRESH not in safe
    assert _FAKE_ACCESS not in safe
    assert safe == "FakeOAuthHTTPError"  # type name only, no message


def test_sanitized_with_safe_code_keeps_code_not_token():
    exc = _token_bearing_exception()
    safe = sanitize_error(exc, code="invalid_grant")
    assert safe == "FakeOAuthHTTPError:invalid_grant"
    assert _FAKE_REFRESH not in safe and _FAKE_ACCESS not in safe


def test_unsafe_code_is_dropped():
    exc = _token_bearing_exception()
    # A "code" that is actually a token must not pass through; it fails the
    # safe-short-code shape and is dropped, leaving only the type name.
    safe = sanitize_error(exc, code=_FAKE_ACCESS)
    assert safe == "FakeOAuthHTTPError"
    assert _FAKE_ACCESS not in safe
