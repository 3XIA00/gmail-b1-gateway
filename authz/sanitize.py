"""Sanitizer for exceptions that may carry a credential.

An OAuth/HTTP failure often puts the token straight into the exception: the
provider's ``invalid_grant`` JSON body, a redirect URL with ``access_token=``,
or an ``HTTPError`` whose ``str()`` is the raw response body. Logging or
returning ``str(exc)`` would leak it.

The safe representation is the exception TYPE name plus an optional short,
whitelisted machine code -- never ``str(exc)``, never its args. Same principle
as the ``authorize`` CLI's top-level boundary ("type only"), factored out so a
send-path failure sanitizes identically and Boris's contrast test can prove it.
"""

from __future__ import annotations

import re
from typing import Optional

# A conservative allow-list of short machine codes we are willing to surface.
# Anything not on the list is dropped -- we never pass through attacker/provider
# controlled free text, which is where a token could hide.
_SAFE_CODE = re.compile(r"\A[a-z][a-z0-9_]{0,39}\Z")


def sanitize_error(exc: BaseException, *, code: Optional[str] = None) -> str:
    """Return a token-free descriptor: ``TypeName`` or ``TypeName:code``.

    ``code`` is surfaced only if it matches the safe short-code shape; the
    exception's message/args are never included, because that is exactly where a
    credential ends up.
    """
    name = type(exc).__name__
    if code is not None and _SAFE_CODE.match(code):
        return "%s:%s" % (name, code)
    return name
