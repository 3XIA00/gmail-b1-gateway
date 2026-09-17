"""`python -m gateway <verb>` -- the local operator CLI (`gmail-gateway`).

Verbs mirror the design's naming (supervisor `start`/`health`/`stop`, actionset
`propose`/`status`):

  - `authorize`              one-time real OAuth, seal the token locally.
  - `send --proposal <id>`   confirm + dispatch one already-approved proposal.

The token-serving proposal channel is a *separate* entrypoint
(`python -m gateway.entrypoint`), spawned by the supervisor -- deliberately not a
verb here, so this operator surface never itself serves the Agent-facing routes.
"""

from __future__ import annotations

import sys

from . import authorize as _authorize
from . import send_cli as _send

_VERBS = {
    "authorize": _authorize.main,
    "send": _send.main,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in _VERBS:
        sys.stderr.write("usage: python -m gateway {%s} ...\n" % "|".join(_VERBS))
        return 2
    return _VERBS[argv[0]](argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
