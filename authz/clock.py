"""The continuous (suspend-inclusive, monotonic) security clock seam (L5 §1).

The §1 response deadline and the R2 dispatch-record offsets are read from a clock
that MUST be monotonic AND keep counting across system sleep/suspend -- otherwise
a machine that suspends between "request sent" and "decision verified" measures a
tiny elapsed time and a stale decision sails through the deadline.

``time.monotonic()`` is NOT such a clock: on macOS and Linux it FREEZES during
suspend, so it under-counts exactly the gap an attacker would exploit. It is
therefore forbidden as the security clock (Jeff: "不要用 time.monotonic() 冒充合规
连续钟"). The correct primitive is platform-specific:

    Darwin  -> time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
    Linux   -> time.clock_gettime_ns(time.CLOCK_BOOTTIME)

Both are monotonic and suspend-inclusive. This module resolves the right one at
STARTUP and FAILS CLOSED on any platform not in the dispatch table -- it never
silently falls back to ``time.monotonic()`` (that would reintroduce the exact
freeze the seam exists to prevent). Windows (``win32``) is unmapped, so a Gateway
started there raises at construction; the deployment host is macOS/Linux.

Scope for this cut: the suspend-inclusive clock folds into the §1 R8 response
deadline acceptance. The full §4.5 T_fresh staleness bound stays deferred.

Diagnostic-only: ``continuous_clock_diagnostic`` compares wall time against
``now - kern.boottime``. That comparison rides the DISTRUSTED wall-clock path, so
per Boris it is release/diagnostic evidence ONLY and is deliberately NOT on the
startup path or the authorize() path -- nothing here calls it.
"""

from __future__ import annotations

import sys
import time
from typing import Callable, Optional, Tuple


class ContinuousClockUnavailable(RuntimeError):
    """Raised at startup when no compliant continuous clock is available for this
    platform. Fail CLOSED -- the Gateway must not run without the §1 clock."""


# platform token (sys.platform) -> the `time` module attribute NAME of its
# suspend-inclusive monotonic clock. Only platforms with a KNOWN such clock are
# listed; every other platform is unmapped and fails closed. This is an
# allow-list, not a deny-list: a novel/unknown platform is refused, never
# defaulted to monotonic. Keyed on the name (not the resolved id) so the dispatch
# is inspectable even on an interpreter that lacks the POSIX constant.
_PLATFORM_CLOCK = {
    "darwin": "CLOCK_MONOTONIC_RAW",
    "linux": "CLOCK_BOOTTIME",
}


def resolve_continuous_clock(platform: Optional[str] = None) -> Tuple[str, int]:
    """Resolve (clock_name, clock_id) for ``platform`` (default: the running one),
    or raise ``ContinuousClockUnavailable``. Pure dispatch -- no wall-clock read,
    so it is safe on the startup path (Boris's boottime caveat)."""
    platform = sys.platform if platform is None else platform
    name = _PLATFORM_CLOCK.get(platform)
    if name is None:
        raise ContinuousClockUnavailable(
            "no compliant continuous (suspend-inclusive monotonic) clock mapped "
            "for platform %r; refusing to fall back to time.monotonic()" % platform)
    clock_id = getattr(time, name, None)
    if clock_id is None:
        # Mapped platform but the interpreter lacks the clock constant.
        raise ContinuousClockUnavailable(
            "platform %r maps to %s but this interpreter does not expose it"
            % (platform, name))
    return name, clock_id


def make_continuous_clock_ns(platform: Optional[str] = None) -> Callable[[], int]:
    """Return a ``() -> int`` nanosecond reader on the platform's continuous
    clock, resolved NOW (startup) and failing closed if unmapped. The returned
    callable carries ``clock_name`` for the release fingerprint."""
    name, clock_id = resolve_continuous_clock(platform)

    def continuous_clock_ns() -> int:
        return time.clock_gettime_ns(clock_id)

    continuous_clock_ns.clock_name = name  # type: ignore[attr-defined]
    return continuous_clock_ns


def continuous_clock_diagnostic() -> dict:
    """RELEASE/DIAGNOSTIC ONLY -- never called on the startup or authorize path.

    Cross-checks the resolved clock against ``now - kern.boottime`` style evidence
    that the clock really is suspend-inclusive. Because it reads the distrusted
    wall clock, its output is evidence for a release note, not an input to any
    security decision (Boris msg_4b1a7c40)."""
    name, clock_id = resolve_continuous_clock()
    return {
        "platform": sys.platform,
        "clock_name": name,
        "continuous_ns": time.clock_gettime_ns(clock_id),
        "wall_ns": time.time_ns(),
    }
