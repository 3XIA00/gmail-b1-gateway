"""The §1 continuous-clock seam: platform dispatch + fail-closed (2026-09-05).

All NON-TIMING: no test sleeps or measures elapsed wall time. Dispatch is proven
by monkeypatching the ``time`` module and capturing which clock id the seam reads;
fail-closed is proven by asserting the seam RAISES on unmapped platforms rather
than returning any callable -- in particular it must never fall back to
``time.monotonic`` (which freezes across suspend, the exact hole §1 closes).
"""

from __future__ import annotations

import sys
import time

import pytest

from authz.clock import (
    ContinuousClockUnavailable,
    _PLATFORM_CLOCK,
    make_continuous_clock_ns,
    resolve_continuous_clock,
)


def test_dispatch_table_maps_the_two_compliant_clocks():
    # The frozen mapping: macOS -> CLOCK_MONOTONIC_RAW, Linux -> CLOCK_BOOTTIME.
    assert _PLATFORM_CLOCK == {
        "darwin": "CLOCK_MONOTONIC_RAW",
        "linux": "CLOCK_BOOTTIME",
    }


def test_darwin_reads_clock_monotonic_raw(monkeypatch):
    monkeypatch.setattr(time, "CLOCK_MONOTONIC_RAW", 4, raising=False)
    captured = {}

    def fake_ns(clock_id):
        captured["clock_id"] = clock_id
        return 111

    monkeypatch.setattr(time, "clock_gettime_ns", fake_ns, raising=False)
    clk = make_continuous_clock_ns("darwin")
    assert clk.clock_name == "CLOCK_MONOTONIC_RAW"
    assert clk() == 111
    assert captured["clock_id"] == 4       # dispatched to CLOCK_MONOTONIC_RAW


def test_linux_reads_clock_boottime(monkeypatch):
    monkeypatch.setattr(time, "CLOCK_BOOTTIME", 7, raising=False)
    captured = {}

    def fake_ns(clock_id):
        captured["clock_id"] = clock_id
        return 222

    monkeypatch.setattr(time, "clock_gettime_ns", fake_ns, raising=False)
    clk = make_continuous_clock_ns("linux")
    assert clk.clock_name == "CLOCK_BOOTTIME"
    assert clk() == 222
    assert captured["clock_id"] == 7       # dispatched to CLOCK_BOOTTIME


@pytest.mark.parametrize("platform", ["win32", "cygwin", "aix", "sunos5", "plan9", "weird-os"])
def test_unmapped_platform_fails_closed(platform):
    # Allow-list: an unmapped platform is REFUSED, never defaulted.
    with pytest.raises(ContinuousClockUnavailable):
        resolve_continuous_clock(platform)
    with pytest.raises(ContinuousClockUnavailable):
        make_continuous_clock_ns(platform)


def test_mapped_platform_missing_constant_fails_closed(monkeypatch):
    # A mapped platform whose interpreter lacks the clock constant also fails
    # closed -- it does NOT fall back to time.monotonic.
    monkeypatch.delattr(time, "CLOCK_BOOTTIME", raising=False)
    with pytest.raises(ContinuousClockUnavailable):
        resolve_continuous_clock("linux")


def test_never_falls_back_to_time_monotonic(monkeypatch):
    # Even if time.monotonic exists (it always does), the unmapped path must raise
    # rather than return a monotonic-backed callable. Assert no callable escapes.
    sentinel = object()
    result = sentinel
    try:
        result = make_continuous_clock_ns("win32")
    except ContinuousClockUnavailable:
        pass
    assert result is sentinel      # nothing returned; strictly fail-closed


def test_default_resolves_running_platform_or_fails_closed():
    # No-arg resolution uses sys.platform: a real continuous clock on macOS/Linux,
    # else fail-closed. It must never silently succeed elsewhere.
    if sys.platform in ("darwin", "linux"):
        clk = make_continuous_clock_ns()
        assert isinstance(clk(), int)
    else:
        with pytest.raises(ContinuousClockUnavailable):
            make_continuous_clock_ns()
