# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import pytest

from lichen.timing.time_fallback import MonotonicFallback, UnixSeconds, consumer_timestamp
from lichen.timing.wall_clock import TimeSourceClass, WallClockError, WallClockValidity


def test_starts_invalid_then_establishes() -> None:
    clock = WallClockValidity()
    assert not clock.is_valid
    assert clock.source is None
    clock.establish(TimeSourceClass.GNSS)
    assert clock.is_valid
    assert clock.source is TimeSourceClass.GNSS
    clock.invalidate()
    assert not clock.is_valid
    assert clock.source is None


def test_monotonic_cannot_establish() -> None:
    clock = WallClockValidity()
    with pytest.raises(WallClockError):
        clock.establish(TimeSourceClass.MONOTONIC)
    assert not clock.is_valid


def test_invalid_clock_falls_back_to_monotonic() -> None:
    stamp = consumer_timestamp(WallClockValidity(), 1_700_000_000, 42)
    assert stamp == MonotonicFallback(42)


def test_established_clock_uses_unix() -> None:
    clock = WallClockValidity()
    clock.establish(TimeSourceClass.GNSS)
    stamp = consumer_timestamp(clock, 1_700_000_000, 99)
    assert stamp == UnixSeconds(1_700_000_000, TimeSourceClass.GNSS)
    clock.invalidate()
    assert consumer_timestamp(clock, 1_700_000_000, 99) == MonotonicFallback(99)
