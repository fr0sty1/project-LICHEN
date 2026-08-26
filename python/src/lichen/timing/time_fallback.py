# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Constrained-node time when wall_clock_valid is false (spec 09 14.6)."""

from __future__ import annotations

from dataclasses import dataclass

from lichen.timing.wall_clock import TimeSourceClass, WallClockValidity


@dataclass(frozen=True)
class UnixSeconds:
    unix: int
    source: TimeSourceClass


@dataclass(frozen=True)
class MonotonicFallback:
    ticks: int


ConsumerTimestamp = UnixSeconds | MonotonicFallback


def consumer_timestamp(
    clock: WallClockValidity, unix: int, uptime_ticks: int
) -> ConsumerTimestamp:
    """Choose a consumer timestamp. Invalid clocks ignore ``unix``."""
    if type(clock) is not WallClockValidity:
        raise TypeError("clock must be WallClockValidity")
    if type(unix) is not int or type(uptime_ticks) is not int:
        raise TypeError("unix and uptime_ticks must be int")
    if clock.is_valid and clock.source is not None:
        return UnixSeconds(unix, clock.source)
    return MonotonicFallback(uptime_ticks)
