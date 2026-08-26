# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Monotonic uptime tracking (spec 09 section 14.6).

Observations are implementation-defined ticks since boot. Equal values are
valid; a decrease or wrap within one power cycle is not.
"""

from __future__ import annotations


class MonotonicError(ValueError):
    """Rejected monotonic observation."""


class MonotonicUptime:
    """Non-decreasing tick counter for one power cycle."""

    __slots__ = ("_last",)

    def __init__(self) -> None:
        self._last: int | None = None

    @property
    def now(self) -> int | None:
        return self._last

    def observe(self, ticks: int) -> int:
        if type(ticks) is not int:
            raise TypeError("ticks must be int")
        if ticks < 0:
            raise ValueError("ticks must be non-negative")
        if self._last is not None and ticks < self._last:
            raise MonotonicError("monotonic regression")
        self._last = ticks
        return ticks
