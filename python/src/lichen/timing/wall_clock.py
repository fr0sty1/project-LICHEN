# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Wall-clock validity flag (spec 09 section 14.6)."""

from __future__ import annotations

from enum import StrEnum


class TimeSourceClass(StrEnum):
    """Provenance class; wire strings match the shared time-sync vocabulary."""

    GNSS = "GNSS"
    NETWORK = "Network"
    LOCAL_CLIENT = "Local-client"
    MANUAL = "Manual/static"
    INTERNAL_RTC = "Internal RTC"
    MONOTONIC = "Monotonic"

    def can_establish_wall_clock(self) -> bool:
        return self is not TimeSourceClass.MONOTONIC


class WallClockError(ValueError):
    """Failed wall-clock establishment."""


class WallClockValidity:
    """Tracks whether a node currently has an established wall clock."""

    __slots__ = ("_valid", "_source")

    def __init__(self) -> None:
        self._valid = False
        self._source: TimeSourceClass | None = None

    @property
    def is_valid(self) -> bool:
        return self._valid

    @property
    def source(self) -> TimeSourceClass | None:
        return self._source

    def establish(self, source: TimeSourceClass) -> None:
        if type(source) is not TimeSourceClass:
            raise TypeError("source must be TimeSourceClass")
        if not source.can_establish_wall_clock():
            raise WallClockError("monotonic cannot establish wall clock")
        self._valid = True
        self._source = source

    def invalidate(self) -> None:
        self._valid = False
        self._source = None
