# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Time provider abstraction for LICHEN nodes.

Provides a protocol for obtaining time from various sources (GNSS, NTP, monotonic)
with awareness of time quality and availability.
"""

from __future__ import annotations

import time
from typing import Protocol


class TimeProvider(Protocol):
    """Protocol for time sources in LICHEN nodes.

    Implementations may provide time from GNSS, NTP, or fallback to
    monotonic-only when no absolute time source is available.
    """

    def unix_time_us(self) -> int | None:
        """Return UTC time in microseconds since Unix epoch, or None if unavailable.

        Returns:
            Unix timestamp in microseconds, or None if absolute time is not available.
        """
        ...

    def has_gnss_fix(self) -> bool:
        """Return True if time source is GNSS with valid fix.

        Returns:
            True if the time source is GNSS and currently has a valid fix.
        """
        ...


class MonotonicTimeProvider:
    """Fallback time provider using system monotonic clock.

    Does not provide absolute Unix time - only useful for relative timing.
    """

    def unix_time_us(self) -> int | None:
        """Return None since monotonic clock has no absolute time reference."""
        return None

    def has_gnss_fix(self) -> bool:
        """Return False since this is not a GNSS source."""
        return False

    def monotonic_ns(self) -> int:
        """Return monotonic time in nanoseconds for relative timing."""
        return time.monotonic_ns()


class SimulatedTimeProvider:
    """Simulated time provider for testing.

    Allows setting arbitrary Unix time and GNSS fix state.
    """

    def __init__(
        self,
        unix_time_us: int | None = None,
        has_gnss: bool = False,
    ) -> None:
        """Initialize simulated time provider.

        Args:
            unix_time_us: Initial Unix time in microseconds, or None.
            has_gnss: Whether to report having a GNSS fix.
        """
        self._unix_time_us = unix_time_us
        self._has_gnss = has_gnss

    def unix_time_us(self) -> int | None:
        """Return configured Unix time in microseconds."""
        return self._unix_time_us

    def has_gnss_fix(self) -> bool:
        """Return configured GNSS fix state."""
        return self._has_gnss

    def set_unix_time_us(self, unix_time_us: int | None) -> None:
        """Set the Unix time in microseconds.

        Args:
            unix_time_us: New Unix time in microseconds, or None.
        """
        self._unix_time_us = unix_time_us

    def set_gnss_fix(self, has_fix: bool) -> None:
        """Set the GNSS fix state.

        Args:
            has_fix: Whether to report having a GNSS fix.
        """
        self._has_gnss = has_fix

    def advance_us(self, delta_us: int) -> None:
        """Advance the simulated time by the given microseconds.

        Args:
            delta_us: Microseconds to advance (can be negative).

        Raises:
            ValueError: If unix_time_us is None.
        """
        if self._unix_time_us is None:
            raise ValueError("Cannot advance time when unix_time_us is None")
        self._unix_time_us += delta_us
