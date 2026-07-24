# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Duty cycle tracking for LoRa transmissions.

EU 868MHz regulations require 1% duty cycle (36 seconds per hour).
This module provides a sliding window tracker for compliance monitoring.
"""

from __future__ import annotations

class DutyCycleTracker:
    """Track transmit duty cycle over a sliding time window.

    Maintains a history of transmissions and calculates usage as a
    fraction of the configured limit. Used by the simulator to enforce
    regulatory duty cycle constraints.

    Attributes:
        limit_percent: Maximum allowed duty cycle as percentage (>0.0, default 1.0%).
        window_seconds: Sliding window duration in seconds (default 3600).
    """

    def __init__(
        self,
        limit_percent: float = 1.0,
        window_seconds: int = 3600,
    ) -> None:
        """Initialize duty cycle tracker.

        Args:
            limit_percent: Maximum duty cycle as percentage (e.g., 1.0 for 1%).
                Must be > 0.0.
            window_seconds: Duration of sliding window in seconds.
        """
        if limit_percent <= 0.0:
            raise ValueError(f"limit_percent must be positive, got {limit_percent}")
        self.limit_percent = limit_percent
        self.window_seconds = window_seconds
        if limit_percent <= 0:
            raise ValueError(f"limit_percent must be positive, got {limit_percent}")
        self._window_us = window_seconds * 1_000_000
        self._limit_ratio = limit_percent / 100.0
        self._transmissions: list[tuple[int, int]] = []

    def _prune(self, time_us: int) -> None:
        """Remove transmissions that ended before the window.

        Args:
            time_us: Current time in microseconds.
        """
        cutoff = time_us - self._window_us
        # Keep TXs where end time (t + d) > cutoff
        self._transmissions = [(t, d) for t, d in self._transmissions if t + d > cutoff]

    def _airtime_in_window(self, time_us: int) -> int:
        """Calculate total airtime within the current window.

        For transmissions spanning the window boundary, only counts
        the portion within the window.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Total airtime in microseconds within the window.
        """
        cutoff = time_us - self._window_us
        total = 0
        for t, d in self._transmissions:
            if t >= cutoff:
                # TX entirely within window
                total += d
            else:
                # TX spans boundary - only count portion after cutoff
                total += (t + d) - cutoff
        return total

    def record_tx(self, airtime_us: int, time_us: int) -> None:
        """Record a transmission.

        Args:
            airtime_us: Duration of transmission in microseconds.
            time_us: Timestamp when transmission started in microseconds.
        """
        self._prune(time_us)
        self._transmissions.append((time_us, airtime_us))

    def get_usage(self, time_us: int) -> float:
        """Get current duty cycle usage as a ratio.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Usage as a ratio from 0.0 to 1.0, where 1.0 means the limit
            has been reached. Can exceed 1.0 if over limit.
        """
        self._prune(time_us)
        if not self._transmissions:
            return 0.0

        total_airtime = self._airtime_in_window(time_us)
        max_airtime = self._window_us * self._limit_ratio
        return total_airtime / max_airtime

    def can_transmit(self, airtime_us: int, time_us: int) -> bool:
        """Check if a transmission would exceed the duty cycle limit.

        Args:
            airtime_us: Duration of proposed transmission in microseconds.
            time_us: Current time in microseconds.

        Returns:
            True if transmission would stay within duty cycle limit.
        """
        self._prune(time_us)
        total_airtime = self._airtime_in_window(time_us)
        max_airtime = self._window_us * self._limit_ratio
        return (total_airtime + airtime_us) <= max_airtime

    def remaining_ms(self, time_us: int) -> int:
        """Return remaining TX budget in milliseconds.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Remaining airtime budget in milliseconds. Can be negative if
            over the limit.
        """
        self._prune(time_us)
        total_airtime = self._airtime_in_window(time_us)
        max_airtime = self._window_us * self._limit_ratio
        remaining_us = int(max_airtime - total_airtime)
        return remaining_us // 1000

    def usage_permille(self, time_us: int) -> int:
        """Return current duty cycle usage in permille (window-relative).

        Computes `(used_airtime * 1000) / window_us`, matching the Rust
        implementation. For 1% duty cycle, at limit this returns 10.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Usage in permille (0 to 1000+).
        """
        self._prune(time_us)
        used = self._airtime_in_window(time_us)
        return (used * 1000) // self._window_us

    def usage_percent(self, time_us: int) -> float:
        """Return current duty cycle usage as a percentage.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Usage as a percentage from 0.0 to 100.0+. Values above 100.0
            indicate the limit has been exceeded.
        """
        return self.get_usage(time_us) * 100.0

    def time_until_budget_refill_ms(self, time_us: int) -> int:
        """Return time until duty cycle budget begins to refill.

        The budget refills as old transmissions slide out of the window.
        Returns 0 if there are no transmissions or budget is already
        available.

        Args:
            time_us: Current time in microseconds.

        Returns:
            Milliseconds until the oldest transmission exits the window,
            or 0 if no transmissions are pending expiration.
        """
        self._prune(time_us)
        if not self._transmissions:
            return 0

        # Find the oldest transmission's end time
        oldest_end_us = min(t + d for t, d in self._transmissions)
        cutoff = time_us - self._window_us

        if oldest_end_us <= cutoff:
            # Already expired
            return 0

        # Time until oldest TX end exits the window
        time_until_us = oldest_end_us - cutoff
        return max(0, time_until_us // 1000)

    def next_tx_available_ms(self, airtime_us: int, time_us: int) -> int:
        """Return when a TX of given airtime will be allowed.

        Uses cumulative-freed algorithm matching Rust implementation:
        computes how much budget must be freed (needed), then walks
        records in chronological order accumulating freed duration
        until enough has aged out.

        Args:
            airtime_us: Duration of proposed transmission in microseconds.
            time_us: Current time in microseconds.

        Returns:
            0 if TX is allowed now, -1 if TX exceeds maximum possible budget
            (impossible even with empty window), otherwise milliseconds until
            enough budget is available.
        """
        max_airtime_us = self._window_us * self._limit_ratio
        max_airtime_ms = max_airtime_us // 1000
        airtime_ms = airtime_us // 1000

        if airtime_us > max_airtime_us:
            return -1

        self._prune(time_us)
        used_ms = self._airtime_in_window(time_us) // 1000

        if used_ms + airtime_ms <= max_airtime_ms:
            return 0

        needed = used_ms + airtime_ms - max_airtime_ms
        freed = 0

        time_ms = time_us // 1000
        window_ms = self._window_us // 1000

        # Records are kept in chronological order
        for ts_us, dur_us in self._transmissions:
            freed += dur_us // 1000
            if freed >= needed:
                ts_ms = ts_us // 1000
                delay = ts_ms + window_ms - time_ms
                return max(0, delay)

        return -1
