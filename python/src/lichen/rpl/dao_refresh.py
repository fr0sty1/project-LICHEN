# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DAO refresh scheduling and timing utilities.

This module handles refresh timing, expiration checks, and deadline calculations
for DAO management. Extracted from dao_manager.py to separate timing concerns
from core DAO processing logic.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from typing import cast

from lichen.rpl.dao_types import DaoError, Freshness


@dataclass
class DaoRefreshScheduler:
    """Manages DAO refresh timing, expiration, and deadline calculations.

    Handles time validation, candidate lifetime calculations, and
    determines when routes should be refreshed or expired.
    """

    lifetime_unit_seconds: float = 60.0
    freshness_retention_seconds: float = 86400.0
    clock: Callable[[], float] | None = None
    _last_now_seconds: float | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        """Validate configuration parameters."""
        for duration_name, duration_value, zero_allowed in (
            ("lifetime_unit_seconds", self.lifetime_unit_seconds, False),
            ("freshness_retention_seconds", self.freshness_retention_seconds, True),
        ):
            if type(duration_value) not in (int, float):
                raise ValueError(f"{duration_name} must be a finite valid duration")
            numeric_duration = cast(int | float, duration_value)
            try:
                normalized_duration = float(numeric_duration)
            except OverflowError:
                raise ValueError(f"{duration_name} must be a finite valid duration") from None
            if (
                not math.isfinite(normalized_duration)
                or normalized_duration < 0
                or (not zero_allowed and normalized_duration == 0)
            ):
                raise ValueError(f"{duration_name} must be a finite valid duration")
            setattr(self, duration_name, normalized_duration)
        if self.clock is not None and not callable(self.clock):
            raise ValueError("clock must be callable")

    def validate_now(self, value: object) -> float:
        """Validate a time sample is finite, non-negative, and non-regressing.

        Args:
            value: A time value to validate

        Returns:
            The validated time as a float

        Raises:
            DaoError: If the time is invalid or moves backward
        """
        if type(value) not in (int, float):
            raise DaoError("DAO time sample must be finite and non-negative", reason="invalid_time")
        numeric_value = cast(int | float, value)
        try:
            now = float(numeric_value)
        except OverflowError:
            raise DaoError(
                "DAO time sample must be finite and non-negative", reason="invalid_time"
            ) from None
        if not math.isfinite(now) or now < 0:
            raise DaoError("DAO time sample must be finite and non-negative", reason="invalid_time")
        if self._last_now_seconds is not None and now < self._last_now_seconds:
            raise DaoError("DAO time moved backwards", reason="invalid_time")
        return now

    @staticmethod
    def checked_time_sum(base: float, delta: float) -> float:
        """Add two time values with overflow checking.

        Args:
            base: The base time value
            delta: The delta to add

        Returns:
            The sum of base and delta

        Raises:
            DaoError: If the result overflows to infinity
        """
        result = base + delta
        if not math.isfinite(result):
            raise DaoError("DAO time arithmetic overflow", reason="invalid_time")
        return result

    def candidate_deadline(self, lifetime: int, now: float) -> float | None:
        """Calculate when a candidate expires based on its lifetime.

        Args:
            lifetime: Path lifetime in lifetime units (0-255)
            now: Current time in seconds

        Returns:
            Expiration deadline in seconds, or None if lifetime is 255 (infinite)

        Raises:
            DaoError: If time arithmetic overflows
        """
        if lifetime == 255:
            return None
        delta = lifetime * self.lifetime_unit_seconds
        if not math.isfinite(delta):
            raise DaoError("DAO time arithmetic overflow", reason="invalid_time")
        return self.checked_time_sum(now, delta)

    def clock_now(self) -> float:
        """Get the current time from the configured clock.

        Returns:
            The current time as validated by validate_now

        Raises:
            DaoError: If no clock is configured or the clock fails
        """
        if self.clock is None:
            raise DaoError("no clock configured", reason="invalid_time")
        try:
            value = self.clock()
        except BaseException as exc:
            raise DaoError("DAO clock failed", reason="invalid_time") from exc
        return self.validate_now(value)

    def record_time(self, now: float) -> None:
        """Record a time sample for regression checking."""
        self._last_now_seconds = now

    def freshness_retention_deadline(self, base_time: float) -> float:
        """Calculate the freshness retention deadline from a base time.

        Args:
            base_time: The base time to calculate from

        Returns:
            The deadline after which freshness state may be evicted
        """
        return self.checked_time_sum(base_time, self.freshness_retention_seconds)

    def is_edge_expired(
        self,
        edge: tuple[IPv6Address, IPv6Address],
        edge_expiry: dict[tuple[IPv6Address, IPv6Address], float | None],
        now: float,
    ) -> bool:
        """Check if an edge has expired.

        Args:
            edge: (target, parent) tuple
            edge_expiry: Map of edges to their expiration times
            now: Current time in seconds

        Returns:
            True if the edge has expired, False otherwise
        """
        deadline = edge_expiry.get(edge)
        if deadline is None:
            return False  # Infinite lifetime
        return now >= deadline

    def compute_active_edges(
        self,
        edge_expiry: dict[tuple[IPv6Address, IPv6Address], float | None],
        now: float,
    ) -> dict[tuple[IPv6Address, IPv6Address], float | None]:
        """Filter edge expiry map to only active (non-expired) edges.

        Args:
            edge_expiry: Map of edges to their expiration times
            now: Current time in seconds

        Returns:
            Filtered map containing only non-expired edges
        """
        return {
            edge: deadline
            for edge, deadline in edge_expiry.items()
            if deadline is None or deadline > now
        }

    def next_expiration(
        self,
        edge_expiry: dict[tuple[IPv6Address, IPv6Address], float | None],
    ) -> float | None:
        """Find the soonest expiration deadline.

        Args:
            edge_expiry: Map of edges to their expiration times

        Returns:
            The soonest finite deadline, or None if all are infinite or empty
        """
        finite_deadlines = [d for d in edge_expiry.values() if d is not None]
        if not finite_deadlines:
            return None
        return min(finite_deadlines)

    def update_freshness_on_withdrawal(
        self,
        freshness: Freshness,
        now: float,
    ) -> Freshness:
        """Create updated freshness state when a target is withdrawn.

        Args:
            freshness: Current freshness state
            now: Current time in seconds

        Returns:
            New Freshness with updated expiration tracking
        """
        return Freshness(
            freshness.sequence,
            now,
            self.freshness_retention_deadline(now),
            now,
        )

    def create_initial_freshness(
        self,
        sequence: int,
        now: float,
    ) -> Freshness:
        """Create initial freshness state for a new target.

        Args:
            sequence: Path sequence number
            now: Current time in seconds

        Returns:
            New Freshness state for tracking
        """
        return Freshness(
            sequence,
            None,
            self.freshness_retention_deadline(now),
            now,
        )

    def create_active_freshness(
        self,
        sequence: int,
        active_until: float | None,
        now: float,
    ) -> Freshness:
        """Create freshness state for an active target.

        Args:
            sequence: Path sequence number
            active_until: When the target will expire (None for infinite)
            now: Current time in seconds

        Returns:
            New Freshness state with proper retention deadline
        """
        retain_base = now if active_until is None else max(now, active_until)
        return Freshness(
            sequence,
            active_until,
            self.freshness_retention_deadline(retain_base),
            now,
        )
