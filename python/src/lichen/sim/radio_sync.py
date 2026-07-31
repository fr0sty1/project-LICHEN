# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Physical radio timing synchronization for mixed-mode simulation.

This module provides clock synchronization between physical radios and the
simulator clock. It handles:
- Clock drift tracking and compensation
- Jitter filtering via exponential moving average
- Time conversion between physical and simulation domains
- Multi-source clock aggregation for HIL testing

The core abstraction is ClockSynchronizer, which maintains a mapping between
a physical radio's local clock and simulation time. Each physical radio
should have its own synchronizer instance.

Typical usage:
    sync = ClockSynchronizer(drift_ppm_max=20.0)

    # When receiving a beacon with known sim time:
    sync.update(physical_rx_time_us, known_sim_time_us)

    # Convert physical timestamps to simulation time:
    sim_time = sync.to_sim_time(physical_time_us)

    # Get current drift estimate:
    drift = sync.drift_ppm
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto


class SyncState(Enum):
    """Synchronization state for a clock source."""

    UNSYNCHRONIZED = auto()  # No sync points yet
    ACQUIRING = auto()  # Building initial estimate (< min_samples)
    SYNCHRONIZED = auto()  # Stable sync with drift compensation
    DRIFTING = auto()  # Sync stale, drift may exceed bounds


@dataclass
class SyncPoint:
    """A single time synchronization observation.

    Attributes:
        physical_us: Physical radio timestamp in microseconds
        sim_us: Corresponding simulation time in microseconds
        wall_us: Wall-clock time when observation was made
    """

    physical_us: int
    sim_us: int
    wall_us: int = field(default_factory=lambda: int(time.monotonic_ns() // 1000))


@dataclass
class ClockStats:
    """Statistics for a synchronized clock.

    Attributes:
        drift_ppm: Estimated clock drift in parts per million
        jitter_us: Estimated jitter (standard deviation) in microseconds
        offset_us: Current offset from simulation time in microseconds
        samples: Number of sync points used in estimate
        last_sync_age_us: Time since last sync point in microseconds
    """

    drift_ppm: float
    jitter_us: float
    offset_us: int
    samples: int
    last_sync_age_us: int


class ClockSynchronizer:
    """Synchronizes a physical radio clock to simulation time.

    Tracks the relationship between a physical radio's local clock and
    simulation time using sync points (paired observations). Estimates
    drift and jitter to provide accurate time conversion.

    The synchronizer uses:
    - Linear regression over recent sync points to estimate drift
    - Exponential moving average to filter jitter
    - Sliding window to adapt to changing drift rates

    Args:
        drift_ppm_max: Maximum expected drift in ppm. Larger values need
            more frequent sync updates. Typical crystals: 10-50 ppm.
        jitter_alpha: EMA smoothing factor for jitter estimate (0-1).
            Lower values = more smoothing. Default 0.1.
        window_size: Number of sync points to retain for regression.
            Larger windows give smoother drift estimates. Default 16.
        min_samples: Minimum sync points before entering SYNCHRONIZED.
            Default 3.
        stale_threshold_us: Max time since last sync before DRIFTING.
            Default 10 seconds.
    """

    def __init__(
        self,
        drift_ppm_max: float = 50.0,
        jitter_alpha: float = 0.1,
        window_size: int = 16,
        min_samples: int = 3,
        stale_threshold_us: int = 10_000_000,
    ) -> None:
        if drift_ppm_max <= 0:
            raise ValueError(f"drift_ppm_max must be positive, got {drift_ppm_max}")
        if not 0 < jitter_alpha <= 1:
            raise ValueError(f"jitter_alpha must be in (0, 1], got {jitter_alpha}")
        if window_size < 2:
            raise ValueError(f"window_size must be >= 2, got {window_size}")
        if min_samples < 1:
            raise ValueError(f"min_samples must be >= 1, got {min_samples}")

        self._drift_ppm_max = drift_ppm_max
        self._jitter_alpha = jitter_alpha
        self._window_size = window_size
        self._min_samples = min_samples
        self._stale_threshold_us = stale_threshold_us

        # Sync state
        self._points: list[SyncPoint] = []
        self._state = SyncState.UNSYNCHRONIZED

        # Estimated parameters
        self._offset_us: int = 0  # sim_time = physical_time + offset
        self._drift_ppm: float = 0.0  # positive = physical faster than sim
        self._jitter_us: float = 0.0  # EMA of absolute residuals

        # Reference point for drift calculation
        self._ref_physical_us: int = 0
        self._ref_sim_us: int = 0

    @property
    def state(self) -> SyncState:
        """Current synchronization state."""
        self._update_state()
        return self._state

    @property
    def drift_ppm(self) -> float:
        """Estimated clock drift in parts per million.

        Positive values mean physical clock runs faster than simulation.
        Returns 0.0 if unsynchronized.
        """
        return self._drift_ppm

    @property
    def jitter_us(self) -> float:
        """Estimated jitter (timing uncertainty) in microseconds.

        Returns 0.0 if unsynchronized or insufficient samples.
        """
        return self._jitter_us

    @property
    def offset_us(self) -> int:
        """Current offset from physical to simulation time.

        sim_time ~= physical_time + offset_us (before drift correction).
        """
        return self._offset_us

    @property
    def sample_count(self) -> int:
        """Number of sync points in the window."""
        return len(self._points)

    def update(self, physical_us: int, sim_us: int) -> None:
        """Add a synchronization point.

        Call this when you receive a timing reference (e.g., beacon with
        known sim time) and know the physical radio's local timestamp.

        Args:
            physical_us: Physical radio timestamp in microseconds
            sim_us: Corresponding simulation time in microseconds
        """
        point = SyncPoint(physical_us, sim_us)
        self._points.append(point)

        # Trim to window size
        if len(self._points) > self._window_size:
            self._points = self._points[-self._window_size :]

        self._recalculate()

    def to_sim_time(self, physical_us: int) -> int:
        """Convert physical radio time to simulation time.

        Applies the current offset and drift correction.

        Args:
            physical_us: Physical radio timestamp in microseconds

        Returns:
            Estimated simulation time in microseconds
        """
        # Check if we have any sync data (not just state)
        if not self._points:
            # No sync - return as-is (assume they're aligned)
            return physical_us

        # Apply offset
        base_sim = physical_us + self._offset_us

        # Apply drift correction relative to reference point
        delta = physical_us - self._ref_physical_us
        drift_correction = int(delta * self._drift_ppm / 1_000_000)

        return base_sim - drift_correction

    def to_physical_time(self, sim_us: int) -> int:
        """Convert simulation time to physical radio time.

        Inverse of to_sim_time().

        Args:
            sim_us: Simulation time in microseconds

        Returns:
            Estimated physical radio time in microseconds
        """
        # Check if we have any sync data (not just state)
        if not self._points:
            return sim_us

        # Inverse of to_sim_time
        # sim = phys + offset - delta * drift_ppm / 1e6
        # sim = phys + offset - (phys - ref_phys) * drift_ppm / 1e6
        # sim = phys * (1 - drift_ppm/1e6) + offset + ref_phys * drift_ppm/1e6
        # phys = (sim - offset - ref_phys * drift_ppm/1e6) / (1 - drift_ppm/1e6)

        scale = 1.0 - self._drift_ppm / 1_000_000
        if abs(scale) < 1e-9:
            return sim_us - self._offset_us

        ref_correction = int(self._ref_physical_us * self._drift_ppm / 1_000_000)
        return int((sim_us - self._offset_us + ref_correction) / scale)

    def get_stats(self) -> ClockStats:
        """Get current synchronization statistics."""
        now_us = int(time.monotonic_ns() // 1000)
        last_sync_age = 0
        if self._points:
            last_sync_age = now_us - self._points[-1].wall_us

        return ClockStats(
            drift_ppm=self._drift_ppm,
            jitter_us=self._jitter_us,
            offset_us=self._offset_us,
            samples=len(self._points),
            last_sync_age_us=last_sync_age,
        )

    def reset(self) -> None:
        """Clear all sync state and return to UNSYNCHRONIZED."""
        self._points.clear()
        self._state = SyncState.UNSYNCHRONIZED
        self._offset_us = 0
        self._drift_ppm = 0.0
        self._jitter_us = 0.0
        self._ref_physical_us = 0
        self._ref_sim_us = 0

    def _update_state(self) -> None:
        """Update synchronization state based on current conditions."""
        if not self._points:
            self._state = SyncState.UNSYNCHRONIZED
            return

        # Check if sync is stale
        now_us = int(time.monotonic_ns() // 1000)
        age = now_us - self._points[-1].wall_us
        if age > self._stale_threshold_us:
            self._state = SyncState.DRIFTING
            return

        if len(self._points) < self._min_samples:
            self._state = SyncState.ACQUIRING
        else:
            self._state = SyncState.SYNCHRONIZED

    def _recalculate(self) -> None:
        """Recalculate offset, drift, and jitter from sync points."""
        n = len(self._points)
        if n == 0:
            return

        if n == 1:
            # Single point: estimate offset only
            p = self._points[0]
            self._offset_us = p.sim_us - p.physical_us
            self._ref_physical_us = p.physical_us
            self._ref_sim_us = p.sim_us
            return

        # Linear regression: sim_us = a + b * physical_us
        # drift_ppm = (1 - b) * 1e6
        sum_x = sum(p.physical_us for p in self._points)
        sum_y = sum(p.sim_us for p in self._points)
        sum_xy = sum(p.physical_us * p.sim_us for p in self._points)
        sum_xx = sum(p.physical_us * p.physical_us for p in self._points)

        # Avoid division by zero
        denom = n * sum_xx - sum_x * sum_x
        if abs(denom) < 1e-9:
            # All points at same physical time - use simple average
            avg_offset = sum_y // n - sum_x // n
            self._offset_us = avg_offset
            return

        b = (n * sum_xy - sum_x * sum_y) / denom
        a = (sum_y - b * sum_x) / n

        # Update drift estimate (clamp to max)
        raw_drift = (1.0 - b) * 1_000_000
        self._drift_ppm = max(-self._drift_ppm_max, min(self._drift_ppm_max, raw_drift))

        # Use most recent point as reference
        self._ref_physical_us = self._points[-1].physical_us
        self._ref_sim_us = self._points[-1].sim_us
        self._offset_us = self._ref_sim_us - self._ref_physical_us

        # Calculate jitter as EMA of absolute residuals
        for p in self._points:
            predicted = int(a + b * p.physical_us)
            residual = abs(p.sim_us - predicted)
            self._jitter_us = (
                self._jitter_alpha * residual + (1 - self._jitter_alpha) * self._jitter_us
            )


class MultiClockAggregator:
    """Aggregates timing from multiple physical radios.

    In HIL scenarios with multiple physical radios, each may have different
    drift characteristics. This class tracks multiple ClockSynchronizers
    and provides aggregate timing information.

    Usage:
        agg = MultiClockAggregator()
        agg.add_source("radio1", drift_ppm_max=20.0)
        agg.add_source("radio2", drift_ppm_max=30.0)

        # Update each source independently
        agg.update("radio1", physical_us, sim_us)
        agg.update("radio2", physical_us, sim_us)

        # Get aggregate stats
        stats = agg.get_aggregate_stats()
    """

    def __init__(self) -> None:
        self._sources: dict[str, ClockSynchronizer] = {}
        self._primary: str | None = None

    def add_source(
        self,
        source_id: str,
        drift_ppm_max: float = 50.0,
        jitter_alpha: float = 0.1,
        **kwargs: int,
    ) -> ClockSynchronizer:
        """Add a clock source.

        Args:
            source_id: Unique identifier for this source
            drift_ppm_max: Maximum expected drift in ppm
            jitter_alpha: Jitter smoothing factor
            **kwargs: Additional ClockSynchronizer parameters

        Returns:
            The created ClockSynchronizer for this source
        """
        sync = ClockSynchronizer(
            drift_ppm_max=drift_ppm_max, jitter_alpha=jitter_alpha, **kwargs
        )
        self._sources[source_id] = sync
        if self._primary is None:
            self._primary = source_id
        return sync

    def remove_source(self, source_id: str) -> bool:
        """Remove a clock source.

        Returns:
            True if source was removed, False if not found
        """
        if source_id in self._sources:
            del self._sources[source_id]
            if self._primary == source_id:
                self._primary = next(iter(self._sources), None)
            return True
        return False

    def get_source(self, source_id: str) -> ClockSynchronizer | None:
        """Get a specific clock source."""
        return self._sources.get(source_id)

    def update(self, source_id: str, physical_us: int, sim_us: int) -> None:
        """Update a specific clock source with a sync point."""
        sync = self._sources.get(source_id)
        if sync is not None:
            sync.update(physical_us, sim_us)

    def set_primary(self, source_id: str) -> None:
        """Set the primary clock source for time conversion.

        Raises:
            KeyError: If source_id not found
        """
        if source_id not in self._sources:
            raise KeyError(f"Unknown source: {source_id}")
        self._primary = source_id

    def to_sim_time(self, source_id: str, physical_us: int) -> int:
        """Convert physical time from a specific source to sim time."""
        sync = self._sources.get(source_id)
        if sync is None:
            raise KeyError(f"Unknown source: {source_id}")
        return sync.to_sim_time(physical_us)

    def get_aggregate_stats(self) -> dict[str, ClockStats]:
        """Get stats for all clock sources."""
        return {sid: sync.get_stats() for sid, sync in self._sources.items()}

    def get_max_drift(self) -> float:
        """Get the maximum absolute drift across all sources."""
        if not self._sources:
            return 0.0
        return max(abs(s.drift_ppm) for s in self._sources.values())

    def get_max_jitter(self) -> float:
        """Get the maximum jitter across all sources."""
        if not self._sources:
            return 0.0
        return max(s.jitter_us for s in self._sources.values())

    def all_synchronized(self) -> bool:
        """Check if all sources are in SYNCHRONIZED state."""
        if not self._sources:
            return False
        return all(s.state == SyncState.SYNCHRONIZED for s in self._sources.values())


# Callback type for sync events
SyncCallback = Callable[[str, SyncState, ClockStats], None]


class TimingSynchronizer:
    """High-level timing synchronization for HIL simulation.

    Coordinates timing between physical radios and the simulator, providing:
    - Automatic sync point extraction from beacons
    - Drift compensation for accurate packet scheduling
    - Jitter-aware timeout calculation

    This class is designed to be used by the HIL bridge (renode_server.py
    or a physical radio bridge) to maintain accurate timing.

    Args:
        simulation: The simulation instance to synchronize with
        on_state_change: Optional callback when sync state changes
    """

    def __init__(
        self,
        on_state_change: SyncCallback | None = None,
    ) -> None:
        self._aggregator = MultiClockAggregator()
        self._on_state_change = on_state_change
        self._last_states: dict[str, SyncState] = {}

    @property
    def aggregator(self) -> MultiClockAggregator:
        """Access the underlying multi-clock aggregator."""
        return self._aggregator

    def register_radio(
        self,
        radio_id: str,
        drift_ppm_max: float = 50.0,
        jitter_alpha: float = 0.1,
    ) -> ClockSynchronizer:
        """Register a physical radio for timing synchronization.

        Args:
            radio_id: Unique identifier for this radio
            drift_ppm_max: Maximum expected crystal drift in ppm
            jitter_alpha: Jitter smoothing factor

        Returns:
            ClockSynchronizer for this radio
        """
        sync = self._aggregator.add_source(
            radio_id, drift_ppm_max=drift_ppm_max, jitter_alpha=jitter_alpha
        )
        self._last_states[radio_id] = SyncState.UNSYNCHRONIZED
        return sync

    def unregister_radio(self, radio_id: str) -> bool:
        """Unregister a physical radio."""
        self._last_states.pop(radio_id, None)
        return self._aggregator.remove_source(radio_id)

    def process_beacon(
        self, radio_id: str, physical_rx_us: int, beacon_sim_time_us: int
    ) -> None:
        """Process a received beacon to update sync state.

        Call this when a physical radio receives a timing beacon
        (e.g., TDMA superframe beacon) with known simulation time.

        Args:
            radio_id: ID of the receiving radio
            physical_rx_us: Physical radio's RX timestamp
            beacon_sim_time_us: Simulation time from beacon payload
        """
        sync = self._aggregator.get_source(radio_id)
        if sync is None:
            return

        old_state = sync.state
        sync.update(physical_rx_us, beacon_sim_time_us)
        new_state = sync.state

        if old_state != new_state and self._on_state_change is not None:
            self._on_state_change(radio_id, new_state, sync.get_stats())
            self._last_states[radio_id] = new_state

    def get_adjusted_timeout(
        self, radio_id: str, nominal_timeout_us: int, safety_factor: float = 2.0
    ) -> int:
        """Calculate drift-adjusted timeout for a physical radio.

        Increases the timeout to account for clock drift and jitter,
        preventing premature timeouts due to clock skew.

        Args:
            radio_id: ID of the radio
            nominal_timeout_us: Base timeout without drift compensation
            safety_factor: Multiplier for jitter margin (default 2.0)

        Returns:
            Adjusted timeout in microseconds
        """
        sync = self._aggregator.get_source(radio_id)
        if sync is None or sync.state == SyncState.UNSYNCHRONIZED:
            return nominal_timeout_us

        stats = sync.get_stats()

        # Add drift margin: timeout could be early/late by drift amount
        drift_margin = int(nominal_timeout_us * abs(stats.drift_ppm) / 1_000_000)

        # Add jitter margin
        jitter_margin = int(stats.jitter_us * safety_factor)

        return nominal_timeout_us + drift_margin + jitter_margin

    def is_ready_for_hil(self) -> bool:
        """Check if timing is stable enough for HIL testing.

        Returns True when all registered radios are synchronized
        with acceptable drift bounds.
        """
        return self._aggregator.all_synchronized()

    def get_sync_quality(self) -> dict[str, float]:
        """Get sync quality score (0-1) for each radio.

        Returns:
            Dict mapping radio_id to quality score.
            1.0 = perfect sync, 0.0 = unsynchronized
        """
        result = {}
        for radio_id, sync in self._aggregator._sources.items():
            if sync.state == SyncState.UNSYNCHRONIZED:
                result[radio_id] = 0.0
            elif sync.state == SyncState.ACQUIRING:
                result[radio_id] = 0.3
            elif sync.state == SyncState.DRIFTING:
                result[radio_id] = 0.5
            else:
                # SYNCHRONIZED: score based on drift and jitter
                stats = sync.get_stats()
                drift_score = max(0, 1.0 - abs(stats.drift_ppm) / 50.0)
                jitter_score = max(0, 1.0 - stats.jitter_us / 1000.0)
                result[radio_id] = 0.6 + 0.4 * (drift_score + jitter_score) / 2
        return result
