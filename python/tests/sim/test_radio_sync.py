# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for physical radio timing synchronization."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from lichen.sim.radio_sync import (
    ClockSynchronizer,
    MultiClockAggregator,
    SyncState,
    TimingSynchronizer,
)


class TestClockSynchronizer:
    """Tests for ClockSynchronizer class."""

    def test_initial_state_unsynchronized(self) -> None:
        """New synchronizer starts in UNSYNCHRONIZED state."""
        sync = ClockSynchronizer()
        assert sync.state == SyncState.UNSYNCHRONIZED
        assert sync.sample_count == 0
        assert sync.drift_ppm == 0.0
        assert sync.jitter_us == 0.0

    def test_single_point_acquiring(self) -> None:
        """Single sync point puts state to ACQUIRING (need min_samples)."""
        sync = ClockSynchronizer(min_samples=3)
        sync.update(1_000_000, 1_000_000)
        assert sync.state == SyncState.ACQUIRING
        assert sync.sample_count == 1

    def test_reaches_synchronized(self) -> None:
        """Reaching min_samples puts state to SYNCHRONIZED."""
        sync = ClockSynchronizer(min_samples=3)
        for i in range(3):
            sync.update(i * 1_000_000, i * 1_000_000)
        assert sync.state == SyncState.SYNCHRONIZED
        assert sync.sample_count == 3

    def test_offset_calculation(self) -> None:
        """Offset is calculated from sync points."""
        sync = ClockSynchronizer(min_samples=1)
        # Physical time 1000, sim time 2000 -> offset = 1000
        sync.update(1000, 2000)
        assert sync.offset_us == 1000

    def test_time_conversion_with_offset(self) -> None:
        """to_sim_time applies offset correctly."""
        sync = ClockSynchronizer(min_samples=1)
        sync.update(0, 1000)  # offset = 1000
        # With no drift, physical 500 -> sim 1500
        assert sync.to_sim_time(500) == 1500

    def test_drift_detection_positive(self) -> None:
        """Detects positive drift (physical faster than sim)."""
        sync = ClockSynchronizer(min_samples=2, drift_ppm_max=100.0)
        # If physical clock runs 100ppm fast, after 1M us it's 100us ahead
        # sim = physical * (1 - drift/1e6) + offset
        # So if we observe (0, 0) and (1_000_000, 999_900) we have drift
        sync.update(0, 0)
        sync.update(1_000_000, 999_900)  # 100ppm slower in sim
        # Drift should be approximately 100 ppm
        assert abs(sync.drift_ppm - 100.0) < 1.0

    def test_drift_detection_negative(self) -> None:
        """Detects negative drift (physical slower than sim)."""
        sync = ClockSynchronizer(min_samples=2, drift_ppm_max=100.0)
        sync.update(0, 0)
        sync.update(1_000_000, 1_000_100)  # sim runs faster
        assert abs(sync.drift_ppm - (-100.0)) < 1.0

    def test_drift_clamped_to_max(self) -> None:
        """Drift is clamped to drift_ppm_max."""
        sync = ClockSynchronizer(min_samples=2, drift_ppm_max=50.0)
        sync.update(0, 0)
        sync.update(1_000_000, 900_000)  # 100000 ppm would be computed
        assert abs(sync.drift_ppm) <= 50.0

    def test_drift_compensation_in_conversion(self) -> None:
        """to_sim_time compensates for drift."""
        sync = ClockSynchronizer(min_samples=2, drift_ppm_max=100.0)
        # Create a known drift scenario
        sync.update(0, 0)
        sync.update(1_000_000, 999_900)  # ~100ppm drift

        # At physical time 2M, without drift compensation we'd get 2M + offset
        # With drift compensation, we account for the accumulated error
        sim_time = sync.to_sim_time(2_000_000)
        # Should be close to 2 * 999_900 = 1_999_800 if linear extrapolation
        assert 1_999_700 < sim_time < 2_000_100

    def test_inverse_conversion(self) -> None:
        """to_physical_time is inverse of to_sim_time."""
        sync = ClockSynchronizer(min_samples=2, drift_ppm_max=50.0)
        sync.update(0, 1000)
        sync.update(1_000_000, 1_001_010)  # Small drift

        physical = 500_000
        sim = sync.to_sim_time(physical)
        recovered = sync.to_physical_time(sim)
        # Should be within ~25us due to integer math and drift correction
        assert abs(recovered - physical) < 25

    def test_window_sliding(self) -> None:
        """Old sync points are removed when window fills."""
        sync = ClockSynchronizer(window_size=4, min_samples=1)
        for i in range(10):
            sync.update(i * 1000, i * 1000)
        assert sync.sample_count == 4  # Only last 4 kept

    def test_jitter_calculation(self) -> None:
        """Jitter is calculated from residuals."""
        sync = ClockSynchronizer(min_samples=2, jitter_alpha=0.5)
        # Add points with some noise
        sync.update(0, 0)
        sync.update(1000, 1010)  # 10us residual
        sync.update(2000, 1990)  # -10us from expected
        # Jitter should be non-zero
        assert sync.jitter_us > 0

    def test_reset(self) -> None:
        """reset() clears all state."""
        sync = ClockSynchronizer(min_samples=1)
        sync.update(1000, 2000)
        assert sync.state != SyncState.UNSYNCHRONIZED

        sync.reset()
        assert sync.state == SyncState.UNSYNCHRONIZED
        assert sync.sample_count == 0
        assert sync.drift_ppm == 0.0
        assert sync.offset_us == 0

    def test_stale_detection(self) -> None:
        """Old sync points cause DRIFTING state."""
        # We need to mock time during both point creation and state check
        base_time = 1_000_000_000_000  # 1 second in ns

        with patch("lichen.sim.radio_sync.time.monotonic_ns") as mock_time:
            # Create sync with point at t=0
            mock_time.return_value = base_time
            sync = ClockSynchronizer(min_samples=1, stale_threshold_us=100)
            sync.update(0, 0)
            assert sync.state == SyncState.SYNCHRONIZED

            # Now simulate staleness - 1ms later (well past 100us threshold)
            mock_time.return_value = base_time + 1_000_000  # 1ms later
            assert sync.state == SyncState.DRIFTING

    def test_get_stats(self) -> None:
        """get_stats returns correct statistics."""
        sync = ClockSynchronizer(min_samples=2)
        sync.update(0, 100)
        sync.update(1000, 1100)

        stats = sync.get_stats()
        assert stats.samples == 2
        assert stats.offset_us == 100
        assert isinstance(stats.drift_ppm, float)
        assert isinstance(stats.jitter_us, float)

    def test_validation_errors(self) -> None:
        """Constructor validates parameters."""
        with pytest.raises(ValueError, match="drift_ppm_max must be positive"):
            ClockSynchronizer(drift_ppm_max=0)

        with pytest.raises(ValueError, match="jitter_alpha"):
            ClockSynchronizer(jitter_alpha=0)

        with pytest.raises(ValueError, match="window_size"):
            ClockSynchronizer(window_size=1)

        with pytest.raises(ValueError, match="min_samples"):
            ClockSynchronizer(min_samples=0)


class TestMultiClockAggregator:
    """Tests for MultiClockAggregator class."""

    def test_add_remove_sources(self) -> None:
        """Can add and remove clock sources."""
        agg = MultiClockAggregator()
        sync1 = agg.add_source("radio1")
        assert agg.get_source("radio1") is sync1
        assert agg.get_source("radio2") is None

        assert agg.remove_source("radio1") is True
        assert agg.get_source("radio1") is None
        assert agg.remove_source("radio1") is False

    def test_first_source_is_primary(self) -> None:
        """First added source becomes primary."""
        agg = MultiClockAggregator()
        agg.add_source("radio1")
        agg.add_source("radio2")
        assert agg._primary == "radio1"

    def test_update_source(self) -> None:
        """Can update individual sources."""
        agg = MultiClockAggregator()
        agg.add_source("radio1")
        agg.update("radio1", 1000, 2000)
        stats = agg.get_aggregate_stats()
        assert stats["radio1"].samples == 1

    def test_to_sim_time(self) -> None:
        """Time conversion works through aggregator."""
        agg = MultiClockAggregator()
        sync = agg.add_source("radio1", drift_ppm_max=10.0)
        sync.update(0, 1000)  # offset = 1000

        result = agg.to_sim_time("radio1", 500)
        assert result == 1500

        with pytest.raises(KeyError):
            agg.to_sim_time("nonexistent", 0)

    def test_get_max_drift(self) -> None:
        """get_max_drift returns maximum across sources."""
        agg = MultiClockAggregator()
        sync1 = agg.add_source("radio1")
        sync2 = agg.add_source("radio2")

        # Create different drifts
        sync1.update(0, 0)
        sync1.update(1_000_000, 999_980)  # ~20ppm
        sync2.update(0, 0)
        sync2.update(1_000_000, 999_950)  # ~50ppm

        max_drift = agg.get_max_drift()
        assert max_drift > 20.0  # At least the larger one

    def test_get_max_jitter(self) -> None:
        """get_max_jitter returns maximum across sources."""
        agg = MultiClockAggregator()
        sync1 = agg.add_source("radio1", jitter_alpha=1.0)  # No smoothing
        sync2 = agg.add_source("radio2", jitter_alpha=1.0)

        sync1.update(0, 0)
        sync1.update(1000, 1100)  # Creates jitter
        sync2.update(0, 0)
        sync2.update(1000, 1000)  # No jitter

        max_jitter = agg.get_max_jitter()
        assert max_jitter >= sync1.jitter_us

    def test_all_synchronized(self) -> None:
        """all_synchronized requires all sources to be SYNCHRONIZED."""
        agg = MultiClockAggregator()
        sync1 = agg.add_source("radio1", min_samples=1)
        sync2 = agg.add_source("radio2", min_samples=1)

        assert agg.all_synchronized() is False

        sync1.update(0, 0)
        assert agg.all_synchronized() is False

        sync2.update(0, 0)
        assert agg.all_synchronized() is True

    def test_set_primary(self) -> None:
        """Can set primary source."""
        agg = MultiClockAggregator()
        agg.add_source("radio1")
        agg.add_source("radio2")

        agg.set_primary("radio2")
        assert agg._primary == "radio2"

        with pytest.raises(KeyError):
            agg.set_primary("nonexistent")


class TestTimingSynchronizer:
    """Tests for TimingSynchronizer class."""

    def test_register_unregister_radio(self) -> None:
        """Can register and unregister radios."""
        ts = TimingSynchronizer()
        sync = ts.register_radio("radio1", drift_ppm_max=30.0)
        assert sync is not None
        assert ts.unregister_radio("radio1") is True
        assert ts.unregister_radio("radio1") is False

    def test_process_beacon(self) -> None:
        """process_beacon updates sync state."""
        ts = TimingSynchronizer()
        ts.register_radio("radio1", drift_ppm_max=30.0)

        ts.process_beacon("radio1", 1000, 2000)
        stats = ts.aggregator.get_aggregate_stats()
        assert stats["radio1"].samples == 1

    def test_state_change_callback(self) -> None:
        """Callback is invoked on state changes."""
        changes: list[tuple[str, SyncState]] = []

        def on_change(
            radio_id: str, state: SyncState, stats: object
        ) -> None:
            changes.append((radio_id, state))

        ts = TimingSynchronizer(on_state_change=on_change)
        ts.register_radio("radio1", drift_ppm_max=30.0)

        # First update: UNSYNCHRONIZED -> ACQUIRING or SYNCHRONIZED
        ts.process_beacon("radio1", 0, 0)
        assert len(changes) == 1
        assert changes[0][0] == "radio1"

    def test_adjusted_timeout(self) -> None:
        """get_adjusted_timeout increases timeout for drift/jitter."""
        ts = TimingSynchronizer()
        sync = ts.register_radio("radio1", drift_ppm_max=50.0)

        # Before sync, returns nominal
        nominal = 100_000  # 100ms
        result = ts.get_adjusted_timeout("radio1", nominal)
        assert result == nominal

        # After sync with drift
        sync.update(0, 0)
        sync.update(1_000_000, 999_900)  # ~100ppm drift
        result = ts.get_adjusted_timeout("radio1", nominal)
        assert result > nominal  # Should have drift margin

    def test_is_ready_for_hil(self) -> None:
        """is_ready_for_hil requires all radios synchronized."""
        ts = TimingSynchronizer()
        assert ts.is_ready_for_hil() is False  # No radios

        sync1 = ts.register_radio("radio1", drift_ppm_max=30.0)
        sync2 = ts.register_radio("radio2", drift_ppm_max=30.0)
        assert ts.is_ready_for_hil() is False

        # Need min_samples (default 3) to reach SYNCHRONIZED
        for i in range(3):
            sync1.update(i * 1000, i * 1000)
        assert ts.is_ready_for_hil() is False  # radio2 not yet synced

        for i in range(3):
            sync2.update(i * 1000, i * 1000)
        assert ts.is_ready_for_hil() is True

    def test_sync_quality(self) -> None:
        """get_sync_quality returns per-radio quality scores."""
        ts = TimingSynchronizer()
        sync = ts.register_radio("radio1", drift_ppm_max=30.0)

        quality = ts.get_sync_quality()
        assert quality["radio1"] == 0.0  # Unsynchronized

        # One point = ACQUIRING state
        sync.update(0, 0)
        quality = ts.get_sync_quality()
        assert quality["radio1"] == 0.3  # ACQUIRING

        # Need min_samples (3) to reach SYNCHRONIZED
        sync.update(1000, 1000)
        sync.update(2000, 2000)
        quality = ts.get_sync_quality()
        assert quality["radio1"] > 0.5  # Now synchronized


class TestIntegrationScenarios:
    """Integration tests for realistic scenarios."""

    def test_crystal_drift_compensation(self) -> None:
        """Simulate typical crystal drift scenario."""
        sync = ClockSynchronizer(drift_ppm_max=50.0, min_samples=2)

        # Simulate a 20ppm drift over several sync points
        drift_ppm = 20.0
        base_offset = 1000

        for i in range(10):
            physical = i * 1_000_000
            # sim = physical + offset - accumulated_drift
            accumulated = int(physical * drift_ppm / 1_000_000)
            sim = physical + base_offset - accumulated
            sync.update(physical, sim)

        # Drift should be close to 20ppm
        assert abs(sync.drift_ppm - drift_ppm) < 5.0

        # Future time conversion should be accurate
        future_physical = 20_000_000
        expected_sim = future_physical + base_offset - int(
            future_physical * drift_ppm / 1_000_000
        )
        actual_sim = sync.to_sim_time(future_physical)
        # Should be within 100us
        assert abs(actual_sim - expected_sim) < 100

    def test_multi_radio_hil_setup(self) -> None:
        """Simulate multi-radio HIL test setup."""
        ts = TimingSynchronizer()

        # Add multiple radios with different characteristics
        ts.register_radio("node_a", drift_ppm_max=30.0)
        ts.register_radio("node_b", drift_ppm_max=40.0)

        # Simulate beacon reception on both
        for i in range(5):
            # Radio A has slight positive drift
            phys_a = i * 100_000
            sim = i * 100_000
            ts.process_beacon("node_a", phys_a + 2 * i, sim)

            # Radio B has slight negative drift
            phys_b = i * 100_000
            ts.process_beacon("node_b", phys_b - 3 * i, sim)

        # Both should be synchronized
        assert ts.is_ready_for_hil()

        # Quality scores should be good
        quality = ts.get_sync_quality()
        assert all(q > 0.5 for q in quality.values())

    def test_recovery_from_stale(self) -> None:
        """Sync recovers after period of no updates."""
        base_time = 1_000_000_000_000  # 1 second in ns

        with patch("lichen.sim.radio_sync.time.monotonic_ns") as mock_time:
            mock_time.return_value = base_time
            sync = ClockSynchronizer(min_samples=1, stale_threshold_us=1000)

            sync.update(0, 0)
            assert sync.state == SyncState.SYNCHRONIZED

            # Simulate staleness - 10ms later (well past 1000us threshold)
            mock_time.return_value = base_time + 10_000_000  # 10ms later
            assert sync.state == SyncState.DRIFTING

            # New update should resynchronize
            sync.update(1000, 1000)
            assert sync.state == SyncState.SYNCHRONIZED
