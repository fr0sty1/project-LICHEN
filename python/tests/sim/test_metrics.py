# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for simulation metrics collection."""

from __future__ import annotations

import random
import tempfile
from pathlib import Path

from lichen.sim.metrics import Metrics, compare_metrics
from lichen.sim.simulation import Simulation


class TestMetricsUnit:
    """Unit tests for the Metrics class in isolation."""

    def test_empty_metrics(self) -> None:
        m = Metrics()
        assert m.transmissions == 0
        assert m.receptions == 0
        assert m.collisions == 0
        assert m.delivery_rate == 0.0
        assert m.collision_rate == 0.0
        stats = m.latency_stats()
        assert stats.count == 0
        assert stats.min_us is None and stats.max_us is None and stats.mean_us is None

    def test_transmission_start_dedup(self) -> None:
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_transmission_start("tx1", 0)  # duplicate ignored
        m.record_transmission_start("tx2", 10)
        assert m.transmissions == 2

    def test_reception_dedup_and_latency(self) -> None:
        m = Metrics()
        m.record_transmission_start("tx1", 100)
        m.record_reception("rxA", "tx1", 350)
        m.record_reception("rxA", "tx1", 999)  # same (node, tx): ignored
        assert m.receptions == 1
        stats = m.latency_stats()
        assert stats.count == 1
        assert stats.min_us == 250  # 350 - 100, recorded once

    def test_reception_counts_per_receiver(self) -> None:
        """One transmission delivered to two distinct receivers counts twice."""
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("rxA", "tx1", 200)
        m.record_reception("rxB", "tx1", 300)
        assert m.receptions == 2

    def test_reception_without_known_tx_has_no_latency(self) -> None:
        m = Metrics()
        m.record_reception("rxA", "unknown_tx", 500)
        assert m.receptions == 1
        assert m.latency_stats().count == 0

    def test_collision_dedup(self) -> None:
        m = Metrics()
        m.record_collision("rx", ["tx1", "tx2"])
        m.record_collision("rx", ["tx2", "tx1"])  # same set, order-independent
        assert m.collisions == 1
        m.record_collision("rx", ["tx1", "tx3"])  # different set -> new event
        assert m.collisions == 2

    def test_delivery_rate(self) -> None:
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_transmission_start("tx2", 0)
        m.record_reception("a", "tx1", 1)
        m.record_reception("b", "tx1", 1)
        m.record_reception("a", "tx2", 1)
        # 3 deliveries over 2 transmissions
        assert m.delivery_rate == 1.5

    def test_collision_rate(self) -> None:
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("a", "tx1", 1)  # 1 reception
        m.record_collision("b", ["tx1", "tx2"])  # 1 collision
        m.record_collision("c", ["tx1", "tx2", "tx3"])  # 1 collision
        # 2 collisions / (2 collisions + 1 reception)
        assert m.collision_rate == 2 / 3

    def test_latency_stats_min_max_mean(self) -> None:
        m = Metrics()
        for i, lat in enumerate([100, 200, 300]):
            tx = f"tx{i}"
            m.record_transmission_start(tx, 0)
            m.record_reception(f"rx{i}", tx, lat)  # start=0 so latency == lat
        stats = m.latency_stats()
        assert stats.count == 3
        assert stats.min_us == 100
        assert stats.max_us == 300
        assert stats.mean_us == 200.0

    def test_reset(self) -> None:
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("a", "tx1", 5)
        m.record_collision("b", ["tx1", "tx2"])
        m.reset()
        assert m.transmissions == 0
        assert m.receptions == 0
        assert m.collisions == 0
        assert m.latency_stats().count == 0

    def test_snapshot_shape(self) -> None:
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("a", "tx1", 5)
        snap = m.snapshot()
        assert snap["transmissions"] == 1
        assert snap["receptions"] == 1
        assert snap["collisions"] == 0
        assert snap["latency_us"]["count"] == 1
        assert snap["latency_us"]["min"] == 5

    def test_tx_start_times_pruned_after_threshold(self) -> None:
        m = Metrics()
        threshold = Metrics._TX_START_TIMES_PRUNE_THRESHOLD
        max_age = Metrics._TX_START_TIMES_MAX_AGE_US

        for i in range(threshold + 1):
            m.record_transmission_start(f"old_tx_{i}", i * 1000)

        assert len(m._tx_start_times) == threshold + 1

        future_time = max_age + 1_000_000_000
        m.record_transmission_start("new_tx", future_time)

        assert "new_tx" in m._tx_start_times
        assert len(m._tx_start_times) <= threshold + 2
        assert m.transmissions == threshold + 2

    def test_delayed_reception_keeps_latency_after_threshold(self) -> None:
        """A 90s delayed RX after >1000 TX starts still records latency."""
        m = Metrics()
        threshold = Metrics._TX_START_TIMES_PRUNE_THRESHOLD
        for i in range(threshold + 1):
            m.record_transmission_start(f"tx_{i}", 0)
        delayed_us = 90_000_000
        m.record_transmission_start("newer", delayed_us)
        assert m.record_reception("rx", "tx_0", delayed_us) is True
        stats = m.latency_stats()
        assert stats.count == 1
        assert stats.min_us == delayed_us
        assert m.receptions == 1

    def test_tx_start_times_recent_not_pruned(self) -> None:
        m = Metrics()
        threshold = Metrics._TX_START_TIMES_PRUNE_THRESHOLD
        base_time = 1_000_000_000_000

        for i in range(threshold + 10):
            m.record_transmission_start(f"tx_{i}", base_time + i * 1000)

        assert len(m._tx_start_times) == threshold + 10

    def test_latency_percentiles(self) -> None:
        """Test p50, p95, p99 latency percentile calculations."""
        m = Metrics()
        # Create 100 latency samples: 1, 2, 3, ..., 100 us.
        for i in range(100):
            tx = f"tx{i}"
            m.record_transmission_start(tx, 0)
            m.record_reception(f"rx{i}", tx, i + 1)

        # Nearest-rank method: idx = int(p/100 * n) clamped to [0, n-1].
        # For 100 samples [1..100]: p50 -> idx 50 -> value 51.
        assert m.latency_p50() == 51  # 50th percentile
        assert m.latency_p95() == 96  # 95th percentile
        assert m.latency_p99() == 100  # 99th percentile (clamped to last)

        stats = m.latency_stats()
        assert stats.p50_us == 51
        assert stats.p95_us == 96
        assert stats.p99_us == 100

    def test_latency_percentiles_empty(self) -> None:
        """Test percentiles return None when no samples."""
        m = Metrics()
        assert m.latency_p50() is None
        assert m.latency_p95() is None
        assert m.latency_p99() is None
        stats = m.latency_stats()
        assert stats.p50_us is None

    def test_latency_percentiles_single_sample(self) -> None:
        """Test percentiles with single sample."""
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("rx1", "tx1", 100)
        assert m.latency_p50() == 100
        assert m.latency_p99() == 100

    def test_per_channel_collision_tracking(self) -> None:
        """Test collisions are tracked per-channel."""
        m = Metrics()
        m.record_collision("rx1", ["tx1", "tx2"], channel=0)
        m.record_collision("rx2", ["tx3", "tx4"], channel=0)
        m.record_collision("rx3", ["tx5", "tx6"], channel=1)

        assert m.collisions == 3
        by_channel = m.collisions_by_channel
        assert by_channel[0] == 2
        assert by_channel[1] == 1

    def test_per_node_collision_tracking(self) -> None:
        """Test collisions are tracked per-node."""
        m = Metrics()
        m.record_collision("nodeA", ["tx1", "tx2"])
        m.record_collision("nodeA", ["tx3", "tx4"])
        m.record_collision("nodeB", ["tx5", "tx6"])

        assert m.collisions == 3
        by_node = m.collisions_by_node
        assert by_node["nodeA"] == 2
        assert by_node["nodeB"] == 1

    def test_collision_without_channel(self) -> None:
        """Test collision recording works without channel parameter."""
        m = Metrics()
        m.record_collision("rx", ["tx1", "tx2"])
        assert m.collisions == 1
        assert len(m.collisions_by_channel) == 0
        assert m.collisions_by_node["rx"] == 1

    def test_csv_export_basic(self) -> None:
        """Test CSV export creates valid file with expected data."""
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("rx1", "tx1", 100)
        m.record_collision("rx2", ["tx1", "tx2"], channel=0, time_us=200)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = Path(f.name)

        try:
            m.export_csv(path)
            content = path.read_text()

            # Check summary statistics are present.
            assert "transmissions,1" in content
            assert "receptions,1" in content
            assert "collisions,1" in content
            assert "latency_min_us,100" in content
            assert "latency_mean_us,100.00" in content

            # Check per-channel section.
            assert "# Collisions by Channel" in content
            assert "0,1" in content  # channel 0, 1 collision

            # Check per-node section.
            assert "# Collisions by Node" in content
            assert "rx2,1" in content

            # Check time-series section.
            assert "# Time-Series Events" in content
            assert "reception" in content
            assert "collision" in content
            assert "tx1,tx2" in content
        finally:
            path.unlink()

    def test_csv_export_empty_metrics(self) -> None:
        """Test CSV export works with empty metrics."""
        m = Metrics()

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = Path(f.name)

        try:
            m.export_csv(path)
            content = path.read_text()
            assert "transmissions,0" in content
            assert "receptions,0" in content
        finally:
            path.unlink()

    def test_csv_export_zero_latency_is_not_blank(self) -> None:
        """A real 0 µs latency must not collapse to the empty-cell sentinel."""
        m = Metrics()
        m.record_transmission_start("tx1", 100)
        m.record_reception("rx1", "tx1", 100)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = Path(f.name)

        try:
            m.export_csv(path)
            content = path.read_text()
            assert "latency_min_us,0" in content
            assert "latency_max_us,0" in content
            assert "latency_mean_us,0.00" in content
            assert "latency_p50_us,0" in content
        finally:
            path.unlink()

    def test_snapshot_includes_percentiles(self) -> None:
        """Test snapshot includes percentile data."""
        m = Metrics()
        for i in range(10):
            m.record_transmission_start(f"tx{i}", 0)
            m.record_reception(f"rx{i}", f"tx{i}", (i + 1) * 10)

        snap = m.snapshot()
        assert "p50" in snap["latency_us"]
        assert "p95" in snap["latency_us"]
        assert "p99" in snap["latency_us"]
        assert snap["latency_us"]["p50"] is not None

    def test_snapshot_includes_per_channel_collisions(self) -> None:
        """Test snapshot includes per-channel collision data."""
        m = Metrics()
        m.record_collision("rx", ["tx1", "tx2"], channel=5)

        snap = m.snapshot()
        assert "collisions_by_channel" in snap
        assert snap["collisions_by_channel"][5] == 1

    def test_snapshot_includes_per_node_collisions(self) -> None:
        """Test snapshot includes per-node collision data."""
        m = Metrics()
        m.record_collision("nodeX", ["tx1", "tx2"])

        snap = m.snapshot()
        assert "collisions_by_node" in snap
        assert snap["collisions_by_node"]["nodeX"] == 1

    def test_reset_clears_new_fields(self) -> None:
        """Test reset clears percentile samples and collision tracking."""
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("rx1", "tx1", 100)
        m.record_collision("rx2", ["tx1", "tx2"], channel=0, time_us=200)

        assert len(m._latency_samples) > 0
        assert len(m._collisions_by_channel) > 0
        assert len(m._collisions_by_node) > 0
        assert len(m._time_series) > 0

        m.reset()

        assert len(m._latency_samples) == 0
        assert len(m._collisions_by_channel) == 0
        assert len(m._collisions_by_node) == 0
        assert len(m._time_series) == 0
        assert m.latency_p50() is None

    def test_delivered_and_time_series_are_capped(self) -> None:
        """Dedup sets and CSV series do not grow without bound."""
        m = Metrics()
        cap = Metrics._DELIVERED_MAX_SIZE
        series_cap = Metrics._TIME_SERIES_MAX_SIZE
        n = cap + 50
        for i in range(n):
            tx = f"tx{i}"
            m.record_transmission_start(tx, 0)
            m.record_reception(f"rx{i}", tx, 10)
        assert m.receptions == n
        # In-window identities must not be LRU-evicted (poll re-inflation).
        assert m.record_reception("rx0", "tx0", 10) is False
        assert m.receptions == n
        assert len(m._time_series) <= series_cap

    def test_tx_latency_recorded_pruned_with_start_times(self) -> None:
        """Latency-recorded ids are dropped when their start times are pruned."""
        m = Metrics()
        threshold = Metrics._TX_START_TIMES_PRUNE_THRESHOLD
        for i in range(threshold + 1):
            tx = f"old_tx_{i}"
            m.record_transmission_start(tx, 0)
            m.record_reception(f"rx_{i}", tx, 10)
        assert len(m._tx_latency_recorded) == threshold + 1
        future_time = Metrics._TX_START_TIMES_MAX_AGE_US + 1_000_000
        m.record_transmission_start("new_tx", future_time)
        assert "old_tx_0" not in m._tx_start_times
        assert "old_tx_0" not in m._tx_latency_recorded
        assert ("rx_0", "old_tx_0") not in m._delivered
        m.reset()
        assert m._tx_latency_recorded == set()

    def test_re_poll_after_many_identities_does_not_inflate(self) -> None:
        """A (rx, tx) still in-flight must not be counted again after cap."""
        m = Metrics()
        n = Metrics._DELIVERED_MAX_SIZE + 25
        for i in range(n):
            tx = f"tx{i}"
            m.record_transmission_start(tx, 0)
            assert m.record_reception(f"rx{i}", tx, 5) is True
        assert m.receptions == n
        for i in range(0, n, 17):
            assert m.record_reception(f"rx{i}", f"tx{i}", 9) is False
        assert m.receptions == n

    def test_reservoir_uses_seeded_rng_not_global_random(self) -> None:
        """Percentiles after the reservoir cap are reproducible per Metrics rng."""
        original_randint = random.randint

        def boom(a: int, b: int) -> int:
            raise AssertionError("Metrics must not call global random.randint")

        random.randint = boom  # type: ignore[method-assign]
        try:
            m1 = Metrics(rng=random.Random(123))
            m2 = Metrics(rng=random.Random(123))
            n = Metrics._MAX_LATENCY_SAMPLES + 250
            for i in range(n):
                tx = f"tx{i}"
                m1.record_transmission_start(tx, 0)
                m1.record_reception("rx", tx, i + 1)
                m2.record_transmission_start(tx, 0)
                m2.record_reception("rx", tx, i + 1)
            assert m1.latency_p50() == m2.latency_p50()
            assert m1.latency_p95() == m2.latency_p95()
            assert m1.latency_p99() == m2.latency_p99()
            assert m1.latency_stats().count == n
        finally:
            random.randint = original_randint  # type: ignore[method-assign]

    def test_global_random_does_not_perturb_percentiles(self) -> None:
        """Process-global random draws must not change seeded reservoir output."""
        m1 = Metrics(rng=random.Random(99))
        m2 = Metrics(rng=random.Random(99))
        n = Metrics._MAX_LATENCY_SAMPLES + 100
        rng_noise = random.Random(0)
        for i in range(n):
            rng_noise.randint(0, 10_000)
            tx = f"tx{i}"
            m1.record_transmission_start(tx, 0)
            m1.record_reception("rx", tx, (i * 17) % 5000)
            m2.record_transmission_start(tx, 0)
            m2.record_reception("rx", tx, (i * 17) % 5000)
        assert m1.latency_p50() == m2.latency_p50()
        assert m1.latency_p99() == m2.latency_p99()


class TestMetricsIntegration:
    """Metrics wired into the Simulation engine via real TX/RX flows."""

    def test_transmission_counted(self) -> None:
        sim = Simulation(sim_id="m")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.start_transmission("tx", b"hello")
        assert sim.metrics.transmissions == 1
        assert sim.metrics.receptions == 0

    def test_successful_reception_and_latency(self) -> None:
        sim = Simulation(sim_id="m")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 100.0, 0.0, 0.0)  # in range (mirrors existing test)

        sim.start_transmission("tx", b"hello world")  # starts at t=0
        sim.advance_to(1000)  # reception observed at t=1000

        result = sim.get_rx_result("rx")
        assert result is not None  # sanity: reception succeeded

        assert sim.metrics.receptions == 1
        assert sim.metrics.collisions == 0
        assert sim.metrics.delivery_rate == 1.0
        stats = sim.metrics.latency_stats()
        assert stats.count == 1
        assert stats.min_us == 1000  # 1000 - 0, independent of the metric code

    def test_reception_not_double_counted_on_poll(self) -> None:
        """The simulator polls get_rx_result; deliveries must count once."""
        sim = Simulation(sim_id="m")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 100.0, 0.0, 0.0)
        sim.start_transmission("tx", b"hello world")
        sim.advance_to(1000)

        for _ in range(5):  # simulate repeated polling
            sim.get_rx_result("rx")
        assert sim.metrics.receptions == 1

    def test_collision_counted_once(self) -> None:
        sim = Simulation(sim_id="m")
        # Equidistant transmitters -> equal RSSI -> capture fails -> collision
        sim.add_node("tx1", 0.0, 100.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, -100.0, 0.0)
        sim.start_transmission("tx1", b"packet1")
        sim.start_transmission("tx2", b"packet2")
        sim.advance_to(1000)

        for _ in range(5):  # repeated polling of the same collision
            assert sim.get_rx_result("rx") is None
        assert sim.metrics.collisions == 1
        assert sim.metrics.receptions == 0
        assert sim.metrics.transmissions == 2

    def test_capture_effect_is_reception_not_collision(self) -> None:
        sim = Simulation(sim_id="m")
        sim.add_node("tx1", 50.0, 0.0, 0.0)  # close, strong
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 500.0, 0.0, 0.0)  # far, weak
        sim.start_transmission("tx1", b"strong signal")
        sim.start_transmission("tx2", b"weak signal")
        sim.advance_to(1000)

        result = sim.get_rx_result("rx")
        assert result is not None  # strong signal captured
        assert sim.metrics.receptions == 1
        assert sim.metrics.collisions == 0


class TestMetricsComparison:
    """Tests for A/B testing metrics comparison."""

    def test_compare_identical_metrics(self) -> None:
        """Identical metrics should show no significant changes."""
        snapshot = {
            "transmissions": 100,
            "receptions": 90,
            "collisions": 5,
            "delivery_rate": 0.9,
            "collision_rate": 0.05,
            "latency_us": {"min": 100, "max": 500, "mean": 250, "p50": 240, "p95": 450, "p99": 490},
        }
        diff = compare_metrics(snapshot, snapshot)
        assert diff.significant_improvements == 0
        assert diff.significant_degradations == 0
        assert diff.overall_verdict == "neutral"
        for change in diff.changes:
            assert not change.significant
            assert change.direction == "unchanged"

    def test_compare_improved_delivery_rate(self) -> None:
        """Higher delivery rate should be flagged as improvement."""
        baseline = {
            "transmissions": 100,
            "receptions": 80,
            "collisions": 10,
            "delivery_rate": 0.8,
            "collision_rate": 0.11,
            "latency_us": {"min": 100, "max": 500, "mean": 250, "p50": 240, "p95": 450, "p99": 490},
        }
        variant = {
            "transmissions": 100,
            "receptions": 95,
            "collisions": 3,
            "delivery_rate": 0.95,  # improved
            "collision_rate": 0.03,  # improved (lower)
            "latency_us": {"min": 100, "max": 500, "mean": 250, "p50": 240, "p95": 450, "p99": 490},
        }
        diff = compare_metrics(baseline, variant)

        # Find delivery_rate change.
        dr_change = next(c for c in diff.changes if c.name == "delivery_rate")
        assert dr_change.significant
        assert dr_change.direction == "improved"
        assert dr_change.delta > 0

        # Find collision_rate change.
        cr_change = next(c for c in diff.changes if c.name == "collision_rate")
        assert cr_change.significant
        assert cr_change.direction == "improved"  # lower is better
        assert cr_change.delta < 0

        assert diff.significant_improvements >= 2
        assert diff.overall_verdict == "better"

    def test_compare_degraded_latency(self) -> None:
        """Higher latency should be flagged as degradation."""
        baseline = {
            "transmissions": 100,
            "receptions": 90,
            "collisions": 5,
            "delivery_rate": 0.9,
            "collision_rate": 0.05,
            "latency_us": {"min": 100, "max": 500, "mean": 200, "p50": 180, "p95": 400, "p99": 480},
        }
        variant = {
            "transmissions": 100,
            "receptions": 90,
            "collisions": 5,
            "delivery_rate": 0.9,
            "collision_rate": 0.05,
            # worse latency
            "latency_us": {"min": 150, "max": 800, "mean": 400, "p50": 360, "p95": 700, "p99": 780},
        }
        diff = compare_metrics(baseline, variant)

        # Latency increases should be degradations.
        mean_change = next(c for c in diff.changes if c.name == "latency_mean_us")
        assert mean_change.significant
        assert mean_change.direction == "degraded"
        assert mean_change.delta > 0  # variant > baseline

        assert diff.significant_degradations >= 1
        assert diff.overall_verdict == "worse"

    def test_compare_mixed_changes(self) -> None:
        """Mixed improvements and degradations should balance out."""
        baseline = {
            "transmissions": 100,
            "receptions": 80,
            "collisions": 10,
            "delivery_rate": 0.8,
            "collision_rate": 0.11,
            "latency_us": {"min": 100, "max": 500, "mean": 200, "p50": 180, "p95": 400, "p99": 480},
        }
        variant = {
            "transmissions": 100,
            "receptions": 95,  # better
            "collisions": 3,  # better
            "delivery_rate": 0.95,  # better
            "collision_rate": 0.03,  # better
            # worse latency
            "latency_us": {"min": 150, "max": 800, "mean": 400, "p50": 360, "p95": 700, "p99": 780},
        }
        diff = compare_metrics(baseline, variant)

        # Should have both improvements and degradations.
        assert diff.significant_improvements > 0
        assert diff.significant_degradations > 0

    def test_compare_threshold_adjustment(self) -> None:
        """Custom threshold should affect significance detection."""
        baseline = {
            "transmissions": 100,
            "receptions": 100,
            "collisions": 0,
            "delivery_rate": 1.0,
            "collision_rate": 0.0,
        }
        variant = {
            "transmissions": 100,
            "receptions": 103,
            "collisions": 0,
            "delivery_rate": 1.03,
            "collision_rate": 0.0,
        }

        # 3% change with default 5% threshold -> not significant.
        diff_default = compare_metrics(baseline, variant)
        dr_default = next(c for c in diff_default.changes if c.name == "delivery_rate")
        assert not dr_default.significant

        # 3% change with 2% threshold -> significant.
        diff_strict = compare_metrics(baseline, variant, threshold=0.02)
        dr_strict = next(c for c in diff_strict.changes if c.name == "delivery_rate")
        assert dr_strict.significant

    def test_compare_zero_baseline(self) -> None:
        """Handle zero baseline gracefully."""
        baseline = {
            "transmissions": 0,
            "receptions": 0,
            "collisions": 0,
            "delivery_rate": 0.0,
            "collision_rate": 0.0,
        }
        variant = {
            "transmissions": 100,
            "receptions": 90,
            "collisions": 5,
            "delivery_rate": 0.9,
            "collision_rate": 0.05,
        }

        diff = compare_metrics(baseline, variant)

        # Non-zero from zero should be significant.
        tx_change = next(c for c in diff.changes if c.name == "transmissions")
        assert tx_change.significant
        assert tx_change.pct_change == float("inf")  # undefined but represented as inf

        delivery = next(c for c in diff.changes if c.name == "delivery_rate")
        assert delivery.significant
        assert delivery.variant == 0.9
        collision = next(c for c in diff.changes if c.name == "collision_rate")
        assert collision.significant

    def test_compare_missing_latency(self) -> None:
        """Handle missing latency data gracefully."""
        baseline = {
            "transmissions": 100,
            "receptions": 90,
            "collisions": 5,
            "delivery_rate": 0.9,
            "collision_rate": 0.05,
        }
        variant = {
            "transmissions": 100,
            "receptions": 90,
            "collisions": 5,
            "delivery_rate": 0.9,
            "collision_rate": 0.05,
        }

        # No latency_us key should not cause errors.
        diff = compare_metrics(baseline, variant)
        assert diff.overall_verdict == "neutral"

    def test_compare_zero_delivery_none_latency_is_not_better(self) -> None:
        """None latency from a zero-delivery snapshot is not a 0 µs win."""
        baseline_m = Metrics()
        baseline_m.record_transmission_start("tx1", 0)
        baseline_m.record_reception("rx1", "tx1", 500)
        variant_m = Metrics()
        variant_m.record_transmission_start("tx1", 0)
        baseline = baseline_m.snapshot()
        variant = variant_m.snapshot()
        lat = variant["latency_us"]
        assert isinstance(lat, dict)
        assert lat["count"] == 0
        assert lat["p50"] is None
        diff = compare_metrics(baseline, variant)
        latency_changes = [c for c in diff.changes if c.name.startswith("latency_")]
        assert latency_changes == []
        assert not any(
            c.significant and c.direction == "improved" for c in latency_changes
        )
        delivery = next(c for c in diff.changes if c.name == "delivery_rate")
        assert delivery.variant < delivery.baseline
        assert diff.overall_verdict != "better"

    def test_diff_to_dict(self) -> None:
        """MetricsDiff.to_dict returns JSON-serializable output."""
        baseline = {
            "transmissions": 100,
            "receptions": 80,
            "collisions": 10,
            "delivery_rate": 0.8,
            "collision_rate": 0.11,
        }
        variant = {
            "transmissions": 100,
            "receptions": 95,
            "collisions": 3,
            "delivery_rate": 0.95,
            "collision_rate": 0.03,
        }

        diff = compare_metrics(baseline, variant)
        d = diff.to_dict()

        assert "changes" in d
        assert "significant_improvements" in d
        assert "significant_degradations" in d
        assert "overall_verdict" in d
        assert isinstance(d["changes"], list)
        assert all(isinstance(c, dict) for c in d["changes"])

    def test_diff_summary(self) -> None:
        """MetricsDiff.summary returns human-readable output."""
        baseline = {
            "transmissions": 100,
            "receptions": 80,
            "collisions": 10,
            "delivery_rate": 0.8,
            "collision_rate": 0.11,
        }
        variant = {
            "transmissions": 100,
            "receptions": 95,
            "collisions": 3,
            "delivery_rate": 0.95,
            "collision_rate": 0.03,
        }

        diff = compare_metrics(baseline, variant)
        summary = diff.summary()

        assert "A/B Test Result" in summary
        assert "Improvements" in summary
        assert "Degradations" in summary
        assert "Significant changes" in summary

    def test_real_simulation_comparison(self) -> None:
        """Integration test: compare snapshots from real simulations."""
        # Create baseline simulation.
        sim_baseline = Simulation(sim_id="baseline")
        sim_baseline.add_node("tx", 0.0, 0.0, 0.0)
        sim_baseline.add_node("rx", 100.0, 0.0, 0.0)
        for i in range(10):
            sim_baseline.start_transmission("tx", f"packet{i}".encode())
            sim_baseline.advance_to((i + 1) * 10000)
            sim_baseline.get_rx_result("rx")
        baseline_snap = sim_baseline.metrics.snapshot()

        # Create variant simulation with different conditions.
        sim_variant = Simulation(sim_id="variant")
        sim_variant.add_node("tx", 0.0, 0.0, 0.0)
        sim_variant.add_node("rx", 100.0, 0.0, 0.0)
        for i in range(10):
            sim_variant.start_transmission("tx", f"packet{i}".encode())
            sim_variant.advance_to((i + 1) * 10000)
            sim_variant.get_rx_result("rx")
        variant_snap = sim_variant.metrics.snapshot()

        # Compare the two runs.
        diff = compare_metrics(baseline_snap, variant_snap)

        # Both runs are identical, so no significant changes.
        assert diff.overall_verdict == "neutral"
        assert diff.significant_improvements == 0
        assert diff.significant_degradations == 0


class TestMetricsTimeSeries:
    """Tests for MetricsTimeSeries class for dashboard visualization."""

    def test_time_series_empty(self) -> None:
        """Empty time series returns no samples."""
        from lichen.sim.metrics import MetricsTimeSeries

        ts = MetricsTimeSeries()
        assert len(ts) == 0
        assert ts.get_latest() is None
        assert ts.get_samples() == []
        assert ts.to_dict_list() == []

    def test_time_series_records_samples(self) -> None:
        """Time series records samples at the specified interval."""
        from lichen.sim.metrics import MetricsTimeSeries

        ts = MetricsTimeSeries(sample_interval_us=1_000_000)  # 1 second

        # Should sample immediately for first entry
        assert ts.should_sample(0)
        sample1 = ts.record_sample(0, 0.9, 0.1, 0.01, 10, 9, 1)
        assert sample1.time_us == 0
        assert sample1.delivery_rate == 0.9

        # Should not sample before interval
        assert not ts.should_sample(500_000)

        # Should sample after interval
        assert ts.should_sample(1_000_000)
        sample2 = ts.record_sample(1_000_000, 0.95, 0.05, 0.02, 20, 19, 1)

        assert len(ts) == 2
        samples = ts.get_samples()
        assert len(samples) == 2
        assert samples[0].time_us == 0
        assert samples[1].time_us == 1_000_000

    def test_time_series_since_filter(self) -> None:
        """get_samples(since_us) filters out older samples."""
        from lichen.sim.metrics import MetricsTimeSeries

        ts = MetricsTimeSeries(sample_interval_us=1_000_000)
        ts.record_sample(0, 0.9, 0.1, 0.01, 10, 9, 1)
        ts.record_sample(1_000_000, 0.92, 0.08, 0.015, 20, 18, 2)
        ts.record_sample(2_000_000, 0.95, 0.05, 0.02, 30, 28, 2)

        samples = ts.get_samples(since_us=1_000_000)
        assert len(samples) == 1  # Only the one at 2_000_000
        assert samples[0].time_us == 2_000_000

    def test_time_series_max_samples(self) -> None:
        """Time series respects max_samples limit."""
        from lichen.sim.metrics import MetricsTimeSeries

        ts = MetricsTimeSeries(max_samples=3, sample_interval_us=1_000_000)
        for i in range(5):
            ts.record_sample(i * 1_000_000, 0.9, 0.1, 0.01, i, i, 0)

        assert len(ts) == 3
        samples = ts.get_samples()
        # Should retain the most recent 3 samples
        assert samples[0].time_us == 2_000_000
        assert samples[1].time_us == 3_000_000
        assert samples[2].time_us == 4_000_000

    def test_time_series_to_dict_list(self) -> None:
        """to_dict_list returns JSON-serializable dicts."""
        from lichen.sim.metrics import MetricsTimeSeries

        ts = MetricsTimeSeries(sample_interval_us=1_000_000)
        ts.record_sample(0, 0.9, 0.1, 0.01, 10, 9, 1)

        dicts = ts.to_dict_list()
        assert len(dicts) == 1
        d = dicts[0]
        assert d["time_us"] == 0
        assert d["delivery_rate"] == 0.9
        assert d["collision_rate"] == 0.1
        assert d["duty_cycle"] == 0.01
        assert d["transmissions"] == 10
        assert d["receptions"] == 9
        assert d["collisions"] == 1

    def test_time_series_clear(self) -> None:
        """clear() removes all samples."""
        from lichen.sim.metrics import MetricsTimeSeries

        ts = MetricsTimeSeries(sample_interval_us=1_000_000)
        ts.record_sample(0, 0.9, 0.1, 0.01, 10, 9, 1)
        assert len(ts) == 1

        ts.clear()
        assert len(ts) == 0
        assert ts.should_sample(0)  # Can sample again after clear


class TestMetricsDashboard:
    """Tests for dashboard metrics integration."""

    def test_metrics_has_dashboard_time_series(self) -> None:
        """Metrics class has dashboard_time_series property."""
        m = Metrics()
        ts = m.dashboard_time_series
        assert ts is not None
        assert len(ts) == 0

    def test_metrics_record_dashboard_sample(self) -> None:
        """record_dashboard_sample captures current metrics."""
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("rx1", "tx1", 100)

        sample = m.record_dashboard_sample(1_000_000)
        assert sample is not None
        assert sample.time_us == 1_000_000
        assert sample.transmissions == 1
        assert sample.receptions == 1
        assert sample.delivery_rate == 1.0

    def test_metrics_record_dashboard_sample_respects_interval(self) -> None:
        """record_dashboard_sample returns None before interval."""
        m = Metrics()
        m.record_transmission_start("tx1", 0)

        # First sample
        sample1 = m.record_dashboard_sample(0)
        assert sample1 is not None

        # Before interval (1 second)
        sample2 = m.record_dashboard_sample(500_000)
        assert sample2 is None

        # After interval
        sample3 = m.record_dashboard_sample(1_000_000)
        assert sample3 is not None

    def test_metrics_get_dashboard_snapshot(self) -> None:
        """get_dashboard_snapshot returns current and time-series data."""
        m = Metrics()
        m.record_transmission_start("tx1", 0)
        m.record_reception("rx1", "tx1", 100)
        m.set_duty_cycle(0.02)
        m.record_dashboard_sample(0)

        snap = m.get_dashboard_snapshot()

        assert "current" in snap
        assert snap["current"]["transmissions"] == 1
        assert snap["current"]["receptions"] == 1
        assert snap["current"]["duty_cycle"] == 0.02

        assert "time_series" in snap
        assert len(snap["time_series"]) == 1

        assert "last_sample_time_us" in snap
        assert snap["last_sample_time_us"] == 0

    def test_metrics_snapshot_includes_duty_cycle(self) -> None:
        """Metrics snapshot includes duty cycle."""
        m = Metrics()
        m.set_duty_cycle(0.05)

        snap = m.snapshot()
        assert "duty_cycle" in snap
        assert snap["duty_cycle"] == 0.05

    def test_metrics_reset_clears_dashboard(self) -> None:
        """reset() clears dashboard time series."""
        m = Metrics()
        m.record_dashboard_sample(0)
        m.set_duty_cycle(0.1)
        assert len(m.dashboard_time_series) == 1
        assert m.duty_cycle == 0.1

        m.reset()

        assert len(m.dashboard_time_series) == 0
        assert m.duty_cycle == 0.0


class TestMetricsDashboardIntegration:
    """Integration tests for dashboard metrics with simulation."""

    def test_simulation_records_dashboard_samples(self) -> None:
        """Simulation records dashboard samples during advance_to."""
        sim = Simulation(sim_id="dashboard_test")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 100.0, 0.0, 0.0)

        # First transmission
        sim.start_transmission("tx", b"hello")
        sim.advance_to(1_000_000)  # 1 second - should trigger sample
        sim.get_rx_result("rx")

        # Check that a sample was recorded
        ts = sim.metrics.dashboard_time_series
        assert len(ts) >= 1

        sample = ts.get_latest()
        assert sample is not None
        assert sample.transmissions >= 1

    def test_simulation_dashboard_snapshot_api(self) -> None:
        """get_dashboard_snapshot returns complete data."""
        sim = Simulation(sim_id="dashboard_api_test")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 100.0, 0.0, 0.0)

        for i in range(3):
            sim.start_transmission("tx", f"msg{i}".encode())
            sim.advance_to((i + 1) * 1_000_000)
            sim.get_rx_result("rx")

        snap = sim.metrics.get_dashboard_snapshot()

        assert snap["current"]["transmissions"] == 3
        assert len(snap["time_series"]) >= 1
