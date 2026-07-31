# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for baseline regression detection system."""

from __future__ import annotations

import json
import tempfile

import pytest

from lichen.sim.baseline import (
    BaselineSnapshot,
    RegressionThresholds,
    baseline_exists,
    compare_to_baseline,
    list_baselines,
    load_baseline,
    save_baseline,
    update_baseline,
)
from lichen.sim.simulation import Simulation


class TestRegressionThresholds:
    """Tests for RegressionThresholds class."""

    def test_default_thresholds(self) -> None:
        """Test default threshold values."""
        t = RegressionThresholds()
        assert t.delivery_rate == 0.05
        assert t.collision_rate == 0.20
        assert t.latency_p95 == 0.20
        assert t.default == 0.10

    def test_get_specific_metric(self) -> None:
        """Test getting specific metric threshold."""
        t = RegressionThresholds(delivery_rate=0.03)
        assert t.get("delivery_rate") == 0.03
        assert t.get("collision_rate") == 0.20

    def test_get_unknown_metric_uses_default(self) -> None:
        """Test unknown metric uses default threshold."""
        t = RegressionThresholds(default=0.15)
        assert t.get("unknown_metric") == 0.15


class TestBaselineSnapshot:
    """Tests for BaselineSnapshot dataclass."""

    def test_to_dict_round_trip(self) -> None:
        """Test serialization round trip."""
        snap = BaselineSnapshot(
            name="test-baseline",
            metrics={"delivery_rate": 0.95, "collisions": 5},
            description="Test baseline",
            scenario="grid-50-nodes",
        )

        d = snap.to_dict()
        loaded = BaselineSnapshot.from_dict(d)

        assert loaded.name == snap.name
        assert loaded.metrics == snap.metrics
        assert loaded.description == snap.description
        assert loaded.scenario == snap.scenario
        assert loaded.version == snap.version

    def test_default_created_at(self) -> None:
        """Test that created_at is set by default."""
        snap = BaselineSnapshot(name="test", metrics={})
        assert snap.created_at  # Non-empty
        assert "T" in snap.created_at  # ISO format


class TestSaveLoadBaseline:
    """Tests for save/load baseline functions."""

    def test_save_and_load_baseline(self) -> None:
        """Test saving and loading a baseline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics = {
                "transmissions": 100,
                "receptions": 95,
                "collisions": 3,
                "delivery_rate": 0.95,
                "collision_rate": 0.03,
            }

            path = save_baseline(
                name="test-scenario",
                metrics_snapshot=metrics,
                baselines_dir=tmpdir,
                description="Test scenario baseline",
                scenario="grid-10-nodes",
            )

            assert path.exists()
            assert path.name == "test-scenario.json"

            loaded = load_baseline("test-scenario", tmpdir)
            assert loaded is not None
            assert loaded.name == "test-scenario"
            assert loaded.metrics == metrics
            assert loaded.description == "Test scenario baseline"
            assert loaded.scenario == "grid-10-nodes"

    def test_load_nonexistent_baseline(self) -> None:
        """Test loading a baseline that doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = load_baseline("nonexistent", tmpdir)
            assert result is None

    def test_list_baselines(self) -> None:
        """Test listing available baselines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Initially empty
            assert list_baselines(tmpdir) == []

            # Add some baselines
            save_baseline("alpha", {}, tmpdir)
            save_baseline("beta", {}, tmpdir)
            save_baseline("gamma", {}, tmpdir)

            baselines = list_baselines(tmpdir)
            assert baselines == ["alpha", "beta", "gamma"]

    def test_baseline_exists(self) -> None:
        """Test checking baseline existence."""
        with tempfile.TemporaryDirectory() as tmpdir:
            assert not baseline_exists("test", tmpdir)
            save_baseline("test", {}, tmpdir)
            assert baseline_exists("test", tmpdir)

    def test_update_baseline(self) -> None:
        """Test updating an existing baseline."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create initial baseline
            save_baseline(
                name="test",
                metrics_snapshot={"delivery_rate": 0.9},
                baselines_dir=tmpdir,
                description="Original",
                scenario="test-scenario",
            )

            # Update with new metrics
            update_baseline(
                name="test",
                current_snapshot={"delivery_rate": 0.95},
                baselines_dir=tmpdir,
            )

            loaded = load_baseline("test", tmpdir)
            assert loaded is not None
            assert loaded.metrics["delivery_rate"] == 0.95
            assert loaded.description == "Original"  # Preserved
            assert loaded.scenario == "test-scenario"  # Preserved


class TestCompareToBaseline:
    """Tests for baseline comparison functionality."""

    def test_compare_identical_metrics(self) -> None:
        """Test comparing identical metrics passes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            metrics = {
                "transmissions": 100,
                "receptions": 95,
                "delivery_rate": 0.95,
                "collision_rate": 0.05,
            }
            save_baseline("test", metrics, tmpdir)

            result = compare_to_baseline("test", metrics, tmpdir)

            assert result.passed
            assert len(result.regressions) == 0
            assert result.baseline_name == "test"

    def test_compare_detects_delivery_rate_regression(self) -> None:
        """Test that decreased delivery rate is detected as regression."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.95}
            current = {"delivery_rate": 0.80}  # 15.8% decrease

            save_baseline("test", baseline, tmpdir)
            result = compare_to_baseline("test", current, tmpdir)

            assert not result.passed
            assert len(result.regressions) == 1
            assert result.regressions[0].metric == "delivery_rate"
            assert result.regressions[0].is_regression

    def test_compare_detects_collision_rate_regression(self) -> None:
        """Test that increased collision rate is detected as regression."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"collision_rate": 0.05}
            current = {"collision_rate": 0.10}  # 100% increase

            save_baseline("test", baseline, tmpdir)
            result = compare_to_baseline("test", current, tmpdir)

            assert not result.passed
            assert len(result.regressions) == 1
            assert result.regressions[0].metric == "collision_rate"

    def test_compare_detects_latency_regression(self) -> None:
        """Test that increased latency is detected as regression."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {
                "latency_us": {"mean": 100, "p95": 200, "p99": 300},
            }
            current = {
                "latency_us": {"mean": 150, "p95": 300, "p99": 500},  # All increased
            }

            save_baseline("test", baseline, tmpdir)
            result = compare_to_baseline("test", current, tmpdir)

            assert not result.passed
            # Should detect latency regressions
            latency_regs = [r for r in result.regressions if "latency" in r.metric]
            assert len(latency_regs) > 0

    def test_compare_within_threshold_passes(self) -> None:
        """Test that changes within threshold pass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.95}
            current = {"delivery_rate": 0.94}  # 1% decrease, within 5% threshold

            save_baseline("test", baseline, tmpdir)
            result = compare_to_baseline("test", current, tmpdir)

            assert result.passed
            assert len(result.regressions) == 0

    def test_compare_with_custom_thresholds(self) -> None:
        """Test comparison with custom thresholds."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.95}
            current = {"delivery_rate": 0.93}  # ~2% decrease

            save_baseline("test", baseline, tmpdir)

            # With tight threshold, this should be a regression
            strict = RegressionThresholds(delivery_rate=0.01)
            result = compare_to_baseline("test", current, tmpdir, thresholds=strict)
            assert not result.passed

            # With loose threshold, this should pass
            lenient = RegressionThresholds(delivery_rate=0.05)
            result = compare_to_baseline("test", current, tmpdir, thresholds=lenient)
            assert result.passed

    def test_compare_nonexistent_baseline_raises(self) -> None:
        """Test comparing to nonexistent baseline raises error."""
        with tempfile.TemporaryDirectory() as tmpdir, pytest.raises(FileNotFoundError):
            compare_to_baseline("nonexistent", {}, tmpdir)

    def test_report_output(self) -> None:
        """Test human-readable report generation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.95}
            current = {"delivery_rate": 0.80}

            save_baseline("test", baseline, tmpdir, description="Test baseline")
            result = compare_to_baseline("test", current, tmpdir)

            report = result.report()
            assert "FAILED" in report
            assert "delivery_rate" in report
            assert "Regressions detected" in report

    def test_report_verbose(self) -> None:
        """Test verbose report includes all metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.95, "collision_rate": 0.05}
            save_baseline("test", baseline, tmpdir)

            result = compare_to_baseline("test", baseline, tmpdir)
            report = result.report(verbose=True)

            assert "All metrics" in report
            assert "delivery_rate" in report
            assert "collision_rate" in report

    def test_to_dict_serializable(self) -> None:
        """Test result can be serialized to JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.95}
            current = {"delivery_rate": 0.80}

            save_baseline("test", baseline, tmpdir)
            result = compare_to_baseline("test", current, tmpdir)

            d = result.to_dict()
            # Should be JSON serializable
            json_str = json.dumps(d)
            assert "test" in json_str
            assert "regressions" in json_str


class TestIntegrationWithSimulation:
    """Integration tests with actual simulation metrics."""

    def test_baseline_from_simulation(self) -> None:
        """Test creating baseline from real simulation."""
        sim = Simulation(sim_id="baseline_test")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 100.0, 0.0, 0.0)

        # Run some traffic
        for i in range(10):
            sim.start_transmission("tx", f"packet{i}".encode())
            sim.advance_to((i + 1) * 10000)
            sim.get_rx_result("rx")

        snapshot = sim.metrics.snapshot()

        with tempfile.TemporaryDirectory() as tmpdir:
            save_baseline("sim-test", snapshot, tmpdir, description="Test sim baseline")
            loaded = load_baseline("sim-test", tmpdir)

            assert loaded is not None
            assert loaded.metrics["transmissions"] == 10

    def test_regression_detection_across_runs(self) -> None:
        """Test detecting regression between simulation runs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Baseline run: close nodes, good delivery
            sim1 = Simulation(sim_id="baseline")
            sim1.add_node("tx", 0.0, 0.0, 0.0)
            sim1.add_node("rx", 100.0, 0.0, 0.0)
            for i in range(10):
                sim1.start_transmission("tx", f"p{i}".encode())
                sim1.advance_to((i + 1) * 10000)
                sim1.get_rx_result("rx")

            baseline_snap = sim1.metrics.snapshot()
            save_baseline("test-scenario", baseline_snap, tmpdir)

            # Current run: same setup, should pass
            sim2 = Simulation(sim_id="current")
            sim2.add_node("tx", 0.0, 0.0, 0.0)
            sim2.add_node("rx", 100.0, 0.0, 0.0)
            for i in range(10):
                sim2.start_transmission("tx", f"p{i}".encode())
                sim2.advance_to((i + 1) * 10000)
                sim2.get_rx_result("rx")

            current_snap = sim2.metrics.snapshot()
            result = compare_to_baseline("test-scenario", current_snap, tmpdir)

            assert result.passed, f"Expected pass but got: {result.report()}"

    def test_captures_collision_regression(self) -> None:
        """Test detecting increased collisions as regression."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Baseline: no collisions
            sim1 = Simulation(sim_id="baseline")
            sim1.add_node("tx1", 0.0, 0.0, 0.0)
            sim1.add_node("rx", 100.0, 0.0, 0.0)
            sim1.start_transmission("tx1", b"packet1")
            sim1.advance_to(10000)
            sim1.get_rx_result("rx")

            baseline_snap = sim1.metrics.snapshot()
            assert baseline_snap["collision_rate"] == 0.0
            save_baseline("collision-test", baseline_snap, tmpdir)

            # Current: add collisions
            sim2 = Simulation(sim_id="current")
            sim2.add_node("tx1", 0.0, 100.0, 0.0)  # Equidistant
            sim2.add_node("rx", 0.0, 0.0, 0.0)
            sim2.add_node("tx2", 0.0, -100.0, 0.0)  # Equidistant
            sim2.start_transmission("tx1", b"packet1")
            sim2.start_transmission("tx2", b"packet2")
            sim2.advance_to(10000)
            sim2.get_rx_result("rx")

            current_snap = sim2.metrics.snapshot()

            # The baseline had 0 collisions, current may have collisions.
            # With 0 baseline, any increase is flagged.
            result = compare_to_baseline("collision-test", current_snap, tmpdir)

            # If collision_rate increased from 0, should detect regression
            if current_snap["collision_rate"] > 0:
                collision_regs = [
                    r for r in result.regressions if r.metric == "collision_rate"
                ]
                # Any increase from 0 should be flagged as regression
                assert len(collision_regs) == 1


class TestEdgeCases:
    """Edge case tests."""

    def test_zero_baseline_values(self) -> None:
        """Test handling of zero baseline values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.0, "collision_rate": 0.0}
            current = {"delivery_rate": 0.5, "collision_rate": 0.1}

            save_baseline("zero-test", baseline, tmpdir)
            result = compare_to_baseline("zero-test", current, tmpdir)

            # Delivery rate improved (0 -> 0.5), not a regression
            # Collision rate worsened (0 -> 0.1), is a regression
            collision_regs = [r for r in result.regressions if r.metric == "collision_rate"]
            assert len(collision_regs) == 1

    def test_missing_metrics_in_current(self) -> None:
        """Test handling when current snapshot is missing metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {"delivery_rate": 0.95, "collision_rate": 0.05}
            current = {"delivery_rate": 0.95}  # Missing collision_rate

            save_baseline("missing-test", baseline, tmpdir)
            result = compare_to_baseline("missing-test", current, tmpdir)

            # Missing metric is treated as 0, which is improvement for collision_rate
            assert result.passed or all(
                r.metric != "delivery_rate" for r in result.regressions
            )

    def test_nested_latency_handling(self) -> None:
        """Test proper handling of nested latency metrics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            baseline = {
                "latency_us": {
                    "count": 100,
                    "min": 50,
                    "max": 500,
                    "mean": 150,
                    "p50": 140,
                    "p95": 400,
                    "p99": 480,
                },
            }
            save_baseline("latency-test", baseline, tmpdir)

            # Same values should pass
            result = compare_to_baseline("latency-test", baseline, tmpdir)
            assert result.passed

            # Increased p95 should be detected
            current = {
                "latency_us": {
                    "count": 100,
                    "min": 50,
                    "max": 500,
                    "mean": 150,
                    "p50": 140,
                    "p95": 600,  # 50% increase
                    "p99": 480,
                },
            }
            result = compare_to_baseline("latency-test", current, tmpdir)
            p95_regs = [r for r in result.regressions if "p95" in r.metric]
            assert len(p95_regs) == 1
