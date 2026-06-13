"""Tests for simulation metrics collection."""

from __future__ import annotations

from lichen.sim.metrics import Metrics
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
