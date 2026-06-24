# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for TX jitter in the simulation.

These tests verify that the simulation correctly applies transmission jitter:
- Disabled by default (jitter_max_us=0 means immediate TX)
- When enabled, TX starts later than request time
- Multiple TXs have varied start times within the jitter range
- Deterministic behavior when a seed is provided
- ChaosRule TxJitterRule can override default jitter per-node
"""

from __future__ import annotations

import random

from lichen.sim.chaos import ChaosEngine, TxJitterRule
from lichen.sim.events import TxStartDelayedEvent
from lichen.sim.simulation import Simulation


class TestJitterDisabledByDefault:
    """Test that jitter is disabled by default (jitter_max_us=0)."""

    def test_default_simulation_has_no_jitter(self) -> None:
        """Simulation created without jitter params has jitter disabled."""
        sim = Simulation("test-no-jitter")
        assert sim.jitter_min_us == 0
        assert sim.jitter_max_us == 0

    def test_immediate_tx_when_jitter_disabled(self) -> None:
        """With jitter_max_us=0, transmission starts immediately."""
        sim = Simulation("test-immediate", jitter_max_us=0)
        sim.add_node("sender", 0.0, 0.0, 0.0)

        # Record time before TX
        time_before = sim.current_time_us

        # Start transmission
        tx_id = sim.start_transmission("sender", b"hello")

        # TX should have a real ID (not empty string which indicates delayed)
        assert tx_id != ""

        # Time should not have advanced
        assert sim.current_time_us == time_before

        # No TxStartDelayedEvent should be in the queue
        for event in sim.event_queue:
            assert not isinstance(event, TxStartDelayedEvent)

    def test_tx_id_returned_immediately_when_no_jitter(self) -> None:
        """When jitter is disabled, start_transmission returns a valid TX ID."""
        sim = Simulation("test-txid")
        sim.add_node("sender", 0.0, 0.0, 0.0)

        tx_id = sim.start_transmission("sender", b"data")

        # Should be a valid UUID-like string
        assert tx_id != ""
        assert len(tx_id) > 0


class TestJitterDelaysTransmission:
    """Test that jitter delays transmission start."""

    def test_tx_delayed_when_jitter_enabled(self) -> None:
        """With jitter enabled, TX queues a delayed event instead of starting immediately."""
        sim = Simulation(
            "test-delay",
            jitter_min_us=1000,  # 1ms minimum
            jitter_max_us=5000,  # 5ms maximum
        )
        sim.add_node("sender", 0.0, 0.0, 0.0)

        # Start transmission
        tx_id = sim.start_transmission("sender", b"hello")

        # TX ID should be empty string (indicating delayed)
        assert tx_id == ""

        # Should have a TxStartDelayedEvent in the queue
        delayed_events = [
            e for e in sim.event_queue if isinstance(e, TxStartDelayedEvent)
        ]
        assert len(delayed_events) == 1

        # The delayed event should fire within jitter range
        event = delayed_events[0]
        assert event.time_us >= sim.jitter_min_us
        assert event.time_us <= sim.jitter_max_us
        assert event.node_id == "sender"
        assert event.payload == b"hello"

    def test_tx_starts_after_jitter_delay(self) -> None:
        """Processing the delayed event actually starts the transmission."""
        sim = Simulation(
            "test-process-delay",
            jitter_min_us=1000,
            jitter_max_us=1000,  # Fixed delay for predictable testing
        )
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 50.0, 0.0, 0.0)

        # Start transmission at time 0
        sim.start_transmission("sender", b"test-data")

        # Advance time to process the delayed event
        sim.advance_to(1000)  # 1ms = 1000us

        # Now receiver should be able to receive
        sim.start_receive("receiver", timeout_ms=100)
        result = sim.get_rx_result("receiver")

        assert result is not None
        payload, rssi, snr = result
        assert payload == b"test-data"


class TestJitterDistribution:
    """Test that multiple TXs have varied start times within range."""

    def test_multiple_txs_have_varied_jitter(self) -> None:
        """Multiple transmissions get different jitter values within range."""
        sim = Simulation(
            "test-distribution",
            jitter_min_us=1000,
            jitter_max_us=10000,
            seed=42,  # Reproducible but varied
        )

        # Create multiple sender nodes
        for i in range(10):
            sim.add_node(f"sender-{i}", float(i * 10), 0.0, 0.0)

        # Queue 10 transmissions
        for i in range(10):
            sim.start_transmission(f"sender-{i}", f"msg-{i}".encode())

        # Collect all delayed event times
        delayed_events = [
            e for e in sim.event_queue if isinstance(e, TxStartDelayedEvent)
        ]
        assert len(delayed_events) == 10

        fire_times = [e.time_us for e in delayed_events]

        # All times should be within range
        for t in fire_times:
            assert 1000 <= t <= 10000

        # Should have some variation (not all the same)
        unique_times = set(fire_times)
        assert len(unique_times) > 1, "Expected varied jitter values"

    def test_jitter_values_uniformly_distributed(self) -> None:
        """Jitter values should be uniformly distributed across the range."""
        sim = Simulation(
            "test-uniform",
            jitter_min_us=0,
            jitter_max_us=10000,
            seed=12345,
        )

        # Generate many jitter values
        jitters = [sim.calculate_tx_jitter() for _ in range(1000)]

        # Check they're within range
        assert all(0 <= j <= 10000 for j in jitters)

        # Check roughly uniform distribution (split into quartiles)
        q1 = sum(1 for j in jitters if 0 <= j < 2500)
        q2 = sum(1 for j in jitters if 2500 <= j < 5000)
        q3 = sum(1 for j in jitters if 5000 <= j < 7500)
        q4 = sum(1 for j in jitters if 7500 <= j <= 10000)

        # Each quartile should have roughly 25% (allow 15-35%)
        for q in [q1, q2, q3, q4]:
            assert 150 <= q <= 350, f"Quartile {q} outside expected range"


class TestJitterDeterministicWithSeed:
    """Test that same seed produces same jitter sequence."""

    def test_same_seed_same_jitter_sequence(self) -> None:
        """Two simulations with same seed produce identical jitter sequences."""
        jitters1 = []
        jitters2 = []

        # First simulation
        sim1 = Simulation(
            "test-seed-1",
            jitter_min_us=100,
            jitter_max_us=5000,
            seed=42,
        )
        for _ in range(10):
            jitters1.append(sim1.calculate_tx_jitter())

        # Second simulation with same seed
        sim2 = Simulation(
            "test-seed-2",
            jitter_min_us=100,
            jitter_max_us=5000,
            seed=42,
        )
        for _ in range(10):
            jitters2.append(sim2.calculate_tx_jitter())

        assert jitters1 == jitters2

    def test_different_seeds_different_sequences(self) -> None:
        """Two simulations with different seeds produce different jitter sequences."""
        sim1 = Simulation(
            "test-seed-a",
            jitter_min_us=100,
            jitter_max_us=5000,
            seed=42,
        )
        sim2 = Simulation(
            "test-seed-b",
            jitter_min_us=100,
            jitter_max_us=5000,
            seed=99,
        )

        jitters1 = [sim1.calculate_tx_jitter() for _ in range(10)]
        jitters2 = [sim2.calculate_tx_jitter() for _ in range(10)]

        assert jitters1 != jitters2

    def test_reseed_resets_sequence(self) -> None:
        """Reseeding the simulation resets the jitter sequence."""
        sim = Simulation(
            "test-reseed",
            jitter_min_us=100,
            jitter_max_us=5000,
            seed=42,
        )

        # Generate some values
        first_run = [sim.calculate_tx_jitter() for _ in range(5)]

        # Reseed and generate again
        sim.reseed(42)
        second_run = [sim.calculate_tx_jitter() for _ in range(5)]

        assert first_run == second_run

    def test_delayed_events_deterministic_with_seed(self) -> None:
        """TxStartDelayedEvent times are deterministic with a seed."""
        def run_simulation(seed: int) -> list[int]:
            sim = Simulation(
                f"test-det-{seed}",
                jitter_min_us=100,
                jitter_max_us=5000,
                seed=seed,
            )
            for i in range(5):
                sim.add_node(f"node-{i}", float(i * 10), 0.0, 0.0)
            for i in range(5):
                sim.start_transmission(f"node-{i}", b"test")

            events = [
                e for e in sim.event_queue if isinstance(e, TxStartDelayedEvent)
            ]
            return [e.time_us for e in events]

        times1 = run_simulation(42)
        times2 = run_simulation(42)

        assert times1 == times2


class TestChaosRuleOverridesDefault:
    """Test that TxJitterRule can change jitter per-node.

    The TxJitterRule in the chaos engine provides per-node jitter overrides.
    These tests verify the rule's behavior when integrated with the simulation.
    """

    def test_tx_jitter_rule_generates_jitter_in_range(self) -> None:
        """TxJitterRule generates jitter values within its configured range."""
        rng = random.Random(42)
        rule = TxJitterRule(
            jitter_min_us=500,
            jitter_max_us=2000,
            node_id="special-node",
            rng=rng,
        )

        # Generate multiple jitter values
        jitters = [rule.get_jitter_us() for _ in range(100)]

        # All values should be within range
        assert all(500 <= j <= 2000 for j in jitters)

    def test_tx_jitter_rule_deterministic_with_seed(self) -> None:
        """TxJitterRule produces deterministic sequence with seeded RNG."""
        rng1 = random.Random(42)
        rng2 = random.Random(42)

        rule1 = TxJitterRule(
            jitter_min_us=100,
            jitter_max_us=1000,
            rng=rng1,
        )
        rule2 = TxJitterRule(
            jitter_min_us=100,
            jitter_max_us=1000,
            rng=rng2,
        )

        jitters1 = [rule1.get_jitter_us() for _ in range(10)]
        jitters2 = [rule2.get_jitter_us() for _ in range(10)]

        assert jitters1 == jitters2

    def test_tx_jitter_rule_per_node_targeting(self) -> None:
        """TxJitterRule with node_id only matches that specific node."""
        from lichen.sim.transmission import Transmission

        rule = TxJitterRule(
            jitter_min_us=1000,
            jitter_max_us=5000,
            node_id="target-node",
        )

        tx_target = Transmission(
            source_node_id="target-node",
            payload=b"test",
            tx_power_dbm=14,
            start_time_us=0,
            end_time_us=1000,
        )
        tx_other = Transmission(
            source_node_id="other-node",
            payload=b"test",
            tx_power_dbm=14,
            start_time_us=0,
            end_time_us=1000,
        )

        assert rule.matches(tx_target, "receiver") is True
        assert rule.matches(tx_other, "receiver") is False

    def test_tx_jitter_rule_global_when_no_node_id(self) -> None:
        """TxJitterRule with node_id=None matches all nodes."""
        from lichen.sim.transmission import Transmission

        rule = TxJitterRule(
            jitter_min_us=1000,
            jitter_max_us=5000,
            node_id=None,
        )

        for node_name in ["node-a", "node-b", "node-c"]:
            tx = Transmission(
                source_node_id=node_name,
                payload=b"test",
                tx_power_dbm=14,
                start_time_us=0,
                end_time_us=1000,
            )
            assert rule.matches(tx, "receiver") is True

    def test_chaos_engine_can_hold_tx_jitter_rules(self) -> None:
        """ChaosEngine accepts and stores TxJitterRule."""
        engine = ChaosEngine()

        rule1 = TxJitterRule(jitter_min_us=100, jitter_max_us=500, node_id="node-a")
        rule2 = TxJitterRule(jitter_min_us=200, jitter_max_us=1000, node_id="node-b")

        engine.add_rule(rule1)
        engine.add_rule(rule2)

        rules = engine.get_rules()
        assert len(rules) == 2
        assert rule1 in rules
        assert rule2 in rules

    def test_simulation_can_have_chaos_engine_with_jitter_rules(self) -> None:
        """Simulation accepts chaos engine containing TxJitterRule."""
        engine = ChaosEngine()
        rule = TxJitterRule(
            jitter_min_us=500,
            jitter_max_us=2000,
            node_id="special-node",
        )
        engine.add_rule(rule)

        sim = Simulation(
            "test-chaos-jitter",
            chaos_engine=engine,
            jitter_min_us=100,  # Default jitter
            jitter_max_us=1000,
        )

        assert sim.chaos_engine is engine
        assert rule in sim.chaos_engine.get_rules()

    def test_tx_jitter_rule_can_override_default_per_node(self) -> None:
        """TxJitterRule can specify different jitter ranges for specific nodes.

        This test documents the expected behavior: a TxJitterRule registered
        for a specific node should provide custom jitter values distinct from
        the simulation's default jitter range.

        Note: Full integration requires the simulation's start_transmission()
        to query the chaos engine for applicable TxJitterRules.
        """
        # Simulation with default jitter range
        engine = ChaosEngine()
        sim = Simulation(
            "test-override",
            chaos_engine=engine,
            jitter_min_us=100,
            jitter_max_us=500,
            seed=42,
        )

        # Add a rule that overrides jitter for a specific node
        rule_rng = random.Random(42)
        custom_rule = TxJitterRule(
            jitter_min_us=5000,  # Much higher than default
            jitter_max_us=10000,
            node_id="slow-node",
            rng=rule_rng,
        )
        engine.add_rule(custom_rule)

        # Verify the rule generates values in its custom range
        custom_jitter = custom_rule.get_jitter_us()
        assert 5000 <= custom_jitter <= 10000

        # Verify simulation's default is in the simulation's range
        default_jitter = sim.calculate_tx_jitter()
        assert 100 <= default_jitter <= 500

        # The two ranges are non-overlapping
        assert custom_jitter > default_jitter


class TestEdgeCases:
    """Test edge cases for TX jitter."""

    def test_zero_jitter_range(self) -> None:
        """When min==max, all jitter values are the same."""
        sim = Simulation(
            "test-fixed-jitter",
            jitter_min_us=1000,
            jitter_max_us=1000,
        )

        jitters = [sim.calculate_tx_jitter() for _ in range(10)]
        assert all(j == 1000 for j in jitters)

    def test_node_removed_before_jitter_fires(self) -> None:
        """Removing a node cancels its pending delayed TX event."""
        sim = Simulation(
            "test-remove-node",
            jitter_min_us=10000,  # Long delay
            jitter_max_us=10000,
        )
        sim.add_node("sender", 0.0, 0.0, 0.0)

        # Queue a delayed transmission
        sim.start_transmission("sender", b"test")

        # Verify event is queued
        delayed_before = [
            e for e in sim.event_queue if isinstance(e, TxStartDelayedEvent)
        ]
        assert len(delayed_before) == 1

        # Remove the node
        sim.remove_node("sender")

        # Event should be removed from queue
        delayed_after = [
            e for e in sim.event_queue if isinstance(e, TxStartDelayedEvent)
        ]
        assert len(delayed_after) == 0

    def test_node_disconnected_before_jitter_fires(self) -> None:
        """Disconnecting a node before jitter delay fires should not crash.

        The delayed event should be silently ignored when processed.
        """
        sim = Simulation(
            "test-disconnect",
            jitter_min_us=1000,
            jitter_max_us=1000,
        )
        node = sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 50.0, 0.0, 0.0)

        # Queue a delayed transmission
        sim.start_transmission("sender", b"test")

        # Disconnect the node (but don't remove it)
        node.disconnect()

        # Advance time to process the delayed event - should not crash
        sim.advance_to(2000)

        # Receiver should not have received anything (node was disconnected)
        sim.start_receive("receiver", timeout_ms=100)
        result = sim.get_rx_result("receiver")
        assert result is None

    def test_large_jitter_value(self) -> None:
        """Jitter can be set to large values (simulating high-latency scenarios)."""
        sim = Simulation(
            "test-large-jitter",
            jitter_min_us=1_000_000,  # 1 second
            jitter_max_us=5_000_000,  # 5 seconds
        )
        sim.add_node("sender", 0.0, 0.0, 0.0)

        sim.start_transmission("sender", b"test")

        delayed_events = [
            e for e in sim.event_queue if isinstance(e, TxStartDelayedEvent)
        ]
        assert len(delayed_events) == 1

        event = delayed_events[0]
        assert 1_000_000 <= event.time_us <= 5_000_000
