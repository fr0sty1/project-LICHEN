# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration tests for the Simulation class.

Unit tests for specific functionality are in:
- test_nodes.py - node management
- test_events.py - event handling and time advancement
- test_radio.py - transmission and reception
"""

import pytest

from lora_medium import Medium
from lichen.sim.node import NodeState
from lichen.sim.simulation import Simulation, TimeMode


class TestSimulationInit:
    """Test Simulation initialization."""

    def test_init_with_defaults(self) -> None:
        """Simulation initializes with default values."""
        sim = Simulation(sim_id="test-sim")

        assert sim.id == "test-sim"
        assert sim.current_time_us == 0
        assert sim.time_mode == TimeMode.BARRIER_SYNC
        assert isinstance(sim.medium, Medium)
        assert sim.event_queue.is_empty()

    def test_init_with_realtime_mode(self) -> None:
        """Simulation can be initialized with REALTIME mode."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.REALTIME)

        assert sim.time_mode == TimeMode.REALTIME


class TestTransmissionReceiveFlow:
    """Test complete transmission/receive flow."""

    def test_tx_rx_flow_with_barrier_sync(self) -> None:
        """Test complete TX/RX flow using barrier sync.

        Time advances to the next event while any node is waiting to receive;
        an idle node (e.g. one whose timeout already fired) does not block a
        still-waiting receiver. Once no node is waiting, the clock stops.
        """
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)
        node2 = sim.add_node("node2", 100.0, 0.0, 0.0)

        # Both nodes start listening with different timeouts
        sim.start_receive("node1", timeout_ms=100)
        sim.start_receive("node2", timeout_ms=200)
        assert node1.state == NodeState.RX_WAIT
        assert node2.state == NodeState.RX_WAIT

        # First advance processes node1's earlier timeout.
        advanced = sim.maybe_advance_time()
        assert advanced is True
        assert sim.current_time_us == 100 * 1000
        assert node1.state == NodeState.IDLE

        # node2 is still waiting, so the clock advances to its timeout even
        # though node1 is now idle.
        advanced = sim.maybe_advance_time()
        assert advanced is True
        assert sim.current_time_us == 200 * 1000
        assert node2.state == NodeState.IDLE

        # Nothing is waiting now, so the clock stops.
        advanced = sim.maybe_advance_time()
        assert advanced is False

    def test_multiple_transmitters_collision(self) -> None:
        """Test collision when two nodes transmit simultaneously."""
        sim = Simulation(sim_id="test-sim")

        # Three nodes in a line, equidistant
        sim.add_node("tx1", 0.0, 100.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, -100.0, 0.0)

        # Both transmit at same time, same power, same distance to RX
        sim.start_transmission("tx1", b"packet1")
        sim.start_transmission("tx2", b"packet2")

        # Check during transmission
        sim.advance_to(1000)

        result = sim.get_rx_result("rx")

        # Should be collision (equal power, both lost)
        assert result is None

    def test_capture_effect_stronger_wins(self) -> None:
        """Test capture effect where stronger signal wins."""
        sim = Simulation(sim_id="test-sim")

        # TX1 close, TX2 far (10x distance = 26.6dB difference with n=2.7)
        sim.add_node("tx1", 50.0, 0.0, 0.0)
        sim.add_node("rx", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 500.0, 0.0, 0.0)

        payload1 = b"strong signal"
        payload2 = b"weak signal"

        sim.start_transmission("tx1", payload1)
        sim.start_transmission("tx2", payload2)

        # Check during transmission
        sim.advance_to(1000)

        result = sim.get_rx_result("rx")

        # Strong signal should win via capture effect
        assert result is not None
        rx_payload, rssi, snr = result
        assert rx_payload == payload1


class TestChaosEngineIntegration:
    """Tests that chaos rules actually affect simulation results."""

    def test_drop_rule_blocks_reception(self) -> None:
        """DropRule prevents node from receiving packets."""
        from lora_medium import ChaosEngine, DropRule

        chaos = ChaosEngine()
        chaos.add_rule(DropRule(node_id="receiver", direction="rx"))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        # Sender transmits
        sim.start_transmission("sender", b"hello")
        # Advance time into the transmission (not past it)
        sim.advance_to(1000)

        # Receiver should NOT get the packet due to drop rule
        result = sim.get_rx_result("receiver")
        assert result is None

    def test_drop_rule_blocks_transmission(self) -> None:
        """DropRule on sender prevents receiver from getting packet."""
        from lora_medium import ChaosEngine, DropRule

        chaos = ChaosEngine()
        chaos.add_rule(DropRule(node_id="sender", direction="tx"))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        sim.start_transmission("sender", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("receiver")
        assert result is None

    def test_no_chaos_engine_allows_reception(self) -> None:
        """Without chaos engine, reception works normally."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        sim.start_transmission("sender", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("receiver")
        assert result is not None
        assert result[0] == b"hello"

    def test_partition_rule_blocks_cross_partition(self) -> None:
        """PartitionRule blocks communication between partitions."""
        from lora_medium import ChaosEngine, PartitionRule

        chaos = ChaosEngine()
        chaos.add_rule(PartitionRule(groups=[{"node-a"}, {"node-b"}]))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("node-a", 0.0, 0.0, 0.0)
        sim.add_node("node-b", 100.0, 0.0, 0.0)

        sim.start_transmission("node-a", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("node-b")
        assert result is None

    def test_degrade_rule_reduces_rssi(self) -> None:
        """DegradeRule reduces received signal strength."""
        from lora_medium import ChaosEngine, DegradeRule

        # First get baseline RSSI without degradation
        sim_baseline = Simulation(sim_id="baseline")
        sim_baseline.add_node("sender", 0.0, 0.0, 0.0)
        sim_baseline.add_node("receiver", 100.0, 0.0, 0.0)
        sim_baseline.start_transmission("sender", b"test")
        sim_baseline.advance_to(1000)
        baseline_result = sim_baseline.get_rx_result("receiver")
        assert baseline_result is not None
        baseline_rssi = baseline_result[1]

        # Now with degradation
        chaos = ChaosEngine()
        chaos.add_rule(DegradeRule(node_id="receiver", rssi_penalty_db=20.0))

        sim_degraded = Simulation(sim_id="degraded", chaos_engine=chaos)
        sim_degraded.add_node("sender", 0.0, 0.0, 0.0)
        sim_degraded.add_node("receiver", 100.0, 0.0, 0.0)
        sim_degraded.start_transmission("sender", b"test")
        sim_degraded.advance_to(1000)
        degraded_result = sim_degraded.get_rx_result("receiver")
        assert degraded_result is not None
        degraded_rssi = degraded_result[1]

        # Degraded RSSI should be ~20 dB lower
        assert baseline_rssi - degraded_rssi >= 19  # Allow 1 dB tolerance

    def test_jammer_blocks_nearby_receivers(self) -> None:
        """JammerRule blocks reception for nodes within radius."""
        from lora_medium import ChaosEngine, JammerRule

        chaos = ChaosEngine()
        # Jammer at (50, 0, 0) with 100m radius - receiver at (100, 0, 0) is 50m away
        chaos.add_rule(JammerRule(x=50.0, y=0.0, z=0.0, radius_m=100.0))

        sim = Simulation(sim_id="test-sim", chaos_engine=chaos)
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        sim.start_transmission("sender", b"hello")
        sim.advance_to(1000)

        result = sim.get_rx_result("receiver")
        assert result is None

    def test_chaos_engine_setter(self) -> None:
        """Chaos engine can be set after construction."""
        from lora_medium import ChaosEngine, DropRule

        sim = Simulation(sim_id="test-sim")
        assert sim.chaos_engine is None

        chaos = ChaosEngine()
        chaos.add_rule(DropRule(node_id="node", direction="both"))
        sim.chaos_engine = chaos

        assert sim.chaos_engine is chaos
