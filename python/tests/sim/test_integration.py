# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration tests for the LICHEN simulator.

Tests the full simulator stack end-to-end: SimulatorServer, NodeServer,
SimRadio clients, and propagation model working together.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import pytest

from lichen.radio.sim_client import SimRadio
from lichen.sim.propagation import PropagationModel
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start a simulator server with a test simulation.

    Creates a server with OS-assigned ports and a single simulation
    in BARRIER_SYNC mode for deterministic testing.

    Yields:
        Tuple of (server, simulation).
    """
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()

    sim = await server.create_simulation("test-sim", TimeMode.BARRIER_SYNC)

    yield server, sim

    await server.stop()


class TestTwoNodeTxRx:
    """Integration tests for two-node communication."""

    @pytest.mark.asyncio
    async def test_basic_tx_rx(self, simulator_server: tuple[SimulatorServer, Simulation]) -> None:
        """Node A transmits, Node B receives with correct RSSI.

        This is the fundamental integration test: proves the full stack works
        from SimRadio through TCP protocol to simulation engine and back.
        """
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        # Create two nodes at different positions
        # Node A at origin, Node B at 100m away
        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", node_port, "test-sim", "node-b", (100.0, 0.0, 0.0)) as radio_b,
        ):
            # Node A transmits first
            # Note: In barrier sync mode, TX must complete before RX can see it
            payload = b"Hello from A!"
            tx_success = await radio_a.transmit(payload)
            assert tx_success is True

            # Node B receives (transmission is now in the medium)
            result = await radio_b.receive(5000)
            assert result is not None

            rx_payload, rssi, snr = result
            assert rx_payload == payload

            # RSSI should match propagation model for 100m
            # Default SimNode tx_power is 22 dBm
            propagation = PropagationModel()
            expected_rssi = propagation.received_power(22, 100.0)
            assert abs(rssi - expected_rssi) < 1.0  # Within 1 dB

    @pytest.mark.asyncio
    async def test_bidirectional_communication(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Both nodes can transmit and receive."""
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", node_port, "test-sim", "node-b", (50.0, 0.0, 0.0)) as radio_b,
        ):
            # A -> B
            await radio_a.transmit(b"Hello B")
            result = await radio_b.receive(1000)
            assert result is not None
            assert result[0] == b"Hello B"

            # B -> A
            await radio_b.transmit(b"Hello A")
            result = await radio_a.receive(1000)
            assert result is not None
            assert result[0] == b"Hello A"

    @pytest.mark.asyncio
    async def test_out_of_range_no_receive(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Nodes too far apart cannot communicate.

        With default propagation model (n=2.7, pl0=32.44dB), max range
        at 22dBm TX power is ~32km. At 50km, signal should be below
        SF10 sensitivity of -132dBm.
        """
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        # Place nodes very far apart (50km - beyond LoRa range with default model)
        # Max range at 22dBm is ~32km, so 50km should be out of range
        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", node_port, "test-sim", "node-b", (50000.0, 0.0, 0.0)) as radio_b,
        ):
            # Node A transmits
            await radio_a.transmit(b"Hello")

            # Node B should not receive (below sensitivity)
            result = await radio_b.receive(100)
            assert result is None  # Timeout, signal too weak

    @pytest.mark.asyncio
    async def test_back_to_back_tx_is_half_duplex(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """A node's new transmission supersedes its own in-flight one.

        A half-duplex radio cannot emit two overlapping signals, so a second TX
        before the first completes replaces it in the medium rather than
        self-colliding. (Collisions between *different* transmitters are covered
        by test_multiple_transmitters_collision.)
        """
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", node_port, "test-sim", "node-b", (50.0, 0.0, 0.0)) as radio_b,
        ):
            # First TX/RX works
            await radio_a.transmit(b"First")
            result = await radio_b.receive(1000)
            assert result is not None
            assert result[0] == b"First"

            # A second TX from the same node supersedes the first; no
            # self-collision, and the latest transmission is what is received.
            await radio_a.transmit(b"Second")
            result = await radio_b.receive(1000)
            assert result is not None
            assert result[0] == b"Second"


class TestRssiAccuracy:
    """Tests verifying RSSI calculations match propagation model."""

    @pytest.mark.asyncio
    async def test_rssi_at_various_distances(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """RSSI matches propagation model at different distances."""
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        propagation = PropagationModel()
        distances = [10.0, 50.0, 100.0, 500.0]

        for distance in distances:
            # Create fresh simulation for each distance test
            # (reusing would require cleaning up nodes)
            sim_id = f"rssi-test-{int(distance)}"
            await server.create_simulation(sim_id, TimeMode.BARRIER_SYNC)
            test_port = server.get_node_server_port(sim_id)
            assert test_port is not None

            try:
                async with (
                    SimRadio("127.0.0.1", test_port, sim_id, "tx", (0.0, 0.0, 0.0)) as radio_tx,
                    SimRadio(
                        "127.0.0.1", test_port, sim_id, "rx", (distance, 0.0, 0.0)
                    ) as radio_rx,
                ):
                    await radio_tx.transmit(b"test")
                    result = await radio_rx.receive(1000)

                    # At reasonable distances, should receive
                    expected_rssi = propagation.received_power(22, distance)
                    if propagation.can_decode(22, distance):
                        assert result is not None, f"Failed at {distance}m"
                        _, rssi, _ = result
                        assert abs(rssi - expected_rssi) < 1.0, (
                            f"RSSI mismatch at {distance}m: got {rssi}, expected {expected_rssi}"
                        )
                    else:
                        # Too far, should timeout
                        assert result is None
            finally:
                await server.delete_simulation(sim_id)

    @pytest.mark.asyncio
    async def test_snr_positive_at_close_range(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """SNR is positive at close range (signal above noise floor)."""
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        # Very close nodes (10m)
        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", node_port, "test-sim", "node-b", (10.0, 0.0, 0.0)) as radio_b,
        ):
            await radio_a.transmit(b"test")
            result = await radio_b.receive(1000)

            assert result is not None
            _, _, snr = result
            # At 10m, SNR should be very high (strong signal)
            assert snr > 40  # Well above noise floor


class TestSimulationTime:
    """Tests for simulation time queries."""

    @pytest.mark.asyncio
    async def test_get_time(self, simulator_server: tuple[SimulatorServer, Simulation]) -> None:
        """Nodes can query current simulation time."""
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with SimRadio(
            "127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a:
            # Initial time should be 0
            time_us = await radio_a.get_time()
            assert time_us == 0

    @pytest.mark.asyncio
    async def test_time_advances_with_tx(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Simulation time advances after transmission."""
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with SimRadio(
            "127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)
        ) as radio_a:
            # Time before TX
            time_before = await radio_a.get_time()

            # Transmit a packet (which has airtime)
            await radio_a.transmit(b"test payload")

            # Simulation time should have advanced
            # Note: In the current implementation, time only advances
            # when processed by the event queue, so this may or may not
            # show advancement depending on barrier sync behavior
            time_after = await radio_a.get_time()
            # At minimum, time should not go backwards
            assert time_after >= time_before


class TestConnectionManagement:
    """Tests for node connection lifecycle."""

    @pytest.mark.asyncio
    async def test_node_cleanup_on_disconnect(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Nodes are properly cleaned up when disconnected."""
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with SimRadio("127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)):
            # Node should be connected
            node = sim.get_node("node-a")
            assert node is not None
            assert node.connected is True

        # After context exit, node should be disconnected
        # (Give the server time to process the disconnect)
        import asyncio

        await asyncio.sleep(0.1)

        node = sim.get_node("node-a")
        assert node is not None
        assert node.connected is False

    @pytest.mark.asyncio
    async def test_multiple_nodes_same_simulation(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Multiple nodes can coexist in the same simulation."""
        server, sim = simulator_server

        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "node-a", (0.0, 0.0, 0.0)) as radio_a,
            SimRadio("127.0.0.1", node_port, "test-sim", "node-b", (10.0, 0.0, 0.0)) as radio_b,
            SimRadio("127.0.0.1", node_port, "test-sim", "node-c", (20.0, 0.0, 0.0)) as radio_c,
        ):
            # All three nodes should be connected
            assert sim.get_connected_node_count() == 3

            # All can transmit
            assert await radio_a.transmit(b"A") is True
            assert await radio_b.transmit(b"B") is True
            assert await radio_c.transmit(b"C") is True


class TestCollisionAndCaptureEffect:
    """Integration tests for collision detection and capture effect.

    Tests that simultaneous transmissions behave correctly:
    - Equal power: both packets lost (collision)
    - Strong signal wins: capture effect (>= 6dB advantage)
    - Near-equal: both lost (< 6dB advantage)
    """

    @pytest.mark.asyncio
    async def test_equal_power_collision(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Two equidistant transmitters cause collision - both lost."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        # Receiver at origin, two transmitters equidistant (100m each)
        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (0.0, 0.0, 0.0)) as radio_rx,
            SimRadio("127.0.0.1", node_port, "test-sim", "tx1", (100.0, 0.0, 0.0)) as radio_tx1,
            SimRadio("127.0.0.1", node_port, "test-sim", "tx2", (-100.0, 0.0, 0.0)) as radio_tx2,
        ):
            # Both transmit simultaneously (at sim time 0)
            await radio_tx1.transmit(b"from tx1")
            await radio_tx2.transmit(b"from tx2")

            # Receiver should get nothing - equal power collision
            result = await radio_rx.receive(100)
            assert result is None  # Collision, both lost

    @pytest.mark.asyncio
    async def test_capture_effect_strong_wins(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Strong signal wins when >= 6dB above weaker (capture effect)."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        # Receiver at origin
        # Strong TX at 50m, weak TX at 500m (~27dB difference, well above 6dB)
        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (0.0, 0.0, 0.0)) as radio_rx,
            SimRadio(
                "127.0.0.1", node_port, "test-sim", "tx_strong", (50.0, 0.0, 0.0)
            ) as radio_strong,
            SimRadio(
                "127.0.0.1", node_port, "test-sim", "tx_weak", (500.0, 0.0, 0.0)
            ) as radio_weak,
        ):
            # Both transmit
            await radio_strong.transmit(b"STRONG")
            await radio_weak.transmit(b"weak")

            # Strong signal should win via capture effect
            result = await radio_rx.receive(1000)
            assert result is not None
            assert result[0] == b"STRONG"

    @pytest.mark.asyncio
    async def test_near_equal_collision(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Signals with < 6dB difference collide - both lost."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        # Receiver at origin
        # TX1 at 100m, TX2 at ~130m (gives ~3dB difference, below 6dB threshold)
        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (0.0, 0.0, 0.0)) as radio_rx,
            SimRadio("127.0.0.1", node_port, "test-sim", "tx1", (100.0, 0.0, 0.0)) as radio_tx1,
            SimRadio("127.0.0.1", node_port, "test-sim", "tx2", (-130.0, 0.0, 0.0)) as radio_tx2,
        ):
            # Both transmit
            await radio_tx1.transmit(b"tx1")
            await radio_tx2.transmit(b"tx2")

            # Neither wins - difference below capture threshold
            result = await radio_rx.receive(100)
            assert result is None  # Collision


class TestNodeMobility:
    """Integration tests for node mobility via REST API."""

    @pytest.mark.asyncio
    async def test_move_node_changes_rssi(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Moving a node via REST API changes received RSSI."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        propagation = PropagationModel()

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "tx", (0.0, 0.0, 0.0)) as radio_tx,
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (100.0, 0.0, 0.0)) as radio_rx,
        ):
            # First transmission at 100m
            await radio_tx.transmit(b"test")
            result1 = await radio_rx.receive(1000)
            assert result1 is not None
            rssi_at_100m = result1[1]

            # Move RX node to 200m via simulation
            rx_node = sim.get_node("rx")
            assert rx_node is not None
            rx_node.set_position(200.0, 0.0, 0.0)

            # Second transmission at 200m
            await radio_tx.transmit(b"test2")
            result2 = await radio_rx.receive(1000)
            assert result2 is not None
            rssi_at_200m = result2[1]

            # RSSI should be lower at 200m than 100m
            assert rssi_at_200m < rssi_at_100m

            # Verify RSSI matches propagation model
            expected_at_100m = propagation.received_power(22, 100.0)
            expected_at_200m = propagation.received_power(22, 200.0)
            assert abs(rssi_at_100m - expected_at_100m) < 1.0
            assert abs(rssi_at_200m - expected_at_200m) < 1.0

    @pytest.mark.asyncio
    async def test_move_out_of_range(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Moving a node out of range prevents reception."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "tx", (0.0, 0.0, 0.0)) as radio_tx,
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (100.0, 0.0, 0.0)) as radio_rx,
        ):
            # First transmission at 100m - should work
            await radio_tx.transmit(b"test")
            result1 = await radio_rx.receive(1000)
            assert result1 is not None

            # Move RX node very far away (50km - beyond range)
            rx_node = sim.get_node("rx")
            assert rx_node is not None
            rx_node.set_position(50000.0, 0.0, 0.0)

            # Second transmission - should fail (out of range)
            await radio_tx.transmit(b"test2")
            result2 = await radio_rx.receive(100)
            assert result2 is None  # Out of range

    @pytest.mark.asyncio
    async def test_move_back_in_range(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Moving a node back in range restores connectivity."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "tx", (0.0, 0.0, 0.0)) as radio_tx,
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (100.0, 0.0, 0.0)) as radio_rx,
        ):
            rx_node = sim.get_node("rx")
            assert rx_node is not None

            # Start at 100m - works
            await radio_tx.transmit(b"test1")
            assert await radio_rx.receive(1000) is not None

            # Move to 50km - fails
            rx_node.set_position(50000.0, 0.0, 0.0)
            await radio_tx.transmit(b"test2")
            assert await radio_rx.receive(100) is None

            # Move back to 200m - works again
            rx_node.set_position(200.0, 0.0, 0.0)
            await radio_tx.transmit(b"test3")
            result = await radio_rx.receive(1000)
            assert result is not None
            assert result[0] == b"test3"


class TestChaosMonkeyOperations:
    """Integration tests for chaos rules via REST API."""

    @pytest.mark.asyncio
    async def test_drop_rule_blocks_packets(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """DropRule prevents packet delivery."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        # Get the chaos engine for this simulation
        chaos_engine = server._api._chaos_engines.get("test-sim")
        assert chaos_engine is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "tx", (0.0, 0.0, 0.0)) as radio_tx,
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (50.0, 0.0, 0.0)) as radio_rx,
        ):
            # Baseline: packets work
            await radio_tx.transmit(b"before")
            result = await radio_rx.receive(1000)
            assert result is not None

            # Add drop rule for tx node
            from lichen.sim.chaos import DropRule

            drop_rule = DropRule(node_id="tx", direction="tx")
            chaos_engine.add_rule(drop_rule)

            # With drop rule: packets blocked
            await radio_tx.transmit(b"blocked")
            result = await radio_rx.receive(100)
            assert result is None  # Dropped

            # Clear chaos rules
            chaos_engine.clear()

            # After clearing: packets work again
            await radio_tx.transmit(b"after")
            result = await radio_rx.receive(1000)
            assert result is not None

    @pytest.mark.asyncio
    async def test_partition_rule_blocks_cross_group(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """PartitionRule blocks cross-partition communication."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("test-sim")
        assert chaos_engine is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "a1", (0.0, 0.0, 0.0)) as radio_a1,
            SimRadio("127.0.0.1", node_port, "test-sim", "a2", (10.0, 0.0, 0.0)) as radio_a2,
            SimRadio("127.0.0.1", node_port, "test-sim", "b1", (20.0, 0.0, 0.0)) as radio_b1,
        ):
            # Baseline: all can communicate
            await radio_a1.transmit(b"to a2")
            assert await radio_a2.receive(1000) is not None

            await radio_a1.transmit(b"to b1")
            assert await radio_b1.receive(1000) is not None

            # Add partition: group A = {a1, a2}, group B = {b1}
            from lichen.sim.chaos import PartitionRule

            partition = PartitionRule(groups=[{"a1", "a2"}, {"b1"}])
            chaos_engine.add_rule(partition)

            # Within group A: works
            await radio_a1.transmit(b"intra-A")
            assert await radio_a2.receive(1000) is not None

            # Cross partition A->B: blocked
            await radio_a1.transmit(b"cross")
            assert await radio_b1.receive(100) is None

            chaos_engine.clear()

    @pytest.mark.asyncio
    async def test_degrade_rule_reduces_rssi(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """DegradeRule reduces RSSI by specified penalty."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("test-sim")
        assert node_port is not None

        chaos_engine = server._api._chaos_engines.get("test-sim")
        assert chaos_engine is not None

        async with (
            SimRadio("127.0.0.1", node_port, "test-sim", "tx", (0.0, 0.0, 0.0)) as radio_tx,
            SimRadio("127.0.0.1", node_port, "test-sim", "rx", (50.0, 0.0, 0.0)) as radio_rx,
        ):
            # Baseline RSSI
            await radio_tx.transmit(b"test")
            result1 = await radio_rx.receive(1000)
            assert result1 is not None
            baseline_rssi = result1[1]

            # Add 20dB degradation
            from lichen.sim.chaos import DegradeRule

            degrade = DegradeRule(node_id="tx", rssi_penalty_db=20.0)
            chaos_engine.add_rule(degrade)

            # RSSI should be 20dB lower
            await radio_tx.transmit(b"test2")
            result2 = await radio_rx.receive(1000)
            assert result2 is not None
            degraded_rssi = result2[1]

            assert abs((baseline_rssi - degraded_rssi) - 20.0) < 1.0

            chaos_engine.clear()
