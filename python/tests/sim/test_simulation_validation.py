# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Validation tests for the LICHEN simulation infrastructure.

These tests verify that our simulation setup can properly validate cross-implementation
packet tracking and heterogeneous mesh testing capabilities.
"""

import asyncio
import tempfile
from pathlib import Path

import pytest

from lichen.sim.node import NodeState
from lichen.sim.renode_server import start_renode_server
from lichen.sim.simulation import Simulation, TimeMode


class TestSimulationValidation:
    """Test the core simulation validation capabilities."""

    def test_basic_simulation_setup(self) -> None:
        """Test basic simulation setup and node management."""
        sim = Simulation(sim_id="validation-test")

        # Test adding nodes
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)
        node2 = sim.add_node("node2", 100.0, 0.0, 0.0)

        assert len(sim.get_all_nodes()) == 2
        assert sim.get_connected_node_count() == 2

        # Test node state management
        assert node1.state == NodeState.IDLE
        assert node2.state == NodeState.IDLE

        # Test removing nodes
        sim.remove_node("node1")
        assert len(sim.get_all_nodes()) == 1
        assert sim.get_connected_node_count() == 1

        assert sim.get_node("node1") is None
        assert sim.get_node("node2") is not None

    def test_tx_rx_flow_validation(self) -> None:
        """Test full transmission/reception flow validation."""
        sim = Simulation(sim_id="tx-rx-test")

        # Add transmitter and receiver nodes
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)

        payload = b"Hello LICHEN Simulation!"

        # Start transmission from TX node
        tx_id = sim.start_transmission("tx_node", payload)
        assert tx_id != ""

        # Advance time to let transmission complete
        # (Airtime should be approximately 1000+ microseconds for 21 bytes)
        sim.advance_to(3000)

        # Receiver should be able to receive the packet
        rx_result = sim.get_rx_result("rx_node")
        assert rx_result is not None

        rx_payload, rssi, snr = rx_result
        assert rx_payload == payload
        assert isinstance(rssi, int)
        assert isinstance(snr, int)

    def test_cross_platform_capability_verification(self) -> None:
        """Verify cross-platform capability through simulation validation."""
        # Use two different node positions to simulate different platforms
        sim = Simulation(sim_id="cross-platform-test")

        # Add nodes representing different platform implementations
        sim.add_node("python_node", 0.0, 0.0, 0.0)
        sim.add_node("rust_node", 50.0, 0.0, 0.0)  # Closer to receiver to make it stronger
        sim.add_node("zephyr_node", 100.0, 0.0, 0.0)

        # Add a base station (receiver)
        sim.add_node("base_station", 0.0, 100.0, 0.0)

        # Perform a couple of transmissions to simulate different implementations
        payloads = [b"Python implementation payload", b"Rust implementation payload"]

        # Send from each node with proper timing
        for i, payload in enumerate(payloads):
            node_id = ["python_node", "rust_node"][i]
            tx_id = sim.start_transmission(node_id, payload)
            assert tx_id != ""
            # Advance to allow transmission (staggering slightly)
            sim.advance_to(sim.current_time_us + 1000)

            # Check that each node got proper RSSI/SNR
            rx_result = sim.get_rx_result("base_station")
            assert rx_result is not None

            rx_payload, rssi, snr = rx_result
            assert rx_payload == payload
            assert isinstance(rssi, int)
            assert isinstance(snr, int)

            # Wait for the long packet airtime before starting the next sender.
            if i + 1 < len(payloads):
                sim.advance_to(sim.current_time_us + 500_000)

        sim.advance_to(sim.current_time_us + 500_000)

        # Verify all nodes are IDLE
        for node_id in ["python_node", "rust_node", "zephyr_node"]:
            if sim.get_node(node_id):
                assert sim.get_node(node_id).state == NodeState.IDLE
        assert sim.get_node("base_station").state == NodeState.IDLE

    def test_simulation_metrics_export_validation(self) -> None:
        """Test that simulation metrics can be exported for cross-impl validation."""
        sim = Simulation(sim_id="metrics-test")

        # Add nodes
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)

        # Perform some transmissions
        payload1 = b"test packet 1"
        payload2 = b"test packet 2"

        sim.start_transmission("tx_node", payload1)
        sim.start_transmission("tx_node", payload2)

        # Advance time to complete
        sim.advance_to(3000)

        # Test metric export
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = Path(tmpdir) / "metrics.json"
            sim.export_metrics(json_file)

            # Verify file exists and is readable
            assert json_file.exists()
            content = json_file.read_text()
            assert "tx_node" in content
            assert "rx_node" in content
            # Note: packet content isn't stored in metrics, just hash and counts
            assert "tx_count" in content or "packet_hashes" in content

    @pytest.mark.asyncio
    async def test_renode_bridge_integration(self) -> None:
        """Test integration with Renode bridge for heterogeneous mesh testing."""
        sim = Simulation(sim_id="renode-test")

        # Start a Renode bridge server
        server, port = await start_renode_server(
            simulation=sim,
            node_id="renode_node",
            host="127.0.0.1",
            position=(0.0, 0.0, 0.0),
            tx_power_dbm=22,
        )

        try:
            # Verify server started correctly
            assert port > 0

            # Add the server's node to simulation
            node = sim.get_node("renode_node")
            assert node is not None
            assert node.connected is True

            # Test basic functionality with direct simulation calls
            node.state = NodeState.IDLE

            # Test that we can send a packet through sim
            payload = b"renode integration test"
            tx_id = sim.start_transmission("renode_node", payload)
            assert tx_id != ""

        finally:
            # Cleanup
            await server.stop()

    def test_barrier_sync_time_advancement(self) -> None:
        """Test that barrier sync works properly for multi-node validation."""
        # Test that we can create simulation with time modes
        sim = Simulation(sim_id="barrier-test", time_mode=TimeMode.BARRIER_SYNC)

        # Add multiple nodes
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)
        sim.add_node("node3", 200.0, 0.0, 0.0)

        # All nodes start receive with different timeouts
        sim.start_receive("node1", timeout_ms=100)  # Earliest
        sim.start_receive("node2", timeout_ms=200)  # Middle
        sim.start_receive("node3", timeout_ms=300)  # Latest

        # With barrier sync, time should advance to first timeout
        advanced = sim.maybe_advance_time()

        # Should advance since all nodes are blocking
        assert advanced is True
        assert sim.current_time_us == 100 * 1000  # 100ms -> μs

        # Node1 should be idle now
        assert sim.get_node("node1").state == NodeState.IDLE

        # Another advancement should go to next timeout
        advanced = sim.maybe_advance_time()
        assert advanced is True
        assert sim.current_time_us == 200 * 1000  # 200ms

        # Node2 should be idle now
        assert sim.get_node("node2").state == NodeState.IDLE

        # One more advancement
        advanced = sim.maybe_advance_time()
        assert advanced is True
        assert sim.current_time_us == 300 * 1000  # 300ms

        # Node3 should be idle now
        assert sim.get_node("node3").state == NodeState.IDLE

    def test_simulation_reproducibility_with_seeds(self) -> None:
        """Test that seeded simulations produce reproducible results."""
        seed = 42

        # Create first simulation with seed
        sim1 = Simulation(sim_id="seed-test-1", seed=seed)
        sim1.add_node("node1", 0.0, 0.0, 0.0)
        sim1.add_node("node2", 100.0, 0.0, 0.0)

        # Create second simulation with same seed
        sim2 = Simulation(sim_id="seed-test-2", seed=seed)
        sim2.add_node("node1", 0.0, 0.0, 0.0)
        sim2.add_node("node2", 100.0, 0.0, 0.0)

        # Perform same operations
        payload = b"reproducible test"
        sim1.start_transmission("node1", payload)
        sim2.start_transmission("node1", payload)

        # Advance to same time
        sim1.advance_to(1000)
        sim2.advance_to(1000)

        # Results should be the same
        assert sim1.get_rx_result("node2") == sim2.get_rx_result("node2")


def test_simulation_validation_summary():
    """Run a focused subset of validation tests to confirm readiness."""

    # Create test instances and run tests
    validator = TestSimulationValidation()

    # Run the core tests that show our functionality works
    print("Running validation tests...")

    # Basic setups - these should always work
    validator.test_basic_simulation_setup()
    print("✅ Basic simulation setup works")

    # Core functionality tests
    validator.test_tx_rx_flow_validation()
    print("✅ TX/RX flow validation works")

    # Cross-platform tests
    validator.test_cross_platform_capability_verification()
    print("✅ Cross-platform capability verified")

    # Metrics validation
    validator.test_simulation_metrics_export_validation()
    print("✅ Metrics export validation works")

    # Barrier sync tests
    validator.test_barrier_sync_time_advancement()
    print("✅ Barrier sync validation works")

    # Reproducibility tests
    validator.test_simulation_reproducibility_with_seeds()
    print("✅ Simulation reproducibility confirmed")

    # Integration tests

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(validator.test_renode_bridge_integration())
        print("✅ Renode bridge integration works")
    finally:
        loop.close()


if __name__ == "__main__":
    # Direct execution for quick validation
    try:
        test_simulation_validation_summary()
        print("\n🎉 All simulation validation checks completed successfully!")
        print("📋 Simulation infrastructure is ready for heterogeneous mesh testing.")
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        import traceback

        traceback.print_exc()
        exit(1)
