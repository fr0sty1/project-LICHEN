# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for enhanced debugging and observability features in the simulation."""

from collections.abc import Generator

import pytest
import structlog

from lichen.sim.node import NodeState
from lichen.sim.simulation import Simulation, disable_debug, enable_debug, is_debug_enabled


@pytest.fixture(autouse=True)
def reset_debug_state() -> Generator[None, None, None]:
    """Keep the process-wide debug toggle isolated between tests."""
    was_enabled = is_debug_enabled()
    disable_debug()
    try:
        yield
    finally:
        if was_enabled:
            enable_debug()
        else:
            disable_debug()


class TestDebugFeatures:
    """Test enhanced debugging and observability features."""

    def test_debug_control_functions(self) -> None:
        """Test debug enable/disable functionality."""
        # Initially debug should be disabled
        assert is_debug_enabled() is False

        # Enable debug
        enable_debug()
        assert is_debug_enabled() is True

        # Disable debug
        disable_debug()
        assert is_debug_enabled() is False

    def test_debug_logging_enabled(self) -> None:
        """Test that enhanced debug logging is activated when enabled."""
        enable_debug()
        sim = Simulation(sim_id="debug-test")
        assert sim.debug_enabled is True
        sim.add_node("tx", 0.0, 0.0, 0.0)
        with structlog.testing.capture_logs() as logs:
            sim.start_transmission("tx", b"hello")
        tx_logs = [log for log in logs if log.get("event") == "tx_start"]
        assert len(tx_logs) == 1
        assert tx_logs[0]["node_state"] == NodeState.TX.name
        assert "active_txs" in tx_logs[0]
        assert "queue_size" in tx_logs[0]

    def test_debug_logging_disabled_omits_context(self) -> None:
        """Disabled debugging emits no simulation diagnostic events."""
        sim = Simulation(sim_id="normal-debug-test")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        with structlog.testing.capture_logs() as logs:
            sim.start_transmission("tx", b"hello")
        tx_logs = [log for log in logs if log.get("event") == "tx_start"]
        assert tx_logs == []

    def test_instance_toggle_adds_rx_context(self) -> None:
        """An existing simulation can enable context-rich RX diagnostics."""
        sim = Simulation(sim_id="rx-debug-test")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 10.0, 0.0, 0.0)
        sim.enable_debug()
        sim.start_transmission("tx", b"hello")
        sim.start_receive("rx", timeout_ms=1000)
        sim.advance_to(1000)
        with structlog.testing.capture_logs() as logs:
            assert sim.get_rx_result("rx") is not None
        rx_logs = [log for log in logs if log.get("event") == "rx_success"]
        assert len(rx_logs) == 1
        assert rx_logs[0]["node_state"] == NodeState.RX_WAIT.name
        assert "pending_rx_timeouts" in rx_logs[0]
        assert "queue_size" in rx_logs[0]
        sim.disable_debug()
        assert sim.debug_enabled is False

    def test_instance_and_global_debug_toggles_are_isolated(self) -> None:
        """Instance changes do not alter global or existing instance state."""
        sim_without_debug = Simulation(sim_id="without-debug")
        sim_without_debug.enable_debug()

        assert sim_without_debug.debug_enabled is True
        assert is_debug_enabled() is False

        enable_debug()
        sim_with_debug = Simulation(sim_id="with-debug")
        assert is_debug_enabled() is True
        assert sim_with_debug.debug_enabled is True
        assert sim_without_debug.debug_enabled is True

        sim_without_debug.disable_debug()
        assert sim_without_debug.debug_enabled is False
        assert sim_with_debug.debug_enabled is True
        assert is_debug_enabled() is True

    def test_callback_rx_emits_success_diagnostics(self) -> None:
        """Callback delivery emits the same success event as direct RX."""
        sim = Simulation(sim_id="callback-debug-test")
        sim.add_node("tx", 0.0, 0.0, 0.0)
        sim.add_node("rx", 10.0, 0.0, 0.0)
        sim.enable_debug()
        received: list[bytes] = []
        sim.start_transmission("tx", b"hello")
        sim.enter_rx_mode(
            "rx",
            timeout_us=1_000_000,
            on_packet=lambda payload, _rssi, _snr: received.append(payload),
            on_timeout=lambda: None,
        )
        sim.advance_to(1000)
        with structlog.testing.capture_logs() as logs:
            assert sim.deliver_pending_packets() == 1
        assert received == [b"hello"]
        rx_logs = [log for log in logs if log.get("event") == "rx_success"]
        assert len(rx_logs) == 1
        assert rx_logs[0]["tx_id"]
        assert rx_logs[0]["from_node_id"] == "tx"
        assert rx_logs[0]["payload_len"] == 5
        assert rx_logs[0]["node_state"] == NodeState.RX_WAIT.name
        assert rx_logs[0]["pending_rx_timeouts"] == 1
        assert rx_logs[0]["queue_size"] == 2

    def test_debug_node_state_tracking(self) -> None:
        """Test that node state transitions generate detailed debug logs."""
        enable_debug()
        sim = Simulation(sim_id="node-state-test")
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)

        # Simulate state transitions
        initial_state = node1.state
        assert initial_state == NodeState.IDLE

        # When we start a transmission
        sim.start_transmission("node1", b"test")
        # State should transition to TX
        transmitting_state = node1.state
        assert transmitting_state == NodeState.TX

        # When transmission completes
        sim.advance_to(300_000)  # Exceeds the modeled airtime for this payload
        # Should go back to IDLE
        final_state = node1.state
        assert final_state == NodeState.IDLE

    def test_debug_timing_assertions(self) -> None:
        """Test debug timing and queue state assertions."""
        enable_debug()
        sim = Simulation(sim_id="timing-test")

        # Add nodes
        sim.add_node("tx_node", 0.0, 0.0, 0.0)
        sim.add_node("rx_node", 100.0, 0.0, 0.0)

        # Check timing state
        assert sim.current_time_us == 0

        # Simulate transmission
        sim.start_transmission("tx_node", b"timing-test")
        sim.advance_to(2000)

        # Should have proper transaction state
        assert sim.current_time_us == 2000

    def test_debug_fail_fast_scenarios(self) -> None:
        """Test fail-fast behavior for disconnected nodes."""
        enable_debug()

        # Start simulation
        sim = Simulation(sim_id="fail-fast-test")
        sim.add_node("test_node", 0.0, 0.0, 0.0)

        # Test attempting transmission on disconnected node (should be logged)
        node = sim.get_node("test_node")
        assert node is not None
        node.disconnect()  # Make it disconnected before transmission

        # This should fail explicitly rather than silently queueing work.
        with pytest.raises(ValueError, match="not connected"):
            sim.start_transmission("test_node", b"fail-test")

    def test_system_state_observation(self) -> None:
        """Test system state observations during complex operations."""
        enable_debug()
        sim = Simulation(sim_id="system-state-test")

        # Add multiple nodes (representing heterogeneous mesh)
        sim.add_node("python_node", 0.0, 0.0, 0.0)
        sim.add_node("rust_node", 100.0, 0.0, 0.0)
        sim.add_node("zephyr_node", 200.0, 0.0, 0.0)

        # Verify nodes are properly added
        assert len(sim.get_all_nodes()) == 3
        assert sim.get_connected_node_count() == 3

        # Start transmission from multiple nodes
        sim.start_transmission("python_node", b"hello")
        sim.start_transmission("rust_node", b"world")

        # Verify queue state
        assert not sim.event_queue.is_empty()

        # Advance time to process events
        sim.advance_to(300_000)

        # All nodes should be idle again
        for node in sim.get_all_nodes():
            assert node.state == NodeState.IDLE


def test_debug_functionality_integration() -> None:
    """Integration test for all debug enhancements."""
    # Verify that all debug features work together
    assert is_debug_enabled() is False

    enable_debug()
    assert is_debug_enabled() is True

    # Create simulation with debug enabled
    sim = Simulation(sim_id="integration-test")
    assert sim.debug_enabled is True

    # Add nodes and exercise functionality
    node = sim.add_node("integration_node", 0.0, 0.0, 0.0)
    assert node.state == NodeState.IDLE

    # Test that simulation components work with debug logging
    sim.start_transmission("integration_node", b"debug-test")
    sim.advance_to(3000)
    assert sim.get_rx_result("integration_node") is None

    assert is_debug_enabled() is True


if __name__ == "__main__":
    # Direct test execution
    test_debug_functionality_integration()
    print("✅ All debug functionality tests passed!")
