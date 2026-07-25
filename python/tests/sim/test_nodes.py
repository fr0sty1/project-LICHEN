# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for node management in the Simulation class."""

import pytest

from lichen.sim.node import NodeState, SimNode
from lichen.sim.simulation import Simulation


class TestNodeManagement:
    """Test node add/remove/get operations."""

    def test_add_node_creates_node(self) -> None:
        """add_node creates a SimNode with correct parameters."""
        sim = Simulation(sim_id="test-sim")

        node = sim.add_node("node1", x=10.0, y=20.0, z=5.0)

        assert isinstance(node, SimNode)
        assert node.id == "node1"
        assert node.position == (10.0, 20.0, 5.0)
        assert node.connected is True
        assert node.state == NodeState.IDLE

    def test_add_node_returns_same_node(self) -> None:
        """add_node returns the node that was created."""
        sim = Simulation(sim_id="test-sim")

        node = sim.add_node("node1", 0.0, 0.0, 0.0)
        retrieved = sim.get_node("node1")

        assert retrieved is node

    def test_add_duplicate_node_raises(self) -> None:
        """add_node raises ValueError for duplicate node ID."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        with pytest.raises(ValueError, match="already exists"):
            sim.add_node("node1", 1.0, 1.0, 1.0)

    def test_get_node_returns_none_for_missing(self) -> None:
        """get_node returns None for nonexistent node."""
        sim = Simulation(sim_id="test-sim")

        result = sim.get_node("nonexistent")

        assert result is None

    def test_remove_node_removes_from_simulation(self) -> None:
        """remove_node removes node from simulation."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.remove_node("node1")

        assert sim.get_node("node1") is None

    def test_remove_node_disconnects_node(self) -> None:
        """remove_node disconnects the node."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        sim.remove_node("node1")

        assert node.connected is False

    def test_remove_node_purges_events(self) -> None:
        """remove_node removes pending events for that node."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Queue events for both nodes
        sim.start_receive("node1", timeout_ms=1000)
        sim.start_receive("node2", timeout_ms=2000)

        assert len(sim.event_queue) == 2

        # Remove node1 - its events should be purged
        sim.remove_node("node1")

        assert len(sim.event_queue) == 1
        # Remaining event should be for node2
        event = sim.event_queue.peek()
        assert event is not None
        assert event.node_id == "node2"  # type: ignore[union-attr]

    def test_remove_nonexistent_node_is_safe(self) -> None:
        """remove_node with nonexistent ID does not raise."""
        sim = Simulation(sim_id="test-sim")

        sim.remove_node("nonexistent")  # Should not raise

    def test_get_connected_node_count(self) -> None:
        """get_connected_node_count returns correct count."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 1.0, 0.0, 0.0)

        assert sim.get_connected_node_count() == 2

        sim.remove_node("node1")
        assert sim.get_connected_node_count() == 1

    def test_get_all_nodes(self) -> None:
        """get_all_nodes returns all nodes."""
        sim = Simulation(sim_id="test-sim")
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)
        node2 = sim.add_node("node2", 1.0, 0.0, 0.0)

        nodes = sim.get_all_nodes()

        assert len(nodes) == 2
        assert node1 in nodes
        assert node2 in nodes
