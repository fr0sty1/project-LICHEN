# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for topology generators."""

import math

from lichen.sim.simulation import Simulation
from lichen.sim.topology import apply_topology, grid, line, random_disk, star


class TestGrid:
    def test_grid_4_nodes(self) -> None:
        positions = grid(4, spacing=100)
        assert len(positions) == 4
        # 2x2 grid
        assert positions[0].x == 0 and positions[0].y == 0
        assert positions[1].x == 100 and positions[1].y == 0
        assert positions[2].x == 0 and positions[2].y == 100
        assert positions[3].x == 100 and positions[3].y == 100

    def test_grid_9_nodes(self) -> None:
        positions = grid(9, spacing=50)
        assert len(positions) == 9
        # 3x3 grid
        assert positions[8].x == 100 and positions[8].y == 100

    def test_grid_custom_prefix(self) -> None:
        positions = grid(4, prefix="sensor-")
        assert positions[0].node_id == "sensor-0"
        assert positions[3].node_id == "sensor-3"


class TestLine:
    def test_line_basic(self) -> None:
        positions = line(5, spacing=100)
        assert len(positions) == 5
        for i, pos in enumerate(positions):
            assert pos.x == i * 100
            assert pos.y == 0

    def test_line_custom_z(self) -> None:
        positions = line(3, z=10.0)
        assert all(pos.z == 10.0 for pos in positions)


class TestRandomDisk:
    def test_random_disk_count(self) -> None:
        positions = random_disk(10, radius=500)
        assert len(positions) == 10

    def test_random_disk_within_radius(self) -> None:
        positions = random_disk(100, radius=500, seed=42)
        for pos in positions:
            dist = math.sqrt(pos.x**2 + pos.y**2)
            assert dist <= 500

    def test_random_disk_reproducible(self) -> None:
        p1 = random_disk(10, seed=123)
        p2 = random_disk(10, seed=123)
        for a, b in zip(p1, p2, strict=True):
            assert a.x == b.x
            assert a.y == b.y


class TestStar:
    def test_star_basic(self) -> None:
        positions = star(4, radius=100)
        assert len(positions) == 5  # 1 gateway + 4 leaves
        assert positions[0].node_id == "gateway"
        assert positions[0].x == 0 and positions[0].y == 0

    def test_star_leaves_on_circle(self) -> None:
        positions = star(4, radius=100)
        for pos in positions[1:]:
            dist = math.sqrt(pos.x**2 + pos.y**2)
            assert abs(dist - 100) < 0.001


class TestApplyTopology:
    def test_apply_grid_topology(self) -> None:
        """Test apply_topology with a grid topology."""
        sim = Simulation(sim_id="test-grid")
        positions = grid(4, spacing=100)
        node_ids = apply_topology(sim, positions)

        # Check returned node IDs
        assert node_ids == ["node-0", "node-1", "node-2", "node-3"]

        # Check all nodes exist in simulation
        assert len(sim.get_all_nodes()) == 4

        # Check each node has correct position
        node0 = sim.get_node("node-0")
        assert node0 is not None
        assert node0.position == (0, 0, 0)

        node1 = sim.get_node("node-1")
        assert node1 is not None
        assert node1.position == (100, 0, 0)

        node2 = sim.get_node("node-2")
        assert node2 is not None
        assert node2.position == (0, 100, 0)

        node3 = sim.get_node("node-3")
        assert node3 is not None
        assert node3.position == (100, 100, 0)

    def test_apply_random_disk_topology(self) -> None:
        """Test apply_topology with a random_disk topology."""
        sim = Simulation(sim_id="test-disk")
        positions = random_disk(10, radius=500, seed=42)
        node_ids = apply_topology(sim, positions)

        # Check returned node IDs
        assert len(node_ids) == 10
        assert node_ids == [f"node-{i}" for i in range(10)]

        # Check all nodes exist in simulation
        assert len(sim.get_all_nodes()) == 10

        # Check nodes are positioned within the disk radius
        for node_id in node_ids:
            node = sim.get_node(node_id)
            assert node is not None
            x, y, z = node.position
            dist = math.sqrt(x**2 + y**2)
            assert dist <= 500

    def test_apply_topology_preserves_z_coordinate(self) -> None:
        """Test that apply_topology preserves z coordinates."""
        sim = Simulation(sim_id="test-z")
        positions = grid(4, spacing=100, z=50.0)
        apply_topology(sim, positions)

        for i in range(4):
            node = sim.get_node(f"node-{i}")
            assert node is not None
            assert node.position[2] == 50.0

    def test_apply_empty_topology(self) -> None:
        """Test apply_topology with empty list."""
        sim = Simulation(sim_id="test-empty")
        node_ids = apply_topology(sim, [])

        assert node_ids == []
        assert len(sim.get_all_nodes()) == 0
