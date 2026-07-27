# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Topology generators for LICHEN simulator.

Generate node positions for common network layouts.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lichen.sim.simulation import Simulation


@dataclass
class NodePosition:
    """A node ID and its 3D position."""

    node_id: str
    x: float
    y: float
    z: float = 0.0


def grid(
    n: int,
    spacing: float = 100.0,
    prefix: str = "node-",
    z: float = 0.0,
) -> list[NodePosition]:
    """Generate a square grid topology.

    Args:
        n: Total number of nodes (will be rounded up to perfect square).
        spacing: Distance between adjacent nodes in meters.
        prefix: Node ID prefix.
        z: Altitude for all nodes.

    Returns:
        List of NodePosition objects.
    """
    side = math.ceil(math.sqrt(n))
    positions = []
    for i in range(n):
        row, col = divmod(i, side)
        positions.append(
            NodePosition(
                node_id=f"{prefix}{i}",
                x=col * spacing,
                y=row * spacing,
                z=z,
            )
        )
    return positions


def line(
    n: int,
    spacing: float = 100.0,
    prefix: str = "node-",
    z: float = 0.0,
) -> list[NodePosition]:
    """Generate a linear chain topology.

    Args:
        n: Number of nodes.
        spacing: Distance between adjacent nodes in meters.
        prefix: Node ID prefix.
        z: Altitude for all nodes.

    Returns:
        List of NodePosition objects.
    """
    return [
        NodePosition(node_id=f"{prefix}{i}", x=i * spacing, y=0.0, z=z)
        for i in range(n)
    ]


def random_disk(
    n: int,
    radius: float = 500.0,
    prefix: str = "node-",
    z: float = 0.0,
    seed: int | None = None,
) -> list[NodePosition]:
    """Generate nodes randomly distributed in a disk.

    Args:
        n: Number of nodes.
        radius: Radius of the disk in meters.
        prefix: Node ID prefix.
        z: Altitude for all nodes.
        seed: Random seed for reproducibility.

    Returns:
        List of NodePosition objects.
    """
    rng = random.Random(seed)
    positions = []
    for i in range(n):
        # Uniform distribution in disk (sqrt for uniform area)
        r = radius * math.sqrt(rng.random())
        theta = rng.random() * 2 * math.pi
        positions.append(
            NodePosition(
                node_id=f"{prefix}{i}",
                x=r * math.cos(theta),
                y=r * math.sin(theta),
                z=z,
            )
        )
    return positions


def star(
    n: int,
    radius: float = 100.0,
    prefix: str = "node-",
    center_id: str = "gateway",
    z: float = 0.0,
) -> list[NodePosition]:
    """Generate a star topology with central gateway.

    Args:
        n: Number of leaf nodes (plus one gateway).
        radius: Distance from gateway to leaf nodes.
        prefix: Node ID prefix for leaf nodes.
        center_id: ID for the central gateway.
        z: Altitude for all nodes.

    Returns:
        List of NodePosition objects (gateway first).
    """
    positions = [NodePosition(node_id=center_id, x=0.0, y=0.0, z=z)]
    for i in range(n):
        theta = (2 * math.pi * i) / n
        positions.append(
            NodePosition(
                node_id=f"{prefix}{i}",
                x=radius * math.cos(theta),
                y=radius * math.sin(theta),
                z=z,
            )
        )
    return positions


def apply_topology(sim: Simulation, positions: list[NodePosition]) -> list[str]:
    """Apply a topology to a simulation by adding nodes.

    Args:
        sim: The simulation instance.
        positions: List of NodePosition objects.

    Returns:
        List of node IDs that were added.
    """
    node_ids = []
    for pos in positions:
        sim.add_node(pos.node_id, pos.x, pos.y, pos.z)
        node_ids.append(pos.node_id)
    return node_ids
