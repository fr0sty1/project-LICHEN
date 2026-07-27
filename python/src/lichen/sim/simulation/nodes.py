# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node management mixin for the simulation.

This module provides the NodeManagementMixin class that adds node CRUD
operations to the simulation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from lichen.sim.node import SimNode


class NodeManagementMixin:
    """Mixin providing node management operations.

    This mixin adds methods for adding, removing, and querying nodes.
    It requires the base class to have:
    - _id: str
    - _nodes: dict[str, SimNode]
    - _gateways: dict[str, dict[str, Any]]
    - _pending_rx_timeouts: dict[str, int]
    - _active_transmissions: dict[str, str]
    - _event_queue: EventQueue
    - _observers: ObserverRegistry
    """

    # Type hints for attributes from base class
    _id: str
    _nodes: dict[str, Any]
    _gateways: dict[str, dict[str, Any]]
    _pending_rx_timeouts: dict[str, int]
    _active_transmissions: dict[str, str]

    def add_node(self, node_id: str, x: float, y: float, z: float) -> SimNode:
        """Create and add a new node to the simulation.

        Args:
            node_id: Unique identifier for the node.
            x: X coordinate in meters.
            y: Y coordinate in meters.
            z: Z coordinate in meters (altitude).

        Returns:
            The newly created SimNode.

        Raises:
            ValueError: If a node with this ID already exists.
        """
        from lichen.sim.node import SimNode

        if node_id in self._nodes:
            raise ValueError(f"Node '{node_id}' already exists")

        node = SimNode(id=node_id, position=(x, y, z), connected=True)
        self._nodes[node_id] = node

        # Notify observers (after node is fully added)
        self._observers.notify(  # type: ignore[attr-defined]
            "on_node_added",
            sim_id=self._id,
            node_id=node_id,
            x=x,
            y=y,
            z=z,
        )

        return node

    def add_gateway(
        self,
        gateway_id: str,
        x: float,
        y: float,
        z: float,
        slot_range: tuple[int, int] = (0, 10),
    ) -> SimNode:
        """Add a gateway node to the simulation.

        Args:
            gateway_id: Unique identifier for the gateway.
            x: X coordinate in meters.
            y: Y coordinate in meters.
            z: Z coordinate in meters (altitude).
            slot_range: TDMA slot range for the gateway.

        Returns:
            The newly created SimNode.

        Raises:
            ValueError: If a node with this ID already exists.
        """
        from lichen.sim.node import SimNode

        if gateway_id in self._nodes:
            raise ValueError(f"Node '{gateway_id}' already exists")

        node = SimNode(id=gateway_id, position=(x, y, z), connected=True)
        self._nodes[gateway_id] = node
        self._gateways[gateway_id] = {
            "node": node,
            "slot_range": slot_range,
            "backbone_id": f"bb-{gateway_id}",
            "owned_nodes": set(),
            "negotiation_state": "idle",
        }
        self._observers.notify(  # type: ignore[attr-defined]
            "on_node_added",
            sim_id=self._id,
            node_id=gateway_id,
            x=x,
            y=y,
            z=z,
        )
        return node

    def remove_node(self, node_id: str) -> None:
        """Remove a node from the simulation.

        Disconnects the node, removes pending events, and removes it from
        the simulation. Silently ignores if node doesn't exist.

        Args:
            node_id: ID of the node to remove.
        """
        node = self._nodes.pop(node_id, None)
        if node is None:
            return

        node.disconnect()
        self._pending_rx_timeouts.pop(node_id, None)
        self._active_transmissions.pop(node_id, None)
        self._event_queue.remove_events_for_node(node_id)  # type: ignore[attr-defined]

        # Notify observers (after cleanup complete)
        self._observers.notify(  # type: ignore[attr-defined]
            "on_node_removed",
            sim_id=self._id,
            node_id=node_id,
        )

    def get_node(self, node_id: str) -> SimNode | None:
        """Get a node by ID.

        Args:
            node_id: ID of the node to retrieve.

        Returns:
            The SimNode, or None if not found.
        """
        return self._nodes.get(node_id)

    def get_all_nodes(self) -> list[SimNode]:
        """Return all nodes in the simulation.

        Returns:
            List of all SimNode objects.
        """
        return list(self._nodes.values())

    def update_position(self, node_id: str, x: float, y: float, z: float) -> bool:
        """Update a node's position for mobility simulation.

        Args:
            node_id: ID of the node to move.
            x: New X coordinate in meters.
            y: New Y coordinate in meters.
            z: New Z coordinate in meters (altitude).

        Returns:
            True if node was found and moved, False if not found.
        """
        node = self._nodes.get(node_id)
        if node is None:
            return False
        node.set_position(x, y, z)
        self._observers.notify(  # type: ignore[attr-defined]
            "on_node_moved",
            sim_id=self._id,
            node_id=node_id,
            x=x,
            y=y,
            z=z,
        )
        return True
