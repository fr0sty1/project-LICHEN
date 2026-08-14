# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Hybrid sim-real topology support for LICHEN simulator.

Supports topologies mixing simulated and real (hardware) nodes. When actual RF
measurements are available between node pairs (from prior calibration or live
feedback), uses those measurements instead of modeled propagation.

Usage:
    # Create hybrid model wrapping the standard propagation model
    model = HybridPropagationModel(base_model=PropagationModel())

    # Register real nodes (hardware devices)
    model.register_real_node("hw-0001", position=(45.0, -122.0, 10.0))

    # Store RF measurement from calibration or live feedback
    model.store_measurement("hw-0001", "sim-node-0", RFMeasurement(
        rssi_dbm=-85.0,
        snr_db=12.0,
        distance_m=500.0,
    ))

    # Propagation uses measurement for hw-0001 <-> sim-node-0, model otherwise
    rssi = model.received_power_between("hw-0001", "sim-node-0", tx_power_dbm=14)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING

from lora_medium import SENSITIVITY_SF10, PropagationModel

from lichen.sim.topology import NodePosition

if TYPE_CHECKING:
    pass


class NodeType(Enum):
    """Classification of a node in a hybrid topology."""

    SIMULATED = auto()  # Pure simulation, no hardware
    REAL = auto()       # Hardware device (HIL)
    GATEWAY = auto()    # Gateway bridging sim and real networks


@dataclass
class RFMeasurement:
    """A single RF measurement between two nodes.

    Stores actual measured values from hardware for use in hybrid topologies.
    Can be updated with new measurements to track time-varying channels.

    Attributes:
        rssi_dbm: Received signal strength in dBm.
        snr_db: Signal-to-noise ratio in dB.
        distance_m: Physical distance in meters (if known).
        timestamp: Unix timestamp when measurement was taken (0 = static).
        tx_power_dbm: Transmit power used during measurement.
        measurement_count: Number of samples averaged into this measurement.
        variance_db: Variance of RSSI measurements (if multiple samples).
    """

    rssi_dbm: float
    snr_db: float = 0.0
    distance_m: float | None = None
    timestamp: float = 0.0
    tx_power_dbm: float = 14.0
    measurement_count: int = 1
    variance_db: float = 0.0

    def update(self, new_rssi_dbm: float, new_snr_db: float = 0.0) -> None:
        """Update measurement with a new sample (exponential moving average).

        Args:
            new_rssi_dbm: New RSSI measurement in dBm.
            new_snr_db: New SNR measurement in dB.
        """
        alpha = 0.3  # EMA smoothing factor
        old_rssi = self.rssi_dbm
        self.rssi_dbm = alpha * new_rssi_dbm + (1 - alpha) * self.rssi_dbm
        self.snr_db = alpha * new_snr_db + (1 - alpha) * self.snr_db
        self.timestamp = time.time()
        self.measurement_count += 1
        # Update variance estimate
        delta = new_rssi_dbm - old_rssi
        self.variance_db = (1 - alpha) * (self.variance_db + alpha * delta * delta)


@dataclass
class HybridNode:
    """A node in a hybrid sim-real topology.

    Extends standard NodePosition with node type classification and
    optional hardware metadata.

    Attributes:
        node_id: Unique identifier for the node.
        position: (x, y, z) coordinates in meters.
        node_type: SIMULATED, REAL, or GATEWAY.
        hardware_id: Hardware serial/EUI for real nodes.
        firmware_version: Firmware version string for real nodes.
        last_seen_us: Last communication timestamp in microseconds.
    """

    node_id: str
    position: tuple[float, float, float] = (0.0, 0.0, 0.0)
    node_type: NodeType = NodeType.SIMULATED
    hardware_id: str | None = None
    firmware_version: str | None = None
    last_seen_us: int = 0

    def to_node_position(self) -> NodePosition:
        """Convert to standard NodePosition for topology functions."""
        return NodePosition(
            node_id=self.node_id,
            x=self.position[0],
            y=self.position[1],
            z=self.position[2],
        )


def _make_pair_key(node_a: str, node_b: str) -> tuple[str, str]:
    """Create a canonical key for a node pair (order-independent)."""
    return (min(node_a, node_b), max(node_a, node_b))


@dataclass
class HybridPropagationModel:
    """Propagation model that uses RF measurements for hybrid sim-real pairs.

    For pairs where actual RF measurements are available (e.g., from hardware
    calibration or live feedback), uses those measurements. Falls back to the
    base propagation model for pure-simulation pairs or when no measurement
    exists.

    Attributes:
        base_model: The underlying propagation model for simulated links.
        measurement_max_age_s: Maximum age of measurements before they're
            considered stale and the model falls back (0 = never expire).
        allow_asymmetric: If True, measurements are stored per-direction.
            If False (default), measurements are symmetric (average used).
    """

    base_model: PropagationModel = field(default_factory=PropagationModel)
    measurement_max_age_s: float = 0.0
    allow_asymmetric: bool = False

    _real_nodes: dict[str, HybridNode] = field(default_factory=dict, repr=False)
    _measurements: dict[tuple[str, str], RFMeasurement] = field(
        default_factory=dict, repr=False
    )
    _asymmetric_measurements: dict[tuple[str, str], RFMeasurement] = field(
        default_factory=dict, repr=False
    )

    def register_real_node(
        self,
        node_id: str,
        position: tuple[float, float, float] = (0.0, 0.0, 0.0),
        hardware_id: str | None = None,
        firmware_version: str | None = None,
        node_type: NodeType = NodeType.REAL,
    ) -> HybridNode:
        """Register a real (hardware) node in the hybrid topology.

        Args:
            node_id: Unique identifier for the node.
            position: (x, y, z) coordinates in meters.
            hardware_id: Hardware serial/EUI.
            firmware_version: Firmware version string.
            node_type: Node type (REAL or GATEWAY).

        Returns:
            The created HybridNode.
        """
        node = HybridNode(
            node_id=node_id,
            position=position,
            node_type=node_type,
            hardware_id=hardware_id,
            firmware_version=firmware_version,
        )
        self._real_nodes[node_id] = node
        return node

    def unregister_node(self, node_id: str) -> bool:
        """Remove a node from the hybrid topology.

        Args:
            node_id: ID of the node to remove.

        Returns:
            True if the node was removed, False if not found.
        """
        if node_id in self._real_nodes:
            del self._real_nodes[node_id]
            # Remove associated measurements
            self._measurements = {
                k: v for k, v in self._measurements.items()
                if node_id not in k
            }
            self._asymmetric_measurements = {
                k: v for k, v in self._asymmetric_measurements.items()
                if node_id not in k
            }
            return True
        return False

    def is_real_node(self, node_id: str) -> bool:
        """Check if a node is registered as a real (hardware) node."""
        return node_id in self._real_nodes

    def get_real_nodes(self) -> list[HybridNode]:
        """Get all registered real nodes."""
        return list(self._real_nodes.values())

    def store_measurement(
        self,
        from_node: str,
        to_node: str,
        measurement: RFMeasurement,
    ) -> None:
        """Store an RF measurement between two nodes.

        If allow_asymmetric is True, stores direction-specific measurements.
        Otherwise, averages with any existing measurement for the pair.

        Args:
            from_node: Transmitting node ID.
            to_node: Receiving node ID.
            measurement: The RF measurement data.
        """
        if self.allow_asymmetric:
            self._asymmetric_measurements[(from_node, to_node)] = measurement
        else:
            key = _make_pair_key(from_node, to_node)
            if key in self._measurements:
                # Average with existing measurement
                existing = self._measurements[key]
                existing.update(measurement.rssi_dbm, measurement.snr_db)
            else:
                self._measurements[key] = measurement

    def get_measurement(
        self,
        from_node: str,
        to_node: str,
    ) -> RFMeasurement | None:
        """Get the RF measurement between two nodes, if available.

        Checks for staleness if measurement_max_age_s is set.

        Args:
            from_node: Transmitting node ID.
            to_node: Receiving node ID.

        Returns:
            RFMeasurement if available and fresh, None otherwise.
        """
        measurement = None

        if self.allow_asymmetric:
            measurement = self._asymmetric_measurements.get((from_node, to_node))
        else:
            key = _make_pair_key(from_node, to_node)
            measurement = self._measurements.get(key)

        if measurement is None:
            return None

        # Check staleness
        if self.measurement_max_age_s > 0 and measurement.timestamp > 0:
            age = time.time() - measurement.timestamp
            if age > self.measurement_max_age_s:
                return None

        return measurement

    def clear_measurements(self) -> None:
        """Clear all stored RF measurements."""
        self._measurements.clear()
        self._asymmetric_measurements.clear()

    def received_power_between(
        self,
        from_node: str,
        to_node: str,
        tx_power_dbm: float,
        from_position: tuple[float, float, float] | None = None,
        to_position: tuple[float, float, float] | None = None,
    ) -> float:
        """Calculate received power between two nodes.

        Uses actual RF measurement if available for this pair, otherwise
        falls back to the base propagation model.

        Args:
            from_node: Transmitting node ID.
            to_node: Receiving node ID.
            tx_power_dbm: Transmit power in dBm.
            from_position: Position of transmitter (required for model fallback).
            to_position: Position of receiver (required for model fallback).

        Returns:
            Received power in dBm.
        """
        measurement = self.get_measurement(from_node, to_node)

        if measurement is not None:
            # Adjust for different TX power than measurement
            power_delta = tx_power_dbm - measurement.tx_power_dbm
            return measurement.rssi_dbm + power_delta

        # Fall back to model
        if from_position is None or to_position is None:
            # Try to get positions from registered nodes
            if from_node in self._real_nodes:
                from_position = self._real_nodes[from_node].position
            if to_node in self._real_nodes:
                to_position = self._real_nodes[to_node].position

        if from_position is None or to_position is None:
            raise ValueError(
                f"No measurement and no positions for {from_node} -> {to_node}"
            )

        import math
        distance = math.sqrt(
            (to_position[0] - from_position[0]) ** 2
            + (to_position[1] - from_position[1]) ** 2
            + (to_position[2] - from_position[2]) ** 2
        )
        if distance <= 0:
            distance = 0.001

        return self.base_model.received_power(tx_power_dbm, distance)

    def can_decode_between(
        self,
        from_node: str,
        to_node: str,
        tx_power_dbm: float,
        from_position: tuple[float, float, float] | None = None,
        to_position: tuple[float, float, float] | None = None,
        sensitivity_dbm: float = SENSITIVITY_SF10,
    ) -> bool:
        """Check if a transmission can be decoded.

        Args:
            from_node: Transmitting node ID.
            to_node: Receiving node ID.
            tx_power_dbm: Transmit power in dBm.
            from_position: Position of transmitter.
            to_position: Position of receiver.
            sensitivity_dbm: Receiver sensitivity threshold.

        Returns:
            True if the transmission can be decoded.
        """
        rx_power = self.received_power_between(
            from_node, to_node, tx_power_dbm, from_position, to_position
        )
        return rx_power >= sensitivity_dbm

    def get_link_quality(
        self,
        from_node: str,
        to_node: str,
    ) -> dict[str, float | int | bool] | None:
        """Get link quality metrics for a node pair.

        Returns None if no measurement exists. Otherwise returns metrics
        computed from actual RF measurements.

        Args:
            from_node: Transmitting node ID.
            to_node: Receiving node ID.

        Returns:
            Dict with rssi_dbm, snr_db, variance_db, measurement_count, is_stale
            or None if no measurement.
        """
        measurement = self.get_measurement(from_node, to_node)
        if measurement is None:
            return None

        is_stale = False
        if self.measurement_max_age_s > 0 and measurement.timestamp > 0:
            age = time.time() - measurement.timestamp
            is_stale = age > self.measurement_max_age_s

        return {
            "rssi_dbm": measurement.rssi_dbm,
            "snr_db": measurement.snr_db,
            "variance_db": measurement.variance_db,
            "measurement_count": measurement.measurement_count,
            "is_stale": is_stale,
        }


def create_hybrid_topology(
    simulated_nodes: list[NodePosition],
    real_nodes: list[HybridNode],
    gateway_node: HybridNode | None = None,
) -> tuple[list[HybridNode], HybridPropagationModel]:
    """Create a hybrid topology with simulated and real nodes.

    Convenience function to set up a hybrid sim-real topology.

    Args:
        simulated_nodes: List of simulated node positions.
        real_nodes: List of real (hardware) nodes.
        gateway_node: Optional gateway bridging sim and real networks.

    Returns:
        Tuple of (all_nodes, propagation_model).

    Example:
        >>> from lichen.sim.topology import grid
        >>> sim_nodes = grid(9, spacing=100.0)
        >>> real_nodes = [
        ...     HybridNode("hw-0001", (500.0, 0.0, 0.0), NodeType.REAL),
        ...     HybridNode("hw-0002", (600.0, 0.0, 0.0), NodeType.REAL),
        ... ]
        >>> all_nodes, model = create_hybrid_topology(sim_nodes, real_nodes)
    """
    model = HybridPropagationModel()
    all_nodes: list[HybridNode] = []

    # Add simulated nodes
    for pos in simulated_nodes:
        node = HybridNode(
            node_id=pos.node_id,
            position=(pos.x, pos.y, pos.z),
            node_type=NodeType.SIMULATED,
        )
        all_nodes.append(node)

    # Register and add real nodes
    for node in real_nodes:
        model.register_real_node(
            node.node_id,
            position=node.position,
            hardware_id=node.hardware_id,
            firmware_version=node.firmware_version,
            node_type=node.node_type,
        )
        all_nodes.append(node)

    # Add gateway if provided
    if gateway_node is not None:
        model.register_real_node(
            gateway_node.node_id,
            position=gateway_node.position,
            hardware_id=gateway_node.hardware_id,
            firmware_version=gateway_node.firmware_version,
            node_type=NodeType.GATEWAY,
        )
        all_nodes.append(gateway_node)

    return all_nodes, model
