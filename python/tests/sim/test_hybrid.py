# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for hybrid sim-real topology support."""

from __future__ import annotations

import time

from lora_medium import PropagationModel

from lichen.sim.hybrid import (
    HybridNode,
    HybridPropagationModel,
    NodeType,
    RFMeasurement,
    create_hybrid_topology,
)
from lichen.sim.topology import grid


class TestRFMeasurement:
    """Tests for RFMeasurement dataclass."""

    def test_basic_measurement(self) -> None:
        """Test creating a basic RF measurement."""
        m = RFMeasurement(rssi_dbm=-85.0, snr_db=12.0)
        assert m.rssi_dbm == -85.0
        assert m.snr_db == 12.0
        assert m.measurement_count == 1

    def test_measurement_update(self) -> None:
        """Test updating measurement with EMA."""
        m = RFMeasurement(rssi_dbm=-80.0, snr_db=10.0)
        m.update(-90.0, 8.0)

        # EMA with alpha=0.3: new = 0.3 * new + 0.7 * old
        expected_rssi = 0.3 * (-90.0) + 0.7 * (-80.0)
        assert abs(m.rssi_dbm - expected_rssi) < 0.01
        assert m.measurement_count == 2
        assert m.timestamp > 0

    def test_measurement_with_distance(self) -> None:
        """Test measurement with distance metadata."""
        m = RFMeasurement(
            rssi_dbm=-95.0,
            snr_db=5.0,
            distance_m=1000.0,
            tx_power_dbm=22.0,
        )
        assert m.distance_m == 1000.0
        assert m.tx_power_dbm == 22.0


class TestHybridNode:
    """Tests for HybridNode dataclass."""

    def test_simulated_node(self) -> None:
        """Test creating a simulated node."""
        node = HybridNode("sim-0", (100.0, 200.0, 0.0))
        assert node.node_id == "sim-0"
        assert node.node_type == NodeType.SIMULATED
        assert node.position == (100.0, 200.0, 0.0)

    def test_real_node(self) -> None:
        """Test creating a real (hardware) node."""
        node = HybridNode(
            "hw-0001",
            (50.0, 50.0, 10.0),
            node_type=NodeType.REAL,
            hardware_id="00:11:22:33:44:55:66:77",
            firmware_version="1.2.3",
        )
        assert node.node_type == NodeType.REAL
        assert node.hardware_id == "00:11:22:33:44:55:66:77"
        assert node.firmware_version == "1.2.3"

    def test_to_node_position(self) -> None:
        """Test conversion to standard NodePosition."""
        node = HybridNode("test", (10.0, 20.0, 30.0))
        pos = node.to_node_position()
        assert pos.node_id == "test"
        assert pos.x == 10.0
        assert pos.y == 20.0
        assert pos.z == 30.0


class TestHybridPropagationModel:
    """Tests for HybridPropagationModel."""

    def test_register_real_node(self) -> None:
        """Test registering a real node."""
        model = HybridPropagationModel()
        node = model.register_real_node(
            "hw-001",
            position=(100.0, 0.0, 0.0),
            hardware_id="ABC123",
        )
        assert node.node_id == "hw-001"
        assert model.is_real_node("hw-001")
        assert not model.is_real_node("sim-001")

    def test_unregister_node(self) -> None:
        """Test unregistering a node."""
        model = HybridPropagationModel()
        model.register_real_node("hw-001")
        model.store_measurement(
            "hw-001", "sim-001",
            RFMeasurement(rssi_dbm=-80.0)
        )

        assert model.unregister_node("hw-001")
        assert not model.is_real_node("hw-001")
        # Measurement should be cleared
        assert model.get_measurement("hw-001", "sim-001") is None

    def test_store_and_get_measurement(self) -> None:
        """Test storing and retrieving measurements."""
        model = HybridPropagationModel()
        m = RFMeasurement(rssi_dbm=-85.0, snr_db=12.0, tx_power_dbm=14.0)
        model.store_measurement("node-a", "node-b", m)

        # Symmetric lookup
        result = model.get_measurement("node-a", "node-b")
        assert result is not None
        assert result.rssi_dbm == -85.0

        result2 = model.get_measurement("node-b", "node-a")
        assert result2 is not None
        assert result2.rssi_dbm == -85.0

    def test_asymmetric_measurements(self) -> None:
        """Test asymmetric measurement mode."""
        model = HybridPropagationModel(allow_asymmetric=True)
        model.store_measurement(
            "node-a", "node-b",
            RFMeasurement(rssi_dbm=-80.0)
        )
        model.store_measurement(
            "node-b", "node-a",
            RFMeasurement(rssi_dbm=-90.0)  # Different direction
        )

        m_ab = model.get_measurement("node-a", "node-b")
        m_ba = model.get_measurement("node-b", "node-a")

        assert m_ab is not None
        assert m_ba is not None
        assert m_ab.rssi_dbm == -80.0
        assert m_ba.rssi_dbm == -90.0

    def test_measurement_staleness(self) -> None:
        """Test measurement expiration."""
        model = HybridPropagationModel(measurement_max_age_s=0.1)

        m = RFMeasurement(rssi_dbm=-85.0, timestamp=time.time())
        model.store_measurement("a", "b", m)

        # Fresh measurement should be returned
        assert model.get_measurement("a", "b") is not None

        # Wait for expiration
        time.sleep(0.15)
        assert model.get_measurement("a", "b") is None

    def test_received_power_with_measurement(self) -> None:
        """Test received power calculation using actual measurement."""
        model = HybridPropagationModel()
        model.store_measurement(
            "hw-001", "sim-001",
            RFMeasurement(rssi_dbm=-80.0, tx_power_dbm=14.0)
        )

        # Same TX power as measurement
        rx_power = model.received_power_between("hw-001", "sim-001", tx_power_dbm=14.0)
        assert rx_power == -80.0

        # Higher TX power - should adjust
        rx_power_high = model.received_power_between("hw-001", "sim-001", tx_power_dbm=22.0)
        assert rx_power_high == -80.0 + (22.0 - 14.0)  # +8 dB

    def test_received_power_model_fallback(self) -> None:
        """Test fallback to propagation model when no measurement."""
        base_model = PropagationModel(pl0_dbm=32.44, n=2.7)
        model = HybridPropagationModel(base_model=base_model)

        model.register_real_node("hw-001", position=(0.0, 0.0, 0.0))

        # No measurement stored, should use model
        rx_power = model.received_power_between(
            "hw-001", "sim-001",
            tx_power_dbm=14.0,
            from_position=(0.0, 0.0, 0.0),
            to_position=(100.0, 0.0, 0.0),
        )

        # Compare with direct model calculation
        expected = base_model.received_power(14.0, 100.0)
        assert abs(rx_power - expected) < 0.01

    def test_can_decode_between(self) -> None:
        """Test decode check using measurement."""
        model = HybridPropagationModel()

        # Strong signal - should decode
        model.store_measurement(
            "a", "b",
            RFMeasurement(rssi_dbm=-80.0, tx_power_dbm=14.0)
        )
        assert model.can_decode_between("a", "b", tx_power_dbm=14.0)

        # Weak signal - should not decode
        model.store_measurement(
            "c", "d",
            RFMeasurement(rssi_dbm=-140.0, tx_power_dbm=14.0)
        )
        assert not model.can_decode_between("c", "d", tx_power_dbm=14.0)

    def test_get_link_quality(self) -> None:
        """Test link quality metrics retrieval."""
        model = HybridPropagationModel()

        # No measurement
        assert model.get_link_quality("a", "b") is None

        # With measurement
        m = RFMeasurement(rssi_dbm=-85.0, snr_db=12.0)
        model.store_measurement("a", "b", m)

        quality = model.get_link_quality("a", "b")
        assert quality is not None
        assert quality["rssi_dbm"] == -85.0
        assert quality["snr_db"] == 12.0
        assert quality["measurement_count"] == 1
        assert quality["is_stale"] is False

    def test_clear_measurements(self) -> None:
        """Test clearing all measurements."""
        model = HybridPropagationModel()
        model.store_measurement("a", "b", RFMeasurement(rssi_dbm=-80.0))
        model.store_measurement("c", "d", RFMeasurement(rssi_dbm=-90.0))

        model.clear_measurements()

        assert model.get_measurement("a", "b") is None
        assert model.get_measurement("c", "d") is None


class TestCreateHybridTopology:
    """Tests for create_hybrid_topology helper."""

    def test_basic_hybrid_topology(self) -> None:
        """Test creating a basic hybrid topology."""
        sim_nodes = grid(4, spacing=100.0, prefix="sim-")
        real_nodes = [
            HybridNode("hw-001", (500.0, 0.0, 0.0), NodeType.REAL),
            HybridNode("hw-002", (600.0, 0.0, 0.0), NodeType.REAL),
        ]

        all_nodes, model = create_hybrid_topology(sim_nodes, real_nodes)

        assert len(all_nodes) == 6  # 4 sim + 2 real
        assert model.is_real_node("hw-001")
        assert model.is_real_node("hw-002")
        assert not model.is_real_node("sim-0")

    def test_hybrid_topology_with_gateway(self) -> None:
        """Test hybrid topology with gateway node."""
        sim_nodes = grid(2, spacing=100.0)
        real_nodes = [HybridNode("hw-001", (200.0, 0.0, 0.0), NodeType.REAL)]
        gateway = HybridNode("gw-001", (100.0, 50.0, 0.0), NodeType.GATEWAY)

        all_nodes, model = create_hybrid_topology(sim_nodes, real_nodes, gateway)

        assert len(all_nodes) == 4  # 2 sim + 1 real + 1 gateway
        assert model.is_real_node("gw-001")
        real_nodes_list = model.get_real_nodes()
        assert len(real_nodes_list) == 2  # hw-001 and gw-001


class TestHybridTopologyIntegration:
    """Integration tests for hybrid topology with Medium."""

    def test_measurement_vs_model_comparison(self) -> None:
        """Compare measurement-based and model-based propagation."""
        base_model = PropagationModel(pl0_dbm=32.44, n=2.7)
        hybrid = HybridPropagationModel(base_model=base_model)

        # Register nodes
        hybrid.register_real_node("hw-001", position=(0.0, 0.0, 0.0))
        hybrid.register_real_node("hw-002", position=(500.0, 0.0, 0.0))

        # Model-based (no measurement)
        model_rx = hybrid.received_power_between(
            "hw-001", "hw-002",
            tx_power_dbm=14.0,
        )

        # Now add actual measurement (better than model predicts)
        hybrid.store_measurement(
            "hw-001", "hw-002",
            RFMeasurement(rssi_dbm=-70.0, tx_power_dbm=14.0, distance_m=500.0)
        )

        measurement_rx = hybrid.received_power_between(
            "hw-001", "hw-002",
            tx_power_dbm=14.0,
        )

        # Measurement should be used (better signal)
        assert measurement_rx == -70.0
        assert measurement_rx > model_rx  # Actual measurement is stronger

    def test_sim_real_link_quality_tracking(self) -> None:
        """Test tracking link quality evolution in hybrid topology."""
        model = HybridPropagationModel()
        model.register_real_node("hw-001", position=(0.0, 0.0, 0.0))

        # Initial measurement
        m = RFMeasurement(rssi_dbm=-80.0, snr_db=10.0, tx_power_dbm=14.0)
        model.store_measurement("hw-001", "sim-001", m)

        # Simulate multiple updates (channel varying)
        for rssi in [-82.0, -79.0, -81.0, -78.0]:
            stored = model.get_measurement("hw-001", "sim-001")
            assert stored is not None
            stored.update(rssi, 10.0)

        quality = model.get_link_quality("hw-001", "sim-001")
        assert quality is not None
        assert quality["measurement_count"] == 5
        assert quality["variance_db"] > 0  # Should have variance from updates
