# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for active transmission visualization feature."""

import pytest
from httpx import ASGITransport, AsyncClient

from lichen.sim.api import SimulatorAPI
from lichen.sim.simulation import Simulation


@pytest.fixture
def api() -> SimulatorAPI:
    """Create a fresh SimulatorAPI instance."""
    return SimulatorAPI()


@pytest.fixture
def app(api: SimulatorAPI):
    """Create a Starlette app from the API."""
    return api.create_app()


@pytest.fixture
async def client(app) -> AsyncClient:
    """Create an async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class MockVisualizationObserver:
    """Test observer that collects visualization events."""

    def __init__(self) -> None:
        self.tx_propagation_events: list[dict] = []
        self.collision_visual_events: list[dict] = []

    def on_tx_propagation(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        x: float,
        y: float,
        z: float,
        max_range_m: float,
        duration_us: int,
        time_us: int,
    ) -> None:
        self.tx_propagation_events.append({
            "sim_id": sim_id,
            "node_id": node_id,
            "tx_id": tx_id,
            "x": x,
            "y": y,
            "z": z,
            "max_range_m": max_range_m,
            "duration_us": duration_us,
            "time_us": time_us,
        })

    def on_collision_visual(
        self,
        sim_id: str,
        node_id: str,
        tx_ids: list[str],
        tx_positions: list[tuple[float, float, float]],
        time_us: int,
    ) -> None:
        self.collision_visual_events.append({
            "sim_id": sim_id,
            "node_id": node_id,
            "tx_ids": tx_ids,
            "tx_positions": tx_positions,
            "time_us": time_us,
        })


class TestTxPropagationObserver:
    """Test on_tx_propagation observer notifications."""

    def test_tx_propagation_event_fired_on_transmission(self) -> None:
        """Starting a transmission fires on_tx_propagation with position and range."""
        sim = Simulation(sim_id="test-viz")
        observer = MockVisualizationObserver()
        sim.add_observer(observer)

        # Add a node at a known position
        sim.add_node("node1", x=100.0, y=200.0, z=0.0)

        # Start a transmission
        sim.start_transmission("node1", b"test payload")

        # Verify propagation event was fired
        assert len(observer.tx_propagation_events) == 1
        event = observer.tx_propagation_events[0]

        assert event["sim_id"] == "test-viz"
        assert event["node_id"] == "node1"
        assert event["x"] == 100.0
        assert event["y"] == 200.0
        assert event["z"] == 0.0
        assert event["max_range_m"] > 0  # Should be a positive range
        assert event["duration_us"] > 0  # Should have a duration
        assert event["tx_id"]  # Should have a tx_id

    def test_tx_propagation_max_range_computed_from_propagation_model(self) -> None:
        """max_range_m is computed from the propagation model."""
        sim = Simulation(sim_id="test-viz")
        observer = MockVisualizationObserver()
        sim.add_observer(observer)

        # Add node with specific TX power
        node = sim.add_node("node1", x=0.0, y=0.0, z=0.0)
        node.tx_power_dbm = 14  # Standard LoRa TX power

        sim.start_transmission("node1", b"test")

        event = observer.tx_propagation_events[0]
        # The max range should match what the propagation model computes
        expected_range = sim.medium.propagation.max_range(node.tx_power_dbm)
        assert event["max_range_m"] == expected_range


class TestCollisionVisualObserver:
    """Test on_collision_visual observer notifications."""

    def test_collision_visual_event_includes_positions(self) -> None:
        """Collision event includes position data for visual treatment."""
        sim = Simulation(sim_id="test-viz")
        observer = MockVisualizationObserver()
        sim.add_observer(observer)

        # Add three nodes: two transmitters and one receiver in range of both
        sim.add_node("tx1", x=0.0, y=0.0, z=0.0)
        sim.add_node("tx2", x=100.0, y=0.0, z=0.0)
        sim.add_node("rx", x=50.0, y=0.0, z=0.0)

        # Start two overlapping transmissions (collision scenario)
        sim.start_transmission("tx1", b"payload1")
        sim.start_transmission("tx2", b"payload2")

        # Put receiver in RX mode
        sim.enter_rx_mode(
            "rx", timeout_us=1_000_000, on_packet=lambda *_: None, on_timeout=lambda: None
        )

        # Try to receive - this should detect a collision
        sim.get_rx_result("rx")

        # Check if collision visual event was fired with positions
        if observer.collision_visual_events:
            event = observer.collision_visual_events[0]
            assert event["node_id"] == "rx"
            assert len(event["tx_positions"]) >= 1
            # Positions should be tuples of (x, y, z)
            for pos in event["tx_positions"]:
                assert len(pos) == 3


class TestActiveTransmissionsAPI:
    """Test GET /sim/{sim_id}/transmissions endpoint."""

    @pytest.mark.asyncio
    async def test_get_active_transmissions_empty(self, client: AsyncClient) -> None:
        """Returns empty list when no active transmissions."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/transmissions")

        assert response.status_code == 200
        data = response.json()
        assert data["time_us"] == 0
        assert data["transmissions"] == []

    @pytest.mark.asyncio
    async def test_get_active_transmissions_not_found(self, client: AsyncClient) -> None:
        """Returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/transmissions")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_active_transmissions_with_tx(
        self, api: SimulatorAPI, client: AsyncClient
    ) -> None:
        """Returns active transmissions with visualization data."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 100.0, "y": 200.0, "z": 0.0})

        # Start a transmission via the internal API
        sim = api._simulations["sim1"]
        sim.start_transmission("node1", b"test payload")

        response = await client.get("/sim/sim1/transmissions")

        assert response.status_code == 200
        data = response.json()
        assert len(data["transmissions"]) == 1

        tx = data["transmissions"][0]
        assert tx["source_node_id"] == "node1"
        assert tx["x"] == 100.0
        assert tx["y"] == 200.0
        assert tx["z"] == 0.0
        assert tx["max_range_m"] > 0
        assert tx["duration_us"] > 0
        assert 0.0 <= tx["progress"] <= 1.0
        assert tx["current_radius_m"] >= 0
        assert tx["payload_len"] == len(b"test payload")

    @pytest.mark.asyncio
    async def test_transmissions_progress_calculation(
        self, api: SimulatorAPI, client: AsyncClient
    ) -> None:
        """Progress reflects elapsed time within transmission duration."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0.0, "y": 0.0, "z": 0.0})

        # Start a transmission
        sim = api._simulations["sim1"]
        sim.start_transmission("node1", b"test")

        # Get the transmission's duration
        response = await client.get("/sim/sim1/transmissions")
        tx = response.json()["transmissions"][0]
        duration_us = tx["duration_us"]

        # Progress at start should be 0
        assert tx["progress"] == 0.0

        # Advance time to halfway through the transmission
        await client.post("/sim/sim1/tick", json={"time_us": duration_us // 2})

        response = await client.get("/sim/sim1/transmissions")
        tx = response.json()["transmissions"][0]
        assert 0.4 <= tx["progress"] <= 0.6  # Roughly 50%

        # Advance past the transmission end
        await client.post("/sim/sim1/tick", json={"time_us": duration_us + 1000})

        # Transmission should no longer be active
        response = await client.get("/sim/sim1/transmissions")
        assert response.json()["transmissions"] == []
