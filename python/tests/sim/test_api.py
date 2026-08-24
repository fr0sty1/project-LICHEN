# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the REST API controller."""

import pytest
from httpx import ASGITransport, AsyncClient

from lichen.sim.api import SimulatorAPI


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


class TestSimulationCallbacks:
    """The API invokes lifecycle callbacks (used by SimulatorServer instead of
    monkey-patching) on create and delete."""

    @pytest.mark.asyncio
    async def test_create_and_delete_invoke_callbacks(self) -> None:
        created: list[str] = []
        deleted: list[str] = []

        async def on_created(sim_id: str) -> None:
            created.append(sim_id)

        async def on_deleted(sim_id: str) -> None:
            deleted.append(sim_id)

        api = SimulatorAPI(on_simulation_created=on_created, on_simulation_deleted=on_deleted)
        transport = ASGITransport(app=api.create_app())
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            await client.post("/sim", json={"id": "sim1"})
            assert created == ["sim1"]
            assert deleted == []

            await client.delete("/sim/sim1")
            assert deleted == ["sim1"]

    @pytest.mark.asyncio
    async def test_delete_missing_does_not_invoke_callback(self) -> None:
        deleted: list[str] = []

        async def on_deleted(sim_id: str) -> None:
            deleted.append(sim_id)

        api = SimulatorAPI(on_simulation_deleted=on_deleted)
        transport = ASGITransport(app=api.create_app())
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.delete("/sim/missing")
            assert resp.status_code == 404
            assert deleted == []  # callback not fired for a non-existent sim


class TestSimulationCRUD:
    """Test simulation create/read/delete operations."""

    @pytest.mark.asyncio
    async def test_create_simulation(self, client: AsyncClient) -> None:
        """POST /sim creates a new simulation."""
        response = await client.post("/sim", json={"id": "sim1"})

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "sim1"
        assert data["status"] == "created"

    @pytest.mark.asyncio
    async def test_create_simulation_with_time_mode(self, client: AsyncClient) -> None:
        """POST /sim accepts time_mode parameter."""
        response = await client.post("/sim", json={"id": "sim1", "time_mode": "realtime"})

        assert response.status_code == 200

        # Verify time mode was set
        get_response = await client.get("/sim/sim1")
        assert get_response.json()["time_mode"] == "realtime"

    @pytest.mark.asyncio
    async def test_create_simulation_invalid_time_mode(self, client: AsyncClient) -> None:
        """POST /sim rejects invalid time_mode."""
        response = await client.post("/sim", json={"id": "sim1", "time_mode": "invalid"})

        assert response.status_code == 400
        assert "Invalid time_mode" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_create_simulation_missing_id(self, client: AsyncClient) -> None:
        """POST /sim requires id field."""
        response = await client.post("/sim", json={})

        assert response.status_code == 400
        assert "Missing required field: id" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_create_simulation_duplicate_id(self, client: AsyncClient) -> None:
        """POST /sim rejects duplicate simulation ID."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim", json={"id": "sim1"})

        assert response.status_code == 400
        assert "already exists" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_create_simulation_invalid_json(self, client: AsyncClient) -> None:
        """POST /sim rejects invalid JSON body."""
        response = await client.post(
            "/sim",
            content="not json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 400
        assert "Invalid JSON" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_simulation(self, client: AsyncClient) -> None:
        """GET /sim/{id} returns simulation status."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "sim1"
        assert data["time_us"] == 0
        assert data["node_count"] == 0
        assert data["time_mode"] == "barrier_sync"

    @pytest.mark.asyncio
    async def test_get_simulation_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id} returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown")

        assert response.status_code == 404
        assert "not found" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_metrics(self, client: AsyncClient) -> None:
        """GET /sim/{id}/metrics returns a zeroed metrics snapshot for a new sim."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/metrics")

        assert response.status_code == 200
        data = response.json()
        assert data["transmissions"] == 0
        assert data["receptions"] == 0
        assert data["collisions"] == 0
        assert data["delivery_rate"] == 0.0
        assert data["collision_rate"] == 0.0
        assert data["latency_us"]["count"] == 0

    @pytest.mark.asyncio
    async def test_get_metrics_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id}/metrics returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/metrics")

        assert response.status_code == 404
        assert "not found" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_dashboard_metrics(self, client: AsyncClient) -> None:
        """GET /sim/{id}/metrics/dashboard returns dashboard snapshot."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/metrics/dashboard")

        assert response.status_code == 200
        data = response.json()
        assert "current" in data
        assert "time_series" in data
        assert "last_sample_time_us" in data
        assert data["current"]["transmissions"] == 0
        assert data["current"]["delivery_rate"] == 0.0
        assert data["current"]["collision_rate"] == 0.0
        assert data["current"]["duty_cycle"] == 0.0

    @pytest.mark.asyncio
    async def test_get_dashboard_metrics_with_since(self, client: AsyncClient) -> None:
        """GET /sim/{id}/metrics/dashboard?since_us filters time series."""
        await client.post("/sim", json={"id": "sim1"})
        # Advance time to trigger some samples
        await client.post("/sim/sim1/tick", json={"time_us": 2_000_000})
        response = await client.get("/sim/sim1/metrics/dashboard?since_us=1000000")

        assert response.status_code == 200
        data = response.json()
        # All samples should be after since_us
        for sample in data["time_series"]:
            assert sample["time_us"] > 1_000_000

    @pytest.mark.asyncio
    async def test_get_dashboard_metrics_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id}/metrics/dashboard returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/metrics/dashboard")

        assert response.status_code == 404
        assert "not found" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_dashboard_metrics_invalid_since(self, client: AsyncClient) -> None:
        """GET /sim/{id}/metrics/dashboard rejects invalid since_us parameter."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/metrics/dashboard?since_us=invalid")

        assert response.status_code == 400
        assert "must be an integer" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_dashboard_metrics_huge_since(self, client: AsyncClient) -> None:
        """GET /sim/{id}/metrics/dashboard rejects integers exceeding 64-bit bounds."""
        await client.post("/sim", json={"id": "sim1"})
        huge = 10**400
        response = await client.get(f"/sim/sim1/metrics/dashboard?since_us={huge}")

        assert response.status_code == 400
        assert "must be an integer" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_delete_simulation(self, client: AsyncClient) -> None:
        """DELETE /sim/{id} removes simulation."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.delete("/sim/sim1")

        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

        # Verify simulation is gone
        get_response = await client.get("/sim/sim1")
        assert get_response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_simulation_not_found(self, client: AsyncClient) -> None:
        """DELETE /sim/{id} returns 404 for unknown simulation."""
        response = await client.delete("/sim/unknown")

        assert response.status_code == 404
        assert "not found" in response.json()["error"]


class TestSimulationTick:
    """Test simulation time advancement."""

    @pytest.mark.asyncio
    async def test_tick_simulation(self, client: AsyncClient) -> None:
        """POST /sim/{id}/tick advances simulation time."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/tick", json={"time_us": 1000000})

        assert response.status_code == 200
        data = response.json()
        assert data["time_us"] == 1000000
        assert "events_processed" in data

    @pytest.mark.asyncio
    async def test_tick_simulation_not_found(self, client: AsyncClient) -> None:
        """POST /sim/{id}/tick returns 404 for unknown simulation."""
        response = await client.post("/sim/unknown/tick", json={"time_us": 1000})

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_tick_simulation_missing_time(self, client: AsyncClient) -> None:
        """POST /sim/{id}/tick requires time_us field."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/tick", json={})

        assert response.status_code == 400
        assert "Missing required field: time_us" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_tick_simulation_negative_time(self, client: AsyncClient) -> None:
        """POST /sim/{id}/tick rejects negative time."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/tick", json={"time_us": -100})

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_tick_simulation_backwards_time(self, client: AsyncClient) -> None:
        """POST /sim/{id}/tick rejects going backwards in time."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/tick", json={"time_us": 1000})
        response = await client.post("/sim/sim1/tick", json={"time_us": 500})

        assert response.status_code == 400
        assert "backwards" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_tick_simulation_invalid_json(self, client: AsyncClient) -> None:
        """POST /sim/{id}/tick rejects invalid JSON."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/tick",
            content="not json",
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_tick_simulation_counts_events(self, api: SimulatorAPI) -> None:
        """POST /sim/{id}/tick returns correct events_processed count."""
        from httpx import ASGITransport, AsyncClient

        app = api.create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post("/sim", json={"id": "sim1"})
            await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})

            # Queue some events by starting a receive (queues RxTimeoutEvent)
            sim = api._simulations["sim1"]
            sim.start_receive("node1", timeout_ms=100)  # Event at 100,000 us

            # Tick past the timeout - should process 1 event
            response = await client.post("/sim/sim1/tick", json={"time_us": 200_000})

            assert response.status_code == 200
            data = response.json()
            assert data["events_processed"] == 1


class TestNodeManagement:
    """Test node add/remove/move operations."""

    @pytest.mark.asyncio
    async def test_add_node(self, client: AsyncClient) -> None:
        """POST /sim/{id}/node adds a node."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/node", json={"id": "node1", "x": 10.0, "y": 20.0, "z": 5.0}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "node1"
        assert data["position"] == [10.0, 20.0, 5.0]

    @pytest.mark.asyncio
    async def test_add_node_default_position(self, client: AsyncClient) -> None:
        """POST /sim/{id}/node uses default position when not specified."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/node", json={"id": "node1"})

        assert response.status_code == 200
        assert response.json()["position"] == [0.0, 0.0, 0.0]

    @pytest.mark.asyncio
    async def test_add_node_simulation_not_found(self, client: AsyncClient) -> None:
        """POST /sim/{id}/node returns 404 for unknown simulation."""
        response = await client.post("/sim/unknown/node", json={"id": "node1"})

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_add_node_missing_id(self, client: AsyncClient) -> None:
        """POST /sim/{id}/node requires node id."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/node", json={})

        assert response.status_code == 400
        assert "Missing required field: id" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_node_duplicate_id(self, client: AsyncClient) -> None:
        """POST /sim/{id}/node rejects duplicate node ID."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1"})
        response = await client.post("/sim/sim1/node", json={"id": "node1"})

        assert response.status_code == 400
        assert "already exists" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_node_invalid_position(self, client: AsyncClient) -> None:
        """POST /sim/{id}/node rejects non-numeric position."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/node", json={"id": "node1", "x": "bad"})

        assert response.status_code == 400
        assert "numeric" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_node_updates_count(self, client: AsyncClient) -> None:
        """Adding nodes updates the simulation node count."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1"})
        await client.post("/sim/sim1/node", json={"id": "node2"})

        response = await client.get("/sim/sim1")
        assert response.json()["node_count"] == 2

    @pytest.mark.asyncio
    async def test_remove_node(self, client: AsyncClient) -> None:
        """DELETE /sim/{id}/node/{node_id} removes a node."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1"})
        response = await client.delete("/sim/sim1/node/node1")

        assert response.status_code == 200
        assert response.json()["status"] == "removed"

        # Verify node is gone
        get_response = await client.get("/sim/sim1")
        assert get_response.json()["node_count"] == 0

    @pytest.mark.asyncio
    async def test_remove_node_simulation_not_found(self, client: AsyncClient) -> None:
        """DELETE /sim/{id}/node/{node_id} returns 404 for unknown simulation."""
        response = await client.delete("/sim/unknown/node/node1")

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_remove_node_not_found(self, client: AsyncClient) -> None:
        """DELETE /sim/{id}/node/{node_id} returns 404 for unknown node."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.delete("/sim/sim1/node/unknown")

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_move_node(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/node/{node_id} moves a node."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        response = await client.patch("/sim/sim1/node/node1", json={"x": 100, "y": 200, "z": 50})

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "node1"
        assert data["position"] == [100.0, 200.0, 50.0]

    @pytest.mark.asyncio
    async def test_move_node_partial(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/node/{node_id} allows partial position update."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 10, "y": 20, "z": 30})
        response = await client.patch("/sim/sim1/node/node1", json={"x": 100})

        assert response.status_code == 200
        assert response.json()["position"] == [100.0, 20.0, 30.0]

    @pytest.mark.asyncio
    async def test_move_node_simulation_not_found(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/node/{node_id} returns 404 for unknown simulation."""
        response = await client.patch("/sim/unknown/node/node1", json={"x": 0})

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_move_node_not_found(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/node/{node_id} returns 404 for unknown node."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/node/unknown", json={"x": 0})

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_move_node_invalid_position(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/node/{node_id} rejects non-numeric position."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1"})
        response = await client.patch("/sim/sim1/node/node1", json={"x": "bad"})

        assert response.status_code == 400


class TestChaosRules:
    """Test chaos rule operations."""

    @pytest.mark.asyncio
    async def test_add_drop_rule(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/drop adds a drop rule."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/drop", json={"node_id": "node1", "direction": "both"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "rule_id" in data
        assert data["type"] == "drop"

    @pytest.mark.asyncio
    async def test_add_drop_rule_default_direction(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/drop uses default direction."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/drop", json={"node_id": "node1"})

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_add_drop_rule_invalid_direction(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/drop rejects invalid direction."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/drop", json={"node_id": "node1", "direction": "invalid"}
        )

        assert response.status_code == 400
        assert "Invalid direction" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_drop_rule_missing_node_id(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/drop requires node_id."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/drop", json={})

        assert response.status_code == 400
        assert "Missing required field: node_id" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_drop_rule_simulation_not_found(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/drop returns 404 for unknown simulation."""
        response = await client.post("/sim/unknown/chaos/drop", json={"node_id": "node1"})

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_add_partition_rule(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/partition adds a partition rule."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/partition",
            json={"groups": [["node1", "node2"], ["node3", "node4"]]},
        )

        assert response.status_code == 200
        data = response.json()
        assert "rule_id" in data
        assert data["type"] == "partition"

    @pytest.mark.asyncio
    async def test_add_partition_rule_missing_groups(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/partition requires groups."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/partition", json={})

        assert response.status_code == 400
        assert "Missing required field: groups" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_partition_rule_invalid_groups(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/partition rejects invalid groups format."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/partition", json={"groups": "not a list"})

        assert response.status_code == 400
        assert "must be a list" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_degrade_rule(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/degrade adds a degrade rule."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/degrade",
            json={"node_id": "node1", "rssi_penalty_db": 10.0},
        )

        assert response.status_code == 200
        data = response.json()
        assert "rule_id" in data
        assert data["type"] == "degrade"

    @pytest.mark.asyncio
    async def test_add_degrade_rule_missing_node_id(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/degrade requires node_id."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/degrade", json={"rssi_penalty_db": 10})

        assert response.status_code == 400
        assert "Missing required field: node_id" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_degrade_rule_missing_penalty(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/degrade requires rssi_penalty_db."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/degrade", json={"node_id": "node1"})

        assert response.status_code == 400
        assert "Missing required field: rssi_penalty_db" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_degrade_rule_overflow_penalty(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/degrade rejects overflow values for rssi_penalty_db."""
        await client.post("/sim", json={"id": "sim1"})
        # Very large integer that overflows on float conversion
        huge = 10**400
        response = await client.post(
            "/sim/sim1/chaos/degrade",
            json={"node_id": "node1", "rssi_penalty_db": huge},
        )

        assert response.status_code == 400
        assert "must be numeric" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_degrade_rule_nonfinite(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/degrade rejects non-finite numbers (inf, nan).

        Standard JSON doesn't encode infinity, so we send raw JSON with
        the non-standard "Infinity" literal that Python's json.loads()
        can parse with parse_constant.
        """
        await client.post("/sim", json={"id": "sim1"})
        # Send raw JSON with Infinity literal (non-standard but parseable)
        response = await client.post(
            "/sim/sim1/chaos/degrade",
            content=b'{"node_id": "node1", "rssi_penalty_db": Infinity}',
            headers={"Content-Type": "application/json"},
        )

        # Server may reject at JSON parse stage or at isfinite check
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_add_jammer_rule(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/jam adds a jammer rule."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/jam",
            json={"x": 0, "y": 0, "z": 0, "radius_m": 100},
        )

        assert response.status_code == 200
        data = response.json()
        assert "rule_id" in data
        assert data["type"] == "jammer"

    @pytest.mark.asyncio
    async def test_add_jammer_rule_missing_position(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/jam requires position."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/jam", json={"radius_m": 100})

        assert response.status_code == 400
        assert "Missing required fields: x, y, z" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_jammer_rule_missing_radius(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/jam requires radius."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/jam", json={"x": 0, "y": 0, "z": 0})

        assert response.status_code == 400
        assert "Missing required field: radius_m" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_jammer_rule_invalid_radius(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/jam rejects non-positive radius."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/jam",
            json={"x": 0, "y": 0, "z": 0, "radius_m": 0},
        )

        assert response.status_code == 400
        assert "must be positive" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_jammer_rule_overflow(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/jam rejects values that cause OverflowError."""
        await client.post("/sim", json={"id": "sim1"})
        # Very large integer that overflows when converted to float
        huge = 10**1000
        response = await client.post(
            "/sim/sim1/chaos/jam",
            json={"x": huge, "y": 0, "z": 0, "radius_m": 100},
        )

        assert response.status_code == 400
        assert "must be numeric" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_add_jammer_rule_nonfinite(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/jam rejects non-finite numbers (inf, nan).

        Standard JSON doesn't encode infinity, so we send raw JSON with
        the non-standard "Infinity" literal that Python's json.loads()
        can parse with parse_constant.
        """
        await client.post("/sim", json={"id": "sim1"})
        # Send raw JSON with Infinity literal (non-standard but parseable)
        response = await client.post(
            "/sim/sim1/chaos/jam",
            content=b'{"x": Infinity, "y": 0, "z": 0, "radius_m": 100}',
            headers={"Content-Type": "application/json"},
        )

        # Server may reject at JSON parse stage or at isfinite check
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_add_latency_rule(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/latency adds a latency rule."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/latency",
            json={"node_id": "node1", "added_us": 5000},
        )

        assert response.status_code == 200
        data = response.json()
        assert "rule_id" in data
        assert data["type"] == "latency"

    @pytest.mark.asyncio
    async def test_add_latency_rule_missing_node_id(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/latency requires node_id."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/chaos/latency", json={"added_us": 1000})
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_add_latency_rule_invalid_added_us(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/latency rejects non-positive added_us."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post(
            "/sim/sim1/chaos/latency", json={"node_id": "node1", "added_us": 0}
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_add_latency_rule_overflow(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/latency rejects values that cause OverflowError."""
        await client.post("/sim", json={"id": "sim1"})
        # Float infinity cannot be converted to int
        response = await client.post(
            "/sim/sim1/chaos/latency",
            content=b'{"node_id": "node1", "added_us": Infinity}',
            headers={"Content-Type": "application/json"},
        )
        # Server may reject at JSON parse stage or at int conversion
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_add_latency_rule_huge_int(self, client: AsyncClient) -> None:
        """POST /sim/{id}/chaos/latency rejects integers exceeding 64-bit bounds."""
        await client.post("/sim", json={"id": "sim1"})
        # Very large integer that exceeds 64-bit signed range
        huge = 10**400
        response = await client.post(
            "/sim/sim1/chaos/latency",
            json={"node_id": "node1", "added_us": huge},
        )
        assert response.status_code == 400
        assert "must be an integer" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_list_chaos_rules(self, client: AsyncClient) -> None:
        """GET /sim/{id}/chaos lists all rules."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/chaos/drop", json={"node_id": "node1"})
        await client.post(
            "/sim/sim1/chaos/degrade",
            json={"node_id": "node2", "rssi_penalty_db": 5},
        )

        response = await client.get("/sim/sim1/chaos")

        assert response.status_code == 200
        data = response.json()
        assert len(data["rules"]) == 2

    @pytest.mark.asyncio
    async def test_list_chaos_rules_empty(self, client: AsyncClient) -> None:
        """GET /sim/{id}/chaos returns empty list when no rules."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/chaos")

        assert response.status_code == 200
        assert response.json()["rules"] == []

    @pytest.mark.asyncio
    async def test_list_chaos_rules_simulation_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id}/chaos returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/chaos")

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_clear_chaos_rules(self, client: AsyncClient) -> None:
        """DELETE /sim/{id}/chaos clears all rules."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/chaos/drop", json={"node_id": "node1"})
        await client.post("/sim/sim1/chaos/drop", json={"node_id": "node2"})
        await client.post("/sim/sim1/chaos/drop", json={"node_id": "node3"})

        response = await client.delete("/sim/sim1/chaos")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "cleared"
        assert data["rules_removed"] == 3

        # Verify rules are gone
        list_response = await client.get("/sim/sim1/chaos")
        assert list_response.json()["rules"] == []

    @pytest.mark.asyncio
    async def test_clear_chaos_rules_empty(self, client: AsyncClient) -> None:
        """DELETE /sim/{id}/chaos works when no rules exist."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.delete("/sim/sim1/chaos")

        assert response.status_code == 200
        assert response.json()["rules_removed"] == 0

    @pytest.mark.asyncio
    async def test_clear_chaos_rules_simulation_not_found(self, client: AsyncClient) -> None:
        """DELETE /sim/{id}/chaos returns 404 for unknown simulation."""
        response = await client.delete("/sim/unknown/chaos")

        assert response.status_code == 404


class TestChaosRuleSerialization:
    """Test chaos rule serialization in list endpoint."""

    @pytest.mark.asyncio
    async def test_drop_rule_serialization(self, client: AsyncClient) -> None:
        """Drop rules serialize with all fields."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/chaos/drop", json={"node_id": "node1", "direction": "tx"})

        response = await client.get("/sim/sim1/chaos")
        rules = response.json()["rules"]

        assert len(rules) == 1
        rule = rules[0]
        assert rule["type"] == "drop"
        assert rule["node_id"] == "node1"
        assert rule["direction"] == "tx"
        assert "id" in rule

    @pytest.mark.asyncio
    async def test_partition_rule_serialization(self, client: AsyncClient) -> None:
        """Partition rules serialize with all fields."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post(
            "/sim/sim1/chaos/partition",
            json={"groups": [["a", "b"], ["c", "d"]]},
        )

        response = await client.get("/sim/sim1/chaos")
        rules = response.json()["rules"]

        assert len(rules) == 1
        rule = rules[0]
        assert rule["type"] == "partition"
        assert len(rule["groups"]) == 2
        assert "id" in rule

    @pytest.mark.asyncio
    async def test_degrade_rule_serialization(self, client: AsyncClient) -> None:
        """Degrade rules serialize with all fields."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post(
            "/sim/sim1/chaos/degrade",
            json={"node_id": "node1", "rssi_penalty_db": 15.5},
        )

        response = await client.get("/sim/sim1/chaos")
        rules = response.json()["rules"]

        assert len(rules) == 1
        rule = rules[0]
        assert rule["type"] == "degrade"
        assert rule["node_id"] == "node1"
        assert rule["rssi_penalty_db"] == 15.5
        assert "id" in rule

    @pytest.mark.asyncio
    async def test_jammer_rule_serialization(self, client: AsyncClient) -> None:
        """Jammer rules serialize with all fields."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post(
            "/sim/sim1/chaos/jam",
            json={"x": 10, "y": 20, "z": 30, "radius_m": 50},
        )

        response = await client.get("/sim/sim1/chaos")
        rules = response.json()["rules"]

        assert len(rules) == 1
        rule = rules[0]
        assert rule["type"] == "jammer"
        assert rule["x"] == 10.0
        assert rule["y"] == 20.0
        assert rule["z"] == 30.0
        assert rule["radius_m"] == 50.0
        assert "id" in rule


class TestTopology:
    """Test topology observation."""

    @pytest.mark.asyncio
    async def test_get_topology_empty(self, client: AsyncClient) -> None:
        """GET /sim/{id}/topology returns empty list when no nodes."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/topology")

        assert response.status_code == 200
        assert response.json()["nodes"] == []

    @pytest.mark.asyncio
    async def test_get_topology_with_nodes(self, client: AsyncClient) -> None:
        """GET /sim/{id}/topology returns all nodes."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "node2", "x": 100, "y": 200, "z": 0})

        response = await client.get("/sim/sim1/topology")

        assert response.status_code == 200
        nodes = response.json()["nodes"]
        assert len(nodes) == 2

        node_ids = {n["id"] for n in nodes}
        assert node_ids == {"node1", "node2"}

    @pytest.mark.asyncio
    async def test_get_topology_node_details(self, client: AsyncClient) -> None:
        """GET /sim/{id}/topology returns full node details."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 10, "y": 20, "z": 30})

        response = await client.get("/sim/sim1/topology")
        nodes = response.json()["nodes"]

        assert len(nodes) == 1
        node = nodes[0]
        assert node["id"] == "node1"
        assert node["x"] == 10.0
        assert node["y"] == 20.0
        assert node["z"] == 30.0
        assert node["connected"] is True

    @pytest.mark.asyncio
    async def test_get_topology_simulation_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id}/topology returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/topology")

        assert response.status_code == 404


class TestMultipleSimulations:
    """Test managing multiple simulations."""

    @pytest.mark.asyncio
    async def test_multiple_simulations_isolated(self, client: AsyncClient) -> None:
        """Multiple simulations are isolated from each other."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim", json={"id": "sim2"})

        await client.post("/sim/sim1/node", json={"id": "node1"})
        await client.post("/sim/sim2/node", json={"id": "nodeA"})
        await client.post("/sim/sim2/node", json={"id": "nodeB"})

        sim1_response = await client.get("/sim/sim1")
        sim2_response = await client.get("/sim/sim2")

        assert sim1_response.json()["node_count"] == 1
        assert sim2_response.json()["node_count"] == 2

    @pytest.mark.asyncio
    async def test_delete_simulation_preserves_others(self, client: AsyncClient) -> None:
        """Deleting one simulation does not affect others."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim", json={"id": "sim2"})

        await client.delete("/sim/sim1")

        # sim2 should still exist
        response = await client.get("/sim/sim2")
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_chaos_rules_isolated(self, client: AsyncClient) -> None:
        """Chaos rules are isolated between simulations."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim", json={"id": "sim2"})

        await client.post("/sim/sim1/chaos/drop", json={"node_id": "node1"})
        await client.post("/sim/sim1/chaos/drop", json={"node_id": "node2"})

        sim1_rules = (await client.get("/sim/sim1/chaos")).json()["rules"]
        sim2_rules = (await client.get("/sim/sim2/chaos")).json()["rules"]

        assert len(sim1_rules) == 2
        assert len(sim2_rules) == 0


class TestLinkQuality:
    """Test link quality overlay endpoint."""

    @pytest.mark.asyncio
    async def test_get_links_empty(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links returns empty list when no nodes."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/links")

        assert response.status_code == 200
        assert response.json()["links"] == []

    @pytest.mark.asyncio
    async def test_get_links_single_node(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links returns empty list with single node."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/links")

        assert response.status_code == 200
        assert response.json()["links"] == []

    @pytest.mark.asyncio
    async def test_get_links_two_nodes_close(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links returns link between close nodes."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "node2", "x": 100, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/links")

        assert response.status_code == 200
        links = response.json()["links"]
        assert len(links) == 1

        link = links[0]
        assert link["from"] == "node1"
        assert link["to"] == "node2"
        assert link["distance_m"] == 100.0
        assert "rssi_forward_dbm" in link
        assert "rssi_reverse_dbm" in link
        assert "snr_forward_db" in link
        assert "snr_reverse_db" in link
        assert "reachable_forward" in link
        assert "reachable_reverse" in link
        assert "asymmetric" in link
        assert "quality" in link

    @pytest.mark.asyncio
    async def test_get_links_quality_levels(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links assigns quality levels based on RSSI margin."""
        await client.post("/sim", json={"id": "sim1"})
        # Very close nodes should have excellent link quality
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "node2", "x": 10, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/links")
        links = response.json()["links"]

        assert len(links) == 1
        # Very close nodes should have excellent quality
        assert links[0]["quality"] in ["excellent", "good"]
        assert links[0]["reachable_forward"] is True
        assert links[0]["reachable_reverse"] is True

    @pytest.mark.asyncio
    async def test_get_links_multiple_nodes(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links returns links for all node pairs."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "n1", "x": 0, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "n2", "x": 100, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "n3", "x": 200, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/links")
        links = response.json()["links"]

        # 3 nodes = 3 unique pairs (n1-n2, n1-n3, n2-n3)
        assert len(links) == 3

        # Check all pairs are present
        pairs = {(link["from"], link["to"]) for link in links}
        assert ("n1", "n2") in pairs
        assert ("n1", "n3") in pairs
        assert ("n2", "n3") in pairs

    @pytest.mark.asyncio
    async def test_get_links_threshold_filter(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links filters links below threshold."""
        await client.post("/sim", json={"id": "sim1"})
        # Put nodes very far apart (100km) so link is below default threshold
        # With path loss exponent 2.7 and TX power 22 dBm, RSSI at 100km is about -150 dBm
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "node2", "x": 100000, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/links")
        links = response.json()["links"]

        # Very distant nodes should be filtered out (below -137 dBm)
        assert len(links) == 0

        # But with a lower threshold, they should appear
        response = await client.get("/sim/sim1/links?threshold_db=-200")
        links = response.json()["links"]
        assert len(links) == 1

    @pytest.mark.asyncio
    async def test_get_links_invalid_threshold(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links rejects invalid threshold parameter."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/links?threshold_db=invalid")

        assert response.status_code == 400
        assert "must be a number" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_links_symmetric_same_power(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links shows symmetric links when nodes have same TX power."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "node2", "x": 100, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/links")
        link = response.json()["links"][0]

        # With same TX power, forward and reverse RSSI should be equal
        assert link["rssi_forward_dbm"] == link["rssi_reverse_dbm"]
        assert link["asymmetric"] is False

    @pytest.mark.asyncio
    async def test_get_links_asymmetric_different_power(self, api: SimulatorAPI) -> None:
        """GET /sim/{id}/links detects asymmetric links with different TX power."""
        from httpx import ASGITransport, AsyncClient

        app = api.create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post("/sim", json={"id": "sim1"})
            await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
            await client.post("/sim/sim1/node", json={"id": "node2", "x": 100, "y": 0, "z": 0})

            # Set different TX powers (default is 22 dBm)
            sim = api._simulations["sim1"]
            node1 = sim.get_node("node1")
            node2 = sim.get_node("node2")
            node1.tx_power_dbm = 22
            node2.tx_power_dbm = 10  # 12 dB lower

            response = await client.get("/sim/sim1/links")
            link = response.json()["links"][0]

            # Forward (node1->node2) should be stronger than reverse
            assert link["rssi_forward_dbm"] > link["rssi_reverse_dbm"]
            assert link["asymmetric"] is True

    @pytest.mark.asyncio
    async def test_get_links_simulation_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/links")

        assert response.status_code == 404
        assert "not found" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_links_3d_distance(self, client: AsyncClient) -> None:
        """GET /sim/{id}/links calculates correct 3D distance."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        # 3-4-5 triangle: sqrt(3^2 + 4^2) = 5, then 5-12-13 with z
        await client.post("/sim/sim1/node", json={"id": "node2", "x": 30, "y": 40, "z": 120})

        response = await client.get("/sim/sim1/links")
        link = response.json()["links"][0]

        # Expected distance: sqrt(30^2 + 40^2 + 120^2) = sqrt(900+1600+14400) = sqrt(16900) = 130
        assert link["distance_m"] == 130.0


class TestTDMASlots:
    """Test TDMA slot assignment visualization endpoint."""

    @pytest.mark.asyncio
    async def test_get_tdma_slots_empty(self, client: AsyncClient) -> None:
        """GET /sim/{id}/tdma returns empty slots when no nodes."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/tdma")

        assert response.status_code == 200
        data = response.json()
        assert "superframe" in data
        assert data["superframe"]["num_slots"] == 8
        assert data["superframe"]["slot_duration_ms"] == 2346
        assert data["superframe"]["guard_ms"] == 50
        assert data["slots"] == [{"slot": i, "nodes": []} for i in range(8)]
        assert data["conflicts"] == []
        assert data["nodes"] == []

    @pytest.mark.asyncio
    async def test_get_tdma_slots_with_nodes(self, client: AsyncClient) -> None:
        """GET /sim/{id}/tdma returns slot assignments for nodes."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
        await client.post("/sim/sim1/node", json={"id": "node2", "x": 100, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/tdma")

        assert response.status_code == 200
        data = response.json()
        assert len(data["nodes"]) == 2

        # Each node should have slot assignment info
        for node in data["nodes"]:
            assert "id" in node
            assert "assigned_slot" in node
            assert "state" in node
            assert "drift_us" in node

    @pytest.mark.asyncio
    async def test_get_tdma_slots_node_details(self, client: AsyncClient) -> None:
        """GET /sim/{id}/tdma returns correct node details."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/tdma")
        data = response.json()

        assert len(data["nodes"]) == 1
        node = data["nodes"][0]
        assert node["id"] == "node1"
        assert 0 <= node["assigned_slot"] < 8
        assert node["state"] == "UNSYNCED"  # Default state
        assert node["drift_us"] == 0

    @pytest.mark.asyncio
    async def test_get_tdma_slots_shows_superframe_info(self, client: AsyncClient) -> None:
        """GET /sim/{id}/tdma returns superframe configuration."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})

        response = await client.get("/sim/sim1/tdma")
        data = response.json()

        superframe = data["superframe"]
        assert "sfn" in superframe
        assert superframe["num_slots"] == 8
        assert superframe["slot_duration_ms"] == 2346
        assert superframe["guard_ms"] == 50

    @pytest.mark.asyncio
    async def test_get_tdma_slots_simulation_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id}/tdma returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/tdma")

        assert response.status_code == 404
        assert "not found" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_get_tdma_slots_conflict_detection(self, api: SimulatorAPI) -> None:
        """GET /sim/{id}/tdma detects slot conflicts when multiple synced nodes share a slot."""
        from httpx import ASGITransport, AsyncClient

        from lichen.sim.tdma import TDMAState

        app = api.create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post("/sim", json={"id": "sim1"})
            await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})
            await client.post("/sim/sim1/node", json={"id": "node2", "x": 100, "y": 0, "z": 0})

            # Manually force both nodes to same slot and SYNCED state
            sim = api._simulations["sim1"]
            node1 = sim.get_node("node1")
            node2 = sim.get_node("node2")
            node1.tdma_scheduler.assigned_slot = 3
            node1.tdma_scheduler.state = TDMAState.SYNCED
            node2.tdma_scheduler.assigned_slot = 3
            node2.tdma_scheduler.state = TDMAState.SYNCED

            response = await client.get("/sim/sim1/tdma")
            data = response.json()

            # Should detect conflict in slot 3
            assert len(data["conflicts"]) == 1
            conflict = data["conflicts"][0]
            assert conflict["slot"] == 3
            assert set(conflict["nodes"]) == {"node1", "node2"}
            assert conflict["reason"] == "multiple_assignment"


class TestPlaybackControls:
    """Test playback control endpoints."""

    @pytest.mark.asyncio
    async def test_get_playback(self, client: AsyncClient) -> None:
        """GET /sim/{id}/playback returns initial playback state."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.get("/sim/sim1/playback")

        assert response.status_code == 200
        data = response.json()
        assert data["paused"] is False
        assert data["speed"] == 1.0
        assert data["time_us"] == 0

    @pytest.mark.asyncio
    async def test_get_playback_not_found(self, client: AsyncClient) -> None:
        """GET /sim/{id}/playback returns 404 for unknown simulation."""
        response = await client.get("/sim/unknown/playback")

        assert response.status_code == 404
        assert "not found" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_playback_pause(self, client: AsyncClient) -> None:
        """POST /sim/{id}/playback/pause pauses simulation."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/playback/pause")

        assert response.status_code == 200
        data = response.json()
        assert data["paused"] is True

    @pytest.mark.asyncio
    async def test_playback_play(self, client: AsyncClient) -> None:
        """POST /sim/{id}/playback/play resumes simulation."""
        await client.post("/sim", json={"id": "sim1"})
        await client.post("/sim/sim1/playback/pause")  # First pause
        response = await client.post("/sim/sim1/playback/play")

        assert response.status_code == 200
        data = response.json()
        assert data["paused"] is False

    @pytest.mark.asyncio
    async def test_playback_step(self, api: SimulatorAPI) -> None:
        """POST /sim/{id}/playback/step processes one event."""
        from httpx import ASGITransport, AsyncClient

        app = api.create_app()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            await client.post("/sim", json={"id": "sim1"})
            await client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})

            # Queue an event by starting a receive
            sim = api._simulations["sim1"]
            sim.start_receive("node1", timeout_ms=100)

            response = await client.post("/sim/sim1/playback/step")

            assert response.status_code == 200
            data = response.json()
            assert data["paused"] is True
            assert data["event_processed"] is True
            assert data["time_us"] == 100_000  # Timeout at 100ms

    @pytest.mark.asyncio
    async def test_playback_step_no_events(self, client: AsyncClient) -> None:
        """POST /sim/{id}/playback/step with no events returns event_processed=false."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.post("/sim/sim1/playback/step")

        assert response.status_code == 200
        data = response.json()
        assert data["paused"] is True
        assert data["event_processed"] is False

    @pytest.mark.asyncio
    async def test_set_playback_speed(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback can set playback speed."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/playback", json={"speed": 2.0})

        assert response.status_code == 200
        data = response.json()
        assert data["speed"] == 2.0

    @pytest.mark.asyncio
    async def test_set_playback_speed_invalid(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects non-positive speed."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/playback", json={"speed": 0})

        assert response.status_code == 400
        assert "positive" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_speed_non_numeric(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects non-numeric speed values."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/playback", json={"speed": "fast"})

        assert response.status_code == 400
        assert "must be a number" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_speed_infinity(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects infinite speed values."""
        await client.post("/sim", json={"id": "sim1"})
        # Send string "Infinity" which float() converts to inf
        response = await client.patch("/sim/sim1/playback", json={"speed": "Infinity"})

        assert response.status_code == 400
        assert "finite" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_speed_nan(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects NaN speed values."""
        await client.post("/sim", json={"id": "sim1"})
        # Send string "NaN" which float() converts to nan
        response = await client.patch("/sim/sim1/playback", json={"speed": "NaN"})

        assert response.status_code == 400
        assert "finite" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_jump_to_time(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback can jump to specific time."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/playback", json={"jump_to_us": 1_000_000})

        assert response.status_code == 200
        data = response.json()
        assert data["time_us"] == 1_000_000

    @pytest.mark.asyncio
    async def test_set_playback_jump_backwards_fails(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects jumping backwards in time."""
        await client.post("/sim", json={"id": "sim1"})
        await client.patch("/sim/sim1/playback", json={"jump_to_us": 1_000_000})
        response = await client.patch("/sim/sim1/playback", json={"jump_to_us": 500_000})

        assert response.status_code == 400
        assert "backwards" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_jump_non_numeric(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects non-numeric jump_to_us values."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/playback", json={"jump_to_us": "later"})

        assert response.status_code == 400
        assert "must be a non-negative integer" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_jump_negative(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects negative jump_to_us values."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/playback", json={"jump_to_us": -1000})

        assert response.status_code == 400
        assert "must be a non-negative integer" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_jump_boolean(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects boolean jump_to_us values."""
        await client.post("/sim", json={"id": "sim1"})
        response = await client.patch("/sim/sim1/playback", json={"jump_to_us": True})

        assert response.status_code == 400
        assert "must be a non-negative integer" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_set_playback_jump_huge_int(self, client: AsyncClient) -> None:
        """PATCH /sim/{id}/playback rejects integers exceeding 64-bit bounds."""
        await client.post("/sim", json={"id": "sim1"})
        huge = 10**400
        response = await client.patch("/sim/sim1/playback", json={"jump_to_us": huge})

        assert response.status_code == 400
        assert "must be a non-negative integer" in response.json()["error"]

    @pytest.mark.asyncio
    async def test_playback_not_found(self, client: AsyncClient) -> None:
        """Playback endpoints return 404 for unknown simulation."""
        endpoints = [
            ("POST", "/sim/unknown/playback/play"),
            ("POST", "/sim/unknown/playback/pause"),
            ("POST", "/sim/unknown/playback/step"),
            ("PATCH", "/sim/unknown/playback"),
        ]
        for method, url in endpoints:
            if method == "POST":
                response = await client.post(url)
            else:
                response = await client.patch(url, json={"speed": 1.0})
            assert response.status_code == 404, f"{method} {url} should return 404"
