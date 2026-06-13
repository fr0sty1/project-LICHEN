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
        from starlette.testclient import TestClient

        app = api.create_app()
        # Use sync client for direct access to api internals
        with TestClient(app) as client:
            client.post("/sim", json={"id": "sim1"})
            client.post("/sim/sim1/node", json={"id": "node1", "x": 0, "y": 0, "z": 0})

            # Queue some events by starting a receive (queues RxTimeoutEvent)
            sim = api._simulations["sim1"]
            sim.start_receive("node1", timeout_ms=100)  # Event at 100,000 us

            # Tick past the timeout - should process 1 event
            response = client.post("/sim/sim1/tick", json={"time_us": 200_000})

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
