"""REST API for controlling the LICHEN simulator.

This module provides a Starlette-based REST API for managing simulations,
nodes, and chaos rules programmatically.
"""

from __future__ import annotations

import json
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lichen.sim.chaos import (
    ChaosEngine,
    ChaosRule,
    DegradeRule,
    DropRule,
    JammerRule,
    PartitionRule,
)
from lichen.sim.simulation import Simulation, TimeMode


def _error_response(message: str, status_code: int = 400) -> JSONResponse:
    """Create a JSON error response.

    Args:
        message: Error message to return.
        status_code: HTTP status code.

    Returns:
        JSONResponse with error payload.
    """
    return JSONResponse({"error": message}, status_code=status_code)


def _rule_to_dict(rule: ChaosRule) -> dict[str, Any]:
    """Convert a chaos rule to a JSON-serializable dictionary.

    Args:
        rule: The chaos rule to convert.

    Returns:
        Dictionary representation of the rule.
    """
    result: dict[str, Any] = {"id": rule.id}

    if isinstance(rule, DropRule):
        result["type"] = "drop"
        result["node_id"] = rule.node_id
        result["direction"] = rule.direction
    elif isinstance(rule, PartitionRule):
        result["type"] = "partition"
        result["groups"] = [list(group) for group in rule.groups]
    elif isinstance(rule, DegradeRule):
        result["type"] = "degrade"
        result["node_id"] = rule.node_id
        result["rssi_penalty_db"] = rule.rssi_penalty_db
    elif isinstance(rule, JammerRule):
        result["type"] = "jammer"
        result["x"] = rule.x
        result["y"] = rule.y
        result["z"] = rule.z
        result["radius_m"] = rule.radius_m

    return result


class SimulatorAPI:
    """REST API controller for the LICHEN simulator.

    Manages multiple simulation instances with their associated chaos engines.
    Provides endpoints for creating/deleting simulations, managing nodes,
    applying chaos rules, and observing topology.
    """

    def __init__(self) -> None:
        """Initialize the API with empty simulation and chaos engine stores."""
        self._simulations: dict[str, Simulation] = {}
        self._chaos_engines: dict[str, ChaosEngine] = {}
        self._app: Starlette | None = None

    def _get_simulation(self, sim_id: str) -> Simulation | None:
        """Get a simulation by ID.

        Args:
            sim_id: Simulation identifier.

        Returns:
            The simulation, or None if not found.
        """
        return self._simulations.get(sim_id)

    def _get_chaos_engine(self, sim_id: str) -> ChaosEngine | None:
        """Get the chaos engine for a simulation.

        Args:
            sim_id: Simulation identifier.

        Returns:
            The chaos engine, or None if simulation not found.
        """
        return self._chaos_engines.get(sim_id)

    async def create_simulation(self, request: Request) -> JSONResponse:
        """Create a new simulation.

        POST /sim
        Body: {"id": "sim1", "time_mode": "barrier_sync"}
        Returns: {"id": "sim1", "status": "created"}
        """
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        sim_id = body.get("id")
        if not sim_id:
            return _error_response("Missing required field: id")

        if sim_id in self._simulations:
            return _error_response(f"Simulation '{sim_id}' already exists")

        time_mode_str = body.get("time_mode", "barrier_sync")
        if time_mode_str == "barrier_sync":
            time_mode = TimeMode.BARRIER_SYNC
        elif time_mode_str == "realtime":
            time_mode = TimeMode.REALTIME
        else:
            return _error_response(
                f"Invalid time_mode: {time_mode_str}. Must be 'barrier_sync' or 'realtime'"
            )

        chaos_engine = ChaosEngine()
        sim = Simulation(sim_id=sim_id, time_mode=time_mode, chaos_engine=chaos_engine)
        self._simulations[sim_id] = sim
        self._chaos_engines[sim_id] = chaos_engine

        return JSONResponse({"id": sim_id, "status": "created"})

    async def delete_simulation(self, request: Request) -> JSONResponse:
        """Delete a simulation.

        DELETE /sim/{sim_id}
        Returns: {"status": "deleted"}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        del self._simulations[sim_id]
        del self._chaos_engines[sim_id]

        return JSONResponse({"status": "deleted"})

    async def get_simulation(self, request: Request) -> JSONResponse:
        """Get simulation status.

        GET /sim/{sim_id}
        Returns: {"id": "sim1", "time_us": 0, "node_count": 5, "time_mode": "barrier_sync"}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        time_mode_str = "barrier_sync" if sim.time_mode == TimeMode.BARRIER_SYNC else "realtime"

        return JSONResponse(
            {
                "id": sim.id,
                "time_us": sim.current_time_us,
                "node_count": sim.get_connected_node_count(),
                "time_mode": time_mode_str,
            }
        )

    async def get_metrics(self, request: Request) -> JSONResponse:
        """Get collected metrics for a simulation.

        GET /sim/{sim_id}/metrics
        Returns the metrics snapshot: transmissions, receptions, collisions,
        delivery_rate, collision_rate, and latency_us stats.
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        return JSONResponse(sim.metrics.snapshot())

    async def tick_simulation(self, request: Request) -> JSONResponse:
        """Advance simulation time.

        POST /sim/{sim_id}/tick
        Body: {"time_us": 1000000}
        Returns: {"time_us": 1000000, "events_processed": 42}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        time_us = body.get("time_us")
        if time_us is None:
            return _error_response("Missing required field: time_us")

        if not isinstance(time_us, int) or time_us < 0:
            return _error_response("time_us must be a non-negative integer")

        initial_time = sim.current_time_us
        if time_us < initial_time:
            return _error_response(f"Cannot advance backwards: {time_us} < {initial_time}")

        events_before = len(sim.event_queue)

        sim.advance_to(time_us)

        events_after = len(sim.event_queue)
        events_processed = max(0, events_before - events_after)

        return JSONResponse(
            {
                "time_us": sim.current_time_us,
                "events_processed": events_processed,
            }
        )

    async def add_node(self, request: Request) -> JSONResponse:
        """Add a node to the simulation.

        POST /sim/{sim_id}/node
        Body: {"id": "node1", "x": 0, "y": 0, "z": 0}
        Returns: {"id": "node1", "position": [0, 0, 0]}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        node_id = body.get("id")
        if not node_id:
            return _error_response("Missing required field: id")

        x = body.get("x", 0.0)
        y = body.get("y", 0.0)
        z = body.get("z", 0.0)

        try:
            x = float(x)
            y = float(y)
            z = float(z)
        except (TypeError, ValueError):
            return _error_response("Position coordinates must be numeric")

        try:
            node = sim.add_node(node_id, x, y, z)
        except ValueError as e:
            return _error_response(str(e))

        return JSONResponse(
            {
                "id": node.id,
                "position": list(node.position),
            }
        )

    async def remove_node(self, request: Request) -> JSONResponse:
        """Remove a node from the simulation.

        DELETE /sim/{sim_id}/node/{node_id}
        Returns: {"status": "removed"}
        """
        sim_id = request.path_params["sim_id"]
        node_id = request.path_params["node_id"]

        sim = self._get_simulation(sim_id)
        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        if sim.get_node(node_id) is None:
            return _error_response(f"Node '{node_id}' not found", status_code=404)

        sim.remove_node(node_id)

        return JSONResponse({"status": "removed"})

    async def move_node(self, request: Request) -> JSONResponse:
        """Move a node to a new position.

        PATCH /sim/{sim_id}/node/{node_id}
        Body: {"x": 100, "y": 200, "z": 0}
        Returns: {"id": "node1", "position": [100, 200, 0]}
        """
        sim_id = request.path_params["sim_id"]
        node_id = request.path_params["node_id"]

        sim = self._get_simulation(sim_id)
        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        node = sim.get_node(node_id)
        if node is None:
            return _error_response(f"Node '{node_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        x = body.get("x", node.position[0])
        y = body.get("y", node.position[1])
        z = body.get("z", node.position[2])

        try:
            x = float(x)
            y = float(y)
            z = float(z)
        except (TypeError, ValueError):
            return _error_response("Position coordinates must be numeric")

        node.set_position(x, y, z)

        return JSONResponse(
            {
                "id": node.id,
                "position": list(node.position),
            }
        )

    async def add_chaos_drop(self, request: Request) -> JSONResponse:
        """Add a drop rule.

        POST /sim/{sim_id}/chaos/drop
        Body: {"node_id": "node1", "direction": "both"}
        Returns: {"rule_id": "uuid", "type": "drop"}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        engine = self._get_chaos_engine(sim_id)
        if engine is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        node_id = body.get("node_id")
        if not node_id:
            return _error_response("Missing required field: node_id")

        direction = body.get("direction", "both")
        if direction not in ("tx", "rx", "both"):
            return _error_response(f"Invalid direction: {direction}. Must be 'tx', 'rx', or 'both'")

        rule = DropRule(node_id=node_id, direction=direction)  # type: ignore[arg-type]
        engine.add_rule(rule)

        return JSONResponse({"rule_id": rule.id, "type": "drop"})

    async def add_chaos_partition(self, request: Request) -> JSONResponse:
        """Add a partition rule.

        POST /sim/{sim_id}/chaos/partition
        Body: {"groups": [["node1", "node2"], ["node3", "node4"]]}
        Returns: {"rule_id": "uuid", "type": "partition"}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        engine = self._get_chaos_engine(sim_id)
        if engine is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        groups_raw = body.get("groups")
        if not groups_raw:
            return _error_response("Missing required field: groups")

        if not isinstance(groups_raw, list):
            return _error_response("groups must be a list of lists")

        try:
            groups = [set(group) for group in groups_raw]
        except TypeError:
            return _error_response("groups must be a list of lists of node IDs")

        rule = PartitionRule(groups=groups)
        engine.add_rule(rule)

        return JSONResponse({"rule_id": rule.id, "type": "partition"})

    async def add_chaos_degrade(self, request: Request) -> JSONResponse:
        """Add a degrade rule.

        POST /sim/{sim_id}/chaos/degrade
        Body: {"node_id": "node1", "rssi_penalty_db": 10}
        Returns: {"rule_id": "uuid", "type": "degrade"}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        engine = self._get_chaos_engine(sim_id)
        if engine is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        node_id = body.get("node_id")
        if not node_id:
            return _error_response("Missing required field: node_id")

        rssi_penalty_db = body.get("rssi_penalty_db")
        if rssi_penalty_db is None:
            return _error_response("Missing required field: rssi_penalty_db")

        try:
            rssi_penalty_db = float(rssi_penalty_db)
        except (TypeError, ValueError):
            return _error_response("rssi_penalty_db must be numeric")

        rule = DegradeRule(node_id=node_id, rssi_penalty_db=rssi_penalty_db)
        engine.add_rule(rule)

        return JSONResponse({"rule_id": rule.id, "type": "degrade"})

    async def add_chaos_jam(self, request: Request) -> JSONResponse:
        """Add a jammer rule.

        POST /sim/{sim_id}/chaos/jam
        Body: {"x": 0, "y": 0, "z": 0, "radius_m": 100}
        Returns: {"rule_id": "uuid", "type": "jammer"}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        engine = self._get_chaos_engine(sim_id)
        if engine is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        x = body.get("x")
        y = body.get("y")
        z = body.get("z")
        radius_m = body.get("radius_m")

        if x is None or y is None or z is None:
            return _error_response("Missing required fields: x, y, z")

        if radius_m is None:
            return _error_response("Missing required field: radius_m")

        try:
            x = float(x)
            y = float(y)
            z = float(z)
            radius_m = float(radius_m)
        except (TypeError, ValueError):
            return _error_response("Position and radius must be numeric")

        if radius_m <= 0:
            return _error_response("radius_m must be positive")

        rule = JammerRule(x=x, y=y, z=z, radius_m=radius_m)
        engine.add_rule(rule)

        return JSONResponse({"rule_id": rule.id, "type": "jammer"})

    async def clear_chaos(self, request: Request) -> JSONResponse:
        """Clear all chaos rules.

        DELETE /sim/{sim_id}/chaos
        Returns: {"status": "cleared", "rules_removed": 3}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        engine = self._get_chaos_engine(sim_id)
        if engine is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        rules_count = len(engine.get_rules())
        engine.clear()

        return JSONResponse({"status": "cleared", "rules_removed": rules_count})

    async def list_chaos(self, request: Request) -> JSONResponse:
        """List all chaos rules.

        GET /sim/{sim_id}/chaos
        Returns: {"rules": [{"id": "uuid", "type": "drop", ...}]}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        engine = self._get_chaos_engine(sim_id)
        if engine is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        rules = [_rule_to_dict(rule) for rule in engine.get_rules()]

        return JSONResponse({"rules": rules})

    async def get_topology(self, request: Request) -> JSONResponse:
        """Get network topology.

        GET /sim/{sim_id}/topology
        Returns: {"nodes": [{"id": "node1", "x": 0, "y": 0, "z": 0, "connected": true}]}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        nodes = []
        for node in sim.get_all_nodes():
            nodes.append(
                {
                    "id": node.id,
                    "x": node.position[0],
                    "y": node.position[1],
                    "z": node.position[2],
                    "connected": node.connected,
                }
            )

        return JSONResponse({"nodes": nodes})

    def create_app(self) -> Starlette:
        """Create or return cached Starlette application with all routes.

        Returns:
            Configured Starlette application (cached after first call).
        """
        if self._app is not None:
            return self._app

        routes = [
            Route("/sim", self.create_simulation, methods=["POST"]),
            Route("/sim/{sim_id}", self.get_simulation, methods=["GET"]),
            Route("/sim/{sim_id}", self.delete_simulation, methods=["DELETE"]),
            Route("/sim/{sim_id}/tick", self.tick_simulation, methods=["POST"]),
            Route("/sim/{sim_id}/node", self.add_node, methods=["POST"]),
            Route("/sim/{sim_id}/node/{node_id}", self.remove_node, methods=["DELETE"]),
            Route("/sim/{sim_id}/node/{node_id}", self.move_node, methods=["PATCH"]),
            Route("/sim/{sim_id}/chaos", self.list_chaos, methods=["GET"]),
            Route("/sim/{sim_id}/chaos", self.clear_chaos, methods=["DELETE"]),
            Route("/sim/{sim_id}/chaos/drop", self.add_chaos_drop, methods=["POST"]),
            Route(
                "/sim/{sim_id}/chaos/partition",
                self.add_chaos_partition,
                methods=["POST"],
            ),
            Route(
                "/sim/{sim_id}/chaos/degrade",
                self.add_chaos_degrade,
                methods=["POST"],
            ),
            Route("/sim/{sim_id}/chaos/jam", self.add_chaos_jam, methods=["POST"]),
            Route("/sim/{sim_id}/topology", self.get_topology, methods=["GET"]),
            Route("/sim/{sim_id}/metrics", self.get_metrics, methods=["GET"]),
        ]
        self._app = Starlette(routes=routes)
        return self._app
