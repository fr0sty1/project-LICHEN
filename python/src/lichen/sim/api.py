# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""REST API for controlling the LICHEN simulator.

This module provides a Starlette-based REST API for managing simulations,
nodes, and chaos rules programmatically.
"""

from __future__ import annotations

import json
import math
import secrets
from collections.abc import Awaitable, Callable
from typing import Any

from lora_medium import (
    ChaosEngine,
    ChaosRule,
    DegradeRule,
    DropRule,
    JammerRule,
    LatencyRule,
    PartitionRule,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket

from lichen.sim.auth import BearerAuthMiddleware, extract_websocket_token
from lichen.sim.simulation import Simulation, TimeMode
from lichen.sim.websocket import (
    WebSocketManager,
    WebSocketObserver,
    handle_websocket,
)
from lichen.timing.sfn import TDMA_GUARD_MS, TDMA_SLOT_MS

# Maximum value for integer parameters (signed 64-bit).
# Python ints have arbitrary precision, so we must bounds-check explicitly
# to avoid accepting values that would overflow in other languages or storage.
_MAX_INT64 = 2**63 - 1


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

    match rule:
        case DropRule():
            result["type"] = "drop"
            result["node_id"] = rule.node_id
            result["direction"] = rule.direction
        case PartitionRule():
            result["type"] = "partition"
            result["groups"] = [list(group) for group in rule.groups]
        case DegradeRule():
            result["type"] = "degrade"
            result["node_id"] = rule.node_id
            result["rssi_penalty_db"] = rule.rssi_penalty_db
        case JammerRule():
            result["type"] = "jammer"
            result["x"] = rule.x
            result["y"] = rule.y
            result["z"] = rule.z
            result["radius_m"] = rule.radius_m
        case LatencyRule():
            result["type"] = "latency"
            result["node_id"] = rule.node_id
            result["added_us"] = rule.added_us

    return result


class SimulatorAPI:
    """REST API controller for the LICHEN simulator.

    Manages multiple simulation instances with their associated chaos engines.
    Provides endpoints for creating/deleting simulations, managing nodes,
    applying chaos rules, and observing topology.
    """

    def __init__(
        self,
        on_simulation_created: Callable[[str], Awaitable[None]] | None = None,
        on_simulation_deleted: Callable[[str], Awaitable[None]] | None = None,
        api_token: str | None = None,
    ) -> None:
        """Initialize the API with empty simulation and chaos engine stores.

        Args:
            on_simulation_created: Optional async callback invoked with the
                simulation ID after a simulation is created via the REST API.
            on_simulation_deleted: Optional async callback invoked with the
                simulation ID just before a simulation is deleted via the API.
            api_token: Optional bearer token for API authentication. When set,
                all requests must include ``Authorization: Bearer <token>``
                header. WebSocket connections use ``Sec-WebSocket-Protocol:
                bearer.<token>`` to avoid exposing the token in URLs.
        """
        self._simulations: dict[str, Simulation] = {}
        self._chaos_engines: dict[str, ChaosEngine] = {}
        self._ws_observers: dict[str, WebSocketObserver] = {}
        self._ws_manager = WebSocketManager()
        self._app: Starlette | None = None
        self._on_simulation_created = on_simulation_created
        self._on_simulation_deleted = on_simulation_deleted
        self._api_token = api_token

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

        # Register WebSocket observer for real-time event streaming
        ws_observer = WebSocketObserver(self._ws_manager, sim_id)
        sim.add_observer(ws_observer)
        self._ws_observers[sim_id] = ws_observer

        if self._on_simulation_created is not None:
            await self._on_simulation_created(sim_id)

        return JSONResponse({"id": sim_id, "status": "created"})

    async def delete_simulation(self, request: Request) -> JSONResponse:
        """Delete a simulation.

        DELETE /sim/{sim_id}
        Returns: {"status": "deleted"}
        """
        sim_id = request.path_params["sim_id"]

        if sim_id not in self._simulations:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        if self._on_simulation_deleted is not None:
            await self._on_simulation_deleted(sim_id)

        # Remove WebSocket observer
        ws_observer = self._ws_observers.pop(sim_id, None)
        if ws_observer is not None:
            sim = self._simulations.get(sim_id)
            if sim is not None:
                sim.remove_observer(ws_observer)

        del self._simulations[sim_id]
        self._chaos_engines.pop(sim_id, None)

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

    async def get_dashboard_metrics(self, request: Request) -> JSONResponse:
        """Get dashboard metrics with time-series data for visualization.

        GET /sim/{sim_id}/metrics/dashboard
        Query params:
          - since_us: Optional. Only return time-series samples after this time.
        Returns: {
            "current": {
                "delivery_rate": 0.95,
                "collision_rate": 0.02,
                "duty_cycle": 0.008,
                "transmissions": 150,
                "receptions": 142,
                "collisions": 3
            },
            "time_series": [
                {"time_us": 1000000, "delivery_rate": 0.9, ...},
                ...
            ],
            "last_sample_time_us": 5000000
        }
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        since_us: int | None = None
        since_param = request.query_params.get("since_us")
        if since_param is not None:
            try:
                since_us = int(since_param)
            except (TypeError, ValueError, OverflowError):
                return _error_response("since_us must be an integer")
            if abs(since_us) > _MAX_INT64:
                return _error_response("since_us must be an integer")

        return JSONResponse(sim.metrics.get_dashboard_snapshot(since_us))

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
        except (TypeError, ValueError, OverflowError):
            return _error_response("Position coordinates must be numeric")
        if not all(math.isfinite(v) for v in (x, y, z)):
            return _error_response("Position coordinates must be finite numbers")

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
        except (TypeError, ValueError, OverflowError):
            return _error_response("Position coordinates must be numeric")
        if not all(math.isfinite(v) for v in (x, y, z)):
            return _error_response("Position coordinates must be finite numbers")

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

        rule = DropRule(node_id=node_id, direction=direction)
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

        for group in groups:
            if not all(isinstance(item, str) for item in group):
                return _error_response("All node IDs in groups must be strings")

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
        except (TypeError, ValueError, OverflowError):
            return _error_response("rssi_penalty_db must be numeric")
        if not math.isfinite(rssi_penalty_db):
            return _error_response("rssi_penalty_db must be a finite number")

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
        except (TypeError, ValueError, OverflowError):
            return _error_response("Position and radius must be numeric")
        if not all(math.isfinite(v) for v in (x, y, z, radius_m)):
            return _error_response("Position and radius must be finite numbers")

        if radius_m <= 0:
            return _error_response("radius_m must be positive")

        rule = JammerRule(x=x, y=y, z=z, radius_m=radius_m)
        engine.add_rule(rule)

        return JSONResponse({"rule_id": rule.id, "type": "jammer"})

    async def add_chaos_latency(self, request: Request) -> JSONResponse:
        """Add a latency rule.

        POST /sim/{sim_id}/chaos/latency
        Body: {"node_id": "n1", "added_us": 5000}
        Returns: {"rule_id": "uuid", "type": "latency"}
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
        added_us = body.get("added_us")

        if node_id is None:
            return _error_response("Missing required field: node_id")
        if added_us is None:
            return _error_response("Missing required field: added_us")

        try:
            added_us = int(added_us)
        except (TypeError, ValueError, OverflowError):
            return _error_response("added_us must be an integer")
        if abs(added_us) > _MAX_INT64:
            return _error_response("added_us must be an integer")

        if added_us <= 0:
            return _error_response("added_us must be positive")

        rule = LatencyRule(node_id=node_id, added_us=added_us)
        engine.add_rule(rule)

        return JSONResponse({"rule_id": rule.id, "type": "latency"})

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

    async def get_playback(self, request: Request) -> JSONResponse:
        """Get playback state.

        GET /sim/{sim_id}/playback
        Returns: {"paused": false, "speed": 1.0, "time_us": 0}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        return JSONResponse(
            {
                **sim.playback.to_dict(),
                "time_us": sim.current_time_us,
            }
        )

    async def set_playback(self, request: Request) -> JSONResponse:
        """Update playback state.

        PATCH /sim/{sim_id}/playback
        Body: {"speed": 2.0} or {"jump_to_us": 1000000}
        Returns: {"paused": false, "speed": 2.0, "time_us": 1000000}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        try:
            body = await request.json()
        except json.JSONDecodeError:
            return _error_response("Invalid JSON body")

        # Handle speed change
        if "speed" in body:
            speed = body["speed"]
            try:
                speed = float(speed)
            except (TypeError, ValueError, OverflowError):
                return _error_response("speed must be a number")
            if not math.isfinite(speed):
                return _error_response("speed must be a finite number")
            if speed <= 0:
                return _error_response("speed must be positive")
            sim.playback.speed = speed

        # Handle jump to time
        if "jump_to_us" in body:
            jump_to_us = body["jump_to_us"]
            # Reject booleans explicitly (bool is a subclass of int in Python)
            if isinstance(jump_to_us, bool):
                return _error_response("jump_to_us must be a non-negative integer")
            try:
                jump_to_us = int(jump_to_us)
            except (TypeError, ValueError, OverflowError):
                return _error_response("jump_to_us must be a non-negative integer")
            if abs(jump_to_us) > _MAX_INT64:
                return _error_response("jump_to_us must be a non-negative integer")
            if jump_to_us < 0:
                return _error_response("jump_to_us must be a non-negative integer")
            if jump_to_us < sim.current_time_us:
                return _error_response(
                    f"Cannot jump backwards: {jump_to_us} < {sim.current_time_us}"
                )
            sim.advance_to(jump_to_us)

        return JSONResponse(
            {
                **sim.playback.to_dict(),
                "time_us": sim.current_time_us,
            }
        )

    async def playback_play(self, request: Request) -> JSONResponse:
        """Resume simulation playback.

        POST /sim/{sim_id}/playback/play
        Returns: {"paused": false, "speed": 1.0, "time_us": 0}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        sim.playback.paused = False

        return JSONResponse(
            {
                **sim.playback.to_dict(),
                "time_us": sim.current_time_us,
            }
        )

    async def playback_pause(self, request: Request) -> JSONResponse:
        """Pause simulation playback.

        POST /sim/{sim_id}/playback/pause
        Returns: {"paused": true, "speed": 1.0, "time_us": 0}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        sim.playback.paused = True

        return JSONResponse(
            {
                **sim.playback.to_dict(),
                "time_us": sim.current_time_us,
            }
        )

    async def playback_step(self, request: Request) -> JSONResponse:
        """Step simulation by processing one event.

        POST /sim/{sim_id}/playback/step
        Returns: {"paused": true, "speed": 1.0, "time_us": 1000, "event_processed": true}
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        # Pause and process one event
        sim.playback.paused = True
        event = sim.process_next_event()

        return JSONResponse(
            {
                **sim.playback.to_dict(),
                "time_us": sim.current_time_us,
                "event_processed": event is not None,
            }
        )

    async def get_topology(self, request: Request) -> JSONResponse:
        """Get network topology.

        GET /sim/{sim_id}/topology
        Returns: {"nodes": [{"id": "...", "x": 0, "y": 0, "z": 0,
                            "connected": true, "state": "IDLE"}]}
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
                    "state": node.state.name,
                }
            )

        return JSONResponse({"nodes": nodes})

    async def get_links(self, request: Request) -> JSONResponse:
        """Get link quality between all node pairs.

        GET /sim/{sim_id}/links
        Optional query params:
            - threshold_db: minimum RSSI to include link (default: -137 dBm)

        Returns: {
            "links": [
                {
                    "from": "node1",
                    "to": "node2",
                    "distance_m": 150.5,
                    "rssi_forward_dbm": -95.2,
                    "rssi_reverse_dbm": -97.1,
                    "snr_forward_db": 24.8,
                    "snr_reverse_db": 22.9,
                    "reachable_forward": true,
                    "reachable_reverse": true,
                    "asymmetric": true,
                    "quality": "good"
                }
            ]
        }

        Quality levels based on RSSI margin above sensitivity (-132 dBm for SF10):
        - "excellent": margin >= 20 dB
        - "good": margin >= 10 dB
        - "fair": margin >= 3 dB
        - "poor": margin >= 0 dB (barely decodable)
        - "none": below sensitivity

        Asymmetric links have >3 dB difference between forward and reverse RSSI.
        """
        from lora_medium import SENSITIVITY_SF10

        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        # Parse optional threshold
        threshold_str = request.query_params.get("threshold_db", "-137")
        try:
            threshold_db = float(threshold_str)
        except (TypeError, ValueError, OverflowError):
            return _error_response("threshold_db must be a number")

        nodes = sim.get_all_nodes()
        propagation = sim.medium.propagation
        links: list[dict[str, Any]] = []

        # Compute link quality for all unique pairs
        for i, node_a in enumerate(nodes):
            for node_b in nodes[i + 1 :]:
                # Calculate distance
                dx = node_b.position[0] - node_a.position[0]
                dy = node_b.position[1] - node_a.position[1]
                dz = node_b.position[2] - node_a.position[2]
                distance_m = math.sqrt(dx * dx + dy * dy + dz * dz)

                if distance_m <= 0:
                    distance_m = 0.001

                # Forward direction: A -> B (using A's TX power)
                rssi_forward = propagation.received_power(node_a.tx_power_dbm, distance_m)
                snr_forward = rssi_forward - propagation.noise_floor_dbm

                # Reverse direction: B -> A (using B's TX power)
                rssi_reverse = propagation.received_power(node_b.tx_power_dbm, distance_m)
                snr_reverse = rssi_reverse - propagation.noise_floor_dbm

                # Skip links below threshold
                max_rssi = max(rssi_forward, rssi_reverse)
                if max_rssi < threshold_db:
                    continue

                # Determine reachability
                reachable_forward = rssi_forward >= SENSITIVITY_SF10
                reachable_reverse = rssi_reverse >= SENSITIVITY_SF10

                # Calculate asymmetry (>3 dB difference)
                rssi_diff = abs(rssi_forward - rssi_reverse)
                asymmetric = rssi_diff > 3.0

                # Quality classification based on margin above sensitivity
                margin = max_rssi - SENSITIVITY_SF10
                if margin >= 20:
                    quality = "excellent"
                elif margin >= 10:
                    quality = "good"
                elif margin >= 3:
                    quality = "fair"
                elif margin >= 0:
                    quality = "poor"
                else:
                    quality = "none"

                links.append(
                    {
                        "from": node_a.id,
                        "to": node_b.id,
                        "distance_m": round(distance_m, 2),
                        "rssi_forward_dbm": round(rssi_forward, 1),
                        "rssi_reverse_dbm": round(rssi_reverse, 1),
                        "snr_forward_db": round(snr_forward, 1),
                        "snr_reverse_db": round(snr_reverse, 1),
                        "reachable_forward": reachable_forward,
                        "reachable_reverse": reachable_reverse,
                        "asymmetric": asymmetric,
                        "quality": quality,
                    }
                )

        return JSONResponse({"links": links})

    async def get_tdma_slots(self, request: Request) -> JSONResponse:
        """Get TDMA slot assignments for all nodes.

        GET /sim/{sim_id}/tdma
        Returns: {
            "superframe": {
                "sfn": 0,
                "num_slots": 8,
                "slot_duration_ms": 2346,
                "guard_ms": 50
            },
            "slots": [
                {"slot": 0, "nodes": [{"id": "n1", "state": "SYNCED"}]},
                {"slot": 1, "nodes": []},
                ...
            ],
            "conflicts": [
                {"slot": 2, "nodes": ["n3", "n4"], "reason": "multiple_assignment"}
            ],
            "nodes": [
                {"id": "n1", "assigned_slot": 0, "state": "SYNCED", "drift_us": 0}
            ]
        }
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        all_nodes = sim.get_all_nodes()

        # Get TDMA parameters from first node or use defaults
        num_slots = 8
        slot_duration_ms = TDMA_SLOT_MS
        guard_ms = TDMA_GUARD_MS
        current_sfn = 0

        if all_nodes:
            sched = all_nodes[0].tdma_scheduler
            num_slots = sched.num_slots
            slot_duration_ms = sched.slot_duration_ms
            guard_ms = sched.guard_ms
            current_sfn = sched.clock.sfn

        # Build slot assignments
        slot_assignments: dict[int, list[dict[str, str]]] = {
            i: [] for i in range(num_slots)
        }
        node_info = []

        for node in all_nodes:
            sched = node.tdma_scheduler
            slot = sched.assigned_slot
            state_name = sched.state.name
            drift_us = sched.apply_drift(sim.current_time_us)

            if 0 <= slot < num_slots:
                slot_assignments[slot].append({
                    "id": node.id,
                    "state": state_name,
                })

            node_info.append({
                "id": node.id,
                "assigned_slot": slot,
                "state": state_name,
                "drift_us": drift_us,
            })

        # Build slot list with utilization
        slots = []
        for i in range(num_slots):
            slots.append({
                "slot": i,
                "nodes": slot_assignments[i],
            })

        # Detect conflicts (multiple nodes in same slot)
        conflicts = []
        for i in range(num_slots):
            assigned_nodes = slot_assignments[i]
            synced_nodes = [n for n in assigned_nodes if n["state"] == "SYNCED"]
            if len(synced_nodes) > 1:
                conflicts.append({
                    "slot": i,
                    "nodes": [n["id"] for n in synced_nodes],
                    "reason": "multiple_assignment",
                })

        return JSONResponse({
            "superframe": {
                "sfn": current_sfn,
                "num_slots": num_slots,
                "slot_duration_ms": slot_duration_ms,
                "guard_ms": guard_ms,
            },
            "slots": slots,
            "conflicts": conflicts,
            "nodes": node_info,
        })

    async def get_active_transmissions(self, request: Request) -> JSONResponse:
        """Get active transmissions with visualization data.

        GET /sim/{sim_id}/transmissions
        Returns: {
            "time_us": 1000000,
            "transmissions": [
                {
                    "tx_id": "uuid",
                    "source_node_id": "node1",
                    "x": 100.0,
                    "y": 200.0,
                    "z": 0.0,
                    "start_time_us": 900000,
                    "end_time_us": 1100000,
                    "duration_us": 200000,
                    "progress": 0.5,
                    "max_range_m": 1500.0,
                    "current_radius_m": 750.0,
                    "payload_len": 50,
                    "channel": 0
                }
            ]
        }

        The progress field (0.0 to 1.0) indicates how far through the
        transmission we are. current_radius_m shows the propagation
        wavefront position, computed as progress * max_range_m.
        """
        sim_id = request.path_params["sim_id"]
        sim = self._get_simulation(sim_id)

        if sim is None:
            return _error_response(f"Simulation '{sim_id}' not found", status_code=404)

        current_time = sim.current_time_us
        active_txs = sim.medium.get_active_transmissions(current_time)
        propagation = sim.medium.propagation

        transmissions = []
        for tx in active_txs:
            # Get transmitter position
            tx_pos = sim.medium._tx_positions.get(tx.id)
            if tx_pos is None:
                continue

            # Compute propagation data
            duration_us = tx.end_time_us - tx.start_time_us
            elapsed_us = current_time - tx.start_time_us
            progress = min(1.0, max(0.0, elapsed_us / duration_us)) if duration_us > 0 else 1.0
            max_range_m = propagation.max_range(tx.tx_power_dbm)
            current_radius_m = progress * max_range_m

            transmissions.append({
                "tx_id": tx.id,
                "source_node_id": tx.source_node_id,
                "x": tx_pos[0],
                "y": tx_pos[1],
                "z": tx_pos[2],
                "start_time_us": tx.start_time_us,
                "end_time_us": tx.end_time_us,
                "duration_us": duration_us,
                "progress": round(progress, 3),
                "max_range_m": round(max_range_m, 1),
                "current_radius_m": round(current_radius_m, 1),
                "payload_len": len(tx.payload),
                "channel": tx.channel,
            })

        return JSONResponse({
            "time_us": current_time,
            "transmissions": transmissions,
        })

    async def websocket_endpoint(self, websocket: WebSocket) -> None:
        """WebSocket endpoint for real-time simulation events.

        GET /sim/{sim_id}/ws

        Protocol:
        - Server sends events as JSON: {"event": "tx_start", ...}
        - Client can send commands:
          - {"cmd": "subscribe", "events": ["tx_start", "rx_success"]}
          - {"cmd": "unsubscribe", "events": ["collision"]}
          - {"cmd": "ping"} -> {"event": "pong"}
        """
        sim_id = websocket.path_params["sim_id"]

        # BaseHTTPMiddleware only processes HTTP scopes, so the bearer
        # middleware used by create_app() cannot authenticate WebSockets.
        # Enforce the same configured credential explicitly before revealing
        # whether a simulation exists or accepting the connection.
        if self._api_token is not None:
            supplied_token = extract_websocket_token(websocket.scope.get("subprotocols", []))
            token_to_compare = supplied_token if supplied_token is not None else ""
            if not secrets.compare_digest(token_to_compare, self._api_token):
                await websocket.close(code=4401, reason="Unauthorized")
                return

        if sim_id not in self._simulations:
            await websocket.close(code=4004, reason=f"Simulation '{sim_id}' not found")
            return

        await handle_websocket(websocket, self._ws_manager, sim_id)

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
            Route(
                "/sim/{sim_id}/chaos/latency",
                self.add_chaos_latency,
                methods=["POST"],
            ),
            Route("/sim/{sim_id}/playback", self.get_playback, methods=["GET"]),
            Route("/sim/{sim_id}/playback", self.set_playback, methods=["PATCH"]),
            Route("/sim/{sim_id}/playback/play", self.playback_play, methods=["POST"]),
            Route("/sim/{sim_id}/playback/pause", self.playback_pause, methods=["POST"]),
            Route("/sim/{sim_id}/playback/step", self.playback_step, methods=["POST"]),
            Route("/sim/{sim_id}/topology", self.get_topology, methods=["GET"]),
            Route("/sim/{sim_id}/links", self.get_links, methods=["GET"]),
            Route("/sim/{sim_id}/metrics", self.get_metrics, methods=["GET"]),
            Route("/sim/{sim_id}/metrics/dashboard", self.get_dashboard_metrics, methods=["GET"]),
            Route("/sim/{sim_id}/tdma", self.get_tdma_slots, methods=["GET"]),
            Route("/sim/{sim_id}/transmissions", self.get_active_transmissions, methods=["GET"]),
            # WebSocket for real-time events
            WebSocketRoute("/sim/{sim_id}/ws", self.websocket_endpoint),
        ]
        self._app = Starlette(routes=routes)

        # Add authentication middleware if token is configured
        if self._api_token is not None:
            self._app.add_middleware(BearerAuthMiddleware, token=self._api_token)

        return self._app
