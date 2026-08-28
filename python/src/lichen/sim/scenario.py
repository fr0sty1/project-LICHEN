# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Scenario DSL for LICHEN simulator.

YAML-based scenario scripting with Python escape hatch.

Example scenario file:
```yaml
name: stress-test
topology:
  type: grid
  n: 9
  spacing: 100

events:
  - at: 0s
    spawn: [node-0, node-1, node-2]
  - at: 30s
    kill: node-5
  - at: 60s
    move:
      node: node-1
      to: [200, 0, 0]
  - at: 90s
    mobility:
      node: node-2
      pattern: random_waypoint
      params:
        area_bounds: [0, 500, 0, 500]
        speed_m_s: 2.0
        seed: 42
  - at: 120s
    chaos:
      type: loss
      node: node-0
      rate: 0.1
  - at: 180s
    python: |
      from lora_medium import LossRule
      if sim.metrics.delivery_rate < 0.8 and sim.chaos_engine:
          sim.chaos_engine.add_rule(LossRule(node_id="node-0", loss_probability=0.2))
```
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from lichen.sim import topology as topo
from lichen.sim.mobility import MobilityManager, MobilityPattern, RandomWaypoint

if TYPE_CHECKING:
    from lichen.sim.simulation import Simulation


def parse_duration(s: str) -> int:
    """Parse duration string to microseconds.

    Supports: 100us, 5ms, 30s, 2m, 1h
    """
    match = re.match(r"^(\d+(?:\.\d+)?)\s*(us|ms|s|m|h)$", s.strip())
    if not match:
        raise ValueError(f"Invalid duration: {s}")
    value, unit = float(match.group(1)), match.group(2)
    multipliers = {"us": 1, "ms": 1000, "s": 1_000_000, "m": 60_000_000, "h": 3_600_000_000}
    return int(value * multipliers[unit])


def format_duration(us: int) -> str:
    """Format microseconds as a human-readable duration string.

    Chooses the most readable unit (us, ms, s, m, h).

    Args:
        us: Duration in microseconds.

    Returns:
        Human-readable duration string (e.g., "100us", "5ms", "30s").
    """
    if us < 1000:
        return f"{us}us"
    if us < 1_000_000:
        ms = us / 1000
        return f"{int(ms)}ms" if ms == int(ms) else f"{ms}ms"
    if us < 60_000_000:
        s = us / 1_000_000
        return f"{int(s)}s" if s == int(s) else f"{s}s"
    if us < 3_600_000_000:
        m = us / 60_000_000
        return f"{int(m)}m" if m == int(m) else f"{m}m"
    h = us / 3_600_000_000
    return f"{int(h)}h" if h == int(h) else f"{h}h"


@dataclass
class ScenarioEvent:
    """A single event in a scenario timeline."""

    time_us: int
    action: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass
class RecordedEvent:
    """A recorded simulation event for replay.

    Unlike ScenarioEvent (which describes actions to take), RecordedEvent
    captures observations from the simulation (transmissions, receptions, etc.).
    """

    time_us: int
    event_type: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a dictionary for YAML serialization."""
        result: dict[str, Any] = {"at": format_duration(self.time_us)}
        result[self.event_type] = self.params if self.params else True
        return result


@dataclass
class Scenario:
    """A parsed scenario with topology and events."""

    name: str
    topology_type: str
    topology_params: dict[str, Any]
    events: list[ScenarioEvent]

    @classmethod
    def from_yaml(cls, yaml_str: str) -> Scenario:
        """Parse a YAML scenario string."""
        data = yaml.safe_load(yaml_str)
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: str | Path) -> Scenario:
        """Load scenario from a YAML file."""
        with open(path) as f:
            return cls.from_yaml(f.read())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scenario:
        """Parse a scenario from a dictionary."""
        name = data.get("name", "unnamed")

        # Parse topology
        topo_data = data.get("topology", {})
        if isinstance(topo_data, str):
            # Simple form: "grid(9, 100)"
            topo_type, topo_params = _parse_topology_string(topo_data)
        else:
            topo_type = topo_data.get("type", "grid")
            topo_params = {k: v for k, v in topo_data.items() if k != "type"}

        # Parse events
        events = []
        for ev in data.get("events", []):
            time_us = parse_duration(str(ev["at"]))
            # Determine action type
            if "spawn" in ev:
                events.append(ScenarioEvent(time_us, "spawn", {"nodes": ev["spawn"]}))
            elif "kill" in ev:
                nodes = ev["kill"] if isinstance(ev["kill"], list) else [ev["kill"]]
                events.append(ScenarioEvent(time_us, "kill", {"nodes": nodes}))
            elif "move" in ev:
                move = ev["move"]
                params: dict[str, Any] = {"node": move["node"], "to": tuple(move["to"])}
                if "duration" in move:
                    params["duration_us"] = parse_duration(str(move["duration"]))
                events.append(ScenarioEvent(time_us, "move", params))
            elif "mobility" in ev:
                events.append(
                    ScenarioEvent(time_us, "mobility", _parse_mobility_params(ev["mobility"]))
                )
            elif "chaos" in ev:
                events.append(ScenarioEvent(time_us, "chaos", ev["chaos"]))
            elif "python" in ev:
                events.append(ScenarioEvent(time_us, "python", {"code": ev["python"]}))
            else:
                raise ValueError(f"Unknown event type: {ev}")

        # Sort by time
        events.sort(key=lambda e: e.time_us)

        return cls(
            name=name,
            topology_type=topo_type,
            topology_params=topo_params,
            events=events,
        )


def _parse_topology_string(s: str) -> tuple[str, dict[str, Any]]:
    """Parse 'grid(9, spacing=100)' format."""
    match = re.match(r"(\w+)\((.*)\)", s.strip())
    if not match:
        return s, {}
    name, args_str = match.groups()
    params: dict[str, Any] = {}
    if args_str.strip():
        for i, arg in enumerate(args_str.split(",")):
            arg = arg.strip()
            if "=" in arg:
                k, v = arg.split("=", 1)
                params[k.strip()] = _parse_value(v.strip())
            else:
                # Positional arg - map to known param names
                param_names = {
                    "grid": ["n", "spacing"],
                    "line": ["n", "spacing"],
                    "random_disk": ["n", "radius"],
                    "star": ["n", "radius"],
                }
                names = param_names.get(name, [])
                if i < len(names):
                    params[names[i]] = _parse_value(arg)
    return name, params


def _parse_value(s: str) -> int | float | str:
    """Parse a value string to int, float, or string."""
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _make_random_waypoint(params: dict[str, Any]) -> RandomWaypoint:
    """Build a RandomWaypoint, normalizing area_bounds to a tuple."""
    bounds = params.get("area_bounds")
    if bounds is not None:
        params = {**params, "area_bounds": tuple(bounds)}
    return RandomWaypoint(**params)


# Named mobility pattern factories for the mobility scenario event.
# Values are callables taking pattern params as keyword arguments.
MOBILITY_PATTERNS: dict[str, Callable[[dict[str, Any]], MobilityPattern]] = {
    "random_waypoint": _make_random_waypoint,
}


def _parse_mobility_params(mobility: Any) -> dict[str, Any]:
    """Parse and validate a mobility event payload.

    Attach form: {node: <id>, pattern: <name>, params: {...}}.
    Detach form: {node: <id>, pattern: null}.

    Raises:
        ValueError: If the payload is malformed.
    """
    if not isinstance(mobility, dict):
        raise ValueError(f"mobility event must be a mapping: {mobility}")
    node_id = mobility.get("node")
    if not isinstance(node_id, str) or not node_id:
        raise ValueError(f"mobility event requires a non-empty 'node': {mobility}")
    pattern_name = mobility.get("pattern")
    if pattern_name is None:
        if mobility.get("params") is not None:
            raise ValueError(f"mobility detach event must not include 'params': {mobility}")
        return {"node": node_id, "pattern": None}
    if not isinstance(pattern_name, str):
        raise ValueError(f"mobility 'pattern' must be a string: {mobility}")
    params = mobility.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValueError(f"mobility 'params' must be a mapping: {mobility}")
    return {"node": node_id, "pattern": pattern_name, "params": dict(params)}


class ScenarioRunner:
    """Runs a scenario against a simulation."""

    def __init__(self, sim: Simulation, scenario: Scenario) -> None:
        self.sim = sim
        self.scenario = scenario
        self._event_index = 0
        self._paused = False
        self._stopped = False
        # Active interpolations: node_id -> (start_pos, end_pos, start_time_us, end_time_us)
        self._active_moves: dict[
            str, tuple[tuple[float, float, float], tuple[float, float, float], int, int]
        ] = {}
        # Attached mobility patterns, stepped by elapsed time on each step()
        self.mobility_manager = MobilityManager()
        self._last_step_time_us = 0

    def pause(self) -> None:
        """Pause scenario execution. Events will not be processed until resume()."""
        self._paused = True

    def resume(self) -> None:
        """Resume scenario execution after pause()."""
        self._paused = False

    def stop(self) -> None:
        """Stop scenario execution. Cannot be resumed."""
        self._stopped = True
        self._active_moves.clear()
        self.mobility_manager.clear()

    @property
    def is_paused(self) -> bool:
        """Return True if scenario is paused."""
        return self._paused

    @property
    def is_stopped(self) -> bool:
        """Return True if scenario has been stopped."""
        return self._stopped

    def setup_topology(self) -> list[str]:
        """Apply the scenario's topology to the simulation."""
        topo_func = getattr(topo, self.scenario.topology_type, None)
        if topo_func is None:
            raise ValueError(f"Unknown topology type: {self.scenario.topology_type}")
        positions = topo_func(**self.scenario.topology_params)
        return topo.apply_topology(self.sim, positions)

    def get_pending_events(self, current_time_us: int) -> list[ScenarioEvent]:
        """Get events that should fire at or before current_time_us."""
        pending = []
        while self._event_index < len(self.scenario.events):
            ev = self.scenario.events[self._event_index]
            if ev.time_us <= current_time_us:
                pending.append(ev)
                self._event_index += 1
            else:
                break
        return pending

    def execute_event(self, event: ScenarioEvent, current_time_us: int = 0) -> None:
        """Execute a single scenario event."""
        if event.action == "spawn":
            for node_id in event.params["nodes"]:
                if self.sim.get_node(node_id) is None:
                    self.sim.add_node(node_id, 0.0, 0.0, 0.0)
        elif event.action == "kill":
            for node_id in event.params["nodes"]:
                self.sim.remove_node(node_id)
        elif event.action == "move":
            self._execute_move(event, current_time_us)
        elif event.action == "mobility":
            self._execute_mobility(event)
        elif event.action == "chaos":
            self._apply_chaos(event.params)
        elif event.action == "python":
            self._exec_python(event.params["code"])
        else:
            raise ValueError(f"Unknown action: {event.action}")

    def _execute_move(self, event: ScenarioEvent, current_time_us: int) -> None:
        """Execute a move event, either instant or interpolated."""
        node_id = event.params["node"]
        end_pos = event.params["to"]
        duration_us = event.params.get("duration_us")

        if duration_us is None or duration_us <= 0:
            # Instant teleport
            x, y, z = end_pos
            self.sim.update_position(node_id, x, y, z)
        else:
            # Start smooth interpolation
            node = self.sim.get_node(node_id)
            if node is not None:
                start_pos = (node.x, node.y, node.z)
                end_time_us = event.time_us + duration_us
                self._active_moves[node_id] = (start_pos, end_pos, event.time_us, end_time_us)

    def _update_interpolations(self, current_time_us: int) -> None:
        """Update all active move interpolations."""
        completed = []
        for node_id, (start_pos, end_pos, start_time, end_time) in self._active_moves.items():
            if current_time_us >= end_time:
                # Move complete
                x, y, z = end_pos
                self.sim.update_position(node_id, x, y, z)
                completed.append(node_id)
            else:
                # Interpolate
                t = (current_time_us - start_time) / (end_time - start_time)
                t = max(0.0, min(1.0, t))  # Clamp to [0, 1]
                x = start_pos[0] + t * (end_pos[0] - start_pos[0])
                y = start_pos[1] + t * (end_pos[1] - start_pos[1])
                z = start_pos[2] + t * (end_pos[2] - start_pos[2])
                self.sim.update_position(node_id, x, y, z)

        for node_id in completed:
            del self._active_moves[node_id]

    def _execute_mobility(self, event: ScenarioEvent) -> None:
        """Attach or detach a mobility pattern for a node.

        Args:
            event: Mobility event params:
                - node: Node ID to attach to or detach from.
                - pattern: Registered pattern name (MOBILITY_PATTERNS key)
                  to attach, or None to detach.
                - params: Keyword arguments for the pattern constructor.

        Raises:
            ValueError: If the pattern name is not registered or the
                params are invalid for the pattern.
        """
        node_id = event.params["node"]
        pattern_name = event.params["pattern"]
        if pattern_name is None:
            self.mobility_manager.detach(node_id)
            return
        factory = MOBILITY_PATTERNS.get(pattern_name)
        if factory is None:
            raise ValueError(f"Unknown mobility pattern: {pattern_name}")
        params = event.params.get("params", {})
        try:
            pattern = factory(params)
        except TypeError as exc:
            raise ValueError(
                f"Invalid params for mobility pattern '{pattern_name}': {exc}"
            ) from exc
        self.mobility_manager.attach(node_id, pattern)

    def _step_mobility(self, current_time_us: int) -> None:
        """Advance attached mobility patterns by the elapsed time."""
        dt_us = max(0, current_time_us - self._last_step_time_us)
        self._last_step_time_us = current_time_us
        if dt_us == 0:
            return
        nodes = {node.id: node for node in self.sim.get_all_nodes()}
        self.mobility_manager.step_all(nodes, dt_us)

    def _apply_chaos(self, params: dict[str, Any]) -> None:
        """Apply a chaos rule.

        Args:
            params: Chaos event parameters. Required keys depend on type:
                - type: "loss" or "partition"
                - For "loss": node (str), rate (float, default 0.1)
                - For "partition": groups (list of node ID sets)

        Raises:
            ValueError: If chaos type is unknown or required params are missing.
            RuntimeError: If no chaos engine is configured on the simulation.
        """
        if self.sim.chaos_engine is None:
            raise RuntimeError("Cannot apply chaos rule: no chaos engine configured")

        chaos_type = params.get("type")
        if chaos_type == "loss":
            from lora_medium import LossRule

            node_id = params.get("node")
            if node_id is None:
                raise ValueError("Chaos type 'loss' requires 'node' parameter")
            rule = LossRule(
                node_id=node_id,
                loss_probability=params.get("rate", 0.1),
            )
            self.sim.chaos_engine.add_rule(rule)
        elif chaos_type == "partition":
            from lora_medium import PartitionRule

            rule = PartitionRule(groups=params.get("groups", []))
            self.sim.chaos_engine.add_rule(rule)
        else:
            raise ValueError(f"Unknown chaos type: {chaos_type}")

    def _exec_python(self, code: str) -> None:
        """Execute Python code with sim in scope."""
        # ponytail: exec is intentional escape hatch, not a security boundary
        exec(code, {"sim": self.sim, "topo": topo})  # noqa: S102

    def step(self, current_time_us: int) -> int:
        """Process pending events and return count executed.

        Returns 0 if paused or stopped. Updates active move interpolations
        and advances attached mobility patterns by the elapsed time.
        """
        if self._stopped or self._paused:
            # Freeze the mobility clock so resumed patterns do not jump
            self._last_step_time_us = current_time_us
            return 0

        # Update active move interpolations
        self._update_interpolations(current_time_us)

        # Advance attached mobility patterns
        self._step_mobility(current_time_us)

        # Process new events
        events = self.get_pending_events(current_time_us)
        for ev in events:
            self.execute_event(ev, current_time_us)
        return len(events)

    def is_complete(self) -> bool:
        """Check if all events have been processed and interpolations finished."""
        if self._stopped:
            return True
        return self._event_index >= len(self.scenario.events) and not self._active_moves

    def has_active_moves(self) -> bool:
        """Check if there are active move interpolations in progress."""
        return bool(self._active_moves)


class ScenarioRecorder:
    """Records simulation events as they occur for later replay.

    Implements the SimulationObserver protocol to capture all observable
    events (transmissions, receptions, collisions, node lifecycle) during
    a simulation run. The recording can be exported to YAML and replayed
    for regression testing.

    Example usage:
        sim = Simulation("test", seed=42)
        recorder = ScenarioRecorder(name="my-test")
        sim.add_observer(recorder)
        # ... run simulation ...
        yaml_str = recorder.to_yaml()
    """

    def __init__(
        self,
        name: str = "recorded",
        topology_type: str = "none",
        topology_params: dict[str, Any] | None = None,
    ) -> None:
        """Initialize a scenario recorder.

        Args:
            name: Name for the recorded scenario.
            topology_type: Topology type (set by ScenarioRunner if used).
            topology_params: Topology parameters.
        """
        self.name = name
        self.topology_type = topology_type
        self.topology_params = topology_params or {}
        self._events: list[RecordedEvent] = []
        self._nodes: dict[str, tuple[float, float, float]] = {}
        self._seed: int | None = None
        self._sim_id: str | None = None

    @property
    def events(self) -> list[RecordedEvent]:
        """Return the list of recorded events."""
        return self._events

    def set_seed(self, seed: int | None) -> None:
        """Record the simulation seed for deterministic replay."""
        self._seed = seed

    def set_topology(self, topo_type: str, topo_params: dict[str, Any]) -> None:
        """Record the topology configuration."""
        self.topology_type = topo_type
        self.topology_params = topo_params

    def on_tx_start(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        payload_len: int,
        time_us: int,
    ) -> None:
        """Record a transmission start event."""
        self._sim_id = sim_id
        self._events.append(
            RecordedEvent(
                time_us=time_us,
                event_type="tx_start",
                params={
                    "node_id": node_id,
                    "tx_id": tx_id,
                    "payload_len": payload_len,
                },
            )
        )

    def on_tx_end(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        time_us: int,
    ) -> None:
        """Record a transmission end event."""
        self._events.append(
            RecordedEvent(
                time_us=time_us,
                event_type="tx_end",
                params={
                    "node_id": node_id,
                    "tx_id": tx_id,
                },
            )
        )

    def on_rx_success(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        from_node_id: str,
        payload_len: int,
        rssi: int,
        snr: int,
        time_us: int,
    ) -> None:
        """Record a successful reception event."""
        self._events.append(
            RecordedEvent(
                time_us=time_us,
                event_type="rx_success",
                params={
                    "node_id": node_id,
                    "tx_id": tx_id,
                    "from_node_id": from_node_id,
                    "payload_len": payload_len,
                    "rssi": rssi,
                    "snr": snr,
                },
            )
        )

    def on_rx_timeout(
        self,
        sim_id: str,
        node_id: str,
        time_us: int,
    ) -> None:
        """Record a receive timeout event."""
        self._events.append(
            RecordedEvent(
                time_us=time_us,
                event_type="rx_timeout",
                params={"node_id": node_id},
            )
        )

    def on_collision(
        self,
        sim_id: str,
        node_id: str,
        tx_ids: list[str],
        time_us: int,
    ) -> None:
        """Record a collision event."""
        self._events.append(
            RecordedEvent(
                time_us=time_us,
                event_type="collision",
                params={
                    "node_id": node_id,
                    "tx_ids": list(tx_ids),
                },
            )
        )

    def on_node_added(
        self,
        sim_id: str,
        node_id: str,
        x: float,
        y: float,
        z: float,
    ) -> None:
        """Record a node addition event."""
        self._sim_id = sim_id
        self._nodes[node_id] = (x, y, z)
        self._events.append(
            RecordedEvent(
                time_us=0,  # Node additions happen at setup
                event_type="node_added",
                params={
                    "node_id": node_id,
                    "x": x,
                    "y": y,
                    "z": z,
                },
            )
        )

    def on_node_removed(
        self,
        sim_id: str,
        node_id: str,
    ) -> None:
        """Record a node removal event."""
        # Find the time from the most recent event, or use 0
        time_us = self._events[-1].time_us if self._events else 0
        self._nodes.pop(node_id, None)
        self._events.append(
            RecordedEvent(
                time_us=time_us,
                event_type="node_removed",
                params={"node_id": node_id},
            )
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the recording to a dictionary for YAML export.

        Returns:
            Dictionary representation of the recorded scenario.
        """
        result: dict[str, Any] = {
            "name": self.name,
            "recorded": True,
        }

        if self._seed is not None:
            result["seed"] = self._seed

        if self.topology_type != "none":
            result["topology"] = {
                "type": self.topology_type,
                **self.topology_params,
            }

        # Export initial node positions (from node_added events)
        initial_nodes = [
            ev for ev in self._events if ev.event_type == "node_added"
        ]
        if initial_nodes:
            result["initial_nodes"] = [
                {
                    "id": ev.params["node_id"],
                    "position": [ev.params["x"], ev.params["y"], ev.params["z"]],
                }
                for ev in initial_nodes
            ]

        # Export all events in chronological order
        result["recorded_events"] = [ev.to_dict() for ev in self._events]

        return result

    def to_yaml(self) -> str:
        """Export the recording to a YAML string.

        Returns:
            YAML string representation of the recorded scenario.
        """
        return yaml.dump(self.to_dict(), sort_keys=False, default_flow_style=False)

    def save(self, path: str | Path) -> None:
        """Save the recording to a YAML file.

        Args:
            path: Path to the output file.
        """
        with open(path, "w") as f:
            f.write(self.to_yaml())

    @classmethod
    def from_yaml(cls, yaml_str: str) -> ScenarioRecorder:
        """Load a recording from a YAML string.

        Args:
            yaml_str: YAML string to parse.

        Returns:
            ScenarioRecorder with the loaded events.
        """
        data = yaml.safe_load(yaml_str)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScenarioRecorder:
        """Load a recording from a dictionary.

        Args:
            data: Dictionary to parse.

        Returns:
            ScenarioRecorder with the loaded events.
        """
        topo_data = data.get("topology", {})
        if isinstance(topo_data, str):
            topo_type, topo_params = _parse_topology_string(topo_data)
        else:
            topo_type = topo_data.get("type", "none")
            topo_params = {k: v for k, v in topo_data.items() if k != "type"}

        recorder = cls(
            name=data.get("name", "loaded"),
            topology_type=topo_type,
            topology_params=topo_params,
        )
        recorder._seed = data.get("seed")

        # Parse recorded events
        for ev_data in data.get("recorded_events", []):
            time_us = parse_duration(str(ev_data["at"]))
            # Find the event type (the key that's not "at")
            for key, value in ev_data.items():
                if key != "at":
                    params = value if isinstance(value, dict) else {}
                    recorder._events.append(
                        RecordedEvent(time_us=time_us, event_type=key, params=params)
                    )
                    break

        return recorder


@dataclass
class ReplayResult:
    """Result of replaying a recorded scenario.

    Attributes:
        original: The original recording that was replayed.
        replay: The new recording from the replay run.
        matches_original: True if the replay produced identical events.
        differences: List of differences if not matching.
        metrics_snapshot: Metrics from the replay run.
    """

    original: ScenarioRecorder
    replay: ScenarioRecorder
    matches_original: bool
    differences: list[str]
    metrics_snapshot: dict[str, object]


def replay(
    recording: str | ScenarioRecorder,
    seed: int | None = None,
    advance_to_us: int | None = None,
) -> ReplayResult:
    """Replay a recorded scenario and compare results.

    Runs the recorded scenario with the same seed (if provided) and compares
    the resulting events. Useful for regression testing: if the simulation
    is deterministic, replaying with the same seed should produce identical
    events.

    Args:
        recording: YAML string or ScenarioRecorder to replay.
        seed: Seed to use for the replay. If None, uses the seed from
            the recording (if present).
        advance_to_us: Simulation time to advance to. If None, advances
            to the time of the last recorded event.

    Returns:
        ReplayResult with comparison data.
    """
    from lichen.sim.simulation import Simulation

    # Parse recording if string
    original = (
        ScenarioRecorder.from_yaml(recording)
        if isinstance(recording, str)
        else recording
    )

    # Determine seed
    replay_seed = seed if seed is not None else original._seed

    # Create simulation
    sim = Simulation("replay", seed=replay_seed)

    # Set up recorder
    replay_recorder = ScenarioRecorder(
        name=f"{original.name}-replay",
        topology_type=original.topology_type,
        topology_params=original.topology_params,
    )
    replay_recorder.set_seed(replay_seed)
    sim.add_observer(replay_recorder)

    # Replay initial nodes
    for ev in original._events:
        if ev.event_type == "node_added":
            sim.add_node(
                ev.params["node_id"],
                ev.params["x"],
                ev.params["y"],
                ev.params["z"],
            )

    # Determine end time
    if advance_to_us is not None:
        end_time = advance_to_us
    elif original._events:
        end_time = max(ev.time_us for ev in original._events)
    else:
        end_time = 0

    # Advance simulation (in steps to allow event processing)
    step_us = 1_000_000  # 1 second steps
    current_time = 0
    while current_time < end_time:
        current_time = min(current_time + step_us, end_time)
        sim.advance_to(current_time)

    # Compare events
    matches, differences = compare_recordings(original, replay_recorder)

    return ReplayResult(
        original=original,
        replay=replay_recorder,
        matches_original=matches,
        differences=differences,
        metrics_snapshot=sim.metrics.snapshot(),
    )


def compare_recordings(
    original: ScenarioRecorder,
    replay: ScenarioRecorder,
) -> tuple[bool, list[str]]:
    """Compare two recordings for differences.

    Compares event sequences, checking event types, times, and parameters.
    Node addition events are compared separately since order may vary.

    Args:
        original: The original recording.
        replay: The replay recording.

    Returns:
        Tuple of (matches, differences list). If matches is True,
        differences list is empty.
    """
    differences: list[str] = []

    # Separate node_added events (order may vary) from other events
    orig_node_events = {
        ev.params["node_id"]: ev
        for ev in original._events
        if ev.event_type == "node_added"
    }
    replay_node_events = {
        ev.params["node_id"]: ev
        for ev in replay._events
        if ev.event_type == "node_added"
    }

    # Compare node events
    orig_node_ids = set(orig_node_events.keys())
    replay_node_ids = set(replay_node_events.keys())

    if orig_node_ids != replay_node_ids:
        missing = orig_node_ids - replay_node_ids
        extra = replay_node_ids - orig_node_ids
        if missing:
            differences.append(f"Missing nodes in replay: {missing}")
        if extra:
            differences.append(f"Extra nodes in replay: {extra}")
    else:
        for node_id in orig_node_ids:
            orig_ev = orig_node_events[node_id]
            replay_ev = replay_node_events[node_id]
            if orig_ev.params != replay_ev.params:
                differences.append(
                    f"Node {node_id} position differs: "
                    f"original={orig_ev.params}, replay={replay_ev.params}"
                )

    # Compare other events (in order)
    orig_other = [ev for ev in original._events if ev.event_type != "node_added"]
    replay_other = [ev for ev in replay._events if ev.event_type != "node_added"]

    if len(orig_other) != len(replay_other):
        differences.append(
            f"Event count differs: original={len(orig_other)}, "
            f"replay={len(replay_other)}"
        )

    # Compare events pairwise (strict=False since we already report length differences)
    for i, (orig_ev, replay_ev) in enumerate(zip(orig_other, replay_other, strict=False)):
        if orig_ev.event_type != replay_ev.event_type:
            differences.append(
                f"Event {i} type differs: "
                f"original={orig_ev.event_type}, replay={replay_ev.event_type}"
            )
        elif orig_ev.time_us != replay_ev.time_us:
            differences.append(
                f"Event {i} ({orig_ev.event_type}) time differs: "
                f"original={orig_ev.time_us}us, replay={replay_ev.time_us}us"
            )
        elif orig_ev.params != replay_ev.params:
            differences.append(
                f"Event {i} ({orig_ev.event_type}) params differ: "
                f"original={orig_ev.params}, replay={replay_ev.params}"
            )

    return len(differences) == 0, differences
