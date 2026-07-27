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
  - at: 120s
    chaos:
      type: loss
      rate: 0.1
  - at: 180s
    python: |
      if sim.metrics.delivery_rate < 0.8:
          sim.chaos.add_loss(0.2)
```
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from lichen.sim import topology as topo

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


@dataclass
class ScenarioEvent:
    """A single event in a scenario timeline."""

    time_us: int
    action: str
    params: dict[str, Any] = field(default_factory=dict)


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
                events.append(
                    ScenarioEvent(
                        time_us,
                        "move",
                        {"node": move["node"], "to": tuple(move["to"])},
                    )
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
                param_names = {"grid": ["n", "spacing"], "line": ["n", "spacing"], "random_disk": ["n", "radius"], "star": ["n", "radius"]}
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


class ScenarioRunner:
    """Runs a scenario against a simulation."""

    def __init__(self, sim: Simulation, scenario: Scenario) -> None:
        self.sim = sim
        self.scenario = scenario
        self._event_index = 0

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

    def execute_event(self, event: ScenarioEvent) -> None:
        """Execute a single scenario event."""
        if event.action == "spawn":
            for node_id in event.params["nodes"]:
                if self.sim.get_node(node_id) is None:
                    self.sim.add_node(node_id, 0.0, 0.0, 0.0)
        elif event.action == "kill":
            for node_id in event.params["nodes"]:
                self.sim.remove_node(node_id)
        elif event.action == "move":
            x, y, z = event.params["to"]
            self.sim.update_position(event.params["node"], x, y, z)
        elif event.action == "chaos":
            self._apply_chaos(event.params)
        elif event.action == "python":
            self._exec_python(event.params["code"])
        else:
            raise ValueError(f"Unknown action: {event.action}")

    def _apply_chaos(self, params: dict[str, Any]) -> None:
        """Apply a chaos rule."""
        chaos_type = params.get("type")
        if chaos_type == "loss":
            from lichen.sim.chaos import LossRule

            rule = LossRule(loss_probability=params.get("rate", 0.1))
            self.sim.chaos.add_rule(rule)
        elif chaos_type == "partition":
            from lichen.sim.chaos import PartitionRule

            rule = PartitionRule(groups=params.get("groups", []))
            self.sim.chaos.add_rule(rule)
        else:
            raise ValueError(f"Unknown chaos type: {chaos_type}")

    def _exec_python(self, code: str) -> None:
        """Execute Python code with sim in scope."""
        # ponytail: exec is intentional escape hatch, not a security boundary
        exec(code, {"sim": self.sim, "topo": topo})  # noqa: S102

    def step(self, current_time_us: int) -> int:
        """Process pending events and return count executed."""
        events = self.get_pending_events(current_time_us)
        for ev in events:
            self.execute_event(ev)
        return len(events)

    def is_complete(self) -> bool:
        """Check if all events have been processed."""
        return self._event_index >= len(self.scenario.events)
