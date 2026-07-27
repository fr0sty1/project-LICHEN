# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for scenario DSL."""

import pytest

from lichen.sim.scenario import Scenario, parse_duration


class TestParseDuration:
    def test_microseconds(self) -> None:
        assert parse_duration("100us") == 100

    def test_milliseconds(self) -> None:
        assert parse_duration("5ms") == 5000

    def test_seconds(self) -> None:
        assert parse_duration("30s") == 30_000_000

    def test_minutes(self) -> None:
        assert parse_duration("2m") == 120_000_000

    def test_hours(self) -> None:
        assert parse_duration("1h") == 3_600_000_000

    def test_float_value(self) -> None:
        assert parse_duration("1.5s") == 1_500_000

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_duration("invalid")


class TestScenarioParsing:
    def test_basic_scenario(self) -> None:
        yaml_str = """
name: test-scenario
topology:
  type: grid
  n: 9
  spacing: 100
events:
  - at: 0s
    spawn: [node-0, node-1]
  - at: 30s
    kill: node-5
"""
        scenario = Scenario.from_yaml(yaml_str)
        assert scenario.name == "test-scenario"
        assert scenario.topology_type == "grid"
        assert scenario.topology_params["n"] == 9
        assert len(scenario.events) == 2
        assert scenario.events[0].action == "spawn"
        assert scenario.events[1].action == "kill"

    def test_topology_string_format(self) -> None:
        yaml_str = """
topology: grid(9, spacing=100)
events: []
"""
        scenario = Scenario.from_yaml(yaml_str)
        assert scenario.topology_type == "grid"
        assert scenario.topology_params["n"] == 9
        assert scenario.topology_params["spacing"] == 100

    def test_move_event(self) -> None:
        yaml_str = """
topology: line(3)
events:
  - at: 60s
    move:
      node: node-1
      to: [200, 0, 0]
"""
        scenario = Scenario.from_yaml(yaml_str)
        ev = scenario.events[0]
        assert ev.action == "move"
        assert ev.params["node"] == "node-1"
        assert ev.params["to"] == (200, 0, 0)

    def test_chaos_event(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 120s
    chaos:
      type: loss
      rate: 0.1
"""
        scenario = Scenario.from_yaml(yaml_str)
        ev = scenario.events[0]
        assert ev.action == "chaos"
        assert ev.params["type"] == "loss"
        assert ev.params["rate"] == 0.1

    def test_python_event(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 180s
    python: |
      x = 1 + 1
"""
        scenario = Scenario.from_yaml(yaml_str)
        ev = scenario.events[0]
        assert ev.action == "python"
        assert "x = 1 + 1" in ev.params["code"]

    def test_events_sorted_by_time(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    kill: node-1
  - at: 30s
    kill: node-0
  - at: 90s
    kill: node-2
"""
        scenario = Scenario.from_yaml(yaml_str)
        times = [ev.time_us for ev in scenario.events]
        assert times == sorted(times)
