# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for scenario DSL."""

from unittest.mock import MagicMock

import pytest

from lichen.sim.scenario import (
    RecordedEvent,
    Scenario,
    ScenarioRecorder,
    ScenarioRunner,
    compare_recordings,
    format_duration,
    parse_duration,
    replay,
)


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

    def test_move_with_duration(self) -> None:
        yaml_str = """
topology: line(3)
events:
  - at: 60s
    move:
      node: node-1
      to: [200, 0, 0]
      duration: 10s
"""
        scenario = Scenario.from_yaml(yaml_str)
        ev = scenario.events[0]
        assert ev.action == "move"
        assert ev.params["node"] == "node-1"
        assert ev.params["to"] == (200, 0, 0)
        assert ev.params["duration_us"] == 10_000_000


class TestMobilityEventParsing:
    def test_attach_event(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    mobility:
      node: node-1
      pattern: random_waypoint
      params:
        area_bounds: [0, 500, 0, 500]
        speed_m_s: 2.0
        pause_time_us: 1000000
        seed: 42
"""
        scenario = Scenario.from_yaml(yaml_str)
        ev = scenario.events[0]
        assert ev.action == "mobility"
        assert ev.params["node"] == "node-1"
        assert ev.params["pattern"] == "random_waypoint"
        assert ev.params["params"]["area_bounds"] == [0, 500, 0, 500]
        assert ev.params["params"]["speed_m_s"] == 2.0
        assert ev.params["params"]["pause_time_us"] == 1000000
        assert ev.params["params"]["seed"] == 42

    def test_attach_without_params_defaults_empty(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    mobility:
      node: node-1
      pattern: random_waypoint
"""
        scenario = Scenario.from_yaml(yaml_str)
        ev = scenario.events[0]
        assert ev.action == "mobility"
        assert ev.params["pattern"] == "random_waypoint"
        assert ev.params["params"] == {}

    def test_detach_event(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    mobility:
      node: node-1
      pattern: null
"""
        scenario = Scenario.from_yaml(yaml_str)
        ev = scenario.events[0]
        assert ev.action == "mobility"
        assert ev.params["node"] == "node-1"
        assert ev.params["pattern"] is None

    def test_missing_node_raises(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    mobility:
      pattern: random_waypoint
"""
        with pytest.raises(ValueError):
            Scenario.from_yaml(yaml_str)

    def test_non_mapping_payload_raises(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    mobility: 42
"""
        with pytest.raises(ValueError):
            Scenario.from_yaml(yaml_str)

    def test_params_not_mapping_raises(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    mobility:
      node: node-1
      pattern: random_waypoint
      params: fast
"""
        with pytest.raises(ValueError):
            Scenario.from_yaml(yaml_str)

    def test_detach_with_params_raises(self) -> None:
        yaml_str = """
topology: grid(4)
events:
  - at: 60s
    mobility:
      node: node-1
      pattern: null
      params:
        speed_m_s: 1.0
"""
        with pytest.raises(ValueError):
            Scenario.from_yaml(yaml_str)


def _make_mock_sim() -> MagicMock:
    """Create a mock simulation for testing ScenarioRunner."""
    sim = MagicMock()
    # Mock node positions
    nodes = {}

    def get_node(node_id: str) -> MagicMock | None:
        return nodes.get(node_id)

    def add_node(node_id: str, x: float, y: float, z: float) -> MagicMock:
        node = MagicMock()
        node.x, node.y, node.z = x, y, z
        nodes[node_id] = node
        return node

    def update_position(node_id: str, x: float, y: float, z: float) -> None:
        if node_id in nodes:
            nodes[node_id].x = x
            nodes[node_id].y = y
            nodes[node_id].z = z

    def remove_node(node_id: str) -> None:
        nodes.pop(node_id, None)

    sim.get_node = get_node
    sim.add_node = add_node
    sim.update_position = update_position
    sim.remove_node = remove_node
    return sim


class TestScenarioRunnerLifecycle:
    def test_initial_state(self) -> None:
        yaml_str = """
topology: line(2)
events:
  - at: 0s
    spawn: [node-0]
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = _make_mock_sim()
        runner = ScenarioRunner(sim, scenario)
        assert not runner.is_paused
        assert not runner.is_stopped
        assert not runner.is_complete()

    def test_pause_resume(self) -> None:
        yaml_str = """
topology: line(2)
events:
  - at: 0s
    spawn: [node-0]
  - at: 10s
    spawn: [node-1]
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = _make_mock_sim()
        runner = ScenarioRunner(sim, scenario)

        # Execute first event
        count = runner.step(0)
        assert count == 1

        # Pause - should not process events
        runner.pause()
        assert runner.is_paused
        count = runner.step(10_000_000)
        assert count == 0

        # Resume - should process pending event
        runner.resume()
        assert not runner.is_paused
        count = runner.step(10_000_000)
        assert count == 1

    def test_stop(self) -> None:
        yaml_str = """
topology: line(2)
events:
  - at: 0s
    spawn: [node-0]
  - at: 10s
    spawn: [node-1]
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = _make_mock_sim()
        runner = ScenarioRunner(sim, scenario)

        # Stop before completion
        runner.stop()
        assert runner.is_stopped
        assert runner.is_complete()  # Stopped means complete

        # Step should do nothing
        count = runner.step(10_000_000)
        assert count == 0


class TestScenarioRunnerSmoothMove:
    def test_instant_move_no_duration(self) -> None:
        yaml_str = """
topology: line(2)
events:
  - at: 0s
    spawn: [node-0]
  - at: 10s
    move:
      node: node-0
      to: [100, 50, 0]
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = _make_mock_sim()
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)  # spawn
        runner.step(10_000_000)  # move

        # Should be instant - no active moves
        assert not runner.has_active_moves()
        node = sim.get_node("node-0")
        assert node.x == 100
        assert node.y == 50
        assert node.z == 0

    def test_smooth_move_with_duration(self) -> None:
        yaml_str = """
topology: line(2)
events:
  - at: 0s
    spawn: [node-0]
  - at: 10s
    move:
      node: node-0
      to: [100, 0, 0]
      duration: 10s
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = _make_mock_sim()
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)  # spawn at (0,0,0)
        runner.step(10_000_000)  # start move at t=10s

        # Should have active move
        assert runner.has_active_moves()

        # At midpoint (t=15s), should be at (50, 0, 0)
        runner.step(15_000_000)
        node = sim.get_node("node-0")
        assert node.x == pytest.approx(50.0)
        assert node.y == pytest.approx(0.0)
        assert node.z == pytest.approx(0.0)

        # At end (t=20s), should be at (100, 0, 0)
        runner.step(20_000_000)
        node = sim.get_node("node-0")
        assert node.x == pytest.approx(100.0)
        assert node.y == pytest.approx(0.0)
        assert node.z == pytest.approx(0.0)

        # Move should be complete
        assert not runner.has_active_moves()

    def test_smooth_move_interpolation_3d(self) -> None:
        yaml_str = """
topology: line(2)
events:
  - at: 0s
    spawn: [node-0]
  - at: 0s
    move:
      node: node-0
      to: [100, 200, 50]
      duration: 1s
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = _make_mock_sim()
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)  # spawn and start move

        # At 25% (t=250ms)
        runner.step(250_000)
        node = sim.get_node("node-0")
        assert node.x == pytest.approx(25.0)
        assert node.y == pytest.approx(50.0)
        assert node.z == pytest.approx(12.5)

    def test_is_complete_waits_for_interpolations(self) -> None:
        yaml_str = """
topology: line(2)
events:
  - at: 0s
    spawn: [node-0]
  - at: 0s
    move:
      node: node-0
      to: [100, 0, 0]
      duration: 10s
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = _make_mock_sim()
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)  # spawn and start move

        # All events processed but move still active
        assert runner.has_active_moves()
        assert not runner.is_complete()

        # Finish the move
        runner.step(10_000_000)
        assert not runner.has_active_moves()
        assert runner.is_complete()


MOBILITY_YAML = """
topology: grid(1)
events:
  - at: 0s
    spawn: [node-0]
  - at: 0s
    mobility:
      node: node-0
      pattern: random_waypoint
      params:
        area_bounds: [0, 500, 0, 500]
        speed_m_s: 2.0
        pause_time_us: 0
        seed: 42
"""

DETACH_YAML = """
topology: grid(1)
events:
  - at: 0s
    spawn: [node-0]
  - at: 0s
    mobility:
      node: node-0
      pattern: random_waypoint
      params:
        area_bounds: [0, 500, 0, 500]
        speed_m_s: 2.0
        pause_time_us: 0
        seed: 42
  - at: 2s
    mobility:
      node: node-0
      pattern: null
"""


class TestScenarioRunnerMobility:
    def test_attach_moves_node_over_steps(self) -> None:
        from lichen.sim.simulation import Simulation

        scenario = Scenario.from_yaml(MOBILITY_YAML)
        sim = Simulation("mobility-move", seed=42)
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)  # spawn + attach; dt is 0 so no movement yet
        node = sim.get_node("node-0")
        assert node is not None
        start = node.position

        runner.step(1_000_000)
        after_1s = node.position
        assert after_1s != start

        runner.step(2_000_000)
        after_2s = node.position
        assert after_2s != after_1s

        # Positions evolved purely from the mobility pattern, not move events
        assert not runner.has_active_moves()

    def test_positions_deterministic_with_seed(self) -> None:
        from lichen.sim.simulation import Simulation

        positions = []
        for name in ("mobility-a", "mobility-b"):
            scenario = Scenario.from_yaml(MOBILITY_YAML)
            sim = Simulation(name, seed=7)
            runner = ScenarioRunner(sim, scenario)
            runner.step(0)
            runner.step(1_000_000)
            runner.step(2_000_000)
            node = sim.get_node("node-0")
            assert node is not None
            positions.append(node.position)
        assert positions[0] == positions[1]

    def test_params_passed_to_pattern(self) -> None:
        from lichen.sim.mobility import RandomWaypoint
        from lichen.sim.simulation import Simulation

        scenario = Scenario.from_yaml(MOBILITY_YAML)
        sim = Simulation("mobility-params", seed=42)
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)
        pattern = runner.mobility_manager.get_pattern("node-0")
        assert isinstance(pattern, RandomWaypoint)
        assert pattern.area_bounds == (0, 500, 0, 500)
        assert pattern.speed_m_s == 2.0
        assert pattern.pause_time_us == 0
        assert pattern.seed == 42

    def test_unknown_pattern_raises(self) -> None:
        from lichen.sim.simulation import Simulation

        yaml_str = """
topology: grid(1)
events:
  - at: 0s
    spawn: [node-0]
  - at: 0s
    mobility:
      node: node-0
      pattern: teleport
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = Simulation("mobility-unknown", seed=42)
        runner = ScenarioRunner(sim, scenario)
        with pytest.raises(ValueError, match="Unknown mobility pattern"):
            runner.step(0)

    def test_invalid_params_raise(self) -> None:
        from lichen.sim.simulation import Simulation

        yaml_str = """
topology: grid(1)
events:
  - at: 0s
    spawn: [node-0]
  - at: 0s
    mobility:
      node: node-0
      pattern: random_waypoint
      params:
        not_a_param: 1
"""
        scenario = Scenario.from_yaml(yaml_str)
        sim = Simulation("mobility-bad-params", seed=42)
        runner = ScenarioRunner(sim, scenario)
        with pytest.raises(ValueError, match="Invalid params"):
            runner.step(0)

    def test_detach_stops_movement(self) -> None:
        from lichen.sim.simulation import Simulation

        scenario = Scenario.from_yaml(DETACH_YAML)
        sim = Simulation("mobility-detach", seed=42)
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)
        assert runner.mobility_manager.get_pattern("node-0") is not None

        runner.step(1_000_000)
        node = sim.get_node("node-0")
        assert node is not None
        pos_before = node.position

        runner.step(2_000_000)  # moves during 1s-2s, then detach fires
        pos_detach = node.position
        assert pos_detach != pos_before
        assert runner.mobility_manager.get_pattern("node-0") is None

        runner.step(3_000_000)  # no pattern attached -> frozen
        assert node.position == pos_detach

    def test_no_double_step_at_same_time(self) -> None:
        from lichen.sim.simulation import Simulation

        scenario = Scenario.from_yaml(MOBILITY_YAML)
        sim = Simulation("mobility-dt", seed=42)
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)
        runner.step(1_000_000)
        node = sim.get_node("node-0")
        assert node is not None
        pos = node.position

        runner.step(1_000_000)  # same timestamp -> dt 0 -> no movement
        assert node.position == pos

    def test_frozen_while_paused(self) -> None:
        from lichen.sim.simulation import Simulation

        scenario = Scenario.from_yaml(MOBILITY_YAML)
        sim = Simulation("mobility-pause", seed=42)
        runner = ScenarioRunner(sim, scenario)

        runner.step(0)
        runner.step(1_000_000)
        node = sim.get_node("node-0")
        assert node is not None
        pos = node.position

        runner.pause()
        runner.step(5_000_000)
        runner.resume()
        runner.step(5_000_000)
        assert node.position == pos


class TestFormatDuration:
    def test_microseconds(self) -> None:
        assert format_duration(100) == "100us"
        assert format_duration(999) == "999us"

    def test_milliseconds(self) -> None:
        assert format_duration(5000) == "5ms"
        assert format_duration(1500) == "1.5ms"

    def test_seconds(self) -> None:
        assert format_duration(30_000_000) == "30s"
        assert format_duration(1_500_000) == "1.5s"

    def test_minutes(self) -> None:
        assert format_duration(120_000_000) == "2m"

    def test_hours(self) -> None:
        assert format_duration(3_600_000_000) == "1h"

    def test_roundtrip(self) -> None:
        # Verify format_duration is inverse of parse_duration for whole units
        for value in [100, 5000, 30_000_000, 120_000_000, 3_600_000_000]:
            assert parse_duration(format_duration(value)) == value


class TestRecordedEvent:
    def test_to_dict(self) -> None:
        ev = RecordedEvent(
            time_us=5000,
            event_type="tx_start",
            params={"node_id": "n1", "tx_id": "tx1", "payload_len": 10},
        )
        d = ev.to_dict()
        assert d["at"] == "5ms"
        assert d["tx_start"]["node_id"] == "n1"
        assert d["tx_start"]["tx_id"] == "tx1"

    def test_to_dict_empty_params(self) -> None:
        ev = RecordedEvent(time_us=1000, event_type="rx_timeout", params={})
        d = ev.to_dict()
        assert d["at"] == "1ms"
        assert d["rx_timeout"] is True


class TestScenarioRecorder:
    def test_record_node_added(self) -> None:
        recorder = ScenarioRecorder(name="test")
        recorder.on_node_added(
            sim_id="sim1", node_id="n1", x=10.0, y=20.0, z=5.0
        )

        assert len(recorder.events) == 1
        ev = recorder.events[0]
        assert ev.event_type == "node_added"
        assert ev.params["node_id"] == "n1"
        assert ev.params["x"] == 10.0
        assert ev.params["y"] == 20.0
        assert ev.params["z"] == 5.0

    def test_record_tx_start(self) -> None:
        recorder = ScenarioRecorder(name="test")
        recorder.on_tx_start(
            sim_id="sim1",
            node_id="n1",
            tx_id="tx1",
            payload_len=50,
            time_us=1000,
        )

        assert len(recorder.events) == 1
        ev = recorder.events[0]
        assert ev.event_type == "tx_start"
        assert ev.time_us == 1000
        assert ev.params["node_id"] == "n1"
        assert ev.params["tx_id"] == "tx1"
        assert ev.params["payload_len"] == 50

    def test_record_rx_success(self) -> None:
        recorder = ScenarioRecorder(name="test")
        recorder.on_rx_success(
            sim_id="sim1",
            node_id="receiver",
            tx_id="tx1",
            from_node_id="sender",
            payload_len=25,
            rssi=-80,
            snr=10,
            time_us=5000,
        )

        assert len(recorder.events) == 1
        ev = recorder.events[0]
        assert ev.event_type == "rx_success"
        assert ev.params["node_id"] == "receiver"
        assert ev.params["from_node_id"] == "sender"
        assert ev.params["rssi"] == -80
        assert ev.params["snr"] == 10

    def test_record_collision(self) -> None:
        recorder = ScenarioRecorder(name="test")
        recorder.on_collision(
            sim_id="sim1",
            node_id="rx",
            tx_ids=["tx1", "tx2"],
            time_us=3000,
        )

        assert len(recorder.events) == 1
        ev = recorder.events[0]
        assert ev.event_type == "collision"
        assert ev.params["tx_ids"] == ["tx1", "tx2"]

    def test_to_yaml_and_from_yaml_roundtrip(self) -> None:
        # Create a recorder with various events
        recorder = ScenarioRecorder(name="roundtrip-test")
        recorder.set_seed(42)
        recorder.set_topology("grid", {"n": 4, "spacing": 100})

        recorder.on_node_added(sim_id="s", node_id="n1", x=0.0, y=0.0, z=0.0)
        recorder.on_node_added(sim_id="s", node_id="n2", x=100.0, y=0.0, z=0.0)
        recorder.on_tx_start(
            sim_id="s", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )
        recorder.on_rx_success(
            sim_id="s",
            node_id="n2",
            tx_id="t1",
            from_node_id="n1",
            payload_len=10,
            rssi=-85,
            snr=8,
            time_us=2000,
        )

        # Export to YAML
        yaml_str = recorder.to_yaml()
        assert "roundtrip-test" in yaml_str
        assert "seed: 42" in yaml_str

        # Re-import
        loaded = ScenarioRecorder.from_yaml(yaml_str)
        assert loaded.name == "roundtrip-test"
        assert loaded._seed == 42
        assert loaded.topology_type == "grid"
        assert loaded.topology_params["n"] == 4
        assert len(loaded.events) == 4  # 2 node_added + 1 tx_start + 1 rx_success

    def test_to_dict_structure(self) -> None:
        recorder = ScenarioRecorder(name="struct-test")
        recorder.set_seed(123)
        recorder.set_topology("line", {"n": 3, "spacing": 50})
        recorder.on_node_added(sim_id="s", node_id="n0", x=0.0, y=0.0, z=0.0)

        d = recorder.to_dict()
        assert d["name"] == "struct-test"
        assert d["recorded"] is True
        assert d["seed"] == 123
        assert d["topology"]["type"] == "line"
        assert len(d["initial_nodes"]) == 1
        assert d["initial_nodes"][0]["id"] == "n0"


class TestCompareRecordings:
    def test_identical_recordings_match(self) -> None:
        r1 = ScenarioRecorder(name="r1")
        r2 = ScenarioRecorder(name="r2")

        # Add identical events
        for r in [r1, r2]:
            r.on_node_added(sim_id="s", node_id="n1", x=0.0, y=0.0, z=0.0)
            r.on_tx_start(
                sim_id="s", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
            )

        matches, diffs = compare_recordings(r1, r2)
        assert matches is True
        assert len(diffs) == 0

    def test_different_node_positions(self) -> None:
        r1 = ScenarioRecorder(name="r1")
        r2 = ScenarioRecorder(name="r2")

        r1.on_node_added(sim_id="s", node_id="n1", x=0.0, y=0.0, z=0.0)
        r2.on_node_added(sim_id="s", node_id="n1", x=100.0, y=0.0, z=0.0)

        matches, diffs = compare_recordings(r1, r2)
        assert matches is False
        assert any("position differs" in d for d in diffs)

    def test_missing_nodes(self) -> None:
        r1 = ScenarioRecorder(name="r1")
        r2 = ScenarioRecorder(name="r2")

        r1.on_node_added(sim_id="s", node_id="n1", x=0.0, y=0.0, z=0.0)
        r1.on_node_added(sim_id="s", node_id="n2", x=100.0, y=0.0, z=0.0)
        r2.on_node_added(sim_id="s", node_id="n1", x=0.0, y=0.0, z=0.0)

        matches, diffs = compare_recordings(r1, r2)
        assert matches is False
        assert any("Missing nodes" in d for d in diffs)

    def test_different_event_times(self) -> None:
        r1 = ScenarioRecorder(name="r1")
        r2 = ScenarioRecorder(name="r2")

        r1.on_tx_start(
            sim_id="s", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )
        r2.on_tx_start(
            sim_id="s", node_id="n1", tx_id="t1", payload_len=10, time_us=2000
        )

        matches, diffs = compare_recordings(r1, r2)
        assert matches is False
        assert any("time differs" in d for d in diffs)

    def test_different_event_types(self) -> None:
        r1 = ScenarioRecorder(name="r1")
        r2 = ScenarioRecorder(name="r2")

        r1.on_tx_start(
            sim_id="s", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )
        r2.on_tx_end(
            sim_id="s", node_id="n1", tx_id="t1", time_us=1000
        )

        matches, diffs = compare_recordings(r1, r2)
        assert matches is False
        assert any("type differs" in d for d in diffs)


class TestReplay:
    def test_replay_basic_scenario(self) -> None:
        from lichen.sim.simulation import Simulation

        # Create and run original simulation
        sim = Simulation("original", seed=42)
        recorder = ScenarioRecorder(name="replay-test")
        recorder.set_seed(42)
        sim.add_observer(recorder)

        # Add nodes and run
        sim.add_node("n1", 0.0, 0.0, 0.0)
        sim.add_node("n2", 100.0, 0.0, 0.0)

        # Export and replay
        yaml_str = recorder.to_yaml()
        result = replay(yaml_str, seed=42)

        # Node setup should match
        assert result.replay._nodes == recorder._nodes

    def test_replay_returns_metrics(self) -> None:
        from lichen.sim.simulation import Simulation

        sim = Simulation("metrics-test", seed=42)
        recorder = ScenarioRecorder(name="metrics-test")
        recorder.set_seed(42)
        sim.add_observer(recorder)

        sim.add_node("n1", 0.0, 0.0, 0.0)

        yaml_str = recorder.to_yaml()
        result = replay(yaml_str)

        # Should have metrics snapshot
        assert "transmissions" in result.metrics_snapshot
        assert "receptions" in result.metrics_snapshot

    def test_replay_from_recorder_object(self) -> None:
        from lichen.sim.simulation import Simulation

        sim = Simulation("obj-test", seed=42)
        recorder = ScenarioRecorder(name="obj-test")
        recorder.set_seed(42)
        sim.add_observer(recorder)

        sim.add_node("n1", 0.0, 0.0, 0.0)

        # Replay from object, not YAML string
        result = replay(recorder, seed=42)
        assert result.replay._nodes == recorder._nodes


class TestRecordReplayRoundtrip:
    def test_full_roundtrip_with_transmission(self) -> None:
        """Test recording a simulation with TX/RX and replaying it."""
        from lichen.sim.simulation import Simulation

        # Original simulation
        sim = Simulation("roundtrip", seed=42)
        recorder = ScenarioRecorder(name="full-roundtrip")
        recorder.set_seed(42)
        sim.add_observer(recorder)

        # Setup: two nodes close enough to communicate
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)

        # Start transmission and receive
        sim.start_transmission("sender", b"hello")
        sim.start_receive("receiver", timeout_ms=5000)

        # Advance to allow transmission
        sim.advance_to(500_000)  # 500ms

        # Export
        yaml_str = recorder.to_yaml()

        # Verify YAML contains expected events
        assert "tx_start" in yaml_str
        assert "node_added" in yaml_str

        # Parse back
        loaded = ScenarioRecorder.from_yaml(yaml_str)
        assert loaded.name == "full-roundtrip"
        assert loaded._seed == 42

        # Verify events were preserved
        tx_events = [e for e in loaded.events if e.event_type == "tx_start"]
        assert len(tx_events) >= 1

    def test_recording_preserves_event_order(self) -> None:
        """Verify events are recorded and loaded in chronological order."""
        recorder = ScenarioRecorder(name="order-test")

        # Add events out of order (by calling observer methods with different times)
        recorder.on_tx_start(
            sim_id="s", node_id="n1", tx_id="t2", payload_len=10, time_us=2000
        )
        recorder.on_tx_start(
            sim_id="s", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )
        recorder.on_tx_end(sim_id="s", node_id="n1", tx_id="t1", time_us=3000)

        # Events are recorded in call order, not time order
        assert recorder.events[0].time_us == 2000
        assert recorder.events[1].time_us == 1000
        assert recorder.events[2].time_us == 3000

        # Roundtrip preserves order
        yaml_str = recorder.to_yaml()
        loaded = ScenarioRecorder.from_yaml(yaml_str)
        assert len(loaded.events) == 3
        assert loaded.events[0].time_us == 2000
        assert loaded.events[1].time_us == 1000
        assert loaded.events[2].time_us == 3000
