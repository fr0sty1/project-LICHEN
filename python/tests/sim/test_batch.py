# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for batch simulation runner."""

import csv
import tempfile
from pathlib import Path

import pytest

from lichen.sim.batch import (
    BatchRunner,
    ParameterSweep,
    RunResult,
    SimulationConfig,
    parse_float_list,
    parse_int_list,
)


class TestSimulationConfig:
    def test_default_values(self) -> None:
        config = SimulationConfig()
        assert config.node_count == 4
        assert config.spacing == 100.0
        assert config.topology_type == "grid"
        assert config.duration_us == 10_000_000
        assert config.seed is None

    def test_custom_values(self) -> None:
        config = SimulationConfig(
            node_count=9, spacing=50.0, topology_type="line", duration_us=5_000_000, seed=42
        )
        assert config.node_count == 9
        assert config.spacing == 50.0
        assert config.topology_type == "line"
        assert config.duration_us == 5_000_000
        assert config.seed == 42

    def test_to_dict(self) -> None:
        config = SimulationConfig(node_count=9, spacing=50.0)
        d = config.to_dict()
        assert d["node_count"] == 9
        assert d["spacing"] == 50.0
        assert "topology_type" in d
        assert "duration_us" in d


class TestParameterSweep:
    def test_single_values(self) -> None:
        sweep = ParameterSweep(node_counts=[4], spacings=[100.0])
        configs = sweep.generate_configs()
        assert len(configs) == 1
        assert configs[0].node_count == 4
        assert configs[0].spacing == 100.0

    def test_multiple_node_counts(self) -> None:
        sweep = ParameterSweep(node_counts=[4, 9, 16], spacings=[100.0])
        configs = sweep.generate_configs()
        assert len(configs) == 3
        assert [c.node_count for c in configs] == [4, 9, 16]

    def test_multiple_spacings(self) -> None:
        sweep = ParameterSweep(node_counts=[4], spacings=[50.0, 100.0, 200.0])
        configs = sweep.generate_configs()
        assert len(configs) == 3
        assert [c.spacing for c in configs] == [50.0, 100.0, 200.0]

    def test_cartesian_product(self) -> None:
        sweep = ParameterSweep(
            node_counts=[4, 9],
            spacings=[50.0, 100.0],
            topology_types=["grid", "line"],
        )
        configs = sweep.generate_configs()
        # 2 node_counts * 2 spacings * 2 topologies = 8 combinations
        assert len(configs) == 8

    def test_with_seeds(self) -> None:
        sweep = ParameterSweep(node_counts=[4], spacings=[100.0], seeds=[42, 123])
        configs = sweep.generate_configs()
        assert len(configs) == 2
        assert [c.seed for c in configs] == [42, 123]

    def test_duration_passed_through(self) -> None:
        sweep = ParameterSweep(node_counts=[4])
        configs = sweep.generate_configs(duration_us=5_000_000)
        assert all(c.duration_us == 5_000_000 for c in configs)


class TestRunResult:
    def test_to_dict(self) -> None:
        config = SimulationConfig(node_count=9, spacing=50.0)
        result = RunResult(
            config=config,
            run_index=0,
            transmissions=10,
            receptions=8,
            collisions=2,
            delivery_rate=0.8,
            collision_rate=0.2,
            wall_time_ms=100.0,
        )
        d = result.to_dict()
        # Config fields
        assert d["node_count"] == 9
        assert d["spacing"] == 50.0
        # Result fields
        assert d["run_index"] == 0
        assert d["transmissions"] == 10
        assert d["receptions"] == 8
        assert d["delivery_rate"] == 0.8


class TestBatchRunner:
    def test_init_with_configs(self) -> None:
        configs = [SimulationConfig(node_count=4), SimulationConfig(node_count=9)]
        runner = BatchRunner(configs=configs)
        assert len(runner.configs) == 2

    def test_init_with_sweep(self) -> None:
        sweep = ParameterSweep(node_counts=[4, 9, 16])
        runner = BatchRunner(sweep=sweep)
        assert len(runner.configs) == 3

    def test_init_default(self) -> None:
        runner = BatchRunner()
        assert len(runner.configs) == 1

    def test_run_single(self) -> None:
        config = SimulationConfig(node_count=4, duration_us=1_000_000)
        runner = BatchRunner()
        result = runner.run_single(config, 0)
        assert result.run_index == 0
        assert result.config.node_count == 4
        assert result.wall_time_ms > 0

    def test_run_single_different_topologies(self) -> None:
        for topo_type in ["grid", "line", "random_disk", "star"]:
            config = SimulationConfig(node_count=4, topology_type=topo_type)
            runner = BatchRunner()
            result = runner.run_single(config, 0)
            assert result.config.topology_type == topo_type

    def test_run_single_invalid_topology_raises(self) -> None:
        config = SimulationConfig(node_count=4, topology_type="invalid")
        runner = BatchRunner()
        with pytest.raises(ValueError, match="Unknown topology"):
            runner.run_single(config, 0)

    def test_run_all(self) -> None:
        sweep = ParameterSweep(node_counts=[4, 9])
        runner = BatchRunner(sweep=sweep, duration_us=1_000_000)
        results = runner.run_all()
        assert len(results) == 2
        assert runner.results == results

    def test_write_csv(self) -> None:
        sweep = ParameterSweep(node_counts=[4, 9])
        runner = BatchRunner(sweep=sweep, duration_us=1_000_000)
        runner.run_all()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_path = f.name

        try:
            runner.write_csv(csv_path)
            # Read back and verify
            with open(csv_path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["node_count"] == "4"
            assert rows[1]["node_count"] == "9"
        finally:
            Path(csv_path).unlink(missing_ok=True)

    def test_write_csv_no_results_no_error(self) -> None:
        runner = BatchRunner()
        # No results yet
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            csv_path = f.name
        try:
            runner.write_csv(csv_path)  # Should not raise
        finally:
            Path(csv_path).unlink(missing_ok=True)

    def test_aggregate_stats(self) -> None:
        sweep = ParameterSweep(node_counts=[4, 9, 16])
        runner = BatchRunner(sweep=sweep, duration_us=1_000_000)
        runner.run_all()
        stats = runner.aggregate_stats()
        assert stats["total_runs"] == 3
        assert "delivery_rate_mean" in stats
        assert "collision_rate_mean" in stats
        assert "wall_time_total_ms" in stats

    def test_aggregate_stats_empty(self) -> None:
        runner = BatchRunner()
        stats = runner.aggregate_stats()
        assert stats == {}


class TestHelperFunctions:
    def test_parse_int_list_single(self) -> None:
        assert parse_int_list("4") == [4]

    def test_parse_int_list_multiple(self) -> None:
        assert parse_int_list("4,9,16") == [4, 9, 16]

    def test_parse_int_list_with_spaces(self) -> None:
        assert parse_int_list("4, 9, 16") == [4, 9, 16]

    def test_parse_float_list_single(self) -> None:
        assert parse_float_list("100.0") == [100.0]

    def test_parse_float_list_multiple(self) -> None:
        assert parse_float_list("50.0,100.0,200.0") == [50.0, 100.0, 200.0]

    def test_parse_float_list_with_spaces(self) -> None:
        assert parse_float_list("50.0, 100.0, 200.0") == [50.0, 100.0, 200.0]
