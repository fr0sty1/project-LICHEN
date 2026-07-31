# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Batch simulation runner with parameter sweep support.

Runs multiple simulations varying parameters (node count, spacing, etc.),
aggregates metrics, and outputs results to CSV.

Example usage:
    lichen-batch --nodes 4,9,16 --spacing 50,100,200 --output results.csv
"""

from __future__ import annotations

import csv
import itertools
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from lichen.sim import topology as topo
from lichen.sim.simulation import Simulation, TimeMode

logger = structlog.get_logger()


@dataclass
class SimulationConfig:
    """Configuration for a single simulation run."""

    node_count: int = 4
    spacing: float = 100.0
    topology_type: str = "grid"
    duration_us: int = 10_000_000  # 10 seconds
    seed: int | None = None
    jitter_min_us: int = 0
    jitter_max_us: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return configuration as a dictionary."""
        return {
            "node_count": self.node_count,
            "spacing": self.spacing,
            "topology_type": self.topology_type,
            "duration_us": self.duration_us,
            "seed": self.seed,
            "jitter_min_us": self.jitter_min_us,
            "jitter_max_us": self.jitter_max_us,
        }


@dataclass
class RunResult:
    """Result of a single simulation run."""

    config: SimulationConfig
    run_index: int
    transmissions: int = 0
    receptions: int = 0
    collisions: int = 0
    delivery_rate: float = 0.0
    collision_rate: float = 0.0
    latency_min_us: int | None = None
    latency_max_us: int | None = None
    latency_mean_us: float | None = None
    wall_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return result as a flat dictionary for CSV output."""
        d = self.config.to_dict()
        d.update(
            {
                "run_index": self.run_index,
                "transmissions": self.transmissions,
                "receptions": self.receptions,
                "collisions": self.collisions,
                "delivery_rate": self.delivery_rate,
                "collision_rate": self.collision_rate,
                "latency_min_us": self.latency_min_us,
                "latency_max_us": self.latency_max_us,
                "latency_mean_us": self.latency_mean_us,
                "wall_time_ms": self.wall_time_ms,
            }
        )
        return d


@dataclass
class ParameterSweep:
    """Define ranges of parameters to sweep over."""

    node_counts: list[int] = field(default_factory=lambda: [4])
    spacings: list[float] = field(default_factory=lambda: [100.0])
    topology_types: list[str] = field(default_factory=lambda: ["grid"])
    seeds: list[int | None] = field(default_factory=lambda: [None])

    def generate_configs(
        self, duration_us: int = 10_000_000, jitter_min_us: int = 0, jitter_max_us: int = 0
    ) -> list[SimulationConfig]:
        """Generate all configuration combinations from the sweep parameters.

        Returns:
            List of SimulationConfig objects for all parameter combinations.
        """
        configs = []
        for node_count, spacing, topo_type, seed in itertools.product(
            self.node_counts, self.spacings, self.topology_types, self.seeds
        ):
            configs.append(
                SimulationConfig(
                    node_count=node_count,
                    spacing=spacing,
                    topology_type=topo_type,
                    duration_us=duration_us,
                    seed=seed,
                    jitter_min_us=jitter_min_us,
                    jitter_max_us=jitter_max_us,
                )
            )
        return configs


class BatchRunner:
    """Run multiple simulations with parameter sweeps."""

    def __init__(
        self,
        sweep: ParameterSweep | None = None,
        configs: list[SimulationConfig] | None = None,
        duration_us: int = 10_000_000,
        jitter_min_us: int = 0,
        jitter_max_us: int = 0,
    ) -> None:
        """Initialize the batch runner.

        Args:
            sweep: Parameter sweep to generate configs from.
            configs: Explicit list of configs (overrides sweep if provided).
            duration_us: Simulation duration for generated configs.
            jitter_min_us: Min TX jitter for generated configs.
            jitter_max_us: Max TX jitter for generated configs.
        """
        if configs is not None:
            self._configs = configs
        elif sweep is not None:
            self._configs = sweep.generate_configs(duration_us, jitter_min_us, jitter_max_us)
        else:
            self._configs = [SimulationConfig(duration_us=duration_us)]
        self._results: list[RunResult] = []

    @property
    def configs(self) -> list[SimulationConfig]:
        """Return the list of configurations to run."""
        return self._configs

    @property
    def results(self) -> list[RunResult]:
        """Return the results from completed runs."""
        return self._results

    def run_single(self, config: SimulationConfig, run_index: int) -> RunResult:
        """Run a single simulation with the given configuration.

        Args:
            config: Simulation configuration.
            run_index: Index of this run (for tracking).

        Returns:
            RunResult with collected metrics.
        """
        start_time = time.monotonic()

        sim = Simulation(
            sim_id=f"batch-{run_index}",
            time_mode=TimeMode.BARRIER_SYNC,
            seed=config.seed,
            jitter_min_us=config.jitter_min_us,
            jitter_max_us=config.jitter_max_us,
        )

        topo_func = getattr(topo, config.topology_type, None)
        if topo_func is None:
            raise ValueError(f"Unknown topology type: {config.topology_type}")

        # Map spacing to the correct parameter based on topology type
        # grid and line use 'spacing', random_disk and star use 'radius'
        if config.topology_type in ("random_disk", "star"):
            positions = topo_func(n=config.node_count, radius=config.spacing)
        else:
            positions = topo_func(n=config.node_count, spacing=config.spacing)
        topo.apply_topology(sim, positions)

        # Advance simulation time by stepping through events
        # In BARRIER_SYNC mode without actual nodes connected,
        # we just advance time directly
        sim._current_time_us = config.duration_us

        wall_time_ms = (time.monotonic() - start_time) * 1000

        metrics = sim.metrics
        latency = metrics.latency_stats()

        result = RunResult(
            config=config,
            run_index=run_index,
            transmissions=metrics.transmissions,
            receptions=metrics.receptions,
            collisions=metrics.collisions,
            delivery_rate=metrics.delivery_rate,
            collision_rate=metrics.collision_rate,
            latency_min_us=latency.min_us,
            latency_max_us=latency.max_us,
            latency_mean_us=latency.mean_us,
            wall_time_ms=wall_time_ms,
        )

        logger.info(
            "Simulation complete",
            run_index=run_index,
            nodes=config.node_count,
            spacing=config.spacing,
            topology=config.topology_type,
            wall_time_ms=round(wall_time_ms, 2),
        )

        return result

    def run_all(self) -> list[RunResult]:
        """Run all configured simulations.

        Returns:
            List of RunResult objects.
        """
        self._results = []
        total = len(self._configs)

        logger.info("Starting batch run", total_configs=total)

        for i, config in enumerate(self._configs):
            result = self.run_single(config, i)
            self._results.append(result)

        logger.info(
            "Batch run complete",
            total_runs=len(self._results),
        )

        return self._results

    def write_csv(self, path: str | Path) -> None:
        """Write results to a CSV file.

        Args:
            path: Output file path.
        """
        if not self._results:
            logger.warning("No results to write")
            return

        path = Path(path)
        fieldnames = list(self._results[0].to_dict().keys())

        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for result in self._results:
                writer.writerow(result.to_dict())

        logger.info("Results written", path=str(path), rows=len(self._results))

    def aggregate_stats(self) -> dict[str, Any]:
        """Compute aggregate statistics across all runs.

        Returns:
            Dictionary with aggregate statistics.
        """
        if not self._results:
            return {}

        delivery_rates = [r.delivery_rate for r in self._results]
        collision_rates = [r.collision_rate for r in self._results]
        wall_times = [r.wall_time_ms for r in self._results]

        return {
            "total_runs": len(self._results),
            "delivery_rate_mean": sum(delivery_rates) / len(delivery_rates),
            "delivery_rate_min": min(delivery_rates),
            "delivery_rate_max": max(delivery_rates),
            "collision_rate_mean": sum(collision_rates) / len(collision_rates),
            "collision_rate_min": min(collision_rates),
            "collision_rate_max": max(collision_rates),
            "wall_time_total_ms": sum(wall_times),
            "wall_time_mean_ms": sum(wall_times) / len(wall_times),
        }


def parse_int_list(s: str) -> list[int]:
    """Parse a comma-separated list of integers."""
    return [int(x.strip()) for x in s.split(",")]


def parse_float_list(s: str) -> list[float]:
    """Parse a comma-separated list of floats."""
    return [float(x.strip()) for x in s.split(",")]


def main() -> None:
    """CLI entry point for batch simulation runner."""
    import argparse
    import logging
    import sys

    parser = argparse.ArgumentParser(
        description="LICHEN Batch Simulation Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sweep node counts with default spacing
  lichen-batch --nodes 4,9,16,25 --output results.csv

  # Sweep both node counts and spacing
  lichen-batch --nodes 4,9,16 --spacing 50,100,200 --output results.csv

  # Use specific topology type
  lichen-batch --nodes 5,10,20 --topology line --output results.csv
        """,
    )
    parser.add_argument(
        "--nodes",
        type=str,
        default="4",
        metavar="N,N,...",
        help="Comma-separated list of node counts to sweep (default: 4)",
    )
    parser.add_argument(
        "--spacing",
        type=str,
        default="100.0",
        metavar="S,S,...",
        help="Comma-separated list of spacings (meters) to sweep (default: 100.0)",
    )
    parser.add_argument(
        "--topology",
        type=str,
        default="grid",
        choices=["grid", "line", "random_disk", "star"],
        help="Topology type (default: grid)",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=10.0,
        metavar="SEC",
        help="Simulation duration in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--seed",
        type=str,
        default=None,
        metavar="N,N,...",
        help="Comma-separated list of seeds to sweep (default: None)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default="batch_results.csv",
        metavar="FILE",
        help="Output CSV file path (default: batch_results.csv)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()

    # Configure structlog
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, args.log_level)),
    )
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(message)s")

    # Parse parameter lists
    node_counts = parse_int_list(args.nodes)
    spacings = parse_float_list(args.spacing)

    seeds: list[int | None] = [None]
    if args.seed is not None:
        seeds = [int(x.strip()) for x in args.seed.split(",")]

    sweep = ParameterSweep(
        node_counts=node_counts,
        spacings=spacings,
        topology_types=[args.topology],
        seeds=seeds,
    )

    duration_us = int(args.duration * 1_000_000)

    runner = BatchRunner(sweep=sweep, duration_us=duration_us)

    total_configs = len(runner.configs)
    print(f"Running {total_configs} simulation(s)...", file=sys.stderr)

    runner.run_all()
    runner.write_csv(args.output)

    stats = runner.aggregate_stats()
    print("\nAggregate statistics:", file=sys.stderr)
    print(f"  Total runs: {stats['total_runs']}", file=sys.stderr)
    print(f"  Delivery rate: {stats['delivery_rate_mean']:.4f} (mean)", file=sys.stderr)
    print(f"  Collision rate: {stats['collision_rate_mean']:.4f} (mean)", file=sys.stderr)
    print(f"  Wall time: {stats['wall_time_total_ms']:.1f}ms total", file=sys.stderr)
    print(f"\nResults written to: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
