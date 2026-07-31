# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Baseline metric snapshots for regression testing.

Capture and compare metric baselines for key simulation scenarios.
Use for automated regression detection in CI.

Example usage:
    # Save a baseline after a known-good run
    snap = simulation.metrics.snapshot()
    save_baseline("routing-convergence-100nodes", snap, baselines_dir)

    # In CI, compare against baseline
    result = compare_to_baseline("routing-convergence-100nodes", snap, baselines_dir)
    if not result.passed:
        print(result.report())
        sys.exit(1)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


@dataclass
class RegressionThresholds:
    """Thresholds for detecting regressions.

    Each threshold is a relative tolerance (0.0 to 1.0) for that metric.
    A change is flagged as a regression if:
      - For metrics where higher is better: variant < baseline * (1 - threshold)
      - For metrics where lower is better: variant > baseline * (1 + threshold)

    Attributes:
        delivery_rate: Tolerance for delivery rate degradation (default 5%).
        collision_rate: Tolerance for collision rate increase (default 20%).
        latency_p95: Tolerance for p95 latency increase (default 20%).
        latency_p99: Tolerance for p99 latency increase (default 30%).
        latency_mean: Tolerance for mean latency increase (default 15%).
        default: Default tolerance for unspecified metrics (default 10%).
    """

    delivery_rate: float = 0.05
    collision_rate: float = 0.20
    latency_p95: float = 0.20
    latency_p99: float = 0.30
    latency_mean: float = 0.15
    default: float = 0.10

    def get(self, metric_name: str) -> float:
        """Get threshold for a metric by name."""
        mapping = {
            "delivery_rate": self.delivery_rate,
            "collision_rate": self.collision_rate,
            "latency_p95_us": self.latency_p95,
            "latency_p99_us": self.latency_p99,
            "latency_mean_us": self.latency_mean,
        }
        return mapping.get(metric_name, self.default)


# Semantic mapping: True = higher is better, False = lower is better.
METRIC_POLARITY: dict[str, bool] = {
    "transmissions": True,
    "receptions": True,
    "delivery_rate": True,
    "collision_rate": False,
    "collisions": False,
    "latency_min_us": False,
    "latency_max_us": False,
    "latency_mean_us": False,
    "latency_p50_us": False,
    "latency_p95_us": False,
    "latency_p99_us": False,
}


@dataclass
class MetricRegression:
    """A single metric regression finding."""

    metric: str
    baseline_value: float
    current_value: float
    threshold: float
    pct_change: float
    is_regression: bool

    def __str__(self) -> str:
        direction = "worse" if self.is_regression else "ok"
        return (
            f"{self.metric}: {self.baseline_value:.4g} -> {self.current_value:.4g} "
            f"({self.pct_change:+.1f}%) [{direction}]"
        )


@dataclass
class BaselineComparisonResult:
    """Result of comparing metrics to a baseline.

    Attributes:
        baseline_name: Name of the baseline being compared against.
        passed: True if no regressions detected.
        findings: List of metric comparisons.
        regressions: List of findings that are regressions.
        baseline_metadata: Metadata from the baseline file.
    """

    baseline_name: str
    passed: bool
    findings: list[MetricRegression] = field(default_factory=list)
    regressions: list[MetricRegression] = field(default_factory=list)
    baseline_metadata: dict[str, Any] = field(default_factory=dict)

    def report(self, verbose: bool = False) -> str:
        """Generate a human-readable report.

        Args:
            verbose: If True, include all metrics; otherwise only regressions.

        Returns:
            Multi-line report string.
        """
        lines = []
        status = "PASSED" if self.passed else "FAILED"
        lines.append(f"Baseline Comparison: {self.baseline_name} [{status}]")

        if self.baseline_metadata:
            if "created_at" in self.baseline_metadata:
                lines.append(f"  Baseline created: {self.baseline_metadata['created_at']}")
            if "description" in self.baseline_metadata:
                lines.append(f"  Description: {self.baseline_metadata['description']}")

        if self.regressions:
            lines.append("")
            lines.append("Regressions detected:")
            for reg in self.regressions:
                lines.append(f"  - {reg}")

        if verbose and self.findings:
            lines.append("")
            lines.append("All metrics:")
            for f in self.findings:
                lines.append(f"  - {f}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "baseline_name": self.baseline_name,
            "passed": self.passed,
            "regressions": [
                {
                    "metric": r.metric,
                    "baseline": r.baseline_value,
                    "current": r.current_value,
                    "pct_change": r.pct_change,
                    "threshold": r.threshold,
                }
                for r in self.regressions
            ],
            "findings_count": len(self.findings),
            "regressions_count": len(self.regressions),
        }


@dataclass
class BaselineSnapshot:
    """A baseline snapshot with metrics and metadata.

    Attributes:
        name: Unique name for this baseline.
        metrics: The metric snapshot dictionary.
        created_at: ISO timestamp of creation.
        description: Optional description of the baseline.
        scenario: Optional scenario name or configuration.
        version: Schema version for forward compatibility.
    """

    _VERSION: ClassVar[int] = 1

    name: str
    metrics: dict[str, Any]
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    description: str = ""
    scenario: str = ""
    version: int = _VERSION

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "description": self.description,
            "scenario": self.scenario,
            "metrics": self.metrics,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineSnapshot:
        """Load from a dictionary."""
        return cls(
            name=data["name"],
            metrics=data["metrics"],
            created_at=data.get("created_at", ""),
            description=data.get("description", ""),
            scenario=data.get("scenario", ""),
            version=data.get("version", 1),
        )


def save_baseline(
    name: str,
    metrics_snapshot: dict[str, Any],
    baselines_dir: str | Path,
    description: str = "",
    scenario: str = "",
) -> Path:
    """Save a baseline snapshot to disk.

    Args:
        name: Unique name for this baseline (used as filename).
        metrics_snapshot: The metrics snapshot from Metrics.snapshot().
        baselines_dir: Directory to store baseline files.
        description: Optional description of what this baseline represents.
        scenario: Optional scenario name or configuration.

    Returns:
        Path to the saved baseline file.
    """
    baselines_dir = Path(baselines_dir)
    baselines_dir.mkdir(parents=True, exist_ok=True)

    baseline = BaselineSnapshot(
        name=name,
        metrics=metrics_snapshot,
        description=description,
        scenario=scenario,
    )

    file_path = baselines_dir / f"{name}.json"
    with file_path.open("w") as f:
        json.dump(baseline.to_dict(), f, indent=2)

    logger.info("Saved baseline %s to %s", name, file_path)
    return file_path


def load_baseline(
    name: str,
    baselines_dir: str | Path,
) -> BaselineSnapshot | None:
    """Load a baseline snapshot from disk.

    Args:
        name: Name of the baseline to load.
        baselines_dir: Directory containing baseline files.

    Returns:
        BaselineSnapshot if found, None otherwise.
    """
    baselines_dir = Path(baselines_dir)
    file_path = baselines_dir / f"{name}.json"

    if not file_path.exists():
        logger.warning("Baseline %s not found at %s", name, file_path)
        return None

    with file_path.open() as f:
        data = json.load(f)

    return BaselineSnapshot.from_dict(data)


def list_baselines(baselines_dir: str | Path) -> list[str]:
    """List all available baseline names.

    Args:
        baselines_dir: Directory containing baseline files.

    Returns:
        List of baseline names (without .json extension).
    """
    baselines_dir = Path(baselines_dir)
    if not baselines_dir.exists():
        return []
    return sorted(p.stem for p in baselines_dir.glob("*.json"))


def _extract_flat_metrics(snapshot: dict[str, Any]) -> dict[str, float]:
    """Extract a flat dictionary of metric values from a snapshot."""
    flat: dict[str, float] = {}

    # Top-level scalar metrics
    for key in ["transmissions", "receptions", "collisions", "delivery_rate", "collision_rate"]:
        if key in snapshot:
            flat[key] = float(snapshot[key])

    # Latency metrics (nested under latency_us)
    latency = snapshot.get("latency_us", {})
    if isinstance(latency, dict):
        for key in ["min", "max", "mean", "p50", "p95", "p99"]:
            value = latency.get(key)
            if value is not None:
                flat[f"latency_{key}_us"] = float(value)

    return flat


def _compute_pct_change(baseline: float, current: float) -> float:
    """Compute percentage change, handling zero baseline."""
    if baseline == 0:
        return float("inf") if current != 0 else 0.0
    return ((current - baseline) / baseline) * 100


def _is_regression(
    metric: str,
    baseline: float,
    current: float,
    threshold: float,
) -> bool:
    """Determine if a metric change is a regression.

    Args:
        metric: Name of the metric.
        baseline: Baseline value.
        current: Current value.
        threshold: Relative tolerance (0.0 to 1.0).

    Returns:
        True if the change represents a regression.
    """
    if baseline == 0 and current == 0:
        return False

    higher_is_better = METRIC_POLARITY.get(metric, True)

    if higher_is_better:
        # Regression if current < baseline * (1 - threshold)
        min_acceptable = baseline * (1 - threshold)
        return current < min_acceptable
    else:
        # Regression if current > baseline * (1 + threshold)
        max_acceptable = baseline * (1 + threshold)
        return current > max_acceptable


def compare_to_baseline(
    name: str,
    current_snapshot: dict[str, Any],
    baselines_dir: str | Path,
    thresholds: RegressionThresholds | None = None,
) -> BaselineComparisonResult:
    """Compare current metrics to a saved baseline.

    Args:
        name: Name of the baseline to compare against.
        current_snapshot: Current metrics from Metrics.snapshot().
        baselines_dir: Directory containing baseline files.
        thresholds: Regression thresholds (uses defaults if None).

    Returns:
        BaselineComparisonResult with comparison details.

    Raises:
        FileNotFoundError: If baseline does not exist.
    """
    if thresholds is None:
        thresholds = RegressionThresholds()

    baseline = load_baseline(name, baselines_dir)
    if baseline is None:
        raise FileNotFoundError(f"Baseline '{name}' not found in {baselines_dir}")

    baseline_flat = _extract_flat_metrics(baseline.metrics)
    current_flat = _extract_flat_metrics(current_snapshot)

    findings: list[MetricRegression] = []
    regressions: list[MetricRegression] = []

    # Compare all metrics present in baseline
    for metric, baseline_value in baseline_flat.items():
        current_value = current_flat.get(metric, 0.0)
        threshold = thresholds.get(metric)
        pct_change = _compute_pct_change(baseline_value, current_value)
        is_reg = _is_regression(metric, baseline_value, current_value, threshold)

        finding = MetricRegression(
            metric=metric,
            baseline_value=baseline_value,
            current_value=current_value,
            threshold=threshold,
            pct_change=pct_change,
            is_regression=is_reg,
        )
        findings.append(finding)
        if is_reg:
            regressions.append(finding)

    return BaselineComparisonResult(
        baseline_name=name,
        passed=len(regressions) == 0,
        findings=findings,
        regressions=regressions,
        baseline_metadata={
            "created_at": baseline.created_at,
            "description": baseline.description,
            "scenario": baseline.scenario,
        },
    )


def update_baseline(
    name: str,
    current_snapshot: dict[str, Any],
    baselines_dir: str | Path,
    description: str | None = None,
) -> Path:
    """Update an existing baseline with new metrics.

    Preserves the original scenario name but updates metrics and timestamp.

    Args:
        name: Name of the baseline to update.
        current_snapshot: New metrics from Metrics.snapshot().
        baselines_dir: Directory containing baseline files.
        description: Optional new description (keeps old if None).

    Returns:
        Path to the updated baseline file.
    """
    existing = load_baseline(name, baselines_dir)
    scenario = existing.scenario if existing else ""
    desc = description if description is not None else (existing.description if existing else "")

    return save_baseline(
        name=name,
        metrics_snapshot=current_snapshot,
        baselines_dir=baselines_dir,
        description=desc,
        scenario=scenario,
    )


def baseline_exists(name: str, baselines_dir: str | Path) -> bool:
    """Check if a baseline exists.

    Args:
        name: Name of the baseline to check.
        baselines_dir: Directory containing baseline files.

    Returns:
        True if baseline file exists.
    """
    baselines_dir = Path(baselines_dir)
    return (baselines_dir / f"{name}.json").exists()
