# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Metrics collection for the LICHEN simulator.

Tracks transmission and reception activity in a running simulation:
transmission starts, successful receptions, collisions, per-delivery latency,
and the derived delivery and collision rates.

The recording methods are deduplicated by design. The simulation polls
``Simulation.get_rx_result`` on a ~1 ms interval while a node waits, so the
same physical delivery or collision is observed many times; each is counted
once via the ``(receiver, transmission)`` key and a radio-layer collision
epoch. Dedup sets and CSV series are capped so long runs cannot grow without
bound.
"""

from __future__ import annotations

import csv
import logging
import random
from collections import OrderedDict, defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, cast

logger = logging.getLogger(__name__)


@dataclass
class NodeMetrics:
    """Per-node telemetry metrics for cross-implementation tracking.

    Tracks transmission/reception counts, byte totals, airtime usage,
    unique peers seen, and packet hashes for verifying cross-implementation
    interoperability.

    The packet hash sets are capped at ``_PACKET_HASH_SET_MAX_SIZE`` to prevent
    unbounded memory growth in long-running simulations. Once the cap is reached,
    no new hashes are added, but counts (tx_count, rx_count) remain accurate.

    Airtime tracking: ``airtime_us`` accumulates actual TX airtime for duty
    cycle enforcement. After each TX, the airtime is deducted from the node's
    duty cycle budget.
    """

    # Maximum entries in packet_hashes_sent and packet_hashes_received.
    # Prevents unbounded memory growth in long-running simulations.
    _PACKET_HASH_SET_MAX_SIZE: ClassVar[int] = 10000
    _MAX_ERRORS: ClassVar[int] = 1000

    tx_count: int = 0
    rx_count: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    airtime_us: int = 0  # Accumulated TX airtime in microseconds
    unique_peers: set[str] = field(default_factory=set)
    errors: set[str] = field(default_factory=set)
    packet_hashes_sent: set[str] = field(default_factory=set)
    packet_hashes_received: set[str] = field(default_factory=set)

    def record_tx(self, payload: bytes, packet_hash: str, airtime_us: int = 0) -> None:
        """Record a transmission.

        Args:
            payload: The transmitted payload bytes.
            packet_hash: SHA256[:16] hash of the payload.
            airtime_us: Actual airtime in microseconds (for duty cycle tracking).
        """
        self.tx_count += 1
        self.tx_bytes += len(payload)
        self.airtime_us += airtime_us
        if len(self.packet_hashes_sent) < self._PACKET_HASH_SET_MAX_SIZE:
            self.packet_hashes_sent.add(packet_hash)

    def record_rx(self, payload: bytes, packet_hash: str, from_peer: str | None = None) -> None:
        """Record a reception.

        Args:
            payload: The received payload bytes.
            packet_hash: SHA256[:16] hash of the payload.
            from_peer: Optional IID or node ID of the sender.
        """
        self.rx_count += 1
        self.rx_bytes += len(payload)
        if len(self.packet_hashes_received) < self._PACKET_HASH_SET_MAX_SIZE:
            self.packet_hashes_received.add(packet_hash)
        if from_peer is not None:
            self.unique_peers.add(from_peer)

    def record_error(self, error: str) -> None:
        """Record an error message.

        Args:
            error: Description of the error.
        """
        if len(self.errors) < self._MAX_ERRORS:
            self.errors.add(error)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of all metrics.

        Returns:
            Dictionary containing all metrics, with sets converted to sorted lists.
        """
        return {
            "tx_count": self.tx_count,
            "rx_count": self.rx_count,
            "tx_bytes": self.tx_bytes,
            "rx_bytes": self.rx_bytes,
            "airtime_us": self.airtime_us,
            "unique_peers": sorted(self.unique_peers),
            "errors": sorted(self.errors),
            "packet_hashes_sent": sorted(self.packet_hashes_sent),
            "packet_hashes_received": sorted(self.packet_hashes_received),
        }


@dataclass(frozen=True)
class LatencyStats:
    """Summary statistics for per-delivery latency, in microseconds."""

    count: int
    min_us: int | None
    max_us: int | None
    mean_us: float | None
    p50_us: int | None = None
    p95_us: int | None = None
    p99_us: int | None = None


@dataclass(frozen=True)
class MetricsSample:
    """A timestamped sample of key metrics for time-series visualization.

    Used by the real-time metrics dashboard to render charts of delivery rate,
    collision rate, and duty cycle utilization over time.
    """

    time_us: int
    delivery_rate: float
    collision_rate: float
    duty_cycle: float
    transmissions: int
    receptions: int
    collisions: int


class MetricsTimeSeries:
    """Stores time-bucketed metrics samples for real-time dashboard visualization.

    Maintains a sliding window of metric samples, each capturing the state at
    regular intervals. Useful for rendering time-series charts of delivery rate,
    collision rate, and duty cycle utilization.

    Attributes:
        max_samples: Maximum number of samples to retain (default 300).
        sample_interval_us: Minimum interval between samples in microseconds.
    """

    # Default retention: 5 minutes at 1-second intervals
    _DEFAULT_MAX_SAMPLES: ClassVar[int] = 300
    _DEFAULT_INTERVAL_US: ClassVar[int] = 1_000_000  # 1 second

    def __init__(
        self,
        max_samples: int | None = None,
        sample_interval_us: int | None = None,
    ) -> None:
        """Initialize time-series storage.

        Args:
            max_samples: Maximum samples to retain in the sliding window.
            sample_interval_us: Minimum interval between samples (microseconds).
        """
        if max_samples is None:
            max_samples = self._DEFAULT_MAX_SAMPLES
        if sample_interval_us is None:
            sample_interval_us = self._DEFAULT_INTERVAL_US
        self._samples: deque[MetricsSample] = deque(maxlen=max_samples)
        self._sample_interval_us = sample_interval_us
        self._last_sample_time_us: int | None = None

    def should_sample(self, time_us: int) -> bool:
        """Check if enough time has passed to record a new sample.

        Args:
            time_us: Current simulation time in microseconds.

        Returns:
            True if a new sample should be recorded.
        """
        if self._last_sample_time_us is None:
            return True
        return time_us >= self._last_sample_time_us + self._sample_interval_us

    def record_sample(
        self,
        time_us: int,
        delivery_rate: float,
        collision_rate: float,
        duty_cycle: float,
        transmissions: int,
        receptions: int,
        collisions: int,
    ) -> MetricsSample:
        """Record a metrics sample at the given time.

        Args:
            time_us: Simulation time in microseconds.
            delivery_rate: Current delivery rate (0.0 to 1.0+).
            collision_rate: Current collision rate (0.0 to 1.0).
            duty_cycle: Current duty cycle utilization (0.0 to 1.0+).
            transmissions: Total transmission count.
            receptions: Total reception count.
            collisions: Total collision count.

        Returns:
            The recorded MetricsSample.
        """
        sample = MetricsSample(
            time_us=time_us,
            delivery_rate=delivery_rate,
            collision_rate=collision_rate,
            duty_cycle=duty_cycle,
            transmissions=transmissions,
            receptions=receptions,
            collisions=collisions,
        )
        self._samples.append(sample)
        self._last_sample_time_us = time_us
        return sample

    def get_samples(self, since_us: int | None = None) -> list[MetricsSample]:
        """Get all samples, optionally filtered by time.

        Args:
            since_us: If provided, only return samples after this time.

        Returns:
            List of MetricsSample objects.
        """
        if since_us is None:
            return list(self._samples)
        return [s for s in self._samples if s.time_us > since_us]

    def get_latest(self) -> MetricsSample | None:
        """Get the most recent sample.

        Returns:
            The latest MetricsSample, or None if no samples exist.
        """
        if not self._samples:
            return None
        return self._samples[-1]

    def to_dict_list(self, since_us: int | None = None) -> list[dict[str, Any]]:
        """Return samples as JSON-serializable list of dicts.

        Args:
            since_us: If provided, only return samples after this time.

        Returns:
            List of dictionaries suitable for JSON serialization.
        """
        samples = self.get_samples(since_us)
        return [
            {
                "time_us": s.time_us,
                "delivery_rate": s.delivery_rate,
                "collision_rate": s.collision_rate,
                "duty_cycle": s.duty_cycle,
                "transmissions": s.transmissions,
                "receptions": s.receptions,
                "collisions": s.collisions,
            }
            for s in samples
        ]

    def clear(self) -> None:
        """Clear all stored samples."""
        self._samples.clear()
        self._last_sample_time_us = None

    def __len__(self) -> int:
        """Return the number of stored samples."""
        return len(self._samples)


class Metrics:
    """Counters and statistics for a single simulation run.

    All counts are deduplicated, so callers may record the same observation
    repeatedly (as the simulator's polling loop does) without inflating the
    totals.
    """

    # Max age for delivered _tx_start_times entries (60 seconds).
    _TX_START_TIMES_MAX_AGE_US = 60_000_000
    # Undelivered start times live long enough for LatencyRule / 90s hops.
    _TX_START_TIMES_UNDELIVERED_MAX_AGE_US = 180_000_000
    # Only prune when dict exceeds this size (avoids overhead for small runs).
    _TX_START_TIMES_PRUNE_THRESHOLD = 1000
    # Max latency samples to store for percentile calculation.
    # Reservoir sampling kicks in beyond this limit.
    _MAX_LATENCY_SAMPLES = 10000
    _DELIVERED_MAX_SIZE = 10000
    _COLLISION_KEYS_MAX_SIZE = 10000
    _TIME_SERIES_MAX_SIZE = 10000

    def __init__(self, rng: random.Random | None = None) -> None:
        self._rng = rng if rng is not None else random.Random()
        self._transmissions = 0
        self._tx_start_times: dict[str, int] = {}  # tx_id -> start_time_us
        self._tx_latency_recorded: set[str] = set()
        self._delivered: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._receptions = 0
        self._collision_keys: OrderedDict[tuple[str, frozenset[str]], None] = OrderedDict()
        self._collisions = 0
        # Running statistics for latency (O(1) memory vs unbounded list).
        self._latency_count = 0
        self._latency_sum_us = 0
        self._latency_min_us: int | None = None
        self._latency_max_us: int | None = None
        # Latency samples for percentile calculation (capped for memory).
        self._latency_samples: list[int] = []
        self._latency_samples_sorted = True  # Track if samples need sorting.
        # Per-channel collision tracking.
        self._collisions_by_channel: dict[int, int] = defaultdict(int)
        # Per-node collision tracking.
        self._collisions_by_node: dict[str, int] = defaultdict(int)
        # Time-series data for CSV export: capped so long runs cannot OOM.
        self._time_series: deque[tuple[int, str, dict[str, Any]]] = deque(
            maxlen=self._TIME_SERIES_MAX_SIZE
        )
        # Time-series for real-time dashboard visualization.
        self._dashboard_time_series = MetricsTimeSeries()
        # Current duty cycle value (set externally by simulation).
        self._duty_cycle: float = 0.0

    def set_rng(self, rng: random.Random) -> None:
        """Replace the RNG used for latency reservoir sampling."""
        self._rng = rng

    def record_transmission_start(self, tx_id: str, start_time_us: int) -> None:
        """Record that a transmission has started.

        Args:
            tx_id: Unique transmission identifier.
            start_time_us: Simulation time the transmission began, in
                microseconds (used to compute delivery latency).
        """
        if tx_id in self._tx_start_times:
            return
        self._tx_start_times[tx_id] = start_time_us
        self._transmissions += 1

        # Prune by age, but keep undelivered starts through delayed-RX windows.
        if len(self._tx_start_times) > self._TX_START_TIMES_PRUNE_THRESHOLD:
            delivered_cutoff = start_time_us - self._TX_START_TIMES_MAX_AGE_US
            undelivered_cutoff = start_time_us - self._TX_START_TIMES_UNDELIVERED_MAX_AGE_US
            old_keys = []
            for k, v in self._tx_start_times.items():
                if k == tx_id:
                    continue
                if k in self._tx_latency_recorded:
                    if v < delivered_cutoff:
                        old_keys.append(k)
                elif v < undelivered_cutoff:
                    old_keys.append(k)
            self._forget_tx_ids(old_keys)

    def record_reception(self, rx_node_id: str, tx_id: str, time_us: int) -> bool:
        """Record a successful reception of a transmission by a node.

        Idempotent per ``(rx_node_id, tx_id)``: repeated calls for the same
        delivery are ignored, so polling does not inflate the count.
        Returns ``True`` only for the first observation, matching
        ``record_collision``.

        Args:
            rx_node_id: ID of the receiving node.
            tx_id: ID of the transmission that was received.
            time_us: Simulation time the reception was observed, in
                microseconds.
        """
        key = (rx_node_id, tx_id)
        if key in self._delivered:
            self._delivered.move_to_end(key)
            return False
        self._evict_stale_identities(
            self._delivered,
            self._DELIVERED_MAX_SIZE,
            lambda k: k[1] not in self._tx_start_times,
        )
        self._delivered[key] = None
        self._receptions += 1
        start = self._tx_start_times.get(tx_id)
        if start is not None:
            if time_us >= start:
                latency = time_us - start
                self._latency_count += 1
                self._latency_sum_us += latency
                if self._latency_min_us is None or latency < self._latency_min_us:
                    self._latency_min_us = latency
                if self._latency_max_us is None or latency > self._latency_max_us:
                    self._latency_max_us = latency
                self._tx_latency_recorded.add(tx_id)
                # Store latency sample for percentile calculation.
                self._add_latency_sample(latency)
                # Record time-series event.
                self._time_series.append(
                    (
                        time_us,
                        "reception",
                        {"rx_node": rx_node_id, "tx_id": tx_id, "latency_us": latency},
                    )
                )
            else:
                logger.warning(
                    "record_reception: time_us=%d < start=%d for tx_id=%s "
                    "rx_node=%s (negative latency=%d us); latency not recorded",
                    time_us,
                    start,
                    tx_id,
                    rx_node_id,
                    start - time_us,
                )
        else:
            logger.warning(
                "record_reception: missing tx start for tx_id=%s rx_node=%s "
                "time_us=%d; reception counted, latency not recorded",
                tx_id,
                rx_node_id,
                time_us,
            )
        return True

    def has_reception(self, rx_node_id: str, tx_id: str) -> bool:
        """Return True if this receiver has already counted tx_id."""
        return (rx_node_id, tx_id) in self._delivered

    def has_any_reception_for_tx(self, tx_id: str) -> bool:
        """Return True if any receiver has already counted tx_id."""
        return any(key[1] == tx_id for key in self._delivered)

    def _forget_tx_ids(self, tx_ids: list[str]) -> None:
        """Drop start times and companion identity caches for pruned TXs."""
        if not tx_ids:
            return
        forgotten = set(tx_ids)
        for tx_id in forgotten:
            self._tx_start_times.pop(tx_id, None)
            self._tx_latency_recorded.discard(tx_id)
        for delivery_key in list(self._delivered):
            if delivery_key[1] in forgotten:
                self._delivered.pop(delivery_key, None)
        for collision_key in list(self._collision_keys):
            if collision_key[1] & forgotten:
                self._collision_keys.pop(collision_key, None)

    def _evict_stale_identities(
        self,
        store: OrderedDict[Any, None],
        max_size: int,
        is_stale: Callable[[Any], bool],
    ) -> None:
        """Evict oldest identities that can no longer be polled.

        Live (in-window) keys are never evicted: LRU of a still-in-flight
        (rx, tx) pair would re-inflate poll counts. If every entry is still
        live the store may grow past ``max_size`` until start-time prune.
        """
        if len(store) < max_size:
            return
        stale_keys = [key for key in store if is_stale(key)]
        for key in stale_keys:
            if len(store) < max_size:
                break
            store.pop(key, None)

    def _add_latency_sample(self, latency_us: int) -> None:
        """Add a latency sample using reservoir sampling if at capacity."""
        if len(self._latency_samples) < self._MAX_LATENCY_SAMPLES:
            self._latency_samples.append(latency_us)
            self._latency_samples_sorted = False
        else:
            # Reservoir sampling: replace random element with probability.
            # This maintains a uniform random sample of all observations.
            idx = self._rng.randint(0, self._latency_count - 1)
            if idx < self._MAX_LATENCY_SAMPLES:
                self._latency_samples[idx] = latency_us
                self._latency_samples_sorted = False

    def record_collision(
        self,
        rx_node_id: str,
        tx_ids: Iterable[str],
        *,
        channel: int | None = None,
        time_us: int | None = None,
    ) -> bool:
        """Record a collision at a receiver among overlapping transmissions.

        Idempotent per ``(rx_node_id, frozenset(tx_ids))`` at this API.
        The radio layer additionally holds a collision epoch so an evolving
        overlap is one event. Returns ``True`` only for the first observation
        of a collision identity.

        Args:
            rx_node_id: ID of the receiving node experiencing the collision.
            tx_ids: IDs of the transmissions overlapping at the receiver.
            channel: Optional channel number where collision occurred.
            time_us: Optional simulation time in microseconds (for time-series).
        """
        tx_ids_frozen = frozenset(tx_ids)
        key = (rx_node_id, tx_ids_frozen)
        if key in self._collision_keys:
            self._collision_keys.move_to_end(key)
            return False
        self._evict_stale_identities(
            self._collision_keys,
            self._COLLISION_KEYS_MAX_SIZE,
            lambda k: not any(tid in self._tx_start_times for tid in k[1]),
        )
        self._collision_keys[key] = None
        self._collisions += 1
        # Track per-node collision.
        self._collisions_by_node[rx_node_id] += 1
        # Track per-channel collision if channel provided.
        if channel is not None:
            self._collisions_by_channel[channel] += 1
        # Record time-series event.
        if time_us is not None:
            self._time_series.append(
                (
                    time_us,
                    "collision",
                    {
                        "rx_node": rx_node_id,
                        "tx_ids": sorted(tx_ids_frozen),
                        "channel": channel,
                    },
                )
            )
        return True

    @property
    def transmissions(self) -> int:
        """Number of transmissions started."""
        return self._transmissions

    @property
    def receptions(self) -> int:
        """Number of distinct successful deliveries (receiver, transmission)."""
        return self._receptions

    @property
    def collisions(self) -> int:
        """Number of distinct collision events."""
        return self._collisions

    @property
    def delivery_rate(self) -> float:
        """Average successful deliveries per transmission.

        Returns 0.0 when no transmissions have occurred. May exceed 1.0 when a
        single transmission is delivered to multiple receivers.
        """
        if self._transmissions == 0:
            return 0.0
        return self.receptions / self._transmissions

    @property
    def collision_rate(self) -> float:
        """Fraction of reception outcomes that were collisions.

        Defined as ``collisions / (collisions + receptions)``. Returns 0.0 when
        there have been no reception outcomes.
        """
        outcomes = self._collisions + self.receptions
        if outcomes == 0:
            return 0.0
        return self._collisions / outcomes

    @property
    def collisions_by_channel(self) -> dict[int, int]:
        """Per-channel collision counts.

        Returns a copy of the internal dictionary mapping channel numbers
        to collision counts.
        """
        return dict(self._collisions_by_channel)

    @property
    def collisions_by_node(self) -> dict[str, int]:
        """Per-node collision counts.

        Returns a copy of the internal dictionary mapping node IDs
        to collision counts experienced at that node.
        """
        return dict(self._collisions_by_node)

    def _ensure_samples_sorted(self) -> None:
        """Sort latency samples if needed."""
        if not self._latency_samples_sorted:
            self._latency_samples.sort()
            self._latency_samples_sorted = True

    def _percentile(self, p: float) -> int | None:
        """Calculate the p-th percentile of latency samples.

        Args:
            p: Percentile to calculate (0-100).

        Returns:
            The percentile value in microseconds, or None if no samples.
        """
        if not self._latency_samples:
            return None
        self._ensure_samples_sorted()
        # Use nearest-rank method.
        idx = int((p / 100.0) * len(self._latency_samples))
        idx = min(idx, len(self._latency_samples) - 1)
        return self._latency_samples[idx]

    def latency_p50(self) -> int | None:
        """Return the 50th percentile (median) latency in microseconds."""
        return self._percentile(50.0)

    def latency_p95(self) -> int | None:
        """Return the 95th percentile latency in microseconds."""
        return self._percentile(95.0)

    def latency_p99(self) -> int | None:
        """Return the 99th percentile latency in microseconds."""
        return self._percentile(99.0)

    def latency_stats(self) -> LatencyStats:
        """Return min/max/mean/percentile latency over all successful deliveries."""
        if self._latency_count == 0:
            return LatencyStats(count=0, min_us=None, max_us=None, mean_us=None)
        return LatencyStats(
            count=self._latency_count,
            min_us=self._latency_min_us,
            max_us=self._latency_max_us,
            mean_us=self._latency_sum_us / self._latency_count,
            p50_us=self.latency_p50(),
            p95_us=self.latency_p95(),
            p99_us=self.latency_p99(),
        )

    def snapshot(self) -> dict[str, object]:
        """Return a JSON-serializable summary of all metrics."""
        stats = self.latency_stats()
        return {
            "transmissions": self.transmissions,
            "receptions": self.receptions,
            "collisions": self.collisions,
            "delivery_rate": self.delivery_rate,
            "collision_rate": self.collision_rate,
            "latency_us": {
                "count": stats.count,
                "min": stats.min_us,
                "max": stats.max_us,
                "mean": stats.mean_us,
                "p50": stats.p50_us,
                "p95": stats.p95_us,
                "p99": stats.p99_us,
            },
            "collisions_by_channel": self.collisions_by_channel,
            "collisions_by_node": self.collisions_by_node,
            "duty_cycle": self._duty_cycle,
        }

    @property
    def duty_cycle(self) -> float:
        """Return the current duty cycle utilization (0.0 to 1.0+)."""
        return self._duty_cycle

    def set_duty_cycle(self, value: float) -> None:
        """Update the current duty cycle utilization.

        Called by the simulation to reflect aggregate duty cycle usage
        across all nodes.

        Args:
            value: Duty cycle as a ratio (0.0 to 1.0, or higher if over limit).
        """
        self._duty_cycle = value

    @property
    def dashboard_time_series(self) -> MetricsTimeSeries:
        """Return the time-series storage for dashboard visualization."""
        return self._dashboard_time_series

    def record_dashboard_sample(self, time_us: int) -> MetricsSample | None:
        """Record a time-series sample if the interval has elapsed.

        This method should be called periodically (e.g., on each simulation
        tick) to capture metrics at regular intervals for dashboard charts.

        Args:
            time_us: Current simulation time in microseconds.

        Returns:
            The recorded MetricsSample, or None if not enough time has passed.
        """
        if not self._dashboard_time_series.should_sample(time_us):
            return None
        return self._dashboard_time_series.record_sample(
            time_us=time_us,
            delivery_rate=self.delivery_rate,
            collision_rate=self.collision_rate,
            duty_cycle=self._duty_cycle,
            transmissions=self.transmissions,
            receptions=self.receptions,
            collisions=self.collisions,
        )

    def get_dashboard_snapshot(self, since_us: int | None = None) -> dict[str, Any]:
        """Return a dashboard-ready snapshot with current metrics and time-series.

        Args:
            since_us: If provided, only include time-series samples after this time.

        Returns:
            Dictionary with current metrics and time-series data.
        """
        latest = self._dashboard_time_series.get_latest()
        return {
            "current": {
                "delivery_rate": self.delivery_rate,
                "collision_rate": self.collision_rate,
                "duty_cycle": self._duty_cycle,
                "transmissions": self.transmissions,
                "receptions": self.receptions,
                "collisions": self.collisions,
            },
            "time_series": self._dashboard_time_series.to_dict_list(since_us),
            "last_sample_time_us": latest.time_us if latest else None,
        }

    def reset(self) -> None:
        """Clear all counters and statistics."""
        self._transmissions = 0
        self._tx_start_times.clear()
        self._tx_latency_recorded.clear()
        self._delivered.clear()
        self._receptions = 0
        self._collision_keys.clear()
        self._collisions = 0
        self._latency_count = 0
        self._latency_sum_us = 0
        self._latency_min_us = None
        self._latency_max_us = None
        self._latency_samples.clear()
        self._latency_samples_sorted = True
        self._collisions_by_channel.clear()
        self._collisions_by_node.clear()
        self._time_series.clear()
        self._dashboard_time_series.clear()
        self._duty_cycle = 0.0

    def export_csv(self, path: str | Path) -> None:
        """Export metrics to a CSV file.

        Exports time-series data (transmissions, receptions, collisions) with
        timestamps, and summary statistics in a header section.

        Args:
            path: File path for the CSV output.
        """
        path = Path(path)
        with path.open("w", newline="") as f:
            writer = csv.writer(f)
            # Write summary header.
            writer.writerow(["# LICHEN Simulation Metrics Export"])
            writer.writerow(["# Summary Statistics"])
            stats = self.latency_stats()
            writer.writerow(["transmissions", self.transmissions])
            writer.writerow(["receptions", self.receptions])
            writer.writerow(["collisions", self.collisions])
            writer.writerow(["delivery_rate", f"{self.delivery_rate:.6f}"])
            writer.writerow(["collision_rate", f"{self.collision_rate:.6f}"])
            writer.writerow(["latency_min_us", _csv_number(stats.min_us)])
            writer.writerow(["latency_max_us", _csv_number(stats.max_us)])
            writer.writerow(["latency_mean_us", _csv_number(stats.mean_us, precision=2)])
            writer.writerow(["latency_p50_us", _csv_number(stats.p50_us)])
            writer.writerow(["latency_p95_us", _csv_number(stats.p95_us)])
            writer.writerow(["latency_p99_us", _csv_number(stats.p99_us)])
            writer.writerow([])
            # Write per-channel collision summary.
            writer.writerow(["# Collisions by Channel"])
            writer.writerow(["channel", "collisions"])
            for channel, count in sorted(self._collisions_by_channel.items()):
                writer.writerow([channel, count])
            writer.writerow([])
            # Write per-node collision summary.
            writer.writerow(["# Collisions by Node"])
            writer.writerow(["node_id", "collisions"])
            for node_id, count in sorted(self._collisions_by_node.items()):
                writer.writerow([node_id, count])
            writer.writerow([])
            # Write time-series data.
            writer.writerow(["# Time-Series Events"])
            writer.writerow(["time_us", "event_type", "rx_node", "tx_id", "latency_us", "channel"])
            for time_us, event_type, details in sorted(self._time_series, key=lambda x: x[0]):
                row = [
                    time_us,
                    event_type,
                    details.get("rx_node", ""),
                    _csv_tx_id(details),
                    details.get("latency_us", ""),
                    details.get("channel", ""),
                ]
                writer.writerow(row)


@dataclass
class MetricChange:
    """A single metric comparison result.

    Attributes:
        name: Name of the metric being compared.
        baseline: Value from the baseline run.
        variant: Value from the variant run.
        delta: Absolute change (variant - baseline).
        pct_change: Percentage change from baseline.
        significant: Whether the change is statistically significant.
        direction: "improved", "degraded", or "unchanged" based on metric semantics.
    """

    name: str
    baseline: float
    variant: float
    delta: float
    pct_change: float | None
    significant: bool
    direction: str


@dataclass
class MetricsDiff:
    """Result of comparing two simulation runs for A/B testing.

    Contains per-metric changes and an overall summary of whether
    the variant shows statistically significant differences.
    """

    changes: list[MetricChange]
    significant_improvements: int
    significant_degradations: int
    overall_verdict: str  # "better", "worse", "neutral"

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dictionary of the diff report."""
        return {
            "changes": [
                {
                    "name": c.name,
                    "baseline": c.baseline,
                    "variant": c.variant,
                    "delta": c.delta,
                    "pct_change": c.pct_change,
                    "significant": c.significant,
                    "direction": c.direction,
                }
                for c in self.changes
            ],
            "significant_improvements": self.significant_improvements,
            "significant_degradations": self.significant_degradations,
            "overall_verdict": self.overall_verdict,
        }

    def summary(self) -> str:
        """Return a human-readable summary of significant changes."""
        lines = []
        lines.append(f"A/B Test Result: {self.overall_verdict.upper()}")
        lines.append(f"  Improvements: {self.significant_improvements}")
        lines.append(f"  Degradations: {self.significant_degradations}")
        lines.append("")
        lines.append("Significant changes:")
        for c in self.changes:
            if c.significant:
                pct = f"{c.pct_change:+.1f}%" if c.pct_change is not None else "N/A"
                lines.append(
                    f"  {c.name}: {c.baseline:.4g} -> {c.variant:.4g} ({pct}) [{c.direction}]"
                )
        if not any(c.significant for c in self.changes):
            lines.append("  (none)")
        return "\n".join(lines)


def _csv_number(value: int | float | None, *, precision: int | None = None) -> str:
    """Serialize a metric for CSV. None is empty; 0 is "0" not blank."""
    if value is None:
        return ""
    if precision is not None:
        return f"{value:.{precision}f}"
    return str(value)


def _csv_tx_id(details: dict[str, Any]) -> str:
    """CSV tx_id cell: receptions use tx_id; collisions use joined tx_ids."""
    tx_id = details.get("tx_id")
    if tx_id is not None and tx_id != "":
        return str(tx_id)
    tx_ids = details.get("tx_ids")
    if tx_ids is None or tx_ids == "":
        return ""
    if isinstance(tx_ids, str):
        return tx_ids
    return ",".join(str(t) for t in tx_ids)


def _compute_pct_change(baseline: float, variant: float) -> float | None:
    """Compute percentage change, handling zero baseline."""
    if baseline == 0:
        return None if variant == 0 else float("inf") if variant > 0 else float("-inf")
    return ((variant - baseline) / baseline) * 100


_RATE_METRICS = frozenset({"delivery_rate", "collision_rate"})


def _is_significant(
    baseline: float,
    variant: float,
    threshold: float = 0.05,
    *,
    rate: bool = False,
) -> bool:
    """Determine if a change is significant based on relative threshold.

    Uses a simple threshold-based approach: a change is significant if
    the relative change exceeds the threshold (default 5%).

    For count-based metrics, a jump from zero requires |variant| >= 1.
    For rates in [0, 1+], that floor would hide 0 → 0.9; use ``threshold``.
    """
    if baseline == 0 and variant == 0:
        return False
    if baseline == 0:
        if rate:
            return abs(variant) >= threshold
        return abs(variant) >= 1
    rel_change = abs(variant - baseline) / abs(baseline)
    return rel_change >= threshold


def _rate_direction(name: str, baseline: float, variant: float) -> str:
    """Determine if a metric change is an improvement or degradation.

    Higher-is-better metrics: delivery_rate
    Lower-is-better metrics: collision_rate, latency_*
    """
    if abs(variant - baseline) < 1e-9:
        return "unchanged"

    # Define metric semantics: True = higher is better, False = lower is better.
    higher_is_better = {
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

    is_higher = variant > baseline
    prefers_higher = higher_is_better.get(name, True)  # default to higher is better

    if is_higher == prefers_higher:
        return "improved"
    return "degraded"


def compare_metrics(
    baseline: dict[str, object],
    variant: dict[str, object],
    threshold: float = 0.05,
) -> MetricsDiff:
    """Compare two metric snapshots for A/B testing.

    Takes two snapshots (from Metrics.snapshot()) and produces a diff report
    highlighting which metrics changed and whether changes are statistically
    significant.

    Args:
        baseline: Metrics snapshot from the baseline/control run.
        variant: Metrics snapshot from the variant/test run.
        threshold: Relative change threshold for significance (default 5%).

    Returns:
        MetricsDiff with per-metric comparisons and overall verdict.
    """
    changes: list[MetricChange] = []

    # Top-level scalar metrics.
    scalar_keys = ["transmissions", "receptions", "collisions", "delivery_rate", "collision_rate"]
    for key in scalar_keys:
        b_val = float(cast(int | float, baseline.get(key, 0)))
        v_val = float(cast(int | float, variant.get(key, 0)))
        delta = v_val - b_val
        pct = _compute_pct_change(b_val, v_val)
        sig = _is_significant(b_val, v_val, threshold, rate=key in _RATE_METRICS)
        direction = _rate_direction(key, b_val, v_val)
        changes.append(
            MetricChange(
                name=key,
                baseline=b_val,
                variant=v_val,
                delta=delta,
                pct_change=pct,
                significant=sig,
                direction=direction,
            )
        )

    # Latency metrics (nested under latency_us).
    b_lat = baseline.get("latency_us", {})
    v_lat = variant.get("latency_us", {})
    if isinstance(b_lat, dict) and isinstance(v_lat, dict):
        lat_keys = ["min", "max", "mean", "p50", "p95", "p99"]
        for key in lat_keys:
            b_latency = b_lat.get(key)
            v_latency = v_lat.get(key)
            # Missing samples are not 0 µs. Skip when either side has no value
            # so None→0 cannot be scored as a latency win.
            if b_latency is None or v_latency is None:
                continue
            b_val = float(cast(int | float, b_latency))
            v_val = float(cast(int | float, v_latency))
            metric_name = f"latency_{key}_us"
            delta = v_val - b_val
            pct = _compute_pct_change(b_val, v_val)
            sig = _is_significant(b_val, v_val, threshold)
            direction = _rate_direction(metric_name, b_val, v_val)
            changes.append(
                MetricChange(
                    name=metric_name,
                    baseline=b_val,
                    variant=v_val,
                    delta=delta,
                    pct_change=pct,
                    significant=sig,
                    direction=direction,
                )
            )

    # Count significant improvements and degradations.
    improvements = sum(1 for c in changes if c.significant and c.direction == "improved")
    degradations = sum(1 for c in changes if c.significant and c.direction == "degraded")

    # Determine overall verdict.
    if degradations > 0 and improvements == 0:
        verdict = "worse"
    elif (improvements > 0 and degradations == 0) or improvements > degradations:
        verdict = "better"
    elif degradations > improvements:
        verdict = "worse"
    else:
        verdict = "neutral"

    return MetricsDiff(
        changes=changes,
        significant_improvements=improvements,
        significant_degradations=degradations,
        overall_verdict=verdict,
    )
