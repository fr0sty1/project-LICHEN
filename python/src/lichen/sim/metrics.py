# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Metrics collection for the LICHEN simulator.

Tracks transmission and reception activity in a running simulation:
transmission starts, successful receptions, collisions, per-delivery latency,
and the derived delivery and collision rates.

The recording methods are deduplicated by design. The simulation polls
``Simulation.get_rx_result`` on a ~1 ms interval while a node waits, so the
same physical delivery or collision is observed many times; each is counted
once via the ``(receiver, transmission)`` and ``(receiver, frozenset of
overlapping transmissions)`` keys.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


@dataclass
class NodeMetrics:
    """Per-node telemetry metrics for cross-implementation tracking.

    Tracks transmission/reception counts, byte totals, unique peers seen,
    and packet hashes for verifying cross-implementation interoperability.

    The packet hash sets are capped at ``_PACKET_HASH_SET_MAX_SIZE`` to prevent
    unbounded memory growth in long-running simulations. Once the cap is reached,
    no new hashes are added, but counts (tx_count, rx_count) remain accurate.
    """

    # Maximum entries in packet_hashes_sent and packet_hashes_received.
    # Prevents unbounded memory growth in long-running simulations.
    _PACKET_HASH_SET_MAX_SIZE: ClassVar[int] = 10000
    _MAX_ERRORS: ClassVar[int] = 1000

    tx_count: int = 0
    rx_count: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    unique_peers: set[str] = field(default_factory=set)
    errors: set[str] = field(default_factory=set)
    packet_hashes_sent: set[str] = field(default_factory=set)
    packet_hashes_received: set[str] = field(default_factory=set)

    def record_tx(self, payload: bytes, packet_hash: str) -> None:
        """Record a transmission.

        Args:
            payload: The transmitted payload bytes.
            packet_hash: SHA256[:16] hash of the payload.
        """
        self.tx_count += 1
        self.tx_bytes += len(payload)
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


class Metrics:
    """Counters and statistics for a single simulation run.

    All counts are deduplicated, so callers may record the same observation
    repeatedly (as the simulator's polling loop does) without inflating the
    totals.
    """

    # Max age for _tx_start_times entries (60 seconds in microseconds).
    # Entries older than this are pruned to prevent unbounded memory growth.
    _TX_START_TIMES_MAX_AGE_US = 60_000_000
    # Only prune when dict exceeds this size (avoids overhead for small runs).
    _TX_START_TIMES_PRUNE_THRESHOLD = 1000

    def __init__(self) -> None:
        self._transmissions = 0
        self._tx_start_times: dict[str, int] = {}  # tx_id -> start_time_us
        self._delivered: set[tuple[str, str]] = set()  # (rx_node_id, tx_id)
        self._collision_keys: set[tuple[str, frozenset[str]]] = set()
        self._collisions = 0
        # Running statistics for latency (O(1) memory vs unbounded list).
        self._latency_count = 0
        self._latency_sum_us = 0
        self._latency_min_us: int | None = None
        self._latency_max_us: int | None = None

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

        # Prune old entries to prevent unbounded memory growth.
        if len(self._tx_start_times) > self._TX_START_TIMES_PRUNE_THRESHOLD:
            cutoff = start_time_us - self._TX_START_TIMES_MAX_AGE_US
            old_keys = [k for k, v in self._tx_start_times.items() if v < cutoff]
            for k in old_keys:
                del self._tx_start_times[k]

    def record_reception(self, rx_node_id: str, tx_id: str, time_us: int) -> None:
        """Record a successful reception of a transmission by a node.

        Idempotent per ``(rx_node_id, tx_id)``: repeated calls for the same
        delivery are ignored, so polling does not inflate the count.

        Args:
            rx_node_id: ID of the receiving node.
            tx_id: ID of the transmission that was received.
            time_us: Simulation time the reception was observed, in
                microseconds.
        """
        key = (rx_node_id, tx_id)
        if key in self._delivered:
            return
        self._delivered.add(key)
        start = self._tx_start_times.get(tx_id)
        if start is not None and time_us >= start:
            latency = time_us - start
            self._latency_count += 1
            self._latency_sum_us += latency
            if self._latency_min_us is None or latency < self._latency_min_us:
                self._latency_min_us = latency
            if self._latency_max_us is None or latency > self._latency_max_us:
                self._latency_max_us = latency
        elif start is not None and time_us < start:
            logger.warning(
                "record_reception: time_us (%d) < start (%d) for tx_id=%s, rx_node_id=%s",
                time_us, start, tx_id, rx_node_id,
            )

    def record_collision(self, rx_node_id: str, tx_ids: Iterable[str]) -> bool:
        """Record a collision at a receiver among overlapping transmissions.

        Idempotent per ``(rx_node_id, frozenset(tx_ids))``: while a given set
        of transmissions overlaps at a receiver, the polling loop observes the
        same collision repeatedly; it is counted once. Returns ``True`` only
        for the first observation of a collision identity.

        Args:
            rx_node_id: ID of the receiving node experiencing the collision.
            tx_ids: IDs of the transmissions overlapping at the receiver.
        """
        key = (rx_node_id, frozenset(tx_ids))
        if key in self._collision_keys:
            return False
        self._collision_keys.add(key)
        self._collisions += 1
        return True

    @property
    def transmissions(self) -> int:
        """Number of transmissions started."""
        return self._transmissions

    @property
    def receptions(self) -> int:
        """Number of distinct successful deliveries (receiver, transmission)."""
        return len(self._delivered)

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

    def latency_stats(self) -> LatencyStats:
        """Return min/max/mean latency over all successful deliveries."""
        if self._latency_count == 0:
            return LatencyStats(count=0, min_us=None, max_us=None, mean_us=None)
        return LatencyStats(
            count=self._latency_count,
            min_us=self._latency_min_us,
            max_us=self._latency_max_us,
            mean_us=self._latency_sum_us / self._latency_count,
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
            },
        }

    def reset(self) -> None:
        """Clear all counters and statistics."""
        self._transmissions = 0
        self._tx_start_times.clear()
        self._delivered.clear()
        self._collision_keys.clear()
        self._collisions = 0
        self._latency_count = 0
        self._latency_sum_us = 0
        self._latency_min_us = None
        self._latency_max_us = None
