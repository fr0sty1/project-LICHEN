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

from collections.abc import Iterable
from dataclasses import dataclass


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

    def __init__(self) -> None:
        self._transmissions = 0
        self._tx_start_times: dict[str, int] = {}  # tx_id -> start_time_us
        self._delivered: set[tuple[str, str]] = set()  # (rx_node_id, tx_id)
        self._collision_keys: set[tuple[str, frozenset[str]]] = set()
        self._collisions = 0
        self._latencies_us: list[int] = []

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
            self._latencies_us.append(time_us - start)

    def record_collision(self, rx_node_id: str, tx_ids: Iterable[str]) -> None:
        """Record a collision at a receiver among overlapping transmissions.

        Idempotent per ``(rx_node_id, frozenset(tx_ids))``: while a given set
        of transmissions overlaps at a receiver, the polling loop observes the
        same collision repeatedly; it is counted once.

        Args:
            rx_node_id: ID of the receiving node experiencing the collision.
            tx_ids: IDs of the transmissions overlapping at the receiver.
        """
        key = (rx_node_id, frozenset(tx_ids))
        if key in self._collision_keys:
            return
        self._collision_keys.add(key)
        self._collisions += 1

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
        if not self._latencies_us:
            return LatencyStats(count=0, min_us=None, max_us=None, mean_us=None)
        return LatencyStats(
            count=len(self._latencies_us),
            min_us=min(self._latencies_us),
            max_us=max(self._latencies_us),
            mean_us=sum(self._latencies_us) / len(self._latencies_us),
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
        self._latencies_us.clear()
