# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TX queue with priority levels and deadline expiry.

Why this exists: LoRa channels are slow and subject to duty cycle limits.
Packets must wait for channel access, but unbounded buffering causes
latency explosion (bufferbloat). This queue provides:

1. Bounded capacity (4 packets max)
2. Priority-based preemption (routing > ACK > urgent > bulk)
3. Time-based expiry (stale packets dropped before TX)
4. Explicit backpressure (QueueFullError exception, not silent drop)

See spec/appendix-bufferbloat.md for design rationale.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger(__name__)

# Queue capacity (spec says 4 packets max)
TX_QUEUE_CAPACITY = 4

# Default deadlines in milliseconds (spec/appendix-bufferbloat.md)
DEADLINE_ROUTING_MS = 5000   # Routing control (DIO/DAO)
DEADLINE_ACK_MS = 10000      # Link-layer ACKs
DEADLINE_APP_MS = 60000      # Application data


class Priority(IntEnum):
    """TX packet priority levels.

    Lower numeric value = higher priority.
    Routing control is most urgent; bulk data can wait.
    """

    ROUTING = 0  # RPL DIO/DAO, network control
    ACK = 1      # Link-layer acknowledgments
    URGENT = 2   # Time-sensitive app messages
    BULK = 3     # Regular data, can tolerate delay


def _default_deadline_for(priority: Priority) -> int:
    """Return default deadline in ms for a priority level."""
    if priority == Priority.ROUTING:
        return DEADLINE_ROUTING_MS
    elif priority == Priority.ACK:
        return DEADLINE_ACK_MS
    else:
        return DEADLINE_APP_MS


class QueueFullError(Exception):
    """Raised when TX queue is full and cannot accept new packet.

    This is explicit backpressure: callers must handle it (back off,
    drop the packet, notify application). Silent drops hide congestion.
    """

    pass


@dataclass
class TxQueueEntry:
    """A packet waiting for transmission.

    Attributes:
        data: The frame bytes to transmit.
        priority: Packet priority (lower = more urgent).
        deadline_ms: Absolute timestamp (ms since epoch) when packet expires.
        enqueue_time_ms: When packet was queued (for latency stats).
    """

    data: bytes
    priority: Priority
    deadline_ms: int
    enqueue_time_ms: int = field(default_factory=lambda: int(time.monotonic() * 1000))


class TxReservation:
    """Per-entry reservation for independent TX tracking.

    Enables concurrent sends without coarse serialization. In-flight entries are
    protected from preemption and removal. Supports per-send completion, safe
    cancellation (no duplicate retries), and unambiguous results.
    """

    def __init__(self, data: bytes, priority: Priority, deadline_ms: int, enqueue_time_ms: int):
        self.data = data
        self.priority = priority
        self.deadline_ms = deadline_ms
        self.enqueue_time_ms = enqueue_time_ms
        self._future: asyncio.Future[bool] = asyncio.Future()
        self._in_flight: bool = False
        self._cancelled: bool = False

    def mark_in_flight(self) -> None:
        self._in_flight = True

    def is_in_flight(self) -> bool:
        return self._in_flight

    def complete(self, success: bool) -> None:
        if not self._future.done():
            self._future.set_result(success)

    def cancel(self) -> bool:
        if not self._future.done():
            self._cancelled = True
            self._future.cancel()
            return True
        return False

    def cancelled(self) -> bool:
        return self._cancelled

    async def wait(self) -> bool:
        try:
            return await self._future
        except asyncio.CancelledError:
            self.cancel()
            raise


@dataclass
class TxQueueStats:
    """Queue statistics for diagnostics.

    Exposed via CoAP /status/queues resource.

    Attributes:
        packets_queued: Total packets pushed to the queue.
        packets_dropped_deadline: Packets dropped due to deadline expiry.
        packets_dropped_preempt: Packets evicted by higher-priority preemption.
        packets_dropped_full: Packets rejected with QueueFullError.
        packets_transmitted: Packets successfully popped for transmission.
        max_latency_ms: Maximum time any packet spent in queue.
        avg_latency_ms: Smoothed average queue latency (EMA, alpha=0.1).
    """

    packets_queued: int = 0
    packets_dropped_deadline: int = 0
    packets_dropped_preempt: int = 0
    packets_dropped_full: int = 0  # Rejected by QueueFullError
    packets_transmitted: int = 0
    max_latency_ms: int = 0
    avg_latency_ms: int = 0


class TxQueue:
    """Priority TX queue with deadline expiry.

    Thread safety: Not thread-safe. Use external synchronization if
    accessed from multiple async tasks.

    Attributes:
        capacity: Maximum number of packets (default: 4).
        clock: Callable returning current time in ms (for testing).
        stats: Cumulative queue statistics.
    """

    # EMA smoothing factor for avg_latency_ms (0.1 = 10% new, 90% old)
    # Why 0.1: Smooths over ~10 samples, responsive but not jumpy.
    _EMA_ALPHA = 0.1

    def __init__(
        self,
        capacity: int = TX_QUEUE_CAPACITY,
        clock: Callable[[], int] | None = None,
    ):
        """Initialize TX queue.

        Args:
            capacity: Maximum packets to buffer. Must be > 0.
            clock: Optional clock function for testing. Returns ms since
                   some epoch. Defaults to time.monotonic() * 1000.

        Raises:
            ValueError: If capacity <= 0.
        """
        if capacity <= 0:
            raise ValueError(f"capacity must be positive, got {capacity}")
        self._capacity = capacity
        self._clock = clock or (lambda: int(time.monotonic() * 1000))
        self._entries: list[TxQueueEntry] = []
        self._in_flight: list[TxQueueEntry] = []
        self.stats = TxQueueStats()
        self._avg_latency_ema: float = 0.0

    def __len__(self) -> int:
        """Return number of packets currently queued."""
        return len(self._entries)

    @property
    def capacity(self) -> int:
        """Maximum queue capacity."""
        return self._capacity

    def expire_stale(self) -> int:
        now = self._clock()
        before_count = len(self._entries) + len(self._in_flight)
        self._entries = [e for e in self._entries if e.deadline_ms > now]
        self._in_flight = [e for e in self._in_flight if e.deadline_ms > now]
        expired = before_count - (len(self._entries) + len(self._in_flight))
        if expired > 0:
            self.stats.packets_dropped_deadline += expired
            logger.debug("expired %d stale packets from TX queue", expired)
        return expired

    def push(
        self,
        data: bytes,
        priority: Priority = Priority.BULK,
        deadline_ms: int | None = None,
        return_reservation: bool = False,
    ) -> TxReservation | None:
        """Add a packet to the queue. If return_reservation=True, returns
        TxReservation for per-entry tracking, completion, and cancellation.

        This enables replacing coarse TX serialization with per-entry reservations
        in LinkLayer. In-flight reservations are protected from preemption.

        Behavior when full:
        - If new packet has higher priority than lowest-priority queued
          packet, evict the lowest and enqueue new packet (preemption).
        - If new packet has same or lower priority than all queued packets,
          raise QueueFullError (explicit backpressure).

        Args:
            data: Frame bytes to transmit.
            priority: Packet priority level.
            deadline_ms: Absolute deadline (ms since monotonic epoch).
                         If None, uses default for priority level.
            return_reservation: If True, return TxReservation instead of None.

        Raises:
            QueueFullError: If queue is full and preemption not possible.
        """
        # Expire stale packets first - might make room
        self.expire_stale()

        now = self._clock()
        if deadline_ms is None:
            deadline_ms = now + _default_deadline_for(priority)

        if return_reservation:
            entry: TxReservation = TxReservation(
                data, priority, deadline_ms, now
            )
        else:
            entry = TxQueueEntry(
                data=data,
                priority=priority,
                deadline_ms=deadline_ms,
                enqueue_time_ms=now,
            )

        if len(self._entries) < self._capacity:
            # Room available - just insert
            self._insert_sorted(entry)
            self.stats.packets_queued += 1
            logger.debug(
                "TX queue push: priority=%s len=%d/%d",
                priority.name,
                len(self._entries),
                self._capacity,
            )
            return entry if return_reservation else None

        # Queue is full - check if we can preempt
        # Find lowest-priority non-inflight packet (in-flight protected)
        non_inflight = [
            e for e in self._entries
            if not getattr(e, "is_in_flight", lambda: False)()
        ]
        lowest = None if not non_inflight else max(non_inflight, key=lambda e: e.priority)

        if lowest is not None and priority < lowest.priority:
            # New packet is higher priority - preempt
            self._entries.remove(lowest)
            self.stats.packets_dropped_preempt += 1
            logger.debug(
                "TX queue preempt: evicted priority=%s for priority=%s",
                Priority(lowest.priority).name,
                priority.name,
            )
            self._insert_sorted(entry)
            self.stats.packets_queued += 1
        else:
            # Cannot preempt (full of in-flight or lower/same priority) - raise
            self.stats.packets_dropped_full += 1
            lowest_p = Priority(lowest.priority).name if lowest is not None else "inflight-only"
            logger.warning(
                "TX queue full: rejected priority=%s (lowest queued=%s)",
                priority.name,
                lowest_p,
            )
            raise QueueFullError(
                f"TX queue full ({self._capacity} packets), "
                f"cannot preempt priority {lowest_p}"
            )

        if return_reservation:
            return entry
        return None

    def pop(self) -> bytes | None:
        entry = self.reserve()
        if entry is None:
            return None
        self.complete(entry, True)
        return entry.data

    def reserve(self) -> TxQueueEntry | None:
        self.expire_stale()
        if not self._entries:
            return None
        entry = self._entries.pop(0)
        self._in_flight.append(entry)
        return entry

    def complete(self, entry: TxQueueEntry, success: bool = True) -> None:
        if entry in self._in_flight:
            self._in_flight.remove(entry)
        if success:
            now = self._clock()
            latency = now - entry.enqueue_time_ms
            if latency > self.stats.max_latency_ms:
                self.stats.max_latency_ms = latency
            self._avg_latency_ema = (
                self._EMA_ALPHA * latency + (1 - self._EMA_ALPHA) * self._avg_latency_ema
            )
            self.stats.avg_latency_ms = int(self._avg_latency_ema)
            self.stats.packets_transmitted += 1
        else:
            now = self._clock()
            if entry.deadline_ms > now:
                self._insert_sorted(entry)
            else:
                self.stats.packets_dropped_deadline += 1

    def pop_reservation(self) -> TxReservation | None:
        """Pop the next highest-priority reservation for transmission.

        Marks it as in-flight (protected from preemption by concurrent pushes).
        Used by LinkLayer.drain_tx_queue for per-entry completion/cancellation.
        Legacy pop() remains unchanged for tests.

        Returns:
            TxReservation or None if no pending non-inflight entry.
        """
        self.expire_stale()

        if not self._entries:
            return None

        # Find first non-inflight entry (highest priority first); supports
        # mixed TxQueueEntry (tests) and TxReservation. In-flight protected.
        for i, entry in enumerate(self._entries):
            if getattr(entry, "is_in_flight", lambda: False)():
                continue
            popped = self._entries.pop(i)
            if isinstance(popped, TxReservation):
                popped.mark_in_flight()
                logger.debug(
                    "TX queue pop_reservation: priority=%s len=%d/%d",
                    popped.priority.name,
                    len(self._entries),
                    self._capacity,
                )
                return popped
            # Legacy entry - wrap in reservation for consistent API
            res = TxReservation(
                popped.data,
                popped.priority,
                popped.deadline_ms,
                popped.enqueue_time_ms,
            )
            res.mark_in_flight()
            logger.debug(
                "TX queue pop_reservation (legacy wrap): priority=%s",
                res.priority.name,
            )
            return res

        return None

    def complete_reservation(self, reservation: TxReservation, success: bool) -> None:
        """Complete a reservation, updating stats only on success.

        Called after radio.transmit. Preserves entry on failure for retry.
        If cancelled, does not count as transmitted or requeue.
        """
        reservation.complete(success)
        now = self._clock()
        latency = now - reservation.enqueue_time_ms
        if success:
            if latency > self.stats.max_latency_ms:
                self.stats.max_latency_ms = latency
            self._avg_latency_ema = (
                self._EMA_ALPHA * latency + (1 - self._EMA_ALPHA) * self._avg_latency_ema
            )
            self.stats.avg_latency_ms = int(self._avg_latency_ema)
            self.stats.packets_transmitted += 1
            logger.debug(
                "TX complete success: priority=%s latency=%dms avg=%dms",
                reservation.priority.name,
                latency,
                self.stats.avg_latency_ms,
            )
        elif not reservation.cancelled():
            # Requeue for retry on radio failure (byte-identical)
            self.push(
                reservation.data,
                priority=reservation.priority,
                deadline_ms=reservation.deadline_ms,
            )
            logger.debug("TX failed, requeued for retry")
        # else: cancelled, drop without retry or stats update

    def peek(self) -> tuple[bytes, Priority] | None:
        """Peek at the highest-priority packet without removing it.

        Does NOT expire stale packets (use expire_stale() explicitly
        if needed before peek).

        Returns:
            (data, priority) tuple or None if queue empty.
        """
        if not self._entries:
            return None
        entry = self._entries[0]
        return (entry.data, entry.priority)

    def clear(self) -> int:
        count = len(self._entries) + len(self._in_flight)
        self._entries.clear()
        self._in_flight.clear()
        return count

    def _insert_sorted(self, entry: TxQueueEntry | TxReservation) -> None:
        """Insert entry maintaining sort order (priority ASC, time ASC).

        Priority is primary key (lower = more urgent).
        Enqueue time is secondary key (older = earlier, FIFO within priority).
        Supports both legacy entries and reservations.
        """
        # Find insertion point
        for i, existing in enumerate(self._entries):
            if (entry.priority, entry.enqueue_time_ms) < (
                existing.priority,
                existing.enqueue_time_ms,
            ):
                self._entries.insert(i, entry)
                return
        # Append at end if no earlier position found
        self._entries.append(entry)
