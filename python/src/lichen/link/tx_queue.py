# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TX queue with priority levels, deadline expiry, and CCP-16 TDMA awareness.

Why this exists: LoRa channels are slow and subject to duty cycle limits +
TDMA slots (worker8 CCP-16). Packets must wait for channel access;
unbounded buffering causes latency explosion (bufferbloat). This queue
provides:

1. Bounded capacity (4 packets max)
2. Priority-based preemption (routing > ACK > urgent > bulk)
3. Time-based expiry (stale packets dropped before TX)
4. Explicit backpressure (QueueFullError exception, not silent drop)

See spec/appendix-bufferbloat.md and spec/02a-coordinated-capacity.md.
"""

from __future__ import annotations

import asyncio
import logging
import time
from asyncio import Future
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
class TxReservation:
    """Reservation for awaiting completion of a specific queued packet.

    Fixes the re-queue deadline bug: the reservation carries the original
    deadline from push(), so re-queues (CAD failure, TX failure) preserve
    the absolute deadline rather than computing a fresh one.
    """

    _future: Future[bool] = field(
        default_factory=lambda: asyncio.Future(), repr=False
    )

    async def wait(self) -> bool:
        """Await transmission outcome. Returns True if transmitted."""
        return await self._future

    def set_result(self, success: bool) -> None:
        if not self._future.done():
            self._future.set_result(success)


@dataclass
class TxQueueEntry:
    """A packet waiting for transmission.

    Attributes:
        data: The frame bytes to transmit.
        priority: Packet priority (lower = more urgent).
        deadline_ms: Absolute timestamp (ms since epoch) when packet expires.
        enqueue_time_ms: When packet was queued (for latency stats).
        reservation: Optional reservation for the send() caller to await.
    """

    data: bytes
    dst_addr: bytes
    priority: Priority
    deadline_ms: int
    enqueue_time_ms: int
    reservation: TxReservation | None = field(default=None, repr=False)


@dataclass
class TxQueueStats:
    """Queue statistics for diagnostics.

    Exposed via CoAP /status/queues resource.

    Attributes:
        packets_queued: Total packets pushed to the queue.
        packets_dropped_deadline: Packets dropped due to deadline expiry.
        packets_dropped_preempt: Packets evicted by higher-priority preemption.
        packets_dropped_full: Packets rejected with QueueFullError.
        packets_transmitted: Packets confirmed transmitted by the radio.
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

    Reentrancy: expire_stale(), push() (which does list rebuild on
    preempt/expire), and pop() are not atomic. The list mutation +
    stats update sequence must not be interrupted (or protected by
    lock). Matches C pending_drop_tail non-atomic tail-update/memset/
    decrement requirement. Caller must ensure single-threaded access
    or external synchronization. See adapter.c:305 comment and
    spec for TDMA/pending semantics.

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
            capacity: Maximum packets to buffer.
            clock: Optional clock function for testing. Returns ms since
                   some epoch. Defaults to time.monotonic() * 1000.
        """
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._clock = clock or (lambda: int(time.monotonic() * 1000))
        self._entries: list[TxQueueEntry] = []
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
        """Remove packets that have passed their deadline.

        Called automatically before push() and pop(). Can also be called
        explicitly for proactive cleanup.

        Returns:
            Number of packets expired.
        """
        now = self._clock()
        before_count = len(self._entries)

        # Keep only entries with deadline in the future
        self._entries = [e for e in self._entries if e.deadline_ms > now]

        expired = before_count - len(self._entries)
        if expired > 0:
            self.stats.packets_dropped_deadline += expired
            logger.debug("expired %d stale packets from TX queue", expired)

        return expired

    def push(
        self,
        data: bytes,
        dst_addr: bytes = b"",
        priority: Priority = Priority.BULK,
        deadline_ms: int | None = None,
        return_reservation: bool = False,
    ) -> TxReservation | None:
        """Add a packet to the queue.

        Behavior when full:
        - If new packet has higher priority than lowest-priority queued
          packet, evict the lowest and enqueue new packet (preemption).
        - If new packet has same or lower priority than all queued packets,
          raise QueueFullError (explicit backpressure).

        The return_reservation option supports LinkLayer.send() awaiting
        specific packet completion. This also fixes the re-queue deadline
        bug by attaching the original absolute deadline to the entry.

        Args:
            data: Frame bytes to transmit.
            priority: Packet priority level.
            deadline_ms: Absolute deadline (ms since monotonic epoch).
                         If None, uses default for priority level.
            return_reservation: If True, return TxReservation for this packet.

        Returns:
            TxReservation if return_reservation=True, else None.

        Raises:
            QueueFullError: If queue is full and preemption not possible.
        """
        self.expire_stale()
        self.ensure_can_push(priority)

        now = self._clock()
        if deadline_ms is None:
            deadline_ms = now + _default_deadline_for(priority)

        reservation: TxReservation | None = None
        if return_reservation:
            reservation = TxReservation()

        entry = TxQueueEntry(
            data=data,
            dst_addr=dst_addr,
            priority=priority,
            deadline_ms=deadline_ms,
            enqueue_time_ms=now,
            reservation=reservation,
        )

        if len(self._entries) < self._capacity:
            self._insert_sorted(entry)
            self.stats.packets_queued += 1
            logger.debug(
                "TX queue push: priority=%s len=%d/%d",
                priority.name,
                len(self._entries),
                self._capacity,
            )
            return reservation

        lowest = max(self._entries, key=lambda e: e.priority)
        self._entries.remove(lowest)
        self.stats.packets_dropped_preempt += 1
        logger.debug(
            "TX queue preempt: evicted priority=%s for priority=%s",
            Priority(lowest.priority).name,
            priority.name,
        )
        self._insert_sorted(entry)
        self.stats.packets_queued += 1
        return reservation

    def ensure_can_push(self, priority: Priority) -> None:
        """Reject a non-preemptible full queue without mutating live entries."""
        now = self._clock()
        active_entries = [entry for entry in self._entries if entry.deadline_ms > now]
        if len(active_entries) < self._capacity:
            return

        lowest = max(active_entries, key=lambda entry: entry.priority)
        if priority >= lowest.priority:
            self.stats.packets_dropped_full += 1
            logger.warning(
                "TX queue full: rejected priority=%s (lowest queued=%s)",
                priority.name,
                Priority(lowest.priority).name,
            )
            raise QueueFullError(
                f"TX queue full ({self._capacity} packets), "
                f"cannot preempt priority {Priority(lowest.priority).name}"
            )

    def pop(self) -> bytes | None:
        """Remove and return the highest-priority packet.

        Expires stale packets first, then returns the packet with lowest
        priority value (highest urgency). If multiple packets have the
        same priority, returns the oldest (FIFO within priority).

        Returns:
            Frame bytes to transmit, or None if queue empty.
        """
        self.expire_stale()

        if not self._entries:
            return None

        return self._entries.pop(0).data

    def confirm_transmitted(self, expected: bytes) -> None:
        """Remove the front packet after the radio confirms transmission.

        The expected bytes bind confirmation to the packet selected by peek().
        No expiry runs here because the packet has already been transmitted.
        """
        if not self._entries or self._entries[0].data != expected:
            raise ValueError("transmitted packet is not at queue front")
        self._remove_first()

    def _remove_first(self) -> TxQueueEntry:
        """Remove the front entry and update successful-transmission stats."""
        entry = self._entries.pop(0)

        # Track latency stats
        latency = self._clock() - entry.enqueue_time_ms
        if latency > self.stats.max_latency_ms:
            self.stats.max_latency_ms = latency

        # Update EMA for average latency
        # Formula: new_avg = alpha * latency + (1 - alpha) * old_avg
        self._avg_latency_ema = (
            self._EMA_ALPHA * latency + (1 - self._EMA_ALPHA) * self._avg_latency_ema
        )
        self.stats.avg_latency_ms = int(self._avg_latency_ema)

        self.stats.packets_transmitted += 1

        logger.debug(
            "TX queue pop: priority=%s latency=%dms avg=%dms len=%d/%d",
            Priority(entry.priority).name,
            latency,
            self.stats.avg_latency_ms,
            len(self._entries),
            self._capacity,
        )

        return entry

    def peek(self) -> tuple[bytes, Priority] | None:
        """Peek at the highest-priority packet without removing it.

        Expires stale packets first (for consistency with pop() and push()),
        then returns the highest-priority packet's data and priority tuple
        without removing it. If the front packet was stale, it is dropped
        and the next valid one (if any) is returned.

        Returns:
            (data, priority) tuple or None if queue empty after expiry.
        """
        self.expire_stale()

        if not self._entries:
            return None
        entry = self._entries[0]
        return (entry.data, entry.priority)

    def clear(self) -> int:
        """Remove all packets from the queue.

        Returns:
            Number of packets cleared.
        """
        count = len(self._entries)
        self._entries.clear()
        return count

    def reserve(self) -> TxQueueEntry | None:
        """Reserve the highest-priority packet for transmission.

        Returns the entry (peek, does not remove) so deadline is preserved
        on failure (the re-queue case). This fixes the bug where re-queue
        after CAD failure would assign a fresh deadline.
        Caller MUST call complete(entry, success) afterward.
        """
        self.expire_stale()
        if not self._entries:
            return None
        return self._entries[0]

    def complete(self, entry: TxQueueEntry, success: bool) -> None:
        """Signal completion of a reserved entry.

        success=True: removes it, updates stats/latency, signals reservation.
        success=False: leaves it queued with ORIGINAL deadline (bug fix),
        signals failure.
        """
        if entry.reservation is not None:
            entry.reservation.set_result(success)

        if success:
            if self._entries and self._entries[0] is entry:
                popped = self._entries.pop(0)
                latency = self._clock() - popped.enqueue_time_ms
                if latency > self.stats.max_latency_ms:
                    self.stats.max_latency_ms = latency
                self._avg_latency_ema = (
                    self._EMA_ALPHA * latency
                    + (1 - self._EMA_ALPHA) * self._avg_latency_ema
                )
                self.stats.avg_latency_ms = int(self._avg_latency_ema)
                self.stats.packets_transmitted += 1
                logger.debug(
                    "TX complete success: priority=%s latency=%dms avg=%dms len=%d/%d",
                    Priority(popped.priority).name,
                    latency,
                    self.stats.avg_latency_ms,
                    len(self._entries),
                    self._capacity,
                )
            else:
                logger.warning("complete(success) but entry not head of queue")
        else:
            # re-queued with original deadline_ms - prevents lifetime extension
            logger.debug(
                "TX re-queued after failure, preserved deadline=%d",
                entry.deadline_ms,
            )

    def signal_all_pending(self, success: bool) -> None:
        """Signal all queued reservations as complete (for CAD failure case).

        Prevents senders from hanging when drain_tx_queue exits without
        attempting transmission. Signals all entries in the queue.
        """
        for entry in self._entries:
            if entry.reservation is not None:
                entry.reservation.set_result(success)

    def _insert_sorted(self, entry: TxQueueEntry) -> None:
        """Insert entry maintaining sort order (priority ASC, time ASC).

        Priority is primary key (lower = more urgent).
        Enqueue time is secondary key (older = earlier, FIFO within priority).
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
