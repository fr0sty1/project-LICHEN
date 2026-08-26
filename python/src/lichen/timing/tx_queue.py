# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Bounded priority TX queue with deadline expiry (appendix-bufferbloat).

Reference oracle for spec/appendix-bufferbloat.md sections B.2 and B.3,
conformed against:
- test/vectors/tx_queue_implementation.json
- test/vectors/tx_queue_bounded.json
- test/vectors/tx_queue_expiry.json
- test/vectors/tx_queue_priority.json
- test/vectors/no_silent_drops.json (TxQueue component vectors)

No silent drops: every drop path (deadline expiry, preemption, clear,
failed transmission) signals the packet's reservation with ``False``;
only a full-capacity reject raises :class:`QueueFullError`.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field

TX_QUEUE_SIZE = 4

DEADLINE_SOS_MS = 2000
DEADLINE_ROUTING_MS = 5000
DEADLINE_ACK_MS = 10000
DEADLINE_URGENT_MS = 30000
DEADLINE_NORMAL_MS = 60000
DEADLINE_BULK_MS = 120000


class Priority(enum.IntEnum):
    """Transmit priority; lower numeric value means higher urgency."""

    SOS = 0
    ROUTING = 1
    ACK = 1  # alias of ROUTING (same numeric priority)
    URGENT = 2
    NORMAL = 3
    BULK = 4


_DEFAULT_DEADLINE_MS: dict[int, int] = {
    int(Priority.SOS): DEADLINE_SOS_MS,
    int(Priority.ROUTING): DEADLINE_ROUTING_MS,
    int(Priority.URGENT): DEADLINE_URGENT_MS,
    int(Priority.NORMAL): DEADLINE_NORMAL_MS,
    int(Priority.BULK): DEADLINE_BULK_MS,
}


class QueueFullError(Exception):
    """Raised when a push cannot admit and cannot preempt (ENOBUFS)."""


@dataclass
class TxQueueEntry:
    """One queued packet.

    ``deadline_ms`` is an absolute timestamp; expiry is ``now >= deadline_ms``.
    """

    data: bytes
    priority: Priority | int
    enqueue_time_ms: int = 0
    deadline_ms: int | None = None
    _reservation_cb: Callable[[bool], None] | None = field(default=None, repr=False, compare=False)

    def effective_deadline(self) -> int:
        if self.deadline_ms is not None:
            return self.deadline_ms
        return self.enqueue_time_ms + _DEFAULT_DEADLINE_MS[int(self.priority)]

    def expired(self, now_ms: int) -> bool:
        return now_ms >= self.effective_deadline()

    def attach_reservation(self, cb: Callable[[bool], None]) -> None:
        """Register the callback signaled exactly once with the outcome."""
        self._reservation_cb = cb

    def has_reservation(self) -> bool:
        return self._reservation_cb is not None

    def signal(self, ok: bool) -> None:
        cb, self._reservation_cb = self._reservation_cb, None
        if cb is not None:
            cb(ok)


def default_deadline_for(priority: Priority | int) -> int:
    """Class default deadline in ms; ACK resolves to ROUTING's value."""
    return _DEFAULT_DEADLINE_MS[int(Priority(int(priority)))]


@dataclass
class TxQueueStats:
    packets_queued: int = 0
    packets_dropped_deadline: int = 0
    packets_dropped_preempt: int = 0
    packets_dropped_full: int = 0
    packets_transmitted: int = 0
    max_latency_ms: int = 0
    _latency_total_ms: int = 0

    @property
    def avg_latency_ms(self) -> float:
        tx = self.packets_transmitted
        return self._latency_total_ms / tx if tx else 0.0


class TxQueue:
    """Bounded strict-priority FIFO with deadline expiry and preemption."""

    def __init__(self, capacity: int = TX_QUEUE_SIZE) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._entries: list[TxQueueEntry] = []  # sorted, head = highest urgency
        self.stats = TxQueueStats()
        self._in_flight: TxQueueEntry | None = None

    # -- internal helpers ---------------------------------------------------

    def _expire_stale_locked(self, now_ms: int) -> int:
        stale = [e for e in self._entries if e.expired(now_ms)]
        if not stale:
            return 0
        keep = {id(e) for e in self._entries} - {id(e) for e in stale}
        self._entries = [e for e in self._entries if id(e) in keep]
        self.stats.packets_dropped_deadline += len(stale)
        for entry in stale:
            entry.signal(False)
        return len(stale)

    def _lowest_priority_index(self) -> int:
        worst = 0
        for i, e in enumerate(self._entries):
            pe, pw = int(e.priority), int(self._entries[worst].priority)
            if pe > pw or (pe == pw and e.enqueue_time_ms < self._entries[worst].enqueue_time_ms):
                worst = i
        return worst

    def _sort(self) -> None:
        self._entries.sort(key=lambda e: (int(e.priority), e.enqueue_time_ms))

    # -- public API ---------------------------------------------------------

    def push(
        self,
        data: bytes,
        priority: Priority | int,
        now_ms: int,
        *,
        enqueue_time_ms: int | None = None,
        deadline_ms: int | None = None,
    ) -> TxQueueEntry:
        """Admit a packet per the B.3.1 contract.

        Order: expire stale, then capacity check, then preempt-or-reject.
        Preemption requires strictly higher incoming priority; among the
        lowest priority class the oldest packet is evicted.
        """
        prio = int(Priority(int(priority)))
        enqueue = now_ms if enqueue_time_ms is None else enqueue_time_ms
        entry = TxQueueEntry(
            data=data,
            priority=prio,
            enqueue_time_ms=enqueue,
            deadline_ms=deadline_ms,
        )

        self._expire_stale_locked(now_ms)

        if len(self._entries) >= self.capacity:
            worst_idx = self._lowest_priority_index()
            worst = self._entries[worst_idx]
            if prio < int(worst.priority):
                del self._entries[worst_idx]
                self.stats.packets_dropped_preempt += 1
                worst.signal(False)
            else:
                self.stats.packets_dropped_full += 1
                raise QueueFullError("tx queue full; cannot preempt")

        self._entries.append(entry)
        self._sort()
        self.stats.packets_queued += 1
        return entry

    def expire_stale(self, now_ms: int) -> int:
        """Drop all expired entries; returns count dropped."""
        return self._expire_stale_locked(now_ms)

    def pop(self, now_ms: int) -> TxQueueEntry | None:
        """Remove and return the highest-urgency unexpired entry."""
        self._expire_stale_locked(now_ms)
        if not self._entries:
            return None
        return self._entries.pop(0)

    def peek(self, now_ms: int) -> TxQueueEntry | None:
        """Return the highest-urgency entry without removing it."""
        self._expire_stale_locked(now_ms)
        return self._entries[0] if self._entries else None

    def reserve(self, now_ms: int) -> TxQueueEntry | None:
        """Mark the highest-urgency entry as in-flight WITHOUT removing it.

        The caller MUST later call :meth:`complete`. The entry stays queued
        (so ``len()`` is unchanged) and keeps its original deadline throughout
        the reservation.
        """
        entry = self.peek(now_ms)
        self._in_flight = entry
        return entry

    def complete(self, success: bool, now_ms: int) -> None:
        """Resolve the in-flight reservation from :meth:`reserve`.

        Success removes the entry, counts a transmission, records latency,
        and signals ``True``. Failure leaves the entry queued with its
        ORIGINAL deadline (no fresh-deadline bug) and signals ``False``.
        """
        entry = self._in_flight
        self._in_flight = None
        if entry is None:
            raise RuntimeError("complete() without reserve()")
        if success:
            try:
                self._entries.remove(entry)
            except ValueError as exc:
                raise RuntimeError("reserved entry no longer queued") from exc
            self.stats.packets_transmitted += 1
            latency = max(0, now_ms - entry.enqueue_time_ms)
            self.stats.max_latency_ms = max(self.stats.max_latency_ms, latency)
            self.stats._latency_total_ms += latency
            entry.signal(True)
            return
        entry.signal(False)

    def __len__(self) -> int:
        return len(self._entries)

    def contains(self, data: bytes) -> bool:
        return any(e.data == data for e in self._entries)

    def order(self) -> list[bytes]:
        """Current queue data in pop order (diagnostics/tests)."""
        return [e.data for e in self._entries]

    def clear(self) -> None:
        """Drop everything, signaling all reservations False."""
        for entry in self._entries:
            entry.signal(False)
        self._entries.clear()
