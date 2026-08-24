# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Forwarding buffer with per-source limits and backpressure (B.2.4, B.3.2).

Implements spec/appendix-bufferbloat.md section "Forwarding Buffer":
- MAX_FORWARDING_SOURCES = 8 (max unique sources tracked)
- MAX_PACKETS_PER_SOURCE = 2 (per-source queue limit)
- Total capacity: 16 packets (8 x 2)
- LRU eviction when max sources reached
- FIFO dequeue within a source
- Deadline-based expiry
- BACKPRESSURE result triggers NACK upstream (B.2.4 explicit backpressure)
- B.2.5 No Silent Drops: on_drop callback for NACK signaling

Why this exists: Relay nodes must buffer packets for forwarding, but unlimited
buffering causes latency explosion. Per-source limits prevent one chatty node
from monopolizing relay capacity. When the limit is reached, we send NACK
upstream so the source can back off (explicit backpressure).
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto

logger = logging.getLogger(__name__)

# Spec constants (appendix-bufferbloat.md)
MAX_FORWARDING_SOURCES = 8
MAX_PACKETS_PER_SOURCE = 2


class BufferResult(Enum):
    """Result of attempting to buffer a packet for forwarding."""

    ACCEPTED = auto()  # Packet buffered successfully
    BACKPRESSURE = auto()  # Per-source limit reached, send NACK upstream
    EVICTED = auto()  # Accepted but evicted an LRU source's packets


class DropReason(Enum):
    """Reason a packet was dropped (B.2.5 No Silent Drops).

    Used by on_drop callback to enable NACK signaling upstream.
    """

    BACKPRESSURE = auto()  # Per-source limit reached
    EVICTED = auto()  # LRU eviction made room for new source
    EXPIRED = auto()  # Packet deadline passed


# Type alias for drop callback: (source_iid, data, reason) -> None
# Caller uses this to send NACK upstream per B.2.5 "No Silent Drops"
DropCallback = Callable[[bytes, bytes, DropReason], None]


@dataclass
class ForwardingEntry:
    """A packet waiting for forwarding.

    Attributes:
        data: The frame bytes to forward.
        source_iid: IID of the original sender (for per-source limits).
        buffered_at_ms: When packet was buffered (for stats).
        deadline_ms: Absolute timestamp (ms) when packet expires.
    """

    data: bytes
    source_iid: bytes
    buffered_at_ms: int
    deadline_ms: int


@dataclass
class ForwardingBufferStats:
    """Forwarding buffer statistics for diagnostics.

    Exposed via CoAP /status/forwarding resource.
    """

    packets_accepted: int = 0
    packets_backpressure: int = 0  # NACK sent upstream
    packets_expired: int = 0
    packets_evicted: int = 0  # LRU source eviction
    packets_forwarded: int = 0


class ForwardingBuffer:
    """Per-source forwarding buffer with LRU eviction and backpressure.

    Invariants:
    - At most max_sources unique sources are tracked
    - Each source has at most max_per_source packets queued
    - Total packets <= max_sources * max_per_source

    B.2.5 No Silent Drops: When packets are dropped (backpressure, eviction,
    expiry), the on_drop callback is invoked with the source IID, packet data,
    and drop reason. Callers use this to send NACK upstream.

    Reentrancy: Not thread-safe. Caller must ensure single-threaded access
    or external synchronization.
    """

    def __init__(
        self,
        max_sources: int = MAX_FORWARDING_SOURCES,
        max_per_source: int = MAX_PACKETS_PER_SOURCE,
        clock: Callable[[], int] | None = None,
        on_drop: DropCallback | None = None,
    ):
        """Initialize forwarding buffer.

        Args:
            max_sources: Maximum unique sources to track.
            max_per_source: Maximum packets per source.
            clock: Optional clock function for testing. Returns ms since epoch.
            on_drop: Callback invoked when packets are dropped (B.2.5 No Silent
                Drops). Receives (source_iid, data, reason). Use to send NACK.
        """
        if max_sources <= 0:
            raise ValueError("max_sources must be positive")
        if max_per_source <= 0:
            raise ValueError("max_per_source must be positive")

        self._max_sources = max_sources
        self._max_per_source = max_per_source
        self._clock = clock or (lambda: 0)  # Caller must provide now_ms
        self._on_drop = on_drop

        # Per-source queues: source_iid -> list of entries
        self._buffer: dict[bytes, list[ForwardingEntry]] = {}

        # LRU tracking: OrderedDict maintains insertion/access order
        # Most recently used at end, LRU at front
        self._source_order: OrderedDict[bytes, None] = OrderedDict()

        self.stats = ForwardingBufferStats()

    @property
    def max_sources(self) -> int:
        """Maximum number of unique sources tracked."""
        return self._max_sources

    @property
    def max_per_source(self) -> int:
        """Maximum packets per source."""
        return self._max_per_source

    @property
    def total_capacity(self) -> int:
        """Total buffer capacity (max_sources * max_per_source)."""
        return self._max_sources * self._max_per_source

    def try_buffer(
        self,
        data: bytes,
        source_iid: bytes,
        now_ms: int,
        deadline_ms: int,
    ) -> BufferResult:
        """Attempt to buffer a packet for forwarding.

        Args:
            data: Frame bytes to forward.
            source_iid: IID of the original sender.
            now_ms: Current time in milliseconds.
            deadline_ms: Absolute deadline (ms) when packet expires.

        Returns:
            BufferResult indicating success or backpressure.

        Spec reference: appendix-bufferbloat.md "Forwarding Buffer"
        """
        entry = ForwardingEntry(
            data=data,
            source_iid=source_iid,
            buffered_at_ms=now_ms,
            deadline_ms=deadline_ms,
        )

        # Expire stale packets first (frees space, maintains invariants)
        self.expire_old(now_ms)

        # Check if source already has a queue
        if source_iid in self._buffer:
            queue = self._buffer[source_iid]
            if len(queue) >= self._max_per_source:
                # Per-source limit reached: NACK upstream (B.2.4 backpressure)
                self.stats.packets_backpressure += 1
                logger.debug(
                    "forwarding buffer backpressure: source=%s has %d packets",
                    source_iid.hex(),
                    len(queue),
                )
                # B.2.5 No Silent Drops: notify caller to send NACK
                if self._on_drop is not None:
                    self._on_drop(source_iid, data, DropReason.BACKPRESSURE)
                return BufferResult.BACKPRESSURE

            # Space available: accept packet
            queue.append(entry)
            self._touch_source(source_iid)
            self.stats.packets_accepted += 1
            logger.debug(
                "forwarding buffer accept: source=%s count=%d",
                source_iid.hex(),
                len(queue),
            )
            return BufferResult.ACCEPTED

        # New source: check if we need to evict LRU
        result = BufferResult.ACCEPTED
        if len(self._buffer) >= self._max_sources:
            # Evict LRU source (first in order)
            oldest_iid = next(iter(self._source_order))
            del self._source_order[oldest_iid]
            evicted_queue = self._buffer.pop(oldest_iid, [])
            evicted_count = len(evicted_queue)
            self.stats.packets_evicted += evicted_count
            logger.debug(
                "forwarding buffer LRU evict: source=%s packets=%d",
                oldest_iid.hex(),
                evicted_count,
            )
            # B.2.5 No Silent Drops: notify for each evicted packet
            if self._on_drop is not None:
                for evicted_entry in evicted_queue:
                    self._on_drop(
                        evicted_entry.source_iid,
                        evicted_entry.data,
                        DropReason.EVICTED,
                    )
            result = BufferResult.EVICTED

        # Create new queue for this source
        self._buffer[source_iid] = [entry]
        self._touch_source(source_iid)
        self.stats.packets_accepted += 1

        return result

    def dequeue(self, source_iid: bytes) -> ForwardingEntry | None:
        """Remove and return the oldest packet for a source (FIFO).

        Args:
            source_iid: IID of the source to dequeue from.

        Returns:
            ForwardingEntry if available, None if source unknown/empty.
        """
        if source_iid not in self._buffer:
            return None

        queue = self._buffer[source_iid]
        if not queue:
            return None

        entry = queue.pop(0)

        # Clean up empty queues
        if not queue:
            del self._buffer[source_iid]
            self._source_order.pop(source_iid, None)

        self.stats.packets_forwarded += 1
        return entry

    def dequeue_any(self) -> ForwardingEntry | None:
        """Remove and return any packet (oldest across all sources).

        Used when the forwarder drains its buffer. Returns the packet
        from the source with the oldest buffered_at_ms timestamp.

        Returns:
            ForwardingEntry if any packet available, None if empty.
        """
        if not self._buffer:
            return None

        # Find source with oldest entry
        oldest_source: bytes | None = None
        oldest_time = float("inf")

        for source_iid, queue in self._buffer.items():
            if queue and queue[0].buffered_at_ms < oldest_time:
                oldest_time = queue[0].buffered_at_ms
                oldest_source = source_iid

        if oldest_source is None:
            return None

        return self.dequeue(oldest_source)

    def expire_old(self, now_ms: int) -> int:
        """Remove packets past their deadline.

        Args:
            now_ms: Current time in milliseconds.

        Returns:
            Number of packets expired.
        """
        expired_count = 0
        empty_sources: list[bytes] = []
        expired_entries: list[ForwardingEntry] = []

        for source_iid in list(self._buffer.keys()):
            queue = self._buffer[source_iid]
            kept: list[ForwardingEntry] = []
            for entry in queue:
                if entry.deadline_ms > now_ms:
                    kept.append(entry)
                else:
                    expired_entries.append(entry)
            expired_count += len(queue) - len(kept)
            self._buffer[source_iid] = kept

            if not kept:
                empty_sources.append(source_iid)

        # Clean up empty source queues
        for source_iid in empty_sources:
            del self._buffer[source_iid]
            self._source_order.pop(source_iid, None)

        if expired_count > 0:
            self.stats.packets_expired += expired_count
            logger.debug("forwarding buffer expired %d packets", expired_count)
            # B.2.5 No Silent Drops: notify for each expired packet
            if self._on_drop is not None:
                for entry in expired_entries:
                    self._on_drop(entry.source_iid, entry.data, DropReason.EXPIRED)

        return expired_count

    def count_for_source(self, source_iid: bytes) -> int:
        """Return number of packets buffered for a source."""
        return len(self._buffer.get(source_iid, []))

    def total_count(self) -> int:
        """Return total number of packets in buffer."""
        return sum(len(q) for q in self._buffer.values())

    def source_count(self) -> int:
        """Return number of unique sources being tracked."""
        return len(self._buffer)

    def clear(self) -> int:
        """Remove all packets from the buffer.

        Returns:
            Number of packets cleared.
        """
        count = self.total_count()
        self._buffer.clear()
        self._source_order.clear()
        return count

    def get_stats(self) -> dict[str, int]:
        """Get buffer statistics as a dict (for CoAP resource)."""
        return {
            "total_packets": self.total_count(),
            "sources": self.source_count(),
            "max_sources": self._max_sources,
            "max_per_source": self._max_per_source,
            "accepted": self.stats.packets_accepted,
            "backpressure": self.stats.packets_backpressure,
            "expired": self.stats.packets_expired,
            "evicted": self.stats.packets_evicted,
            "forwarded": self.stats.packets_forwarded,
        }

    def _touch_source(self, source_iid: bytes) -> None:
        """Move source to MRU position (most recently used)."""
        if source_iid in self._source_order:
            del self._source_order[source_iid]
        self._source_order[source_iid] = None
