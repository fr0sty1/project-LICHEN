#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate fixed, implementation-independent B.3.2 Forwarding Buffer vectors.

Oracle basis: spec/appendix-bufferbloat.md section "Forwarding Buffer"

Requirements:
- MAX_FORWARDING_SOURCES = 8
- MAX_PACKETS_PER_SOURCE = 2
- Send NACK (backpressure) when per-source limit reached
- Total forwarding buffer: 16 packets max
- LRU eviction when max sources reached
- FIFO dequeue within a source
- Deadline-based expiry
"""

from __future__ import annotations

import sys
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import atomic_write_json, json_bytes, read_bounded_exact  # noqa: E402

OUT = Path(__file__).with_name("forwarding_buffer.json")

# Spec constants (appendix-bufferbloat.md)
MAX_FORWARDING_SOURCES = 8
MAX_PACKETS_PER_SOURCE = 2


@dataclass
class BufferEntry:
    """A packet in the forwarding buffer."""

    packet_id: str
    source_iid: str
    buffered_at_ms: int
    deadline_ms: int


@dataclass
class ForwardingBufferOracle:
    """Oracle implementation of B.3.2 Forwarding Buffer.

    This is a reference implementation used to generate test vectors.
    It matches the spec exactly without optimizations.
    """

    max_sources: int = MAX_FORWARDING_SOURCES
    max_per_source: int = MAX_PACKETS_PER_SOURCE
    _buffer: dict[str, list[BufferEntry]] = field(default_factory=dict)
    _source_order: OrderedDict[str, None] = field(default_factory=OrderedDict)
    packets_accepted: int = 0
    packets_backpressure: int = 0
    packets_expired: int = 0
    packets_evicted: int = 0

    def try_buffer(
        self,
        packet_id: str,
        source_iid: str,
        now_ms: int,
        deadline_ms: int,
    ) -> Literal["ACCEPTED", "BACKPRESSURE", "EVICTED"]:
        """Attempt to buffer a packet for forwarding."""
        entry = BufferEntry(
            packet_id=packet_id,
            source_iid=source_iid,
            buffered_at_ms=now_ms,
            deadline_ms=deadline_ms,
        )

        # Check if source already has a queue
        if source_iid in self._buffer:
            queue = self._buffer[source_iid]
            if len(queue) >= self.max_per_source:
                self.packets_backpressure += 1
                return "BACKPRESSURE"

            queue.append(entry)
            self._touch_source(source_iid)
            self.packets_accepted += 1
            return "ACCEPTED"

        # New source - check if we need to evict
        result: Literal["ACCEPTED", "BACKPRESSURE", "EVICTED"] = "ACCEPTED"
        if len(self._buffer) >= self.max_sources:
            # Evict LRU source (first in order)
            oldest_iid = next(iter(self._source_order))
            del self._source_order[oldest_iid]
            evicted_count = len(self._buffer.pop(oldest_iid, []))
            self.packets_evicted += evicted_count
            result = "EVICTED"

        self._buffer[source_iid] = [entry]
        self._touch_source(source_iid)
        self.packets_accepted += 1
        return result

    def dequeue(self, source_iid: str) -> BufferEntry | None:
        """Remove and return the oldest packet for a source."""
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

        return entry

    def expire_old(self, now_ms: int) -> int:
        """Remove packets past their deadline."""
        expired_count = 0
        empty_sources: list[str] = []

        for source_iid in list(self._buffer.keys()):
            queue = self._buffer[source_iid]
            original_len = len(queue)
            self._buffer[source_iid] = [e for e in queue if e.deadline_ms > now_ms]
            expired = original_len - len(self._buffer[source_iid])
            expired_count += expired

            if not self._buffer[source_iid]:
                empty_sources.append(source_iid)

        for source_iid in empty_sources:
            del self._buffer[source_iid]
            self._source_order.pop(source_iid, None)

        if expired_count > 0:
            self.packets_expired += expired_count

        return expired_count

    def count_for_source(self, source_iid: str) -> int:
        """Return number of packets buffered for a source."""
        return len(self._buffer.get(source_iid, []))

    def total_count(self) -> int:
        """Return total number of packets in buffer."""
        return sum(len(q) for q in self._buffer.values())

    def source_count(self) -> int:
        """Return number of unique sources being tracked."""
        return len(self._buffer)

    def get_stats(self) -> dict[str, int]:
        return {
            "total_packets": self.total_count(),
            "sources": self.source_count(),
            "max_sources": self.max_sources,
            "max_per_source": self.max_per_source,
            "accepted": self.packets_accepted,
            "backpressure": self.packets_backpressure,
            "expired": self.packets_expired,
            "evicted": self.packets_evicted,
        }

    def _touch_source(self, source_iid: str) -> None:
        """Move source to MRU position."""
        if source_iid in self._source_order:
            del self._source_order[source_iid]
        self._source_order[source_iid] = None

    def snapshot(self) -> dict[str, object]:
        """Capture current state for vector comparison."""
        return {
            "sources": {
                iid: [
                    {"packet_id": e.packet_id, "deadline_ms": e.deadline_ms}
                    for e in entries
                ]
                for iid, entries in self._buffer.items()
            },
            "source_order": list(self._source_order.keys()),
            "stats": self.get_stats(),
        }


def iid(n: int) -> str:
    """Generate a source IID from an index."""
    return f"{n:016x}"


def build_document() -> dict[str, object]:
    """Generate all test vectors."""
    vectors: list[dict[str, object]] = []

    # --- Basic acceptance vectors ---

    # Vector 1: Accept first packet from new source
    oracle = ForwardingBufferOracle()
    result = oracle.try_buffer("pkt1", iid(1), now_ms=0, deadline_ms=10000)
    vectors.append(
        {
            "name": "accept_first_packet",
            "description": "First packet from a new source is accepted.",
            "operation": "try_buffer",
            "inputs": {
                "packet_id": "pkt1",
                "source_iid": iid(1),
                "now_ms": 0,
                "deadline_ms": 10000,
            },
            "expected": {
                "result": result,
                "state": oracle.snapshot(),
            },
        }
    )

    # Vector 2: Accept second packet from same source
    result = oracle.try_buffer("pkt2", iid(1), now_ms=1, deadline_ms=10000)
    vectors.append(
        {
            "name": "accept_second_packet_same_source",
            "description": "Second packet from same source (under limit) is accepted.",
            "operation": "try_buffer",
            "inputs": {
                "packet_id": "pkt2",
                "source_iid": iid(1),
                "now_ms": 1,
                "deadline_ms": 10000,
            },
            "expected": {
                "result": result,
                "state": oracle.snapshot(),
            },
        }
    )

    # Vector 3: Backpressure on third packet (per-source limit = 2)
    result = oracle.try_buffer("pkt3", iid(1), now_ms=2, deadline_ms=10000)
    vectors.append(
        {
            "name": "backpressure_at_per_source_limit",
            "description": "Third packet from same source triggers backpressure (NACK).",
            "operation": "try_buffer",
            "inputs": {
                "packet_id": "pkt3",
                "source_iid": iid(1),
                "now_ms": 2,
                "deadline_ms": 10000,
            },
            "expected": {
                "result": result,
                "state": oracle.snapshot(),
            },
        }
    )

    # --- LRU eviction vectors ---

    # Fill buffer with max sources
    oracle = ForwardingBufferOracle()
    for i in range(1, MAX_FORWARDING_SOURCES + 1):
        oracle.try_buffer(f"src{i}_pkt1", iid(i), now_ms=i * 10, deadline_ms=10000)

    # Vector 4: State before eviction
    before_state = oracle.snapshot()

    # Vector 5: New source triggers LRU eviction
    result = oracle.try_buffer("src9_pkt1", iid(9), now_ms=100, deadline_ms=10000)
    vectors.append(
        {
            "name": "lru_eviction_at_max_sources",
            "description": "9th source triggers eviction of LRU source (source 1).",
            "operation": "try_buffer",
            "precondition": {
                "description": f"Buffer at max sources ({MAX_FORWARDING_SOURCES})",
                "state": before_state,
            },
            "inputs": {
                "packet_id": "src9_pkt1",
                "source_iid": iid(9),
                "now_ms": 100,
                "deadline_ms": 10000,
            },
            "expected": {
                "result": result,
                "evicted_source": iid(1),
                "state": oracle.snapshot(),
            },
        }
    )

    # --- LRU touch updates order ---

    oracle = ForwardingBufferOracle(max_sources=3, max_per_source=2)
    oracle.try_buffer("s1_p1", iid(1), now_ms=0, deadline_ms=10000)
    oracle.try_buffer("s2_p1", iid(2), now_ms=1, deadline_ms=10000)
    oracle.try_buffer("s3_p1", iid(3), now_ms=2, deadline_ms=10000)
    # Touch source 1 again (moves to MRU)
    oracle.try_buffer("s1_p2", iid(1), now_ms=3, deadline_ms=10000)

    before_state = oracle.snapshot()

    # Now add source 4 - should evict source 2 (LRU), not source 1
    result = oracle.try_buffer("s4_p1", iid(4), now_ms=4, deadline_ms=10000)
    vectors.append(
        {
            "name": "lru_touch_updates_order",
            "description": "Touching a source moves it to MRU; evicts true LRU.",
            "operation": "try_buffer",
            "precondition": {
                "description": "Source 1 touched after sources 2,3 so source 2 is LRU",
                "state": before_state,
            },
            "inputs": {
                "packet_id": "s4_p1",
                "source_iid": iid(4),
                "now_ms": 4,
                "deadline_ms": 10000,
            },
            "expected": {
                "result": result,
                "evicted_source": iid(2),
                "source_order": list(oracle._source_order.keys()),
                "state": oracle.snapshot(),
            },
        }
    )

    # --- Deadline expiry vectors ---

    oracle = ForwardingBufferOracle()
    oracle.try_buffer("pkt_early", iid(1), now_ms=0, deadline_ms=100)
    oracle.try_buffer("pkt_late", iid(1), now_ms=1, deadline_ms=200)

    before_state = oracle.snapshot()
    expired = oracle.expire_old(now_ms=150)

    vectors.append(
        {
            "name": "deadline_expiry_partial",
            "description": "Packets past deadline are expired; others retained.",
            "operation": "expire_old",
            "precondition": {
                "description": "Two packets: deadline 100ms and 200ms",
                "state": before_state,
            },
            "inputs": {"now_ms": 150},
            "expected": {
                "expired_count": expired,
                "state": oracle.snapshot(),
            },
        }
    )

    # --- Deadline expiry boundary: now_ms == deadline_ms ---

    oracle = ForwardingBufferOracle()
    oracle.try_buffer("pkt_boundary", iid(1), now_ms=0, deadline_ms=100)
    oracle.try_buffer("pkt_after", iid(1), now_ms=1, deadline_ms=101)

    before_state = oracle.snapshot()
    expired = oracle.expire_old(now_ms=100)

    vectors.append(
        {
            "name": "deadline_expiry_boundary",
            "description": (
                "Packet expires exactly when now_ms == deadline_ms. "
                "Spec requires deadline_ms <= now_ms triggers expiry."
            ),
            "operation": "expire_old",
            "precondition": {
                "description": "Two packets: deadline 100ms (boundary) and 101ms",
                "state": before_state,
            },
            "inputs": {"now_ms": 100},
            "expected": {
                "expired_count": expired,
                "remaining_count": oracle.count_for_source(iid(1)),
                "state": oracle.snapshot(),
            },
        }
    )

    # --- Expiry cleans up empty sources ---

    oracle = ForwardingBufferOracle()
    oracle.try_buffer("pkt_only", iid(1), now_ms=0, deadline_ms=100)

    before_state = oracle.snapshot()
    expired = oracle.expire_old(now_ms=200)

    vectors.append(
        {
            "name": "expiry_removes_empty_source",
            "description": "When all packets from a source expire, source is removed.",
            "operation": "expire_old",
            "precondition": {
                "description": "One source with one packet expiring",
                "state": before_state,
            },
            "inputs": {"now_ms": 200},
            "expected": {
                "expired_count": expired,
                "source_count": oracle.source_count(),
                "state": oracle.snapshot(),
            },
        }
    )

    # --- Dequeue FIFO order ---

    oracle = ForwardingBufferOracle()
    oracle.try_buffer("first", iid(1), now_ms=0, deadline_ms=10000)
    oracle.try_buffer("second", iid(1), now_ms=1, deadline_ms=10000)

    entry1 = oracle.dequeue(iid(1))
    vectors.append(
        {
            "name": "dequeue_fifo_order",
            "description": "Dequeue returns oldest packet first (FIFO).",
            "operation": "dequeue",
            "inputs": {"source_iid": iid(1)},
            "expected": {
                "packet_id": entry1.packet_id if entry1 else None,
                "remaining_count": oracle.count_for_source(iid(1)),
            },
        }
    )

    entry2 = oracle.dequeue(iid(1))
    vectors.append(
        {
            "name": "dequeue_removes_source_when_empty",
            "description": "Dequeue of last packet removes source from tracking.",
            "operation": "dequeue",
            "inputs": {"source_iid": iid(1)},
            "expected": {
                "packet_id": entry2.packet_id if entry2 else None,
                "source_count": oracle.source_count(),
                "state": oracle.snapshot(),
            },
        }
    )

    # --- Dequeue from unknown source ---

    entry_none = oracle.dequeue(iid(99))
    vectors.append(
        {
            "name": "dequeue_unknown_source",
            "description": "Dequeue from unknown source returns null.",
            "operation": "dequeue",
            "inputs": {"source_iid": iid(99)},
            "expected": {"result": None if entry_none is None else "unexpected"},
        }
    )

    # --- Stats accumulation ---

    oracle = ForwardingBufferOracle(max_sources=2, max_per_source=2)

    # Accept 2 packets
    oracle.try_buffer("p1", iid(1), now_ms=0, deadline_ms=100)
    oracle.try_buffer("p2", iid(1), now_ms=1, deadline_ms=100)

    # Trigger backpressure
    oracle.try_buffer("p3", iid(1), now_ms=2, deadline_ms=100)

    # Add second source
    oracle.try_buffer("p4", iid(2), now_ms=3, deadline_ms=100)

    # Add third source (triggers eviction of source 1)
    oracle.try_buffer("p5", iid(3), now_ms=4, deadline_ms=200)

    # Expire source 2's packet
    oracle.expire_old(now_ms=150)

    vectors.append(
        {
            "name": "stats_accumulation",
            "description": "Stats track all operations: accept, backpressure, evict, expire.",
            "operation": "get_stats",
            "expected": oracle.get_stats(),
        }
    )

    # --- Capacity boundary: exactly 16 packets ---

    oracle = ForwardingBufferOracle()
    for i in range(1, MAX_FORWARDING_SOURCES + 1):
        for j in range(1, MAX_PACKETS_PER_SOURCE + 1):
            oracle.try_buffer(
                f"s{i}_p{j}", iid(i), now_ms=i * 100 + j, deadline_ms=10000
            )

    vectors.append(
        {
            "name": "max_capacity_8x2",
            "description": f"Full buffer: {MAX_FORWARDING_SOURCES} sources x {MAX_PACKETS_PER_SOURCE} packets = 16 total.",
            "operation": "fill_to_capacity",
            "expected": {
                "total_packets": oracle.total_count(),
                "source_count": oracle.source_count(),
                "accepted": oracle.packets_accepted,
                "state": oracle.snapshot(),
            },
        }
    )

    return {
        "vector_type": "forwarding_buffer",
        "format_version": 1,
        "description": (
            "Canonical test vectors for B.3.2 Forwarding Buffer (spec appendix-bufferbloat.md). "
            "Validates per-source limits, LRU eviction, deadline expiry, and backpressure."
        ),
        "oracle": {
            "basis": "spec/appendix-bufferbloat.md section 'Forwarding Buffer'",
            "max_forwarding_sources": MAX_FORWARDING_SOURCES,
            "max_packets_per_source": MAX_PACKETS_PER_SOURCE,
            "total_capacity": MAX_FORWARDING_SOURCES * MAX_PACKETS_PER_SOURCE,
            "eviction_policy": "LRU by source (oldest untouched source evicted)",
            "backpressure_trigger": "per-source limit reached",
            "expiry_condition": "deadline_ms <= now_ms",
            "dequeue_order": "FIFO within source",
        },
        "vectors": vectors,
    }


def main() -> None:
    document = build_document()
    vectors = document["vectors"]
    assert isinstance(vectors, list)

    if sys.argv[1:] == ["--check"]:
        try:
            current = read_bounded_exact(OUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(document):
            raise SystemExit(f"{OUT.name} is not deterministically generated")
        print(f"checked {len(vectors)} vectors in {OUT.name}")
        return

    if sys.argv[1:]:
        raise SystemExit("usage: generate_forwarding_buffer.py [--check]")

    atomic_write_json(OUT, document)
    print(f"wrote {len(vectors)} vectors to {OUT.name}")


if __name__ == "__main__":
    main()
