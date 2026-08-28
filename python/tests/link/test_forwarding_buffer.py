# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for forwarding buffer with per-source limits and backpressure (B.2.4, B.3.2).

Why these tests: The forwarding buffer prevents relay monopolization by chatty sources.
Bugs here mean:
- Unbounded buffering (memory exhaustion, latency explosion)
- No backpressure (senders keep transmitting into full buffer)
- Unfair forwarding (one source starves others)
- Memory leaks (dead sources not evicted)

Test categories:
1. Basic operations: try_buffer, dequeue, capacity limits
2. Per-source limits: BACKPRESSURE when source hits limit
3. LRU eviction: oldest untouched source evicted when full
4. Deadline expiry: stale packets dropped
5. Oracle tests: validate against test/vectors/forwarding_buffer.json
"""

import json
from pathlib import Path

import pytest

from lichen.link.forwarding_buffer import (
    MAX_FORWARDING_SOURCES,
    MAX_PACKETS_PER_SOURCE,
    BufferResult,
    ForwardingBuffer,
)


def iid(n: int) -> bytes:
    """Generate a source IID from an index."""
    return bytes.fromhex(f"{n:016x}")


class TestForwardingBufferBasic:
    """Basic buffer operations."""

    def test_empty_buffer_dequeue_returns_none(self):
        """dequeue() on empty buffer returns None."""
        buf = ForwardingBuffer()
        assert buf.dequeue(iid(1)) is None

    def test_buffer_single_packet(self):
        """Single packet can be buffered and dequeued."""
        buf = ForwardingBuffer()
        result = buf.try_buffer(b"test", iid(1), now_ms=0, deadline_ms=10000)
        assert result == BufferResult.ACCEPTED
        entry = buf.dequeue(iid(1))
        assert entry is not None
        assert entry.data == b"test"

    def test_buffer_count(self):
        """total_count() returns number of buffered packets."""
        buf = ForwardingBuffer()
        assert buf.total_count() == 0

        buf.try_buffer(b"one", iid(1), now_ms=0, deadline_ms=10000)
        assert buf.total_count() == 1

        buf.try_buffer(b"two", iid(2), now_ms=0, deadline_ms=10000)
        assert buf.total_count() == 2

        buf.dequeue(iid(1))
        assert buf.total_count() == 1

    def test_source_count(self):
        """source_count() returns number of unique sources."""
        buf = ForwardingBuffer()
        assert buf.source_count() == 0

        buf.try_buffer(b"s1", iid(1), now_ms=0, deadline_ms=10000)
        assert buf.source_count() == 1

        buf.try_buffer(b"s2", iid(2), now_ms=0, deadline_ms=10000)
        assert buf.source_count() == 2

        buf.try_buffer(b"s1_2", iid(1), now_ms=1, deadline_ms=10000)
        assert buf.source_count() == 2  # Same source, no change

    def test_capacity_default(self):
        """Default capacity is 8 sources x 2 packets = 16."""
        buf = ForwardingBuffer()
        assert buf.max_sources == 8
        assert buf.max_per_source == 2
        assert buf.total_capacity == 16

    def test_capacity_custom(self):
        """Custom capacity can be set."""
        buf = ForwardingBuffer(max_sources=4, max_per_source=3)
        assert buf.max_sources == 4
        assert buf.max_per_source == 3
        assert buf.total_capacity == 12

    def test_invalid_capacity(self):
        """Invalid capacity raises ValueError."""
        with pytest.raises(ValueError):
            ForwardingBuffer(max_sources=0)
        with pytest.raises(ValueError):
            ForwardingBuffer(max_per_source=0)

    def test_clear_removes_all(self):
        """clear() empties the buffer."""
        buf = ForwardingBuffer()
        buf.try_buffer(b"one", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"two", iid(2), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"three", iid(3), now_ms=0, deadline_ms=10000)

        count = buf.clear()

        assert count == 3
        assert buf.total_count() == 0
        assert buf.source_count() == 0

    def test_count_for_source(self):
        """count_for_source() returns packets for specific source."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"s1_a", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"s1_b", iid(1), now_ms=1, deadline_ms=10000)
        buf.try_buffer(b"s2_a", iid(2), now_ms=2, deadline_ms=10000)

        assert buf.count_for_source(iid(1)) == 2
        assert buf.count_for_source(iid(2)) == 1
        assert buf.count_for_source(iid(99)) == 0  # Unknown source


class TestPerSourceLimits:
    """Tests for per-source packet limits and backpressure (B.2.4)."""

    def test_accept_up_to_limit(self):
        """Accept packets up to per-source limit (default 2)."""
        buf = ForwardingBuffer()

        result1 = buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=10000)
        result2 = buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=10000)

        assert result1 == BufferResult.ACCEPTED
        assert result2 == BufferResult.ACCEPTED
        assert buf.count_for_source(iid(1)) == 2

    def test_backpressure_at_limit(self):
        """BACKPRESSURE returned when source hits limit (triggers NACK)."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=10000)

        result = buf.try_buffer(b"p3", iid(1), now_ms=2, deadline_ms=10000)

        assert result == BufferResult.BACKPRESSURE
        assert buf.count_for_source(iid(1)) == 2  # Not increased
        assert buf.stats.packets_backpressure == 1

    def test_backpressure_stat_accumulates(self):
        """Backpressure stat increments for each rejection."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=10000)

        buf.try_buffer(b"p3", iid(1), now_ms=2, deadline_ms=10000)
        buf.try_buffer(b"p4", iid(1), now_ms=3, deadline_ms=10000)
        buf.try_buffer(b"p5", iid(1), now_ms=4, deadline_ms=10000)

        assert buf.stats.packets_backpressure == 3

    def test_multiple_sources_independent(self):
        """Each source has independent limit."""
        buf = ForwardingBuffer()

        # Source 1 at limit
        buf.try_buffer(b"s1_1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"s1_2", iid(1), now_ms=1, deadline_ms=10000)

        # Source 2 should still accept
        result = buf.try_buffer(b"s2_1", iid(2), now_ms=2, deadline_ms=10000)
        assert result == BufferResult.ACCEPTED

        # Source 1 gets backpressure
        result = buf.try_buffer(b"s1_3", iid(1), now_ms=3, deadline_ms=10000)
        assert result == BufferResult.BACKPRESSURE


class TestLRUEviction:
    """Tests for LRU eviction when max sources reached."""

    def test_evict_lru_source(self):
        """New source evicts LRU source when at max."""
        buf = ForwardingBuffer(max_sources=3)

        buf.try_buffer(b"s1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"s2", iid(2), now_ms=1, deadline_ms=10000)
        buf.try_buffer(b"s3", iid(3), now_ms=2, deadline_ms=10000)

        # Add 4th source - should evict source 1 (LRU)
        result = buf.try_buffer(b"s4", iid(4), now_ms=3, deadline_ms=10000)

        assert result == BufferResult.EVICTED
        assert buf.source_count() == 3
        assert buf.count_for_source(iid(1)) == 0  # Evicted
        assert buf.count_for_source(iid(4)) == 1  # New source present

    def test_touch_updates_lru_order(self):
        """Adding to existing source moves it to MRU."""
        buf = ForwardingBuffer(max_sources=3, max_per_source=2)

        buf.try_buffer(b"s1_1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"s2_1", iid(2), now_ms=1, deadline_ms=10000)
        buf.try_buffer(b"s3_1", iid(3), now_ms=2, deadline_ms=10000)

        # Touch source 1 - moves to MRU
        buf.try_buffer(b"s1_2", iid(1), now_ms=3, deadline_ms=10000)

        # Add source 4 - should evict source 2 (now LRU), not source 1
        result = buf.try_buffer(b"s4_1", iid(4), now_ms=4, deadline_ms=10000)

        assert result == BufferResult.EVICTED
        assert buf.count_for_source(iid(1)) == 2  # Still present
        assert buf.count_for_source(iid(2)) == 0  # Evicted
        assert buf.count_for_source(iid(3)) == 1  # Still present
        assert buf.count_for_source(iid(4)) == 1  # New source

    def test_eviction_counts_all_packets(self):
        """Eviction stat counts all packets in evicted source queue."""
        buf = ForwardingBuffer(max_sources=2, max_per_source=2)

        buf.try_buffer(b"s1_1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"s1_2", iid(1), now_ms=1, deadline_ms=10000)
        buf.try_buffer(b"s2_1", iid(2), now_ms=2, deadline_ms=10000)

        # Add source 3 - evicts source 1 with 2 packets
        buf.try_buffer(b"s3_1", iid(3), now_ms=3, deadline_ms=10000)

        assert buf.stats.packets_evicted == 2


class TestDeadlineExpiry:
    """Tests for time-based packet expiry."""

    def test_expire_old_removes_stale(self):
        """expire_old() removes packets past deadline."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"stale", iid(1), now_ms=0, deadline_ms=100)
        buf.try_buffer(b"fresh", iid(1), now_ms=0, deadline_ms=1000)

        expired = buf.expire_old(now_ms=500)

        assert expired == 1
        assert buf.count_for_source(iid(1)) == 1
        assert buf.stats.packets_expired == 1

    def test_expire_removes_empty_source(self):
        """When all packets from source expire, source is removed."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"only", iid(1), now_ms=0, deadline_ms=100)
        assert buf.source_count() == 1

        buf.expire_old(now_ms=200)

        assert buf.source_count() == 0

    def test_expiry_runs_on_try_buffer(self):
        """try_buffer() runs expiry first (makes room, maintains invariants)."""
        buf = ForwardingBuffer(max_sources=1, max_per_source=2)

        buf.try_buffer(b"stale1", iid(1), now_ms=0, deadline_ms=100)
        buf.try_buffer(b"stale2", iid(1), now_ms=1, deadline_ms=100)

        # Source 1 is at limit, but packets are stale. New source should succeed.
        result = buf.try_buffer(b"fresh", iid(2), now_ms=200, deadline_ms=10000)

        # Stale packets expired, source 1 removed, source 2 accepted
        assert result == BufferResult.ACCEPTED
        assert buf.source_count() == 1
        assert buf.count_for_source(iid(2)) == 1


class TestFIFOOrder:
    """Tests for FIFO dequeue order within a source."""

    def test_dequeue_fifo(self):
        """Dequeue returns oldest packet first (FIFO)."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"first", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"second", iid(1), now_ms=1, deadline_ms=10000)

        entry1 = buf.dequeue(iid(1))
        entry2 = buf.dequeue(iid(1))

        assert entry1 is not None
        assert entry1.data == b"first"
        assert entry2 is not None
        assert entry2.data == b"second"

    def test_dequeue_any_oldest_across_sources(self):
        """dequeue_any() returns oldest packet across all sources."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"s1_first", iid(1), now_ms=10, deadline_ms=10000)
        buf.try_buffer(b"s2_second", iid(2), now_ms=5, deadline_ms=10000)  # Oldest
        buf.try_buffer(b"s3_third", iid(3), now_ms=15, deadline_ms=10000)

        entry = buf.dequeue_any()

        assert entry is not None
        assert entry.data == b"s2_second"

    def test_dequeue_removes_source_when_empty(self):
        """Dequeue of last packet removes source from tracking."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"only", iid(1), now_ms=0, deadline_ms=10000)
        assert buf.source_count() == 1

        buf.dequeue(iid(1))

        assert buf.source_count() == 0


class TestStatistics:
    """Tests for buffer statistics tracking."""

    def test_stats_accumulate(self):
        """Stats track all operations."""
        buf = ForwardingBuffer(max_sources=2, max_per_source=2)

        # Accept 2 packets
        buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=100)
        buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=100)

        # Trigger backpressure
        buf.try_buffer(b"p3", iid(1), now_ms=2, deadline_ms=100)

        # Add second source
        buf.try_buffer(b"p4", iid(2), now_ms=3, deadline_ms=100)

        # Add third source (triggers eviction of source 1)
        buf.try_buffer(b"p5", iid(3), now_ms=4, deadline_ms=200)

        # Expire source 2's packet
        buf.expire_old(now_ms=150)

        stats = buf.get_stats()

        assert stats["accepted"] == 4  # p1, p2, p4, p5
        assert stats["backpressure"] == 1  # p3
        assert stats["evicted"] == 2  # p1, p2 from source 1
        assert stats["expired"] == 1  # p4 from source 2

    def test_forwarded_stat(self):
        """packets_forwarded stat increments on dequeue."""
        buf = ForwardingBuffer()

        buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=10000)

        buf.dequeue(iid(1))
        buf.dequeue(iid(1))

        assert buf.stats.packets_forwarded == 2


# --- Oracle Tests ---

def _load_oracle_vectors() -> dict:
    """Load oracle vectors from test/vectors/forwarding_buffer.json."""
    vectors_path = (
        Path(__file__).parent.parent.parent.parent
        / "test"
        / "vectors"
        / "forwarding_buffer.json"
    )
    with vectors_path.open() as f:
        return json.load(f)


class TestOracleForwardingBuffer:
    """Oracle tests per spec appendix-bufferbloat.md B.3.2 Forwarding Buffer.

    Each test validates implementation behavior against the independent oracle
    defined in test/vectors/forwarding_buffer.json. The vectors are the
    source of truth; if implementation diverges, implementation is wrong.
    """

    @pytest.fixture
    def vectors(self) -> dict:
        """Load oracle vectors."""
        return _load_oracle_vectors()

    def test_oracle_constants_match(self, vectors):
        """Oracle: Constants match spec values."""
        oracle = vectors["oracle"]
        assert oracle["max_forwarding_sources"] == MAX_FORWARDING_SOURCES
        assert oracle["max_packets_per_source"] == MAX_PACKETS_PER_SOURCE
        assert oracle["total_capacity"] == MAX_FORWARDING_SOURCES * MAX_PACKETS_PER_SOURCE

    def test_oracle_accept_first_packet(self, vectors):
        """Oracle: First packet from new source is accepted."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "accept_first_packet")
        inputs = vec["inputs"]
        expected = vec["expected"]

        buf = ForwardingBuffer()
        result = buf.try_buffer(
            data=inputs["packet_id"].encode(),
            source_iid=bytes.fromhex(inputs["source_iid"]),
            now_ms=inputs["now_ms"],
            deadline_ms=inputs["deadline_ms"],
        )

        assert result.name == expected["result"]
        assert buf.total_count() == expected["state"]["stats"]["total_packets"]
        assert buf.source_count() == expected["state"]["stats"]["sources"]

    def test_oracle_accept_second_same_source(self, vectors):
        """Oracle: Second packet from same source (under limit) is accepted."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "accept_second_packet_same_source")
        inputs = vec["inputs"]
        expected = vec["expected"]

        buf = ForwardingBuffer()
        # First packet
        buf.try_buffer(b"pkt1", bytes.fromhex("0000000000000001"), now_ms=0, deadline_ms=10000)
        # Second packet
        result = buf.try_buffer(
            data=inputs["packet_id"].encode(),
            source_iid=bytes.fromhex(inputs["source_iid"]),
            now_ms=inputs["now_ms"],
            deadline_ms=inputs["deadline_ms"],
        )

        assert result.name == expected["result"]
        assert buf.total_count() == expected["state"]["stats"]["total_packets"]

    def test_oracle_backpressure_at_limit(self, vectors):
        """Oracle: Third packet from same source triggers backpressure (NACK)."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "backpressure_at_per_source_limit")
        inputs = vec["inputs"]
        expected = vec["expected"]

        buf = ForwardingBuffer()
        # Fill source to limit
        buf.try_buffer(b"pkt1", bytes.fromhex("0000000000000001"), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"pkt2", bytes.fromhex("0000000000000001"), now_ms=1, deadline_ms=10000)

        # Third packet should get backpressure
        result = buf.try_buffer(
            data=inputs["packet_id"].encode(),
            source_iid=bytes.fromhex(inputs["source_iid"]),
            now_ms=inputs["now_ms"],
            deadline_ms=inputs["deadline_ms"],
        )

        assert result.name == expected["result"]
        assert buf.stats.packets_backpressure == expected["state"]["stats"]["backpressure"]

    def test_oracle_lru_eviction(self, vectors):
        """Oracle: 9th source triggers eviction of LRU source (source 1)."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "lru_eviction_at_max_sources")
        inputs = vec["inputs"]
        expected = vec["expected"]

        buf = ForwardingBuffer()
        # Fill with 8 sources
        for i in range(1, 9):
            buf.try_buffer(
                data=f"src{i}_pkt1".encode(),
                source_iid=bytes.fromhex(f"{i:016x}"),
                now_ms=i * 10,
                deadline_ms=10000,
            )

        # Add 9th source
        result = buf.try_buffer(
            data=inputs["packet_id"].encode(),
            source_iid=bytes.fromhex(inputs["source_iid"]),
            now_ms=inputs["now_ms"],
            deadline_ms=inputs["deadline_ms"],
        )

        assert result.name == expected["result"]
        assert buf.count_for_source(bytes.fromhex(expected["evicted_source"])) == 0

    def test_oracle_lru_touch_updates_order(self, vectors):
        """Oracle: Touching a source moves it to MRU; evicts true LRU."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "lru_touch_updates_order")
        inputs = vec["inputs"]
        expected = vec["expected"]

        buf = ForwardingBuffer(max_sources=3, max_per_source=2)

        # Setup: 3 sources, touch source 1 after 2 and 3
        buf.try_buffer(b"s1_p1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"s2_p1", iid(2), now_ms=1, deadline_ms=10000)
        buf.try_buffer(b"s3_p1", iid(3), now_ms=2, deadline_ms=10000)
        buf.try_buffer(b"s1_p2", iid(1), now_ms=3, deadline_ms=10000)  # Touch s1 -> MRU

        # Add source 4
        result = buf.try_buffer(
            data=inputs["packet_id"].encode(),
            source_iid=bytes.fromhex(inputs["source_iid"]),
            now_ms=inputs["now_ms"],
            deadline_ms=inputs["deadline_ms"],
        )

        assert result.name == expected["result"]
        assert buf.count_for_source(bytes.fromhex(expected["evicted_source"])) == 0
        # Source 1 should still be present (was touched)
        assert buf.count_for_source(iid(1)) == 2

    def test_oracle_deadline_expiry_partial(self, vectors):
        """Oracle: Packets past deadline are expired; others retained."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "deadline_expiry_partial")
        inputs = vec["inputs"]
        expected = vec["expected"]

        buf = ForwardingBuffer()
        buf.try_buffer(b"pkt_early", iid(1), now_ms=0, deadline_ms=100)
        buf.try_buffer(b"pkt_late", iid(1), now_ms=1, deadline_ms=200)

        expired = buf.expire_old(now_ms=inputs["now_ms"])

        assert expired == expected["expired_count"]

    def test_oracle_expiry_removes_empty_source(self, vectors):
        """Oracle: When all packets from a source expire, source is removed."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "expiry_removes_empty_source")
        inputs = vec["inputs"]
        expected = vec["expected"]

        buf = ForwardingBuffer()
        buf.try_buffer(b"pkt_only", iid(1), now_ms=0, deadline_ms=100)

        expired = buf.expire_old(now_ms=inputs["now_ms"])

        assert expired == expected["expired_count"]
        assert buf.source_count() == expected["source_count"]

    def test_oracle_dequeue_fifo(self, vectors):
        """Oracle: Dequeue returns oldest packet first (FIFO)."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "dequeue_fifo_order")
        expected = vec["expected"]

        buf = ForwardingBuffer()
        buf.try_buffer(b"first", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"second", iid(1), now_ms=1, deadline_ms=10000)

        entry = buf.dequeue(iid(1))

        assert entry is not None
        assert entry.data.decode() == expected["packet_id"]
        assert buf.count_for_source(iid(1)) == expected["remaining_count"]

    def test_oracle_dequeue_removes_source(self, vectors):
        """Oracle: Dequeue of last packet removes source from tracking."""
        vec_name = "dequeue_removes_source_when_empty"
        vec = next(v for v in vectors["vectors"] if v["name"] == vec_name)
        expected = vec["expected"]

        buf = ForwardingBuffer()
        buf.try_buffer(b"first", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"second", iid(1), now_ms=1, deadline_ms=10000)

        buf.dequeue(iid(1))  # first
        entry = buf.dequeue(iid(1))  # second

        assert entry is not None
        assert entry.data.decode() == expected["packet_id"]
        assert buf.source_count() == expected["source_count"]

    def test_oracle_dequeue_unknown_source(self, vectors):
        """Oracle: Dequeue from unknown source returns null."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "dequeue_unknown_source")
        expected = vec["expected"]

        buf = ForwardingBuffer()
        entry = buf.dequeue(bytes.fromhex(vec["inputs"]["source_iid"]))

        if expected["result"] is None:
            assert entry is None
        else:
            assert entry is not None

    def test_oracle_stats_accumulation(self, vectors):
        """Oracle: Stats track all operations."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "stats_accumulation")
        expected = vec["expected"]

        buf = ForwardingBuffer(max_sources=2, max_per_source=2)

        # Accept 2 packets
        buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=100)
        buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=100)

        # Trigger backpressure
        buf.try_buffer(b"p3", iid(1), now_ms=2, deadline_ms=100)

        # Add second source
        buf.try_buffer(b"p4", iid(2), now_ms=3, deadline_ms=100)

        # Add third source (triggers eviction of source 1)
        buf.try_buffer(b"p5", iid(3), now_ms=4, deadline_ms=200)

        # Expire source 2's packet
        buf.expire_old(now_ms=150)

        assert buf.stats.packets_accepted == expected["accepted"]
        assert buf.stats.packets_backpressure == expected["backpressure"]
        assert buf.stats.packets_evicted == expected["evicted"]
        assert buf.stats.packets_expired == expected["expired"]

    def test_oracle_max_capacity(self, vectors):
        """Oracle: Full buffer at 8 sources x 2 packets = 16 total."""
        vec = next(v for v in vectors["vectors"] if v["name"] == "max_capacity_8x2")
        expected = vec["expected"]

        buf = ForwardingBuffer()

        # Fill to capacity
        for i in range(1, MAX_FORWARDING_SOURCES + 1):
            for j in range(1, MAX_PACKETS_PER_SOURCE + 1):
                buf.try_buffer(
                    data=f"s{i}_p{j}".encode(),
                    source_iid=bytes.fromhex(f"{i:016x}"),
                    now_ms=i * 100 + j,
                    deadline_ms=10000,
                )

        assert buf.total_count() == expected["total_packets"]
        assert buf.source_count() == expected["source_count"]
        assert buf.stats.packets_accepted == expected["accepted"]


# --- B.2.5 No Silent Drops: on_drop callback tests ---
from lichen.link.forwarding_buffer import DropReason  # noqa: E402


class TestNoSilentDrops:
    """Tests for B.2.5 No Silent Drops: on_drop callback mechanism.

    Spec: appendix-bufferbloat.md section 5 "No Silent Drops" requires:
    - Return error to local sender (covered by QueueFullError in tx_queue.py)
    - NACK to mesh source (if routable) - enabled by on_drop callback
    - Log queue-full events for diagnostics (covered by logging)
    """

    def test_backpressure_calls_on_drop(self):
        """on_drop called with BACKPRESSURE when per-source limit reached."""
        dropped: list[tuple[bytes, bytes, DropReason]] = []

        def record_drop(source_iid: bytes, data: bytes, reason: DropReason) -> None:
            dropped.append((source_iid, data, reason))

        buf = ForwardingBuffer(on_drop=record_drop)

        # Fill source to limit
        buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=10000)

        # Third packet triggers backpressure
        result = buf.try_buffer(b"p3", iid(1), now_ms=2, deadline_ms=10000)

        assert result == BufferResult.BACKPRESSURE
        assert len(dropped) == 1
        assert dropped[0][0] == iid(1)  # source_iid
        assert dropped[0][1] == b"p3"  # data
        assert dropped[0][2] == DropReason.BACKPRESSURE

    def test_eviction_calls_on_drop_for_each_packet(self):
        """on_drop called with EVICTED for each packet in evicted source queue."""
        dropped: list[tuple[bytes, bytes, DropReason]] = []

        def record_drop(source_iid: bytes, data: bytes, reason: DropReason) -> None:
            dropped.append((source_iid, data, reason))

        buf = ForwardingBuffer(max_sources=2, max_per_source=2, on_drop=record_drop)

        # Fill 2 sources
        buf.try_buffer(b"s1_p1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"s1_p2", iid(1), now_ms=1, deadline_ms=10000)
        buf.try_buffer(b"s2_p1", iid(2), now_ms=2, deadline_ms=10000)

        # Add 3rd source - evicts source 1 (2 packets)
        result = buf.try_buffer(b"s3_p1", iid(3), now_ms=3, deadline_ms=10000)

        assert result == BufferResult.EVICTED
        assert len(dropped) == 2  # Both packets from source 1
        assert all(d[0] == iid(1) for d in dropped)
        assert all(d[2] == DropReason.EVICTED for d in dropped)
        assert {d[1] for d in dropped} == {b"s1_p1", b"s1_p2"}

    def test_expire_calls_on_drop_for_each_packet(self):
        """on_drop called with EXPIRED for each packet past deadline."""
        dropped: list[tuple[bytes, bytes, DropReason]] = []

        def record_drop(source_iid: bytes, data: bytes, reason: DropReason) -> None:
            dropped.append((source_iid, data, reason))

        buf = ForwardingBuffer(on_drop=record_drop)

        # Add packets from different sources with different deadlines
        buf.try_buffer(b"early", iid(1), now_ms=0, deadline_ms=100)
        buf.try_buffer(b"fresh", iid(2), now_ms=1, deadline_ms=10000)

        # Expire packets older than 150ms
        expired = buf.expire_old(now_ms=150)

        assert expired == 1  # Only "early" expired
        assert len(dropped) == 1
        assert dropped[0][0] == iid(1)
        assert dropped[0][1] == b"early"
        assert dropped[0][2] == DropReason.EXPIRED

    def test_no_callback_when_none(self):
        """No crash when on_drop is None (default)."""
        buf = ForwardingBuffer()  # No callback

        # Fill and trigger backpressure
        buf.try_buffer(b"p1", iid(1), now_ms=0, deadline_ms=10000)
        buf.try_buffer(b"p2", iid(1), now_ms=1, deadline_ms=10000)
        buf.try_buffer(b"p3", iid(1), now_ms=2, deadline_ms=10000)

        # Should work without crash
        assert buf.stats.packets_backpressure == 1

    def test_callback_receives_correct_source_iid(self):
        """on_drop receives the correct source_iid for routing NACK."""
        dropped: list[tuple[bytes, bytes, DropReason]] = []

        def record_drop(source_iid: bytes, data: bytes, reason: DropReason) -> None:
            dropped.append((source_iid, data, reason))

        buf = ForwardingBuffer(max_sources=1, on_drop=record_drop)

        # Add first source
        buf.try_buffer(b"s1_p1", iid(42), now_ms=0, deadline_ms=10000)

        # Add second source - evicts first
        buf.try_buffer(b"s2_p1", iid(99), now_ms=1, deadline_ms=10000)

        assert len(dropped) == 1
        assert dropped[0][0] == iid(42)  # Correct source for NACK routing
