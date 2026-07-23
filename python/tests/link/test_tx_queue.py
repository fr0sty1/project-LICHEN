# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for TX queue with priority and deadline expiry.

Why these tests: The TX queue controls bufferbloat. Bugs here mean:
- Unbounded queuing (latency explosion)
- Wrong priority ordering (routing delayed by bulk data)
- Silent packet drops (hidden congestion)
- Stale packets transmitted (wasted airtime)

Test categories:
1. Basic operations: push, pop, capacity limits
2. Priority ordering: higher priority packets transmit first
3. Deadline expiry: stale packets dropped before TX
4. Preemption: high-priority packets evict low-priority when full
5. Backpressure: QueueFullError raised when appropriate
"""

import pytest

from lichen.link.tx_queue import (
    DEADLINE_ACK_MS,
    DEADLINE_APP_MS,
    DEADLINE_ROUTING_MS,
    Priority,
    QueueFullError,
    TxQueue,
)


class FakeClock:
    """Controllable clock for testing time-dependent behavior."""

    def __init__(self, start_ms: int = 0):
        self._now = start_ms

    def __call__(self) -> int:
        return self._now

    def advance(self, ms: int) -> None:
        self._now += ms


class TestTxQueueBasic:
    """Basic queue operations."""

    def test_empty_queue_returns_none(self):
        """pop() on empty queue returns None."""
        q = TxQueue()
        assert q.pop() is None

    def test_push_pop_single_packet(self):
        """Single packet can be pushed and popped."""
        q = TxQueue()
        data = b"test packet"
        q.push(data)
        assert q.pop() == data

    def test_queue_length(self):
        """len() returns number of queued packets."""
        q = TxQueue()
        assert len(q) == 0

        q.push(b"one")
        assert len(q) == 1

        q.push(b"two")
        assert len(q) == 2

        q.pop()
        assert len(q) == 1

    def test_capacity_default(self):
        """Default capacity is 4 packets."""
        q = TxQueue()
        assert q.capacity == 4

    def test_capacity_custom(self):
        """Custom capacity can be set."""
        q = TxQueue(capacity=8)
        assert q.capacity == 8

    def test_invalid_capacity(self):
        with pytest.raises(ValueError):
            TxQueue(capacity=0)

    def test_clear_removes_all(self):
        """clear() empties the queue."""
        q = TxQueue()
        q.push(b"one")
        q.push(b"two")
        q.push(b"three")

        count = q.clear()

        assert count == 3
        assert len(q) == 0
        assert q.pop() is None

    def test_peek_without_removing(self):
        """peek() returns packet without removing it."""
        q = TxQueue()
        q.push(b"packet", priority=Priority.URGENT)

        result = q.peek()

        assert result == (b"packet", Priority.URGENT)
        assert len(q) == 1  # Still in queue

    def test_peek_empty_returns_none(self):
        """peek() on empty queue returns None."""
        q = TxQueue()
        assert q.peek() is None

    def test_confirm_transmitted_removes_expected_front(self):
        clock = FakeClock(100)
        q = TxQueue(clock=clock)
        q.push(b"first")
        q.push(b"second")
        clock.advance(25)

        q.confirm_transmitted(b"first")

        assert q.peek() == (b"second", Priority.BULK)
        assert q.stats.packets_transmitted == 1
        assert q.stats.max_latency_ms == 25

    def test_confirm_transmitted_mismatch_preserves_queue(self):
        q = TxQueue()
        q.push(b"first")

        with pytest.raises(ValueError, match="not at queue front"):
            q.confirm_transmitted(b"other")

        assert q.peek() == (b"first", Priority.BULK)
        assert q.stats.packets_transmitted == 0


class TestPriorityOrdering:
    """Tests for priority-based packet ordering."""

    def test_higher_priority_pops_first(self):
        """Packets pop in priority order (lower value = higher priority)."""
        q = TxQueue()

        # Push in reverse priority order
        q.push(b"bulk", priority=Priority.BULK)
        q.push(b"urgent", priority=Priority.URGENT)
        q.push(b"ack", priority=Priority.ACK)
        q.push(b"routing", priority=Priority.ROUTING)

        # Should pop in priority order
        assert q.pop() == b"routing"
        assert q.pop() == b"ack"
        assert q.pop() == b"urgent"
        assert q.pop() == b"bulk"

    def test_same_priority_fifo(self):
        """Packets with same priority pop in FIFO order."""
        q = TxQueue()

        q.push(b"first", priority=Priority.BULK)
        q.push(b"second", priority=Priority.BULK)
        q.push(b"third", priority=Priority.BULK)

        assert q.pop() == b"first"
        assert q.pop() == b"second"
        assert q.pop() == b"third"

    def test_mixed_priority_ordering(self):
        """Mixed priorities maintain correct order."""
        q = TxQueue()

        q.push(b"bulk1", priority=Priority.BULK)
        q.push(b"routing1", priority=Priority.ROUTING)
        q.push(b"bulk2", priority=Priority.BULK)
        q.push(b"routing2", priority=Priority.ROUTING)

        # Routing packets first (FIFO within priority), then bulk
        assert q.pop() == b"routing1"
        assert q.pop() == b"routing2"
        assert q.pop() == b"bulk1"
        assert q.pop() == b"bulk2"


class TestDeadlineExpiry:
    """Tests for time-based packet expiry."""

    def test_default_deadline_routing(self):
        """Routing packets get 5s default deadline."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"routing", priority=Priority.ROUTING)

        # Advance past deadline
        clock.advance(DEADLINE_ROUTING_MS + 1)

        # Should be expired
        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_default_deadline_ack(self):
        """ACK packets get 10s default deadline."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"ack", priority=Priority.ACK)

        # Advance past deadline
        clock.advance(DEADLINE_ACK_MS + 1)

        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_default_deadline_app(self):
        """App packets (URGENT, BULK) get 60s default deadline."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"urgent", priority=Priority.URGENT)
        q.push(b"bulk", priority=Priority.BULK)

        # Advance past deadline
        clock.advance(DEADLINE_APP_MS + 1)

        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 2

    def test_custom_deadline(self):
        """Custom deadline overrides default."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        # Custom 100ms deadline for routing packet
        q.push(b"fast", priority=Priority.ROUTING, deadline_ms=100)

        # At 50ms: still valid
        clock.advance(50)
        assert q.peek() is not None

        # At 101ms: expired
        clock.advance(51)
        assert q.pop() is None

    def test_expire_stale_explicit(self):
        """expire_stale() removes expired packets."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"short", deadline_ms=100)
        q.push(b"long", deadline_ms=1000)

        clock.advance(500)

        expired = q.expire_stale()

        assert expired == 1
        assert len(q) == 1
        assert q.pop() == b"long"

    def test_packet_at_deadline_is_expired(self):
        """Packets expire when deadline_ms <= now (deadline_ms > now check)."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"boundary", deadline_ms=100)

        # Exactly at deadline
        clock.advance(100)

        # deadline_ms > now means equal time expires the packet
        assert q.pop() is None


class TestPreemption:
    """Tests for priority-based preemption when queue is full."""

    def test_preempt_lower_priority(self):
        """Higher priority packet preempts lowest when full."""
        q = TxQueue(capacity=2)

        q.push(b"bulk1", priority=Priority.BULK)
        q.push(b"bulk2", priority=Priority.BULK)
        assert len(q) == 2

        # Push higher priority - should preempt one bulk
        q.push(b"routing", priority=Priority.ROUTING)

        assert len(q) == 2
        assert q.stats.packets_dropped_preempt == 1

        # Routing should be first
        assert q.pop() == b"routing"

    def test_preempt_evicts_lowest(self):
        """Preemption evicts the lowest-priority packet."""
        q = TxQueue(capacity=3)

        q.push(b"routing", priority=Priority.ROUTING)
        q.push(b"urgent", priority=Priority.URGENT)
        q.push(b"bulk", priority=Priority.BULK)

        # Push ACK - should evict BULK (lowest priority)
        q.push(b"ack", priority=Priority.ACK)

        # Check contents
        assert q.pop() == b"routing"
        assert q.pop() == b"ack"
        assert q.pop() == b"urgent"
        assert q.pop() is None  # Bulk was evicted


class TestBackpressure:
    """Tests for QueueFullError exception (explicit backpressure)."""

    def test_queue_full_same_priority(self):
        """QueueFullError raised when full and same priority."""
        q = TxQueue(capacity=2)

        q.push(b"one", priority=Priority.BULK)
        q.push(b"two", priority=Priority.BULK)

        with pytest.raises(QueueFullError):
            q.push(b"three", priority=Priority.BULK)

    def test_preemptible_admission_does_not_mutate_queue(self):
        q = TxQueue(capacity=1)
        q.push(b"bulk", priority=Priority.BULK)

        q.ensure_can_push(Priority.ROUTING)

        assert len(q) == 1
        assert q.stats.packets_dropped_preempt == 0
        assert q.pop() == b"bulk"

    def test_admission_does_not_remove_stale_entries(self):
        clock = FakeClock(0)
        q = TxQueue(capacity=1, clock=clock)
        q.push(b"stale", deadline_ms=1)
        clock.advance(2)

        q.ensure_can_push(Priority.BULK)

        assert len(q) == 1
        assert q.stats.packets_dropped_deadline == 0

    def test_queue_full_lower_priority(self):
        """QueueFullError raised when full and lower priority."""
        q = TxQueue(capacity=2)

        q.push(b"urgent1", priority=Priority.URGENT)
        q.push(b"urgent2", priority=Priority.URGENT)

        with pytest.raises(QueueFullError):
            q.push(b"bulk", priority=Priority.BULK)

    def test_queue_full_increments_stat(self):
        """QueueFullError increments packets_dropped_full stat."""
        import contextlib

        q = TxQueue(capacity=1)
        q.push(b"first")

        with contextlib.suppress(QueueFullError):
            q.push(b"second")

        assert q.stats.packets_dropped_full == 1

    def test_no_queue_full_after_expiry(self):
        """push() succeeds if expiry makes room."""
        clock = FakeClock(0)
        q = TxQueue(capacity=2, clock=clock)

        q.push(b"stale1", deadline_ms=100)
        q.push(b"stale2", deadline_ms=100)

        # Both should expire
        clock.advance(200)

        # Should succeed - expiry makes room
        q.push(b"fresh")
        assert len(q) == 1


class TestStatistics:
    """Tests for queue statistics tracking."""

    def test_packets_queued_count(self):
        """packets_queued tracks total pushes."""
        q = TxQueue()
        q.push(b"one")
        q.push(b"two")
        q.push(b"three")

        assert q.stats.packets_queued == 3

    def test_packets_transmitted_count(self):
        """packets_transmitted tracks radio-confirmed packets only."""
        q = TxQueue()
        q.push(b"one")
        q.push(b"two")

        q.confirm_transmitted(b"one")
        q.confirm_transmitted(b"two")

        assert q.stats.packets_transmitted == 2

    def test_pop_does_not_claim_radio_transmission(self):
        q = TxQueue()
        q.push(b"one")

        assert q.pop() == b"one"
        assert q.stats.packets_transmitted == 0

    def test_max_latency_tracking(self):
        """max_latency_ms tracks worst-case queue time."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"slow")
        clock.advance(100)
        q.push(b"fast")
        clock.advance(50)

        q.confirm_transmitted(b"slow")
        q.confirm_transmitted(b"fast")

        assert q.stats.max_latency_ms == 150

    def test_avg_latency_tracking(self):
        """avg_latency_ms tracks smoothed average queue time (EMA)."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        # Push and pop several packets to build up EMA
        # EMA formula: new_avg = 0.1 * latency + 0.9 * old_avg
        #
        # Packet 1: latency=100, avg = 0.1*100 + 0.9*0 = 10
        # Packet 2: latency=100, avg = 0.1*100 + 0.9*10 = 19
        # Packet 3: latency=100, avg = 0.1*100 + 0.9*19 = 27.1
        # ...converges toward 100 over many samples

        q.push(b"p1")
        clock.advance(100)
        q.confirm_transmitted(b"p1")
        assert q.stats.avg_latency_ms == 10  # First sample: 0.1 * 100 = 10

        q.push(b"p2")
        clock.advance(100)
        q.confirm_transmitted(b"p2")
        assert q.stats.avg_latency_ms == 19  # 0.1*100 + 0.9*10 = 19

        q.push(b"p3")
        clock.advance(100)
        q.confirm_transmitted(b"p3")
        assert q.stats.avg_latency_ms == 27  # 0.1*100 + 0.9*19 = 27.1 -> 27

    def test_avg_latency_responds_to_variance(self):
        """avg_latency_ms smooths out variance in queue times."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        # Alternate between high and low latency
        for latency in [200, 10, 200, 10, 200, 10]:
            q.push(b"packet")
            clock.advance(latency)
            q.confirm_transmitted(b"packet")

        # EMA should smooth out the variance
        # After 6 samples alternating 200/10, EMA is somewhere in between
        # Not exactly (200+10)/2=105 due to EMA weighting
        avg = q.stats.avg_latency_ms
        assert 40 < avg < 160, f"avg_latency_ms={avg} should be between extremes"


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_empty_packet(self):
        """Empty packet can be queued."""
        q = TxQueue()
        q.push(b"")
        assert q.pop() == b""

    def test_large_packet(self):
        """Large packet can be queued."""
        q = TxQueue()
        large = bytes(1000)
        q.push(large)
        assert q.pop() == large

    def test_capacity_one(self):
        """Queue with capacity=1 works correctly."""
        q = TxQueue(capacity=1)

        q.push(b"first")

        with pytest.raises(QueueFullError):
            q.push(b"second", priority=Priority.BULK)

        # Higher priority can preempt
        q.push(b"urgent", priority=Priority.ROUTING)
        assert q.pop() == b"urgent"

    def test_all_priorities_coexist(self):
        """All four priority levels can coexist."""
        q = TxQueue(capacity=4)

        q.push(b"bulk", priority=Priority.BULK)
        q.push(b"urgent", priority=Priority.URGENT)
        q.push(b"ack", priority=Priority.ACK)
        q.push(b"routing", priority=Priority.ROUTING)

        assert len(q) == 4
        assert q.pop() == b"routing"
        assert q.pop() == b"ack"
        assert q.pop() == b"urgent"
        assert q.pop() == b"bulk"

    def test_invalid_capacity(self):
        with pytest.raises(ValueError):
            TxQueue(capacity=0)
        with pytest.raises(ValueError):
            TxQueue(capacity=-1)
