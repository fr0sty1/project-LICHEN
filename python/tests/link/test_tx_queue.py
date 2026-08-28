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

import asyncio

import pytest

from lichen.link.tx_queue import (
    DEADLINE_ACK_MS,
    DEADLINE_APP_MS,
    DEADLINE_BULK_MS,
    DEADLINE_ROUTING_MS,
    DEADLINE_SOS_MS,
    DEADLINE_URGENT_MS,
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

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"data": "not-bytes"},
            {"data": b"x", "dst_addr": "not-bytes"},
            {"data": b"x", "priority": 1},
            {"data": b"x", "priority": True},
            {"data": b"x", "deadline_ms": float("nan")},
            {"data": b"x", "deadline_ms": "soon"},
            {"data": b"x", "channel": True},
            {"data": b"x", "return_reservation": 1},
        ],
    )
    def test_invalid_push_is_atomic_before_expiry(self, kwargs: dict[str, object]) -> None:
        clock = FakeClock(0)
        queue = TxQueue(clock=clock)
        queue.push(b"stale-but-untouched", deadline_ms=1)
        clock.advance(2)
        before_entries = list(queue._entries)
        before_stats = vars(queue.stats).copy()

        with pytest.raises(TypeError):
            queue.push(**kwargs)  # type: ignore[arg-type]

        assert queue._entries == before_entries
        assert vars(queue.stats) == before_stats

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

    @pytest.mark.asyncio
    async def test_clear_signals_reservations(self):
        """clear() signals all pending reservations as failed (No Silent Drops).

        Spec compliance: appendix-bufferbloat.md §5 - callers awaiting send()
        must not hang indefinitely when their packet is cleared.
        """
        q = TxQueue()
        res1 = q.push(b"one", return_reservation=True)
        res2 = q.push(b"two", return_reservation=True)
        res3 = q.push(b"three", return_reservation=True)
        assert res1 is not None
        assert res2 is not None
        assert res3 is not None

        # None should be done yet
        assert not res1.done()
        assert not res2.done()
        assert not res3.done()

        count = q.clear()

        # All reservations should be signaled with False
        assert count == 3
        assert res1.done()
        assert res2.done()
        assert res3.done()
        assert res1.result() is False
        assert res2.result() is False
        assert res3.result() is False

    @pytest.mark.asyncio
    async def test_clear_reservation_await_returns_false(self):
        """Awaiting a cleared packet's reservation returns False."""
        q = TxQueue()
        res = q.push(b"will_clear", return_reservation=True)
        assert res is not None

        q.clear()

        # Awaiting should immediately return False
        assert await res.wait() is False

    @pytest.mark.asyncio
    async def test_fail_terminally_removes_exact_reserved_entry(self):
        q = TxQueue()
        reservation = q.push(b"attempted-once", return_reservation=True)
        assert reservation is not None
        entry = q.reserve()
        assert entry is not None

        q.fail(entry)

        assert len(q) == 0
        assert await reservation.wait() is False
        assert q.stats.packets_transmitted == 0

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

        # Push in reverse priority order (spec §10.2.3: P0-P4)
        q.push(b"bulk", priority=Priority.BULK)
        q.push(b"normal", priority=Priority.NORMAL)
        q.push(b"urgent", priority=Priority.URGENT)
        q.push(b"routing", priority=Priority.ROUTING)

        # Should pop in priority order
        assert q.pop() == b"routing"
        assert q.pop() == b"urgent"
        assert q.pop() == b"normal"
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

    def test_default_deadline_sos(self):
        """SOS packets (P0) get 2s default deadline - transmit ASAP."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"sos", priority=Priority.SOS)

        # Advance past deadline
        clock.advance(DEADLINE_SOS_MS + 1)

        # Should be expired
        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_default_deadline_routing(self):
        """Routing packets (P1) get 5s default deadline."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"routing", priority=Priority.ROUTING)

        # Advance past deadline
        clock.advance(DEADLINE_ROUTING_MS + 1)

        # Should be expired
        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_default_deadline_ack(self):
        """ACK packets (alias for ROUTING) get 5s default deadline."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"ack", priority=Priority.ACK)

        # Advance past deadline (ACK is alias for ROUTING, so same deadline)
        clock.advance(DEADLINE_ACK_MS + 1)

        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_default_deadline_urgent(self):
        """Urgent packets (P2) get 30s default deadline."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"urgent", priority=Priority.URGENT)

        # Advance past deadline
        clock.advance(DEADLINE_URGENT_MS + 1)

        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_default_deadline_normal(self):
        """Normal packets (P3) get 60s default deadline."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"normal", priority=Priority.NORMAL)

        # Advance past deadline
        clock.advance(DEADLINE_APP_MS + 1)

        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_default_deadline_bulk(self):
        """Bulk packets (P4) get 120s default deadline - can wait."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        q.push(b"bulk", priority=Priority.BULK)

        # Advance past deadline
        clock.advance(DEADLINE_BULK_MS + 1)

        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

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

    @pytest.mark.asyncio
    async def test_expire_stale_signals_reservation(self):
        """expire_stale() signals reservations on expired packets as failed.

        Spec compliance: callers awaiting send() must not hang indefinitely
        when their packet expires before transmission. See review-r1-4.
        """
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        # Push two packets with reservations: one expires, one survives
        res_short = q.push(b"expires", deadline_ms=100, return_reservation=True)
        res_long = q.push(b"survives", deadline_ms=1000, return_reservation=True)
        assert res_short is not None
        assert res_long is not None

        # Neither reservation should be done yet
        assert not res_short.done()
        assert not res_long.done()

        # Advance past the short deadline
        clock.advance(500)

        expired = q.expire_stale()

        # The short packet should be expired and its reservation signaled False
        assert expired == 1
        assert res_short.done()
        assert res_short.result() is False

        # The long packet is still valid, reservation still pending
        assert not res_long.done()

    @pytest.mark.asyncio
    async def test_expire_stale_reservation_await_returns_false(self):
        """Awaiting an expired packet's reservation returns False."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)

        res = q.push(b"will_expire", deadline_ms=50, return_reservation=True)
        assert res is not None

        # Expire the packet
        clock.advance(100)
        q.expire_stale()

        # Awaiting should immediately return False
        assert await res.wait() is False

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

        # Push SOS - should evict BULK (lowest priority)
        q.push(b"sos", priority=Priority.SOS)

        # Check contents (SOS=0, ROUTING=1, URGENT=2)
        assert q.pop() == b"sos"
        assert q.pop() == b"routing"
        assert q.pop() == b"urgent"
        assert q.pop() is None  # Bulk was evicted

    @pytest.mark.asyncio
    async def test_preempt_signals_evicted_reservation(self):
        """Preemption signals evicted entry's reservation with False.

        Spec compliance: "No Silent Drops" - callers awaiting transmission
        must be notified when their packet is preempted, not left hanging.
        """
        q = TxQueue(capacity=2)

        # Push two bulk packets with reservations
        res1 = q.push(b"bulk1", priority=Priority.BULK, return_reservation=True)
        res2 = q.push(b"bulk2", priority=Priority.BULK, return_reservation=True)
        assert res1 is not None
        assert res2 is not None

        # Push higher priority - should evict one bulk and signal its reservation
        q.push(b"routing", priority=Priority.ROUTING)

        # One reservation should be signaled with False (evicted)
        evicted_count = sum(1 for r in [res1, res2] if r.done())
        assert evicted_count == 1
        assert q.stats.packets_dropped_preempt == 1

        # The evicted reservation should have result=False
        evicted = res1 if res1.done() else res2
        assert evicted.result() is False

    @pytest.mark.asyncio
    async def test_preempt_await_returns_false(self):
        """Awaiting a preempted packet's reservation returns False.

        Spec compliance: Explicit backpressure - sender can await and learn
        their packet was dropped, rather than waiting forever.
        """
        q = TxQueue(capacity=1)

        # Push bulk with reservation
        res = q.push(b"bulk", priority=Priority.BULK, return_reservation=True)
        assert res is not None

        # Preempt with higher priority
        q.push(b"routing", priority=Priority.ROUTING)

        # Await should return False immediately (not hang)
        result = await res.wait()
        assert result is False


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

    def test_pop_records_transmission_stats(self):
        """pop() counts a transmission and records latency, like confirm_transmitted()."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)
        q.push(b"one")
        clock.advance(40)

        assert q.pop() == b"one"

        assert q.stats.packets_transmitted == 1
        assert q.stats.max_latency_ms == 40
        assert q.stats.avg_latency_ms == 4

    def test_pop_then_stale_complete_no_double_count(self):
        """complete(success=True) on an already-popped entry must not count twice."""
        q = TxQueue()
        q.push(b"one")
        entry = q._entries[0]

        assert q.pop() == b"one"
        q.complete(entry, success=True)

        assert q.stats.packets_transmitted == 1
        assert len(q) == 0

    def test_pop_and_confirm_transmitted_paths_both_count(self):
        """Stats are consistent whichever path transmits the packet."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)
        q.push(b"via_pop")
        q.push(b"via_confirm")
        clock.advance(10)

        assert q.pop() == b"via_pop"
        q.confirm_transmitted(b"via_confirm")

        assert q.stats.packets_transmitted == 2
        assert q.stats.max_latency_ms == 10

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
        """All five priority levels can coexist (spec §10.2.3: P0-P4)."""
        q = TxQueue(capacity=5)

        q.push(b"bulk", priority=Priority.BULK)
        q.push(b"normal", priority=Priority.NORMAL)
        q.push(b"urgent", priority=Priority.URGENT)
        q.push(b"routing", priority=Priority.ROUTING)
        q.push(b"sos", priority=Priority.SOS)

        assert len(q) == 5
        assert q.pop() == b"sos"
        assert q.pop() == b"routing"
        assert q.pop() == b"urgent"
        assert q.pop() == b"normal"
        assert q.pop() == b"bulk"

    def test_invalid_capacity(self):
        with pytest.raises(ValueError):
            TxQueue(capacity=0)
        with pytest.raises(ValueError):
            TxQueue(capacity=-1)


class TestReserveComplete:
    """Tests for TxQueue.reserve() and TxQueue.complete()."""

    def test_reserve_returns_front_entry(self):
        q = TxQueue()
        q.push(b"first", priority=Priority.ROUTING)
        q.push(b"second", priority=Priority.BULK)

        entry = q.reserve()
        assert entry is not None
        assert entry.data == b"first"
        assert entry.priority == Priority.ROUTING
        assert len(q) == 2

    def test_reserve_empty_returns_none(self):
        q = TxQueue()
        assert q.reserve() is None

    def test_complete_success_removes_entry(self):
        q = TxQueue()
        q.push(b"packet", priority=Priority.URGENT)

        entry = q.reserve()
        assert entry is not None

        q.complete(entry, success=True)
        assert len(q) == 0
        assert q.stats.packets_transmitted == 1

    def test_complete_success_updates_latency_stats(self):
        clock = FakeClock(0)
        q = TxQueue(clock=clock)
        q.push(b"latency_test", priority=Priority.ACK)
        clock.advance(50)

        entry = q.reserve()
        assert entry is not None

        q.complete(entry, success=True)
        assert q.stats.max_latency_ms >= 50
        assert q.stats.avg_latency_ms > 0

    def test_complete_failure_requeues_entry(self):
        clock = FakeClock(100)
        q = TxQueue(clock=clock)
        q.push(b"retry", priority=Priority.ROUTING, deadline_ms=1000)

        entry = q.reserve()
        assert entry is not None
        original_deadline = entry.deadline_ms

        clock.advance(200)
        q.complete(entry, success=False)
        assert len(q) == 1
        assert q.stats.packets_transmitted == 0
        assert entry.deadline_ms == original_deadline

    def test_complete_failure_preserves_original_deadline(self):
        clock = FakeClock(0)
        q = TxQueue(clock=clock)
        q.push(b"deadline_check", priority=Priority.ACK, deadline_ms=500)

        entry = q.reserve()
        assert entry is not None

        clock.advance(300)
        q.complete(entry, success=False)
        clock.advance(300)

        assert q.pop() is None
        assert q.stats.packets_dropped_deadline == 1

    def test_reserve_then_complete_success_multiple(self):
        q = TxQueue()
        q.push(b"a", priority=Priority.ROUTING)
        q.push(b"b", priority=Priority.ACK)
        q.push(b"c", priority=Priority.BULK)

        e1 = q.reserve()
        assert e1 is not None and e1.data == b"a"
        q.complete(e1, success=True)

        e2 = q.reserve()
        assert e2 is not None and e2.data == b"b"
        q.complete(e2, success=True)

        e3 = q.reserve()
        assert e3 is not None and e3.data == b"c"
        q.complete(e3, success=True)

        assert q.stats.packets_transmitted == 3
        assert len(q) == 0

    def test_reserve_after_complete_failure_returns_same_entry(self):
        q = TxQueue()
        q.push(b"sticky", priority=Priority.URGENT)

        e1 = q.reserve()
        q.complete(e1, success=False)

        e2 = q.reserve()
        assert e2 is e1

    @pytest.mark.asyncio
    async def test_reservation_future_is_set_on_success(self):
        q = TxQueue()
        res = q.push(b"awaitable", return_reservation=True)
        assert res is not None

        entry = q.reserve()
        q.complete(entry, success=True)

        assert res.done()
        assert res.result() is True

    @pytest.mark.asyncio
    async def test_reservation_not_set_on_requeue(self):
        """complete(False) requeues entry - reservation NOT signaled yet.

        The reservation should only be signaled when the entry is definitively
        done (success, expired, or preempted). On requeue, the entry stays
        in the queue for retry.
        """
        q = TxQueue()
        res = q.push(b"fail_me", return_reservation=True)
        assert res is not None

        entry = q.reserve()
        q.complete(entry, success=False)

        # Reservation should NOT be done - entry is still queued for retry
        assert not res.done()
        assert len(q) == 1

    @pytest.mark.asyncio
    async def test_reservation_set_false_on_expiry(self):
        """Reservation is signaled False when entry expires."""
        clock = FakeClock(0)
        q = TxQueue(clock=clock)
        res = q.push(b"will_expire", deadline_ms=100, return_reservation=True)
        assert res is not None

        # Entry expires
        clock.advance(200)
        q.expire_stale()

        assert res.done()
        assert res.result() is False

    @pytest.mark.asyncio
    async def test_reservation_wait_returns_true_on_success(self):
        q = TxQueue()
        res = q.push(b"async_ok", return_reservation=True)
        assert res is not None

        entry = q.reserve()
        q.complete(entry, success=True)

        assert await res.wait() is True

    @pytest.mark.asyncio
    async def test_reservation_wait_returns_true_after_retry_success(self):
        """Retry scenario: first attempt fails (requeue), second succeeds."""
        q = TxQueue()
        res = q.push(b"retry_me", return_reservation=True)
        assert res is not None

        # First attempt fails - entry is requeued
        entry = q.reserve()
        q.complete(entry, success=False)
        assert not res.done()

        # Second attempt succeeds
        entry2 = q.reserve()
        assert entry2 is entry  # Same entry object
        q.complete(entry2, success=True)

        assert await res.wait() is True

    @pytest.mark.asyncio
    async def test_concurrent_reserve_complete_round_robin(self):
        q = TxQueue(capacity=10)
        for i in range(10):
            q.push(f"p{i}".encode(), priority=Priority.BULK)

        lock = asyncio.Lock()

        async def worker(n: int) -> int:
            async with lock:
                entry = q.reserve()
                if entry is None:
                    return 0
                await asyncio.sleep(0)
                q.complete(entry, success=True)
                return 1

        tasks = [asyncio.create_task(worker(i)) for i in range(10)]
        results = await asyncio.gather(*tasks)
        assert sum(results) == 10
        assert q.stats.packets_transmitted == 10

    @pytest.mark.asyncio
    async def test_cancelled_reservation_does_not_corrupt_queue(self):
        q = TxQueue()
        q.push(b"cancel_me", priority=Priority.ACK)
        q.push(b"survivor", priority=Priority.BULK)

        async def reserve_and_cancel():
            entry = q.reserve()
            assert entry is not None
            await asyncio.sleep(0)
            q.complete(entry, success=False)

        task = asyncio.create_task(reserve_and_cancel())
        await task
        assert len(q) == 2

        e = q.reserve()
        assert e is not None
        assert e.data == b"cancel_me"
        q.complete(e, success=True)
        assert q.stats.packets_transmitted == 1

    @pytest.mark.asyncio
    async def test_concurrent_reserve_complete_mixed_success_failure(self):
        clock = FakeClock(0)
        q = TxQueue(capacity=6, clock=clock)
        for i in range(6):
            q.push(f"p{i}".encode(), priority=Priority.BULK, deadline_ms=10000)

        lock = asyncio.Lock()

        async def mixed_worker(idx: int) -> bool:
            async with lock:
                entry = q.reserve()
                if entry is None:
                    return False
                await asyncio.sleep(0)
                success = idx % 2 == 0
                q.complete(entry, success=success)
                return success

        tasks = [asyncio.create_task(mixed_worker(i)) for i in range(6)]
        results = await asyncio.gather(*tasks)
        successes = sum(results)
        assert successes == 3
        assert q.stats.packets_transmitted == 3
        remaining = len(q)
        assert remaining == 3

    @pytest.mark.asyncio
    async def test_complete_non_head_entry_removes_it(self, caplog):
        # ponytail: new behavior - complete() removes entry at any position
        q = TxQueue()
        q.push(b"first", priority=Priority.ROUTING)
        q.push(b"second", priority=Priority.BULK)

        e2 = q._entries[1]
        q.complete(e2, success=True)

        # Entry was removed, only one remains
        assert len(q) == 1
        assert q._entries[0].data == b"first"

    @pytest.mark.asyncio
    async def test_signal_all_pending_then_complete_first_wins(self, caplog):
        """Race: signal_all_pending(False) then complete(True) - first wins.

        Simulates a race condition where queue is being cleared/shutdown
        while a transmission is in progress. The reservation should get
        the first result (False from signal_all_pending), and the later
        complete(True) should be ignored (idempotent set_result).
        """
        q = TxQueue()
        res = q.push(b"race_me", return_reservation=True)
        assert res is not None

        # Get entry reference before any operations
        entry = q.reserve()
        assert entry is not None
        assert entry.reservation is res

        # Simulate race: signal_all_pending called mid-transmission
        q.signal_all_pending(False)

        # Reservation should now be done with False
        assert res.done()
        assert res.result() is False
        assert len(q) == 0

        # complete(True) comes later - entry already removed, set_result ignored
        q.complete(entry, success=True)

        # Result is still False (first wins)
        assert res.result() is False
        # ponytail: warning changed from "not head" to "set_result ignored"
        assert "set_result" in caplog.text and "ignored" in caplog.text

    @pytest.mark.asyncio
    async def test_complete_true_then_clear_no_conflict(self, caplog):
        """complete(True) removes entry, so clear() doesn't touch it.

        This is the normal (non-race) case: successful transmission removes
        the entry before clear() is called, so no conflict occurs.
        """
        q = TxQueue()
        res = q.push(b"normal", return_reservation=True)
        assert res is not None

        entry = q.reserve()
        q.complete(entry, success=True)

        # Reservation is done with True
        assert res.done()
        assert res.result() is True

        # clear() shouldn't affect it (entry was already removed)
        q.clear()

        # Still True, no warning
        assert res.result() is True
        assert "ignored" not in caplog.text


class TestPrioritySpecCompliance:
    """Tests verifying Priority enum matches spec §10.2.3."""

    def test_priority_values_match_spec(self):
        """Priority values match spec §10.2.3 P0-P4 levels."""
        assert int(Priority.SOS) == 0  # P0
        assert int(Priority.ROUTING) == 1  # P1
        assert int(Priority.URGENT) == 2  # P2
        assert int(Priority.NORMAL) == 3  # P3
        assert int(Priority.BULK) == 4  # P4

    def test_ack_alias_equals_routing(self):
        """ACK is a backward-compat alias for ROUTING (both P1)."""
        assert Priority.ACK == Priority.ROUTING
        assert int(Priority.ACK) == 1

    def test_priority_ordering(self):
        """Lower value = higher priority (SOS beats BULK)."""
        assert Priority.SOS < Priority.ROUTING
        assert Priority.ROUTING < Priority.URGENT
        assert Priority.URGENT < Priority.NORMAL
        assert Priority.NORMAL < Priority.BULK

    def test_coap_txpriority_alias_unified(self):
        """TxPriority in coap.params is now unified with link.Priority."""
        from lichen.coap.params import TxPriority

        assert TxPriority is Priority


class TestTxReservationLazyInit:
    """Tests for TxReservation lazy Future initialization.

    The Future is created lazily to allow TxReservation instantiation
    outside of an async context, which is required for push(return_reservation=True)
    called from synchronous code.
    """

    def test_creation_outside_async_context(self):
        """TxReservation can be created without a running event loop."""
        from lichen.link.tx_queue import TxReservation

        # This would raise RuntimeError if Future was created eagerly
        res = TxReservation()
        assert res is not None
        assert not res.done()

    def test_push_reservation_outside_async_context(self):
        """push(return_reservation=True) works outside async context."""
        q = TxQueue()
        res = q.push(b"test", return_reservation=True)
        assert res is not None
        assert not res.done()

    def test_set_result_before_wait(self):
        """set_result() stores result even before Future is created."""
        from lichen.link.tx_queue import TxReservation

        res = TxReservation()
        res.set_result(True)
        assert res.done()
        assert res.result() is True

    @pytest.mark.asyncio
    async def test_wait_after_set_result(self):
        """wait() returns result set before Future was created."""
        from lichen.link.tx_queue import TxReservation

        res = TxReservation()
        res.set_result(False)

        # wait() creates Future and applies stored result
        result = await res.wait()
        assert result is False

    @pytest.mark.asyncio
    async def test_push_complete_await_full_cycle(self):
        """Full cycle: push outside async, complete, await inside async."""
        q = TxQueue()

        # push outside would-be async context (simulated by test setup)
        res = q.push(b"cycle_test", return_reservation=True)
        assert res is not None

        # complete the transmission
        entry = q.reserve()
        q.complete(entry, success=True)

        # await the result
        assert await res.wait() is True

    def test_set_result_idempotent_same_value(self):
        """set_result() is idempotent when called with the same value."""
        from lichen.link.tx_queue import TxReservation

        res = TxReservation()
        res.set_result(True)
        res.set_result(True)  # Same value, should not raise
        assert res.result() is True

        res2 = TxReservation()
        res2.set_result(False)
        res2.set_result(False)  # Same value, should not raise
        assert res2.result() is False

    def test_set_result_conflicting_value_logs_warning(self, caplog):
        """set_result() logs warning when called with a different value (first wins)."""
        from lichen.link.tx_queue import TxReservation

        res = TxReservation()
        res.set_result(True)

        # Conflicting call should NOT raise, just log a warning
        res.set_result(False)

        # Original value is preserved (first wins)
        assert res.result() is True
        assert "set_result(False) ignored: already set to True" in caplog.text

    def test_set_result_conflicting_value_false_then_true_logs_warning(self, caplog):
        """set_result() logs warning: False then True (first wins)."""
        from lichen.link.tx_queue import TxReservation

        res = TxReservation()
        res.set_result(False)

        # Conflicting call should NOT raise, just log a warning
        res.set_result(True)

        # Original value is preserved (first wins)
        assert res.result() is False
        assert "set_result(True) ignored: already set to False" in caplog.text

    @pytest.mark.asyncio
    async def test_result_and_wait_return_same_value_true(self):
        """result() and wait() must return the same value (True case)."""
        from lichen.link.tx_queue import TxReservation

        res = TxReservation()
        res.set_result(True)

        # Both methods must return identical value
        wait_result = await res.wait()
        result_result = res.result()
        assert wait_result is result_result is True

    @pytest.mark.asyncio
    async def test_result_and_wait_return_same_value_false(self):
        """result() and wait() must return the same value (False case)."""
        from lichen.link.tx_queue import TxReservation

        res = TxReservation()
        res.set_result(False)

        # Both methods must return identical value
        wait_result = await res.wait()
        result_result = res.result()
        assert wait_result is result_result is False

    @pytest.mark.asyncio
    async def test_result_and_wait_consistent_after_wait_first(self):
        """result() and wait() consistent when wait() is called before set_result()."""
        import asyncio

        from lichen.link.tx_queue import TxReservation

        res = TxReservation()

        async def delayed_set_result():
            await asyncio.sleep(0.01)
            res.set_result(True)

        # Start wait before result is set
        wait_task = asyncio.create_task(res.wait())
        set_task = asyncio.create_task(delayed_set_result())

        await asyncio.gather(wait_task, set_task)

        # Both must return identical value
        assert wait_task.result() is res.result() is True

    @pytest.mark.asyncio
    async def test_result_and_wait_consistent_multiple_waits(self):
        """Multiple wait() calls and result() all return same value."""
        import asyncio

        from lichen.link.tx_queue import TxReservation

        res = TxReservation()

        async def delayed_set_result():
            await asyncio.sleep(0.01)
            res.set_result(False)

        # Multiple waiters
        wait1 = asyncio.create_task(res.wait())
        wait2 = asyncio.create_task(res.wait())
        set_task = asyncio.create_task(delayed_set_result())

        await asyncio.gather(wait1, wait2, set_task)

        # All must be consistent
        assert wait1.result() is wait2.result() is res.result() is False
