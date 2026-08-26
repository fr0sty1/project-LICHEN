# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests: bounded TX queue vs shared bufferbloat vectors.

Drives ``lichen.timing.tx_queue`` against
``test/vectors/tx_queue_{bounded,expiry,priority,implementation}.json``
and the TxQueue component vectors of ``no_silent_drops.json``
(spec appendix-bufferbloat.md B.2/B.3).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.timing.tx_queue import (
    DEADLINE_ACK_MS,
    DEADLINE_BULK_MS,
    DEADLINE_NORMAL_MS,
    DEADLINE_ROUTING_MS,
    DEADLINE_SOS_MS,
    DEADLINE_URGENT_MS,
    TX_QUEUE_SIZE,
    Priority,
    QueueFullError,
    TxQueue,
    TxQueueEntry,
    default_deadline_for,
)

_VECTORS_DIR = Path(__file__).parents[3] / "test" / "vectors"


def _load(name: str) -> dict:
    return json.loads((_VECTORS_DIR / name).read_text())


# ---------------------------------------------------------------------------
# Constants and enums (tx_queue_bounded / tx_queue_implementation)
# ---------------------------------------------------------------------------


class TestConstants:
    def test_capacity_default_4(self) -> None:
        assert _load("tx_queue_bounded.json")["vectors"][0]["expected"]["capacity"] == 4
        assert TX_QUEUE_SIZE == 4
        assert TxQueue().capacity == 4

    def test_priority_values(self) -> None:
        assert int(Priority.SOS) == 0
        assert int(Priority.ROUTING) == 1
        assert int(Priority.URGENT) == 2
        assert int(Priority.NORMAL) == 3
        assert int(Priority.BULK) == 4

    def test_ack_is_alias_of_routing(self) -> None:
        assert Priority.ACK is Priority.ROUTING

    def test_priority_ordering_lower_value_higher_urgency(self) -> None:
        assert Priority.SOS < Priority.ROUTING < Priority.URGENT
        assert Priority.URGENT < Priority.NORMAL < Priority.BULK
        assert not Priority.BULK < Priority.SOS
        assert Priority.ROUTING == Priority.ACK


class TestDeadlines:
    @pytest.mark.parametrize(
        ("priority", "expected_ms"),
        [
            (Priority.SOS, DEADLINE_SOS_MS),
            (Priority.ROUTING, DEADLINE_ROUTING_MS),
            (Priority.URGENT, DEADLINE_URGENT_MS),
            (Priority.NORMAL, DEADLINE_NORMAL_MS),
            (Priority.BULK, DEADLINE_BULK_MS),
        ],
    )
    def test_class_defaults(self, priority: Priority, expected_ms: int) -> None:
        assert (
            expected_ms
            == {
                Priority.SOS: 2000,
                Priority.ROUTING: 5000,
                Priority.URGENT: 30000,
                Priority.NORMAL: 60000,
                Priority.BULK: 120000,
            }[priority]
        )
        assert default_deadline_for(priority) == expected_ms

    def test_ack_default_resolves_to_routing(self) -> None:
        # Spec's DEADLINE_ACK_MS is 10s, but the priority alias means the
        # default lookup returns ROUTING's 5s; callers pass explicit
        # deadline_ms for the spec's 10s ACK deadline.
        assert DEADLINE_ACK_MS == 10000
        assert default_deadline_for(Priority.ACK) == DEADLINE_ROUTING_MS


# ---------------------------------------------------------------------------
# Deadline expiry arithmetic and interactions (tx_queue_expiry)
# ---------------------------------------------------------------------------


class TestExpiry:
    def _entry(self, **kw: object) -> TxQueueEntry:
        prio = kw.pop("priority", Priority.SOS)
        entry = TxQueueEntry(data=b"x", priority=prio, **kw)  # type: ignore[arg-type]
        return entry

    @pytest.mark.parametrize(
        ("priority", "boundary"),
        [
            (Priority.SOS, 2000),
            (Priority.ROUTING, 5000),
            (Priority.URGENT, 30000),
            (Priority.NORMAL, 60000),
            (Priority.BULK, 120000),
        ],
    )
    def test_boundary_now_ge_deadline(self, priority: Priority, boundary: int) -> None:
        entry = self._entry(priority=priority, enqueue_time_ms=0)
        assert not entry.expired(boundary - 1)
        assert entry.expired(boundary)
        assert entry.expired(boundary + 1)

    def test_custom_deadline_overrides_default(self) -> None:
        entry = self._entry(priority=Priority.ROUTING, enqueue_time_ms=0, deadline_ms=100)
        assert entry.effective_deadline() == 100
        assert not entry.expired(50)
        assert entry.expired(100)

    def test_nonzero_enqueue_time_bases_default(self) -> None:
        entry = self._entry(priority=Priority.SOS, enqueue_time_ms=5000)
        assert entry.effective_deadline() == 7000

    def test_multiple_packets_only_expired_removed(self) -> None:
        q = TxQueue()
        q.push(b"short", Priority.NORMAL, 0, deadline_ms=100)
        q.push(b"long", Priority.NORMAL, 0, deadline_ms=1000)
        assert q.expire_stale(500) == 1
        assert q.order() == [b"long"]

    def test_expiry_makes_room_on_push(self) -> None:
        q = TxQueue(capacity=4)
        for _ in range(4):
            q.push(b"stale", Priority.BULK, 0, deadline_ms=100)
        assert len(q) == 4
        pushed = q.push(b"fresh", Priority.BULK, 200, deadline_ms=10000)
        assert pushed is not None
        assert q.stats.packets_dropped_deadline == 4

    def test_stats_track_drops_by_deadline(self) -> None:
        q = TxQueue()
        q.push(b"a", Priority.NORMAL, 0, deadline_ms=100)
        q.push(b"b", Priority.NORMAL, 0, deadline_ms=100)
        q.push(b"c", Priority.NORMAL, 0, deadline_ms=1000)
        q.expire_stale(500)
        assert q.stats.packets_dropped_deadline == 2

    @pytest.mark.parametrize("op", ["peek", "pop", "reserve"])
    def test_accessors_trigger_expiry(self, op: str) -> None:
        q = TxQueue()
        q.push(b"stale", Priority.NORMAL, 0, deadline_ms=100)
        result = getattr(q, op)(200)
        assert result is None
        assert len(q) == 0

    def test_requeue_preserves_original_deadline(self) -> None:
        # complete(success=False) must NOT grant a fresh deadline: the
        # entry keeps its original 500ms deadline and expires at 600.
        q = TxQueue()
        q.push(b"retry_me", Priority.NORMAL, 100, deadline_ms=500)
        reserved = q.reserve(200)
        assert reserved is not None
        q.complete(False, 300)
        assert q.expire_stale(600) == 1


# ---------------------------------------------------------------------------
# Push contract: expire -> capacity -> preempt/reject (tx_queue_implementation)
# ---------------------------------------------------------------------------


class TestPushContract:
    def test_push_checks_deadline_before_admission(self) -> None:
        q = TxQueue(capacity=2)
        q.push(b"stale1", Priority.BULK, 0, deadline_ms=100)
        q.push(b"stale2", Priority.BULK, 0, deadline_ms=100)
        q.push(b"fresh", Priority.BULK, 200, deadline_ms=10000)
        assert q.contains(b"fresh")
        assert q.stats.packets_dropped_deadline == 2
        assert len(q) == 1

    def test_push_preempts_when_higher_priority(self) -> None:
        q = TxQueue(capacity=2)
        q.push(b"bulk1", Priority.BULK, 0, deadline_ms=10000)
        q.push(b"bulk2", Priority.BULK, 0, deadline_ms=10000)
        q.push(b"routing", Priority.ROUTING, 0, deadline_ms=5000)
        assert q.stats.packets_dropped_preempt == 1
        assert set(q.order()) == {b"routing", b"bulk2"}

    def test_push_rejects_same_priority_when_full(self) -> None:
        q = TxQueue(capacity=2)
        q.push(b"bulk1", Priority.BULK, 0, deadline_ms=10000)
        q.push(b"bulk2", Priority.BULK, 0, deadline_ms=10000)
        with pytest.raises(QueueFullError):
            q.push(b"bulk3", Priority.BULK, 0, deadline_ms=10000)
        assert q.stats.packets_dropped_full == 1

    def test_push_rejects_lower_priority_when_full(self) -> None:
        q = TxQueue(capacity=2)
        q.push(b"urgent1", Priority.URGENT, 0, deadline_ms=30000)
        q.push(b"urgent2", Priority.URGENT, 0, deadline_ms=30000)
        with pytest.raises(QueueFullError):
            q.push(b"bulk", Priority.BULK, 0, deadline_ms=120000)
        assert q.stats.packets_dropped_full == 1

    def test_expiry_then_admit_without_preemption(self) -> None:
        q = TxQueue(capacity=3)
        q.push(b"stale", Priority.BULK, 0, deadline_ms=100)
        q.push(b"valid1", Priority.BULK, 0, deadline_ms=10000)
        q.push(b"valid2", Priority.BULK, 0, deadline_ms=10000)
        q.push(b"routing", Priority.ROUTING, 200, deadline_ms=5200)
        assert q.stats.packets_dropped_deadline == 1
        assert q.stats.packets_dropped_preempt == 0
        assert len(q) == 3
        assert q.order() == [b"routing", b"valid1", b"valid2"]

    def test_preempts_oldest_among_same_lowest(self) -> None:
        q = TxQueue(capacity=3)
        q.push(b"bulk1", Priority.BULK, 0, deadline_ms=120000)
        q.push(b"bulk2", Priority.BULK, 10, deadline_ms=120000)
        q.push(b"bulk3", Priority.BULK, 20, deadline_ms=120000)
        q.push(b"urgent", Priority.URGENT, 30, deadline_ms=30000)
        assert q.stats.packets_dropped_preempt == 1
        assert q.order() == [b"urgent", b"bulk2", b"bulk3"]

    def test_capacity_invariant_under_rapid_push(self) -> None:
        q = TxQueue(capacity=4)
        for i in range(4):
            q.push(f"p{i}".encode(), Priority.BULK, 0, deadline_ms=120000)
        assert len(q) == 4
        q.push(b"p5", Priority.ROUTING, 0, deadline_ms=5000)
        assert len(q) == 4
        q.push(b"p6", Priority.ROUTING, 0, deadline_ms=5000)
        assert len(q) == 4
        assert q.stats.packets_dropped_preempt == 2

    def test_absolute_deadline_semantics(self) -> None:
        entry = TxQueueEntry(data=b"d", priority=Priority.ROUTING, enqueue_time_ms=1000)
        assert entry.effective_deadline() == 6000


# ---------------------------------------------------------------------------
# Pop order and preemption chains (tx_queue_priority)
# ---------------------------------------------------------------------------


class TestPopOrder:
    def test_strict_priority_reverse_of_push(self) -> None:
        q = TxQueue(capacity=5)
        for data, prio in [
            (b"bulk", Priority.BULK),
            (b"normal", Priority.NORMAL),
            (b"urgent", Priority.URGENT),
            (b"routing", Priority.ROUTING),
            (b"sos", Priority.SOS),
        ]:
            q.push(data, prio, 0)
        got = [q.pop(1000).data for _ in range(5)]  # type: ignore[union-attr]
        assert got == [b"sos", b"routing", b"urgent", b"normal", b"bulk"]

    def test_fifo_within_same_priority(self) -> None:
        q = TxQueue(capacity=4)
        for i in range(4):
            q.push(f"bulk{i}".encode(), Priority.BULK, i * 10, deadline_ms=120000)
        got = [q.pop(1000).data for _ in range(4)]  # type: ignore[union-attr]
        assert got == [b"bulk0", b"bulk1", b"bulk2", b"bulk3"]

    def test_mixed_interleaved_priority_then_fifo(self) -> None:
        q = TxQueue(capacity=8)
        seq = [
            (b"bulk_1", Priority.BULK, 0),
            (b"routing_1", Priority.ROUTING, 10),
            (b"urgent_1", Priority.URGENT, 20),
            (b"bulk_2", Priority.BULK, 30),
            (b"routing_2", Priority.ROUTING, 40),
            (b"normal_1", Priority.NORMAL, 50),
        ]
        for data, prio, enq in seq:
            q.push(data, prio, enq)
        got = [q.pop(1000).data for _ in range(6)]  # type: ignore[union-attr]
        assert got == [
            b"routing_1",
            b"routing_2",
            b"urgent_1",
            b"normal_1",
            b"bulk_1",
            b"bulk_2",
        ]

    def test_ack_alias_fifo_with_routing(self) -> None:
        q = TxQueue(capacity=4)
        q.push(b"bulk", Priority.BULK, 0)
        q.push(b"ack", Priority.ACK, 0)
        q.push(b"routing", Priority.ROUTING, 0)
        q.push(b"urgent", Priority.URGENT, 0)
        got = [q.pop(1000).data for _ in range(4)]  # type: ignore[union-attr]
        assert got == [b"ack", b"routing", b"urgent", b"bulk"]

    def test_first_pop_routing_beats_bulk(self) -> None:
        q = TxQueue(capacity=4)
        q.push(b"bulk_1", Priority.BULK, 0)
        q.push(b"bulk_2", Priority.BULK, 0)
        q.push(b"routing", Priority.ROUTING, 0)
        q.push(b"bulk_3", Priority.BULK, 0)
        assert q.pop(1000).data == b"routing"  # type: ignore[union-attr]

    def test_sos_pushed_last_pops_first(self) -> None:
        q = TxQueue(capacity=4)
        q.push(b"routing", Priority.ROUTING, 0)
        q.push(b"urgent", Priority.URGENT, 0)
        q.push(b"normal", Priority.NORMAL, 0)
        q.push(b"sos", Priority.SOS, 0)
        assert q.pop(1000).data == b"sos"  # type: ignore[union-attr]

    def test_peek_returns_highest_without_removal(self) -> None:
        q = TxQueue(capacity=3)
        q.push(b"bulk", Priority.BULK, 0)
        q.push(b"routing", Priority.ROUTING, 0)
        q.push(b"normal", Priority.NORMAL, 0)
        assert q.peek(1000).data == b"routing"  # type: ignore[union-attr]
        assert len(q) == 3

    def test_reserve_keeps_entry_queued(self) -> None:
        q = TxQueue(capacity=3)
        q.push(b"normal", Priority.NORMAL, 0)
        q.push(b"sos", Priority.SOS, 0)
        q.push(b"bulk", Priority.BULK, 0)
        reserved = q.reserve(1000)
        assert reserved is not None and reserved.data == b"sos"
        assert len(q) == 3

    def test_priority_preemption_chain(self) -> None:
        q = TxQueue(capacity=2)
        q.push(b"bulk_1", Priority.BULK, 0)
        q.push(b"bulk_2", Priority.BULK, 0)
        q.push(b"normal", Priority.NORMAL, 0)
        q.push(b"urgent", Priority.URGENT, 0)
        assert q.stats.packets_dropped_preempt == 2
        assert q.order() == [b"urgent", b"normal"]


# ---------------------------------------------------------------------------
# No silent drops (no_silent_drops.json TxQueue component vectors)
# ---------------------------------------------------------------------------


class TestNoSilentDrops:
    def test_full_raises_and_counts(self) -> None:
        q = TxQueue(capacity=2)
        q.push(b"bulk1", Priority.BULK, 0)
        q.push(b"bulk2", Priority.BULK, 0)
        with pytest.raises(QueueFullError):
            q.push(b"bulk3", Priority.BULK, 0)
        assert q.stats.packets_dropped_full == 1

    def test_preemption_signals_reservation_false(self) -> None:
        q = TxQueue(capacity=1)
        results: list[bool] = []
        entry = q.push(b"bulk1", Priority.BULK, 0)
        entry.attach_reservation(results.append)
        q.push(b"routing1", Priority.ROUTING, 0)
        assert results == [False]
        assert q.stats.packets_dropped_preempt == 1

    def test_expiry_signals_reservation_false(self) -> None:
        q = TxQueue()
        results: list[bool] = []
        entry = q.push(b"stale", Priority.NORMAL, 0, deadline_ms=100)
        entry.attach_reservation(results.append)
        q.expire_stale(200)
        assert results == [False]
        assert q.stats.packets_dropped_deadline == 1

    def test_clear_signals_all_reservations_false(self) -> None:
        q = TxQueue()
        results: list[bool] = []
        for i in range(3):
            entry = q.push(f"p{i}".encode(), Priority.NORMAL, 0)
            entry.attach_reservation(results.append)
        q.clear()
        assert results == [False, False, False]

    def test_failed_transmission_signals_false(self) -> None:
        q = TxQueue()
        results: list[bool] = []
        q.push(b"pkt", Priority.NORMAL, 0)
        q.reserve(0)
        q._in_flight.attach_reservation(results.append)  # noqa: SLF001
        q.complete(False, 10)
        assert results == [False]

    def test_successful_transmission_signals_true_and_counts(self) -> None:
        q = TxQueue()
        results: list[bool] = []
        q.push(b"pkt", Priority.NORMAL, 0)
        q.reserve(0)
        q._in_flight.attach_reservation(results.append)  # noqa: SLF001
        q.complete(True, 50)
        assert results == [True]
        assert q.stats.packets_transmitted == 1
        assert q.stats.max_latency_ms == 50
        assert len(q) == 0
