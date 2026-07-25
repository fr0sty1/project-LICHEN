# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LICHEN simulator event queue system."""

import pytest

from lichen.sim.events import (
    Event,
    EventQueue,
    RxTimeoutEvent,
    TxEndEvent,
    TxStartEvent,
)


class TestEventDataclasses:
    """Test event dataclass definitions."""

    def test_event_has_time_us(self) -> None:
        """Base Event stores time in microseconds."""
        event = Event(time_us=1000)
        assert event.time_us == 1000

    def test_tx_start_event_fields(self) -> None:
        """TxStartEvent has time, node_id, and transmission_id."""
        event = TxStartEvent(time_us=100, node_id="node1", transmission_id="tx001")
        assert event.time_us == 100
        assert event.node_id == "node1"
        assert event.transmission_id == "tx001"

    def test_tx_end_event_fields(self) -> None:
        """TxEndEvent has time, node_id, and transmission_id."""
        event = TxEndEvent(time_us=200, node_id="node2", transmission_id="tx002")
        assert event.time_us == 200
        assert event.node_id == "node2"
        assert event.transmission_id == "tx002"

    def test_rx_timeout_event_fields(self) -> None:
        """RxTimeoutEvent has time and node_id."""
        event = RxTimeoutEvent(time_us=300, node_id="node3")
        assert event.time_us == 300
        assert event.node_id == "node3"

    def test_events_are_frozen(self) -> None:
        """Events are immutable (frozen dataclasses)."""
        event = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        with pytest.raises(AttributeError):
            event.time_us = 200  # type: ignore[misc]


class TestEventQueueBasics:
    """Test basic EventQueue operations."""

    def test_new_queue_is_empty(self) -> None:
        """A new queue has no events."""
        queue = EventQueue()
        assert queue.is_empty()
        assert len(queue) == 0

    def test_push_makes_queue_nonempty(self) -> None:
        """Pushing an event makes the queue non-empty."""
        queue = EventQueue()
        queue.push(Event(time_us=100))
        assert not queue.is_empty()
        assert len(queue) == 1

    def test_pop_returns_pushed_event(self) -> None:
        """Pop returns the event that was pushed."""
        queue = EventQueue()
        event = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        queue.push(event)
        popped = queue.pop()
        assert popped == event

    def test_pop_removes_event(self) -> None:
        """Pop removes the event from the queue."""
        queue = EventQueue()
        queue.push(Event(time_us=100))
        queue.pop()
        assert queue.is_empty()
        assert len(queue) == 0

    def test_pop_empty_raises_index_error(self) -> None:
        """Pop from empty queue raises IndexError."""
        queue = EventQueue()
        with pytest.raises(IndexError, match="pop from empty EventQueue"):
            queue.pop()

    def test_peek_returns_event_without_removing(self) -> None:
        """Peek returns earliest event but leaves it in queue."""
        queue = EventQueue()
        event = Event(time_us=100)
        queue.push(event)
        peeked = queue.peek()
        assert peeked == event
        assert len(queue) == 1  # Still there

    def test_peek_empty_returns_none(self) -> None:
        """Peek on empty queue returns None."""
        queue = EventQueue()
        assert queue.peek() is None


class TestEventQueueOrdering:
    """Test EventQueue ordering by time."""

    def test_pop_returns_earliest_event(self) -> None:
        """Events are popped in time order (earliest first)."""
        queue = EventQueue()
        queue.push(Event(time_us=300))
        queue.push(Event(time_us=100))
        queue.push(Event(time_us=200))

        assert queue.pop().time_us == 100
        assert queue.pop().time_us == 200
        assert queue.pop().time_us == 300

    def test_mixed_event_types_ordered_by_time(self) -> None:
        """Different event types are ordered by time regardless of type."""
        queue = EventQueue()
        tx_end = TxEndEvent(time_us=150, node_id="n1", transmission_id="tx1")
        tx_start = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        rx_timeout = RxTimeoutEvent(time_us=200, node_id="n2")

        queue.push(tx_end)
        queue.push(rx_timeout)
        queue.push(tx_start)

        assert queue.pop() == tx_start  # 100
        assert queue.pop() == tx_end  # 150
        assert queue.pop() == rx_timeout  # 200


class TestEventQueueTieBreaking:
    """Test tie-breaking by insertion order."""

    def test_same_time_fifo_order(self) -> None:
        """Events at the same time are returned in insertion order (FIFO)."""
        queue = EventQueue()
        event1 = TxStartEvent(time_us=100, node_id="n1", transmission_id="tx1")
        event2 = TxStartEvent(time_us=100, node_id="n2", transmission_id="tx2")
        event3 = TxStartEvent(time_us=100, node_id="n3", transmission_id="tx3")

        queue.push(event1)
        queue.push(event2)
        queue.push(event3)

        assert queue.pop() == event1
        assert queue.pop() == event2
        assert queue.pop() == event3

    def test_interleaved_times_with_ties(self) -> None:
        """Correct ordering with mix of different times and ties."""
        queue = EventQueue()
        # Push in scrambled order
        e1 = Event(time_us=100)  # First at t=100
        e2 = Event(time_us=200)  # First at t=200
        e3 = Event(time_us=100)  # Second at t=100
        e4 = Event(time_us=200)  # Second at t=200
        e5 = Event(time_us=150)  # Only at t=150

        queue.push(e1)
        queue.push(e2)
        queue.push(e3)
        queue.push(e4)
        queue.push(e5)

        assert queue.pop() == e1  # t=100, first
        assert queue.pop() == e3  # t=100, second
        assert queue.pop() == e5  # t=150
        assert queue.pop() == e2  # t=200, first
        assert queue.pop() == e4  # t=200, second

    def test_peek_respects_ordering(self) -> None:
        """Peek returns the same event that pop would return."""
        queue = EventQueue()
        event_later = Event(time_us=200)
        event_earlier = Event(time_us=100)

        queue.push(event_later)
        queue.push(event_earlier)

        assert queue.peek() == event_earlier
        assert queue.pop() == event_earlier
        assert queue.peek() == event_later


class TestEventQueueIteration:
    """Test EventQueue iteration."""

    def test_iterate_is_non_destructive(self) -> None:
        """Iterating yields events in time order and leaves the queue intact."""
        queue = EventQueue()
        queue.push(Event(time_us=300))
        queue.push(Event(time_us=100))
        queue.push(Event(time_us=200))

        times = [e.time_us for e in queue]

        assert times == [100, 200, 300]
        assert len(queue) == 3  # not emptied
        # Re-iterating yields the same events.
        assert [e.time_us for e in queue] == [100, 200, 300]

    def test_drain_pops_all_events(self) -> None:
        """drain() yields events in order and empties the queue."""
        queue = EventQueue()
        queue.push(Event(time_us=300))
        queue.push(Event(time_us=100))
        queue.push(Event(time_us=200))

        times = [e.time_us for e in queue.drain()]

        assert times == [100, 200, 300]
        assert queue.is_empty()

    def test_repr(self) -> None:
        """Queue has a useful repr."""
        queue = EventQueue()
        assert repr(queue) == "EventQueue(len=0)"
        queue.push(Event(time_us=100))
        queue.push(Event(time_us=200))
        assert repr(queue) == "EventQueue(len=2)"

    def test_remove_events_for_node(self) -> None:
        """remove_events_for_node removes only events for that node."""
        queue = EventQueue()
        queue.push(TxEndEvent(time_us=100, node_id="node1", transmission_id="tx1"))
        queue.push(RxTimeoutEvent(time_us=200, node_id="node2"))
        queue.push(TxEndEvent(time_us=300, node_id="node1", transmission_id="tx2"))
        queue.push(RxTimeoutEvent(time_us=400, node_id="node3"))

        assert len(queue) == 4

        removed = queue.remove_events_for_node("node1")

        assert removed == 2
        assert len(queue) == 2
        # Remaining events should be for node2 and node3
        e1 = queue.pop()
        e2 = queue.pop()
        assert e1.node_id == "node2"  # type: ignore[union-attr]
        assert e2.node_id == "node3"  # type: ignore[union-attr]

    def test_remove_events_for_node_preserves_order(self) -> None:
        """After removal, remaining events maintain time order."""
        queue = EventQueue()
        queue.push(TxEndEvent(time_us=100, node_id="keep", transmission_id="tx1"))
        queue.push(TxEndEvent(time_us=200, node_id="remove", transmission_id="tx2"))
        queue.push(TxEndEvent(time_us=300, node_id="keep", transmission_id="tx3"))
        queue.push(TxEndEvent(time_us=400, node_id="remove", transmission_id="tx4"))
        queue.push(TxEndEvent(time_us=500, node_id="keep", transmission_id="tx5"))

        queue.remove_events_for_node("remove")

        times = [queue.pop().time_us for _ in range(3)]
        assert times == [100, 300, 500]

    def test_remove_events_for_nonexistent_node(self) -> None:
        """Removing events for nonexistent node returns 0."""
        queue = EventQueue()
        queue.push(TxEndEvent(time_us=100, node_id="node1", transmission_id="tx1"))

        removed = queue.remove_events_for_node("nonexistent")

        assert removed == 0
        assert len(queue) == 1


# ============================================================================
# Simulation event processing tests
# ============================================================================

from unittest.mock import patch

from lichen.sim.node import NodeState
from lichen.sim.simulation import Simulation, TimeMode


class TestTimeAdvancement:
    """Test time advancement mechanics."""

    def test_advance_to_updates_time(self) -> None:
        """advance_to updates current_time_us."""
        sim = Simulation(sim_id="test-sim")

        sim.advance_to(1000)

        assert sim.current_time_us == 1000

    def test_advance_to_negative_raises(self) -> None:
        """advance_to raises ValueError for time in the past."""
        sim = Simulation(sim_id="test-sim")
        sim.advance_to(1000)

        with pytest.raises(ValueError, match="Cannot advance backwards"):
            sim.advance_to(500)

    def test_advance_to_processes_events(self) -> None:
        """advance_to processes events up to target time."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        # Start a transmission that will end at some time
        sim.start_transmission("node1", b"test")
        tx_end_time = sim.event_queue.peek().time_us

        # Advance past the transmission end
        sim.advance_to(tx_end_time + 1000)

        # Node should be back to IDLE
        assert node.state == NodeState.IDLE

    def test_advance_to_does_not_process_future_events(self) -> None:
        """advance_to does not process events after target time."""
        sim = Simulation(sim_id="test-sim")
        node = sim.add_node("node1", 0.0, 0.0, 0.0)

        # Start receive with long timeout
        sim.start_receive("node1", timeout_ms=10000)

        # Advance to before timeout
        sim.advance_to(5000)

        # Node should still be in RX_WAIT
        assert node.state == NodeState.RX_WAIT

    def test_process_next_event_returns_event(self) -> None:
        """process_next_event returns the processed event."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_receive("node1", timeout_ms=100)

        event = sim.process_next_event()

        assert isinstance(event, RxTimeoutEvent)
        assert event.node_id == "node1"

    def test_process_next_event_empty_queue_returns_none(self) -> None:
        """process_next_event returns None for empty queue."""
        sim = Simulation(sim_id="test-sim")

        result = sim.process_next_event()

        assert result is None

    def test_process_next_event_updates_time(self) -> None:
        """process_next_event updates current_time_us to event time."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_receive("node1", timeout_ms=100)

        sim.process_next_event()

        assert sim.current_time_us == 100 * 1000  # 100ms in microseconds


class TestBarrierSync:
    """Test BARRIER_SYNC time advancement mode."""

    def test_maybe_advance_time_all_blocked(self) -> None:
        """maybe_advance_time advances when all nodes are in RX_WAIT."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Put both nodes in RX_WAIT
        sim.start_receive("node1", timeout_ms=100)
        sim.start_receive("node2", timeout_ms=200)

        # Both nodes are blocked, should advance to first timeout
        initial_time = sim.current_time_us
        advanced = sim.maybe_advance_time()

        assert advanced is True
        assert sim.current_time_us > initial_time

    def test_maybe_advance_time_idle_node_does_not_block(self) -> None:
        """An idle node must not hold the barrier (regression: fgk deadlock).

        When a receiver is waiting, time advances even if other nodes are idle;
        otherwise a node that transmitted then went idle would freeze the clock
        and the receiver's timeout could never fire.
        """
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)  # stays IDLE

        sim.start_receive("node1", timeout_ms=100)

        initial_time = sim.current_time_us
        advanced = sim.maybe_advance_time()

        assert advanced is True
        assert sim.current_time_us > initial_time

    def test_maybe_advance_time_no_receiver_waiting(self) -> None:
        """No advance when nothing is waiting on the clock, even with events."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        # A transmission schedules a TxEnd event, but no node is in RX_WAIT.
        sim.start_transmission("node1", b"hello")

        initial_time = sim.current_time_us
        advanced = sim.maybe_advance_time()

        assert advanced is False
        assert sim.current_time_us == initial_time

    def test_maybe_advance_time_no_events(self) -> None:
        """maybe_advance_time returns False when no events pending."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        node1 = sim.add_node("node1", 0.0, 0.0, 0.0)
        node1.state = NodeState.RX_WAIT

        advanced = sim.maybe_advance_time()

        assert advanced is False

    def test_maybe_advance_time_no_nodes(self) -> None:
        """maybe_advance_time returns False when no connected nodes."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)

        advanced = sim.maybe_advance_time()

        assert advanced is False

    def test_maybe_advance_time_realtime_mode(self) -> None:
        """maybe_advance_time returns False in REALTIME mode."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.REALTIME)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.start_receive("node1", timeout_ms=100)

        advanced = sim.maybe_advance_time()

        assert advanced is False

    def test_barrier_sync_excludes_disconnected_nodes(self) -> None:
        """Barrier sync ignores disconnected nodes."""
        sim = Simulation(sim_id="test-sim", time_mode=TimeMode.BARRIER_SYNC)
        sim.add_node("node1", 0.0, 0.0, 0.0)
        node2 = sim.add_node("node2", 100.0, 0.0, 0.0)

        # Put node1 in RX_WAIT, disconnect node2
        sim.start_receive("node1", timeout_ms=100)
        node2.disconnect()

        # Only connected node is blocked, should advance
        advanced = sim.maybe_advance_time()

        assert advanced is True


class TestEventOrdering:
    """Test event ordering and processing."""

    def test_events_processed_in_time_order(self) -> None:
        """Events are processed in time order."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Create events in reverse order
        sim.start_receive("node1", timeout_ms=200)
        sim.start_receive("node2", timeout_ms=100)

        # First event should be node2's timeout (earlier)
        event1 = sim.process_next_event()
        assert isinstance(event1, RxTimeoutEvent)
        assert event1.node_id == "node2"

        event2 = sim.process_next_event()
        assert isinstance(event2, RxTimeoutEvent)
        assert event2.node_id == "node1"

    def test_same_time_events_fifo(self) -> None:
        """Events at same time are processed FIFO."""
        sim = Simulation(sim_id="test-sim")
        sim.add_node("node1", 0.0, 0.0, 0.0)
        sim.add_node("node2", 100.0, 0.0, 0.0)

        # Same timeout for both
        sim.start_receive("node1", timeout_ms=100)
        sim.start_receive("node2", timeout_ms=100)

        # First queued should be first processed
        event1 = sim.process_next_event()
        assert event1.node_id == "node1"

        event2 = sim.process_next_event()
        assert event2.node_id == "node2"


class TestRealtimeMode:
    """Test TimeMode.REALTIME time advancement."""

    def _sim(self) -> Simulation:
        sim = Simulation(sim_id="rt", time_mode=TimeMode.REALTIME)
        sim._realtime_epoch_us = 0  # pin epoch so mock ns values are absolute
        return sim

    def test_no_advance_when_wall_clock_unchanged(self) -> None:
        sim = self._sim()
        with patch("lichen.sim.simulation.time") as mock_time:
            mock_time.monotonic_ns.return_value = 0  # now == epoch -> elapsed 0
            result = sim.maybe_advance_time()
        assert result is False
        assert sim.current_time_us == 0

    def test_advances_current_time_to_wall_clock(self) -> None:
        sim = self._sim()
        with patch("lichen.sim.simulation.time") as mock_time:
            mock_time.monotonic_ns.return_value = 500_000_000  # 500ms in ns
            sim.maybe_advance_time()
        assert sim.current_time_us == 500_000  # 500ms in us

    def test_fires_due_events(self) -> None:
        sim = self._sim()
        sim.add_node("a", 0.0, 0.0, 0.0)
        sim.start_receive("a", timeout_ms=100)  # RxTimeout at 100_000 us

        with patch("lichen.sim.simulation.time") as mock_time:
            mock_time.monotonic_ns.return_value = 200_000_000  # 200ms
            result = sim.maybe_advance_time()

        assert result is True
        assert sim.event_queue.is_empty()

    def test_does_not_fire_future_events(self) -> None:
        sim = self._sim()
        sim.add_node("a", 0.0, 0.0, 0.0)
        sim.start_receive("a", timeout_ms=500)  # RxTimeout at 500_000 us

        with patch("lichen.sim.simulation.time") as mock_time:
            mock_time.monotonic_ns.return_value = 100_000_000  # 100ms -- before timeout
            result = sim.maybe_advance_time()

        assert result is False
        assert not sim.event_queue.is_empty()

    def test_returns_false_for_barrier_sync(self) -> None:
        sim = Simulation(sim_id="bs", time_mode=TimeMode.BARRIER_SYNC)
        # BARRIER_SYNC returns False when no nodes are waiting
        result = sim.maybe_advance_time()
        assert result is False
