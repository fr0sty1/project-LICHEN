# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the simulation observer system.

Verifies that observers receive callbacks for simulation events,
and that the system handles edge cases safely (exceptions, concurrent
modification, etc.).
"""

from __future__ import annotations

from lichen.sim.events import ObserverRegistry
from lichen.sim.simulation import Simulation


class RecordingObserver:
    """Test observer that records all events received."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def on_tx_start(self, **kwargs) -> None:
        self.events.append(("tx_start", kwargs))

    def on_tx_end(self, **kwargs) -> None:
        self.events.append(("tx_end", kwargs))

    def on_rx_success(self, **kwargs) -> None:
        self.events.append(("rx_success", kwargs))

    def on_rx_timeout(self, **kwargs) -> None:
        self.events.append(("rx_timeout", kwargs))

    def on_collision(self, **kwargs) -> None:
        self.events.append(("collision", kwargs))

    def on_node_added(self, **kwargs) -> None:
        self.events.append(("node_added", kwargs))

    def on_node_removed(self, **kwargs) -> None:
        self.events.append(("node_removed", kwargs))


class ExplodingObserver:
    """Test observer that raises exceptions on every callback."""

    def on_tx_start(self, **kwargs) -> None:
        raise RuntimeError("Boom!")

    def on_node_added(self, **kwargs) -> None:
        raise ValueError("Kaboom!")


class PartialObserver:
    """Test observer that only implements some methods."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def on_tx_start(self, **kwargs) -> None:
        self.events.append(("tx_start", kwargs))

    # Does NOT implement other methods


class TestObserverRegistry:
    """Tests for the ObserverRegistry class."""

    def test_add_and_notify(self) -> None:
        """Observers receive notifications."""
        registry = ObserverRegistry()
        observer = RecordingObserver()

        registry.add(observer)
        registry.notify(
            "on_tx_start", sim_id="test", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )

        assert len(observer.events) == 1
        assert observer.events[0][0] == "tx_start"
        assert observer.events[0][1]["sim_id"] == "test"
        assert observer.events[0][1]["node_id"] == "n1"

    def test_multiple_observers(self) -> None:
        """Multiple observers all receive notifications."""
        registry = ObserverRegistry()
        obs1 = RecordingObserver()
        obs2 = RecordingObserver()

        registry.add(obs1)
        registry.add(obs2)
        registry.notify("on_node_added", sim_id="s", node_id="n", x=0.0, y=0.0, z=0.0)

        assert len(obs1.events) == 1
        assert len(obs2.events) == 1

    def test_remove_observer(self) -> None:
        """Removed observers stop receiving notifications."""
        registry = ObserverRegistry()
        observer = RecordingObserver()

        registry.add(observer)
        registry.remove(observer)
        registry.notify(
            "on_tx_start", sim_id="test", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )

        assert len(observer.events) == 0

    def test_remove_nonexistent_observer_is_safe(self) -> None:
        """Removing a non-registered observer is a no-op."""
        registry = ObserverRegistry()
        observer = RecordingObserver()

        # Should not raise
        registry.remove(observer)

    def test_duplicate_add_ignored(self) -> None:
        """Adding the same observer twice only registers it once."""
        registry = ObserverRegistry()
        observer = RecordingObserver()

        registry.add(observer)
        registry.add(observer)

        assert len(registry) == 1

        registry.notify(
            "on_tx_start", sim_id="test", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )
        assert len(observer.events) == 1  # Only called once

    def test_exception_does_not_stop_others(self) -> None:
        """An exception in one observer doesn't prevent others from being called."""
        registry = ObserverRegistry()
        exploding = ExplodingObserver()
        recording = RecordingObserver()

        registry.add(exploding)
        registry.add(recording)
        registry.notify(
            "on_tx_start", sim_id="test", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )

        # Recording observer should still have received the event
        assert len(recording.events) == 1

    def test_partial_observer_skips_unimplemented(self) -> None:
        """Observers that don't implement a method are skipped for that method."""
        registry = ObserverRegistry()
        partial = PartialObserver()

        registry.add(partial)
        # Should not raise even though PartialObserver doesn't have on_node_added
        registry.notify("on_node_added", sim_id="s", node_id="n", x=0.0, y=0.0, z=0.0)
        registry.notify(
            "on_tx_start", sim_id="test", node_id="n1", tx_id="t1", payload_len=10, time_us=1000
        )

        # Only tx_start should be recorded
        assert len(partial.events) == 1
        assert partial.events[0][0] == "tx_start"

    def test_clear_removes_all(self) -> None:
        """clear() removes all observers."""
        registry = ObserverRegistry()
        registry.add(RecordingObserver())
        registry.add(RecordingObserver())

        registry.clear()

        assert len(registry) == 0


class TestSimulationObserver:
    """Tests for observer integration with Simulation class."""

    def test_add_observer_to_simulation(self) -> None:
        """Can add observers to a simulation."""
        sim = Simulation("test")
        observer = RecordingObserver()

        sim.add_observer(observer)
        sim.add_node("n1", 0.0, 0.0, 0.0)

        assert len(observer.events) == 1
        assert observer.events[0][0] == "node_added"
        assert observer.events[0][1]["node_id"] == "n1"

    def test_remove_observer_from_simulation(self) -> None:
        """Can remove observers from a simulation."""
        sim = Simulation("test")
        observer = RecordingObserver()

        sim.add_observer(observer)
        sim.remove_observer(observer)
        sim.add_node("n1", 0.0, 0.0, 0.0)

        assert len(observer.events) == 0

    def test_node_added_event(self) -> None:
        """Adding a node fires on_node_added."""
        sim = Simulation("test")
        observer = RecordingObserver()
        sim.add_observer(observer)

        sim.add_node("mynode", 1.0, 2.0, 3.0)

        assert len(observer.events) == 1
        event = observer.events[0]
        assert event[0] == "node_added"
        assert event[1]["sim_id"] == "test"
        assert event[1]["node_id"] == "mynode"
        assert event[1]["x"] == 1.0
        assert event[1]["y"] == 2.0
        assert event[1]["z"] == 3.0

    def test_node_removed_event(self) -> None:
        """Removing a node fires on_node_removed."""
        sim = Simulation("test")
        observer = RecordingObserver()
        sim.add_node("mynode", 0.0, 0.0, 0.0)
        sim.add_observer(observer)

        sim.remove_node("mynode")

        assert len(observer.events) == 1
        event = observer.events[0]
        assert event[0] == "node_removed"
        assert event[1]["sim_id"] == "test"
        assert event[1]["node_id"] == "mynode"

    def test_remove_nonexistent_node_no_event(self) -> None:
        """Removing a non-existent node does not fire an event."""
        sim = Simulation("test")
        observer = RecordingObserver()
        sim.add_observer(observer)

        sim.remove_node("ghost")

        assert len(observer.events) == 0

    def test_tx_start_event(self) -> None:
        """Starting a transmission fires on_tx_start."""
        sim = Simulation("test")
        observer = RecordingObserver()
        sim.add_node("n1", 0.0, 0.0, 0.0)
        sim.add_observer(observer)
        observer.events.clear()  # Clear node_added event

        tx_id = sim.start_transmission("n1", b"hello")

        assert len(observer.events) == 1
        event = observer.events[0]
        assert event[0] == "tx_start"
        assert event[1]["sim_id"] == "test"
        assert event[1]["node_id"] == "n1"
        assert event[1]["tx_id"] == tx_id
        assert event[1]["payload_len"] == 5

    def test_tx_end_event(self) -> None:
        """Transmission completion fires on_tx_end."""
        sim = Simulation("test")
        observer = RecordingObserver()
        sim.add_node("n1", 0.0, 0.0, 0.0)
        sim.add_observer(observer)
        observer.events.clear()

        tx_id = sim.start_transmission("n1", b"hello")
        sim.advance_to(10_000_000)  # Advance past TX end

        tx_end_events = [e for e in observer.events if e[0] == "tx_end"]
        assert len(tx_end_events) == 1
        assert tx_end_events[0][1]["tx_id"] == tx_id

    def test_rx_timeout_event(self) -> None:
        """Receive timeout fires on_rx_timeout."""
        sim = Simulation("test")
        observer = RecordingObserver()
        sim.add_node("n1", 0.0, 0.0, 0.0)
        sim.add_observer(observer)
        observer.events.clear()

        sim.start_receive("n1", timeout_ms=100)
        sim.advance_to(200_000)  # Advance past timeout

        timeout_events = [e for e in observer.events if e[0] == "rx_timeout"]
        assert len(timeout_events) == 1
        assert timeout_events[0][1]["node_id"] == "n1"

    def test_rx_success_event(self) -> None:
        """Successful reception fires on_rx_success."""
        sim = Simulation("test")
        observer = RecordingObserver()

        # Two nodes close together
        sim.add_node("sender", 0.0, 0.0, 0.0)
        sim.add_node("receiver", 100.0, 0.0, 0.0)  # 100m away
        sim.add_observer(observer)
        observer.events.clear()

        # Sender transmits
        tx_id = sim.start_transmission("sender", b"test data")
        # Receiver starts listening
        sim.start_receive("receiver", timeout_ms=5000)
        # Advance to middle of transmission (not past end)
        # TX airtime is ~200ms, so 100ms is during TX
        sim.advance_to(100_000)

        # Check for reception while TX is still in flight
        result = sim.get_rx_result("receiver")
        assert result is not None  # Should have received

        rx_success_events = [e for e in observer.events if e[0] == "rx_success"]
        assert len(rx_success_events) == 1
        event = rx_success_events[0][1]
        assert event["node_id"] == "receiver"
        assert event["from_node_id"] == "sender"
        assert event["tx_id"] == tx_id
        assert event["payload_len"] == 9  # len(b"test data")

    def test_collision_event(self) -> None:
        """Collision detection fires on_collision."""
        sim = Simulation("test")
        observer = RecordingObserver()

        # Three nodes: two transmitters at same position, one receiver
        sim.add_node("tx1", 0.0, 0.0, 0.0)
        sim.add_node("tx2", 0.0, 0.0, 0.0)  # Same position as tx1
        sim.add_node("rx", 100.0, 0.0, 0.0)
        sim.add_observer(observer)
        observer.events.clear()

        # Both transmit simultaneously
        tx1_id = sim.start_transmission("tx1", b"aaa")
        tx2_id = sim.start_transmission("tx2", b"bbb")
        # Receiver listens
        sim.start_receive("rx", timeout_ms=5000)
        # Advance to middle of transmission (both still in flight)
        sim.advance_to(100_000)

        # Check for collision while TXs are still in flight
        result = sim.get_rx_result("rx")
        assert result is None  # Collision
        assert sim.get_rx_result("rx") is None  # Same collision on the next poll

        collision_events = [e for e in observer.events if e[0] == "collision"]
        assert len(collision_events) == 1
        event = collision_events[0][1]
        assert event["node_id"] == "rx"
        assert set(event["tx_ids"]) == {tx1_id, tx2_id}

    def test_observer_exception_does_not_crash_simulation(self) -> None:
        """An observer that raises doesn't crash the simulation."""
        sim = Simulation("test")
        exploding = ExplodingObserver()
        recording = RecordingObserver()

        sim.add_observer(exploding)
        sim.add_observer(recording)

        # Should not raise despite exploding observer
        sim.add_node("n1", 0.0, 0.0, 0.0)

        # Recording observer should still have received the event
        assert len(recording.events) == 1
        assert recording.events[0][0] == "node_added"
