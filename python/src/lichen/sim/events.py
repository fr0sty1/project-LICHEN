# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Event queue system for the LICHEN simulator.

Provides a priority queue of simulation events ordered by time, with
tie-breaking by insertion order to ensure deterministic behavior.

Also provides the SimulationObserver protocol for real-time event
notifications (used by WebSocket, TUI, etc.).
"""

from __future__ import annotations

import heapq
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Event:
    """Base class for simulation events.

    All times are in microseconds (int) for precision without floating-point issues.
    """

    time_us: int


@dataclass(frozen=True)
class TxStartEvent(Event):
    """A node begins transmitting a packet."""

    node_id: str
    transmission_id: str


@dataclass(frozen=True)
class TxEndEvent(Event):
    """A node finishes transmitting a packet."""

    node_id: str
    transmission_id: str


@dataclass(frozen=True)
class TxStartDelayedEvent(Event):
    """A delayed transmission start (after jitter delay)."""

    node_id: str
    payload: bytes
    tx_power_dbm: int
    position: tuple[float, float, float]


@dataclass(frozen=True)
class RxTimeoutEvent(Event):
    """A node's receive timeout expires."""

    node_id: str


@dataclass(order=True)
class _PrioritizedEvent:
    """Wrapper for heap ordering: (time_us, insertion_order, event)."""

    time_us: int
    insertion_order: int
    event: Event = field(compare=False)


class EventQueue:
    """Priority queue of simulation events ordered by time.

    Events are sorted by time_us, with ties broken by insertion order
    (FIFO for events at the same time). Uses a heap for O(log n) push/pop.
    """

    def __init__(self) -> None:
        self._heap: list[_PrioritizedEvent] = []
        self._counter: int = 0

    def push(self, event: Event) -> None:
        """Add an event to the queue."""
        entry = _PrioritizedEvent(
            time_us=event.time_us,
            insertion_order=self._counter,
            event=event,
        )
        self._counter += 1
        heapq.heappush(self._heap, entry)

    def pop(self) -> Event:
        """Remove and return the earliest event.

        Raises:
            IndexError: If the queue is empty.
        """
        if not self._heap:
            raise IndexError("pop from empty EventQueue")
        entry = heapq.heappop(self._heap)
        return entry.event

    def peek(self) -> Event | None:
        """Return the earliest event without removing it, or None if empty."""
        if not self._heap:
            return None
        return self._heap[0].event

    def is_empty(self) -> bool:
        """Return True if the queue has no events."""
        return len(self._heap) == 0

    def __len__(self) -> int:
        """Return the number of events in the queue."""
        return len(self._heap)

    def __iter__(self) -> Iterator[Event]:
        """Iterate over events in time order without modifying the queue.

        Use :meth:`drain` if you want to consume events as you iterate.
        """
        for entry in sorted(self._heap):
            yield entry.event

    def drain(self) -> Iterator[Event]:
        """Yield events in time order, removing each from the queue.

        The queue is empty once the iterator is exhausted.
        """
        while self._heap:
            yield self.pop()

    def __repr__(self) -> str:
        return f"EventQueue(len={len(self)})"

    def remove_events_for_node(self, node_id: str) -> int:
        """Remove all events associated with a specific node.

        This is useful when a node is removed from the simulation to prevent
        orphan events from accumulating.

        Args:
            node_id: ID of the node whose events should be removed.

        Returns:
            Number of events removed.
        """
        original_len = len(self._heap)
        self._heap = [
            entry for entry in self._heap
            if not (hasattr(entry.event, "node_id") and entry.event.node_id == node_id)
        ]
        heapq.heapify(self._heap)
        return original_len - len(self._heap)


# -----------------------------------------------------------------------------
# Observer Protocol for Real-Time Event Notifications
# -----------------------------------------------------------------------------


@runtime_checkable
class SimulationObserver(Protocol):
    """Protocol for observing simulation events in real-time.

    Implementations receive callbacks for transmission, reception, collision,
    and node lifecycle events. Used by WebSocket handlers, TUI, and other
    real-time consumers.

    All methods are optional — implement only what you need. Methods that
    are not implemented will be skipped (duck typing via hasattr check).

    IMPORTANT: Implementations must not raise exceptions. The observer
    registry will catch and log exceptions, but misbehaving observers
    degrade system reliability.

    IMPORTANT: Implementations must not block. If you need to do I/O,
    schedule it asynchronously and return immediately.
    """

    def on_tx_start(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        payload_len: int,
        time_us: int,
    ) -> None:
        """Called when a node begins transmitting.

        Args:
            sim_id: Simulation identifier.
            node_id: Transmitting node ID.
            tx_id: Unique transmission identifier.
            payload_len: Size of payload in bytes.
            time_us: Simulation time in microseconds.
        """
        ...

    def on_tx_end(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        time_us: int,
    ) -> None:
        """Called when a transmission completes.

        Args:
            sim_id: Simulation identifier.
            node_id: Transmitting node ID.
            tx_id: Unique transmission identifier.
            time_us: Simulation time in microseconds.
        """
        ...

    def on_rx_success(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        from_node_id: str,
        payload_len: int,
        rssi: int,
        snr: int,
        time_us: int,
    ) -> None:
        """Called when a node successfully receives a packet.

        Args:
            sim_id: Simulation identifier.
            node_id: Receiving node ID.
            tx_id: Transmission identifier of received packet.
            from_node_id: ID of the transmitting node.
            payload_len: Size of received payload in bytes.
            rssi: Received signal strength in dBm.
            snr: Signal-to-noise ratio in dB (integer).
            time_us: Simulation time in microseconds.
        """
        ...

    def on_rx_timeout(
        self,
        sim_id: str,
        node_id: str,
        time_us: int,
    ) -> None:
        """Called when a receive operation times out.

        Args:
            sim_id: Simulation identifier.
            node_id: Receiving node ID.
            time_us: Simulation time in microseconds.
        """
        ...

    def on_collision(
        self,
        sim_id: str,
        node_id: str,
        tx_ids: list[str],
        time_us: int,
    ) -> None:
        """Called when a collision is detected at a receiver.

        Args:
            sim_id: Simulation identifier.
            node_id: Receiving node ID where collision occurred.
            tx_ids: List of transmission IDs that collided.
            time_us: Simulation time in microseconds.
        """
        ...

    def on_node_added(
        self,
        sim_id: str,
        node_id: str,
        x: float,
        y: float,
        z: float,
    ) -> None:
        """Called when a node is added to the simulation.

        Args:
            sim_id: Simulation identifier.
            node_id: New node ID.
            x: X coordinate in meters.
            y: Y coordinate in meters.
            z: Z coordinate (altitude) in meters.
        """
        ...

    def on_node_removed(
        self,
        sim_id: str,
        node_id: str,
    ) -> None:
        """Called when a node is removed from the simulation.

        Args:
            sim_id: Simulation identifier.
            node_id: Removed node ID.
        """
        ...


class ObserverRegistry:
    """Thread-safe registry for simulation observers.

    Provides safe iteration over observers with exception handling.
    Observers can be added/removed during iteration without causing
    errors (we copy the list before iterating).

    Defensive design:
    - Exceptions in observers are logged but don't propagate
    - Iteration uses a snapshot to allow concurrent modification
    - Duplicate observers are silently ignored
    - Removing non-existent observers is a no-op
    """

    def __init__(self) -> None:
        """Initialize an empty observer registry."""
        self._observers: list[SimulationObserver] = []

    def add(self, observer: SimulationObserver) -> None:
        """Register an observer.

        Args:
            observer: Observer to register. Duplicates are ignored.
        """
        if observer not in self._observers:
            self._observers.append(observer)
            logger.debug("observer_added", observer=type(observer).__name__)

    def remove(self, observer: SimulationObserver) -> None:
        """Unregister an observer.

        Args:
            observer: Observer to remove. No-op if not registered.
        """
        try:
            self._observers.remove(observer)
            logger.debug("observer_removed", observer=type(observer).__name__)
        except ValueError:
            pass  # Not in list, ignore silently

    def notify(
        self,
        method_name: str,
        **kwargs: object,
    ) -> None:
        """Call a method on all registered observers.

        Uses hasattr to check if observer implements the method (duck typing).
        Exceptions are caught and logged but do not propagate.

        Args:
            method_name: Name of the observer method to call.
            **kwargs: Arguments to pass to the method.
        """
        # Snapshot the list to allow modification during iteration
        # This is defensive: an observer's callback could add/remove observers
        observers = list(self._observers)

        for observer in observers:
            # Check if observer implements this method
            method = getattr(observer, method_name, None)
            if method is None or not callable(method):
                continue

            try:
                method(**kwargs)
            except Exception:
                # Log but don't crash — one bad observer shouldn't break others
                logger.exception(
                    "Observer %s.%s raised exception",
                    type(observer).__name__,
                    method_name,
                )

    def __len__(self) -> int:
        """Return number of registered observers."""
        return len(self._observers)

    def clear(self) -> None:
        """Remove all observers."""
        self._observers.clear()
