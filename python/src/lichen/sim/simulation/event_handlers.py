# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Event handling mixin for the simulation.

This module provides the EventHandlersMixin class that adds event processing
and time advancement operations to the simulation.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from lichen.sim.events import (
    Event,
    RxTimeoutEvent,
    TxEndEvent,
    TxStartDelayedEvent,
)
from lichen.sim.node import NodeState


class EventHandlersMixin:
    """Mixin providing event handling operations.

    This mixin adds methods for processing events and advancing simulation time.
    It requires the base class to have various simulation state attributes.
    """

    # Type hints for attributes from base class
    _id: str
    _time_mode: Any  # TimeMode
    _current_time_us: int
    _nodes: dict[str, Any]
    _medium: Any
    _event_queue: Any
    _pending_rx_timeouts: dict[str, int]
    _active_transmissions: dict[str, str]
    _observers: Any
    _debug_enabled: bool
    _realtime_epoch_us: int

    def advance_to(self, time_us: int) -> None:
        """Process all events up to the specified time.

        Processes events in time order until the event queue is empty
        or the next event is after time_us. Updates current_time_us
        to the target time.

        Args:
            time_us: Target simulation time in microseconds.

        Raises:
            ValueError: If time_us is less than current time.
        """
        if time_us < self._current_time_us:
            raise ValueError(f"Cannot advance backwards: {time_us} < {self._current_time_us}")

        while not self._event_queue.is_empty():
            next_event = self._event_queue.peek()
            if next_event is None or next_event.time_us > time_us:
                break
            self.process_next_event()

        self._current_time_us = time_us

        # Record dashboard metrics sample if interval has elapsed
        self._maybe_record_dashboard_sample(time_us)

    def process_next_event(self) -> Event | None:
        """Pop and process the next event from the queue.

        Returns:
            The processed event, or None if the queue was empty.
        """
        if self._event_queue.is_empty():
            return None

        event = self._event_queue.pop()
        self._current_time_us = event.time_us
        if self._debug_enabled:
            self._debug_log(  # type: ignore[attr-defined]
                "process_next_event",
                sim_id=self._id,
                event_type=event.__class__.__name__,
                event_time_us=event.time_us,
                queue_size=len(self._event_queue),
                **self._get_blocked_node_info(),  # type: ignore[attr-defined]
            )
        self._handle_event(event)
        return event

    def _handle_event(self, event: Event) -> None:
        """Handle a specific event type.

        Args:
            event: The event to handle.
        """
        match event:
            case TxStartDelayedEvent():
                self._handle_tx_start_delayed(event)
            case TxEndEvent():
                self._handle_tx_end(event)
            case RxTimeoutEvent():
                self._handle_rx_timeout(event)

    def _handle_tx_start_delayed(self, event: TxStartDelayedEvent) -> None:
        """Handle delayed transmission start event.

        Args:
            event: The TxStartDelayedEvent to handle.
        """
        node = self._nodes.get(event.node_id)
        if node is None or not node.connected:
            return

        self._debug_log(  # type: ignore[attr-defined]
            "tx_start_delayed",
            sim_id=self._id,
            node_id=event.node_id,
            payload_len=len(event.payload),
            node_state=node.state.name if node is not None else None,
            queue_size=len(self._event_queue),
            jitter_enabled=True,
            current_time=self._current_time_us,
        )

        self._do_start_transmission(  # type: ignore[attr-defined]
            node_id=event.node_id,
            payload=event.payload,
            tx_power_dbm=event.tx_power_dbm,
            position=event.position,
            channel=event.channel,
        )

    def _handle_tx_end(self, event: TxEndEvent) -> None:
        """Handle transmission end event.

        Args:
            event: The TxEndEvent to handle.
        """
        self._medium.end_tx(event.transmission_id)
        # Only clear node state for the node's *current* transmission. A stale
        # TxEndEvent from a transmission that was superseded by a later one
        # (half-duplex, see start_transmission) must not retire the new one.
        node = self._nodes.get(event.node_id)
        node_state = node.state.name if node is not None else None
        if self._active_transmissions.get(event.node_id) == event.transmission_id:
            if node is not None and node.state == NodeState.TX:
                node.state = NodeState.IDLE
                node_state = node.state.name
            self._active_transmissions.pop(event.node_id, None)
        self._debug_log(  # type: ignore[attr-defined]
            "tx_end",
            sim_id=self._id,
            node_id=event.node_id,
            tx_id=event.transmission_id,
            time_us=event.time_us,
            current_time_us=self._current_time_us,
            node_state=node_state,
            pending_txs=len(self._active_transmissions),
            event_queue_len=len(self._event_queue),
        )

        # Notify observers
        self._observers.notify(
            "on_tx_end",
            sim_id=self._id,
            node_id=event.node_id,
            tx_id=event.transmission_id,
            time_us=event.time_us,
        )

    def _handle_rx_timeout(self, event: RxTimeoutEvent) -> None:
        """Handle receive timeout event.

        Args:
            event: The RxTimeoutEvent to handle.
        """
        node = self._nodes.get(event.node_id)
        on_timeout: Callable[[], None] | None = None
        node_state = node.state.name if node is not None else None
        if node is not None and node.state == NodeState.RX_WAIT:
            # Capture callback before clearing state
            if node.rx_callbacks is not None:
                on_timeout = node.rx_callbacks[1]
            node.state = NodeState.IDLE
            node.rx_callbacks = None
            node_state = node.state.name
        self._pending_rx_timeouts.pop(event.node_id, None)
        self._debug_log(  # type: ignore[attr-defined]
            "rx_timeout",
            sim_id=self._id,
            node_id=event.node_id,
            time_us=event.time_us,
            current_time_us=self._current_time_us,
            node_state=node_state,
            pending_timeouts=len(self._pending_rx_timeouts),
            event_queue_len=len(self._event_queue),
        )

        # Notify observers
        self._observers.notify(
            "on_rx_timeout",
            sim_id=self._id,
            node_id=event.node_id,
            time_us=event.time_us,
        )

        # Call the timeout callback if set
        if on_timeout is not None:
            on_timeout()

    def maybe_advance_time(self) -> bool:
        """Attempt to advance time in BARRIER_SYNC mode.

        Time advances to the next event when at least one connected node is
        waiting on the simulation clock (RX_WAIT). Idle nodes do not hold the
        barrier, and transmitting nodes must not either -- their TxEndEvent is
        exactly what advancing fires. Callers (the RX wait loop) check for a
        deliverable packet *before* advancing, so advancing can never skip an
        in-range reception; it only drives transmit completion and RX timeouts.

        Returns:
            True if time was advanced, False otherwise.
        """
        from lichen.sim.simulation.base import TimeMode

        if self._time_mode == TimeMode.REALTIME:
            now_us = time.monotonic_ns() // 1000 - self._realtime_epoch_us
            if now_us <= self._current_time_us:
                return False
            self._current_time_us = now_us
            advanced = False
            while True:
                next_event = self._event_queue.peek()
                if next_event is None or next_event.time_us > self._current_time_us:
                    break
                self.process_next_event()
                advanced = True
            return advanced

        if self._time_mode != TimeMode.BARRIER_SYNC:
            return False

        connected_nodes = [n for n in self._nodes.values() if n.connected]
        if not connected_nodes:
            return False

        if not any(n.state == NodeState.RX_WAIT for n in connected_nodes):
            return False

        next_event = self._event_queue.peek()
        if next_event is None:
            return False

        self._debug_log(  # type: ignore[attr-defined]
            "time_advance",
            sim_id=self._id,
            from_us=self._current_time_us,
            to_us=next_event.time_us,
            queue_size=len(self._event_queue),
            pending_rx_timeouts=len(self._pending_rx_timeouts),
            **self._get_blocked_node_info(),  # type: ignore[attr-defined]
        )
        self.process_next_event()
        return True

    def _maybe_record_dashboard_sample(self, time_us: int) -> None:
        """Record a dashboard metrics sample if the sampling interval has elapsed.

        This is called during time advancement to capture periodic snapshots
        of key metrics for real-time dashboard visualization.

        Args:
            time_us: Current simulation time in microseconds.
        """
        # Access metrics from base class
        metrics = getattr(self, "_metrics", None)
        if metrics is None:
            return

        sample = metrics.record_dashboard_sample(time_us)
        if sample is not None:
            # Notify observers to broadcast the sample over WebSocket
            self._observers.notify(
                "on_metrics_sample",
                sim_id=self._id,
                time_us=sample.time_us,
                delivery_rate=sample.delivery_rate,
                collision_rate=sample.collision_rate,
                duty_cycle=sample.duty_cycle,
                transmissions=sample.transmissions,
                receptions=sample.receptions,
                collisions=sample.collisions,
            )
