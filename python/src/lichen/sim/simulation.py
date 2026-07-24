# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Core simulation engine for the LICHEN simulator.

This module provides the Simulation class that orchestrates simulated nodes,
manages time progression, and coordinates transmissions through the radio
medium.
"""

from __future__ import annotations

import hashlib
import json
import random
import time
from collections.abc import Callable
from enum import Enum, auto
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from lichen.sim.events import (
    Event,
    EventQueue,
    ObserverRegistry,
    RxTimeoutEvent,
    SimulationObserver,
    TxEndEvent,
    TxStartDelayedEvent,
)
from lichen.sim.medium import Medium
from lichen.sim.metrics import Metrics
from lichen.sim.node import NodeState, SimNode

if TYPE_CHECKING:
    from lichen.sim.chaos import ChaosEngine

logger = structlog.get_logger()
DEBUG_ENABLED = False


def enable_debug() -> None:
    """Enable enhanced simulation debugging for newly created simulations."""
    global DEBUG_ENABLED
    DEBUG_ENABLED = True


def disable_debug() -> None:
    """Disable enhanced simulation debugging for newly created simulations."""
    global DEBUG_ENABLED
    DEBUG_ENABLED = False


def is_debug_enabled() -> bool:
    """Return whether enhanced simulation debugging is enabled."""
    return DEBUG_ENABLED


class TimeMode(Enum):
    """Time advancement mode for the simulation."""

    BARRIER_SYNC = auto()
    REALTIME = auto()


class Simulation:
    """Core simulation engine that orchestrates nodes and events.

    The Simulation manages a collection of SimNodes, an EventQueue for
    time-ordered events, and a Medium for radio propagation. It supports
    two time modes:

    - BARRIER_SYNC: Deterministic mode where time only advances when all
      connected nodes are blocked (in RX_WAIT state). This ensures
      reproducible behavior for testing.

    - REALTIME: Time advances with the wall clock.

    Attributes:
        id: Unique identifier for this simulation instance.
        time_mode: The time advancement mode.
        medium: The radio medium for propagation simulation.
        event_queue: Priority queue of simulation events.
    """

    def __init__(
        self,
        sim_id: str,
        time_mode: TimeMode = TimeMode.BARRIER_SYNC,
        chaos_engine: ChaosEngine | None = None,
        seed: int | None = None,
        jitter_min_us: int = 0,
        jitter_max_us: int = 0,
    ) -> None:
        """Initialize a new simulation.

        Args:
            sim_id: Unique identifier for this simulation.
            time_mode: Time advancement mode. Defaults to BARRIER_SYNC.
            chaos_engine: Optional ChaosEngine for applying network fault rules.
            seed: Optional seed for the simulation's random number generator.
                Two simulations created with the same seed draw the same random
                sequence, making probabilistic runs (e.g. chaos loss) reproducible.
            jitter_min_us: Minimum TX jitter in microseconds. Defaults to 0.
            jitter_max_us: Maximum TX jitter in microseconds. Defaults to 0
                (disabled). Set to a positive value to enable TX jitter.
        """
        self._id = sim_id
        self._time_mode = time_mode
        self._current_time_us = 0
        self._nodes: dict[str, SimNode] = {}
        self._gateways: dict[str, dict[str, Any]] = {}
        self._medium = Medium()
        self._event_queue = EventQueue()
        self._pending_rx_timeouts: dict[str, int] = {}  # node_id -> timeout_time_us
        self._active_transmissions: dict[str, str] = {}  # node_id -> transmission_id
        self._chaos_engine = chaos_engine
        self._metrics = Metrics()
        self._seed = seed
        self._rng = random.Random(seed)
        self._observers = ObserverRegistry()
        self._debug_enabled = DEBUG_ENABLED
        if jitter_min_us < 0 or jitter_max_us < 0:
            raise ValueError(
                f"jitter values must be non-negative, got min={jitter_min_us} max={jitter_max_us}"
            )
        if jitter_max_us > 0 and jitter_min_us > jitter_max_us:
            raise ValueError(
                f"jitter_min_us ({jitter_min_us}) must be <= jitter_max_us ({jitter_max_us})"
            )
        self._jitter_min_us = jitter_min_us
        self._jitter_max_us = jitter_max_us
        self._realtime_epoch_us: int = time.monotonic_ns() // 1000

    def enable_debug(self) -> None:
        """Enable enhanced debugging for this simulation instance."""
        self._debug_enabled = True

    def disable_debug(self) -> None:
        """Disable enhanced debugging for this simulation instance."""
        self._debug_enabled = False

    @property
    def debug_enabled(self) -> bool:
        """Return whether enhanced debugging is enabled for this simulation."""
        return self._debug_enabled

    @property
    def id(self) -> str:
        """Return the simulation identifier."""
        return self._id

    @property
    def current_time_us(self) -> int:
        """Return the current simulation time in microseconds."""
        return self._current_time_us

    def _debug_log(self, event: str, **fields: object) -> None:
        """Emit simulation diagnostics only when debugging is enabled."""
        if self._debug_enabled:
            logger.debug(event, **fields)

    @property
    def time_mode(self) -> TimeMode:
        """Return the time advancement mode."""
        return self._time_mode

    @property
    def medium(self) -> Medium:
        """Return the radio medium."""
        return self._medium

    @property
    def event_queue(self) -> EventQueue:
        """Return the event queue."""
        return self._event_queue

    @property
    def metrics(self) -> Metrics:
        """Return the metrics collector for this simulation."""
        return self._metrics

    @property
    def seed(self) -> int | None:
        """Return the seed used for this simulation's RNG (None if unseeded)."""
        return self._seed

    @property
    def rng(self) -> random.Random:
        """Return the simulation's seedable random number generator.

        Simulation components requiring randomness should draw from this
        generator (rather than the global :mod:`random`) so that runs are
        reproducible when a seed is set.
        """
        return self._rng

    def reseed(self, seed: int | None) -> None:
        """Reset the RNG to a new seed, restoring reproducible state."""
        self._seed = seed
        self._rng = random.Random(seed)

    @property
    def jitter_min_us(self) -> int:
        """Return the minimum TX jitter in microseconds."""
        return self._jitter_min_us

    @property
    def jitter_max_us(self) -> int:
        """Return the maximum TX jitter in microseconds."""
        return self._jitter_max_us

    def calculate_tx_jitter(self) -> int:
        """Calculate a random TX jitter delay.

        Returns a uniformly distributed random value in the range
        [jitter_min_us, jitter_max_us] using the simulation's seedable RNG.

        Returns:
            Jitter delay in microseconds.
        """
        return self._rng.randint(self._jitter_min_us, self._jitter_max_us)

    @property
    def chaos_engine(self) -> ChaosEngine | None:
        """Return the chaos engine, if any."""
        return self._chaos_engine

    @chaos_engine.setter
    def chaos_engine(self, engine: ChaosEngine | None) -> None:
        """Set the chaos engine."""
        self._chaos_engine = engine

    def add_observer(self, observer: SimulationObserver) -> None:
        """Register an observer for simulation events.

        Observers receive callbacks for TX/RX, collisions, and node lifecycle.
        See SimulationObserver protocol for available callbacks.

        Args:
            observer: Observer to register. Duplicates are silently ignored.
        """
        self._observers.add(observer)

    def remove_observer(self, observer: SimulationObserver) -> None:
        """Unregister an observer.

        Args:
            observer: Observer to remove. No-op if not registered.
        """
        self._observers.remove(observer)

    def add_node(self, node_id: str, x: float, y: float, z: float) -> SimNode:
        """Create and add a new node to the simulation.

        Args:
            node_id: Unique identifier for the node.
            x: X coordinate in meters.
            y: Y coordinate in meters.
            z: Z coordinate in meters (altitude).

        Returns:
            The newly created SimNode.

        Raises:
            ValueError: If a node with this ID already exists.
        """
        if node_id in self._nodes:
            raise ValueError(f"Node '{node_id}' already exists")

        node = SimNode(id=node_id, position=(x, y, z), connected=True)
        self._nodes[node_id] = node

        # Notify observers (after node is fully added)
        self._observers.notify(
            "on_node_added",
            sim_id=self._id,
            node_id=node_id,
            x=x,
            y=y,
            z=z,
        )

        return node

    def add_gateway(
        self,
        gateway_id: str,
        x: float,
        y: float,
        z: float,
        slot_range: tuple[int, int] = (0, 10),
    ) -> SimNode:
        if gateway_id in self._nodes:
            raise ValueError(f"Node '{gateway_id}' already exists")
        node = SimNode(id=gateway_id, position=(x, y, z), connected=True)
        self._nodes[gateway_id] = node
        self._gateways[gateway_id] = {
            "node": node,
            "slot_range": slot_range,
            "backbone_id": f"bb-{gateway_id}",
            "owned_nodes": set(),
            "negotiation_state": "idle",
        }
        self._observers.notify(
            "on_node_added",
            sim_id=self._id,
            node_id=gateway_id,
            x=x,
            y=y,
            z=z,
        )
        return node

    def remove_node(self, node_id: str) -> None:
        """Remove a node from the simulation.

        Disconnects the node, removes pending events, and removes it from
        the simulation. Silently ignores if node doesn't exist.

        Args:
            node_id: ID of the node to remove.
        """
        node = self._nodes.pop(node_id, None)
        if node is None:
            return

        node.disconnect()
        self._pending_rx_timeouts.pop(node_id, None)
        self._active_transmissions.pop(node_id, None)
        self._event_queue.remove_events_for_node(node_id)

        # Notify observers (after cleanup complete)
        self._observers.notify(
            "on_node_removed",
            sim_id=self._id,
            node_id=node_id,
        )

    def get_node(self, node_id: str) -> SimNode | None:
        """Get a node by ID.

        Args:
            node_id: ID of the node to retrieve.

        Returns:
            The SimNode, or None if not found.
        """
        return self._nodes.get(node_id)

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

    def process_next_event(self) -> Event | None:
        """Pop and process the next event from the queue.

        Returns:
            The processed event, or None if the queue was empty.
        """
        if self._event_queue.is_empty():
            return None

        event = self._event_queue.pop()
        self._current_time_us = event.time_us
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
        node = self._nodes.get(event.node_id)
        if node is None or not node.connected:
            return

        self._debug_log(
            "tx_start_delayed",
            sim_id=self._id,
            node_id=event.node_id,
            payload_len=len(event.payload),
            node_state=node.state.name if node is not None else None,
            queue_size=len(self._event_queue),
            jitter_enabled=True,
            current_time=self._current_time_us,
        )

        self._do_start_transmission(
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
        self._debug_log(
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
        self._debug_log(
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
        barrier, and transmitting nodes must not either — their TxEndEvent is
        exactly what advancing fires. Callers (the RX wait loop) check for a
        deliverable packet *before* advancing, so advancing can never skip an
        in-range reception; it only drives transmit completion and RX timeouts.

        Returns:
            True if time was advanced, False otherwise.
        """
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

        blocked_info = self._get_blocked_node_info()
        self._debug_log(
            "time_advance",
            sim_id=self._id,
            from_us=self._current_time_us,
            to_us=next_event.time_us,
            queue_size=len(self._event_queue),
            pending_rx_timeouts=len(self._pending_rx_timeouts),
            **blocked_info,
        )
        self.process_next_event()
        return True

    def start_transmission(self, node_id: str, payload: bytes, channel: int = 0) -> str:
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node '{node_id}' does not exist")
        if not node.connected:
            raise ValueError(f"Node '{node_id}' is not connected")
        if node.hop_schedule and len(node.hop_schedule) > 0:
            current_sfn = node.tdma_scheduler.clock.sfn
            channel = node.synchronized_hop_channel(current_sfn)
        elif channel == 0:
            channel = node.current_channel
        if self._jitter_max_us > 0:
            jitter = self.calculate_tx_jitter()
            delayed_event = TxStartDelayedEvent(
                time_us=self._current_time_us + jitter,
                node_id=node_id,
                payload=payload,
                tx_power_dbm=node.tx_power_dbm,
                position=node.position,
                channel=channel,
            )
            self._event_queue.push(delayed_event)
            self._debug_log(
                "tx_delayed",
                sim_id=self._id,
                node_id=node_id,
                jitter_us=jitter,
                fire_at_us=delayed_event.time_us,
            )
            return ""
        return self._do_start_transmission(
            node_id=node_id,
            payload=payload,
            tx_power_dbm=node.tx_power_dbm,
            position=node.position,
            channel=channel,
        )

    def _do_start_transmission(
        self,
        node_id: str,
        payload: bytes,
        tx_power_dbm: int,
        position: tuple[float, float, float],
        channel: int = 0,
    ) -> str:
        """Execute the actual transmission start in the medium.

        This is the core TX logic, called either immediately from
        start_transmission() or later via TxStartDelayedEvent.
        Integrates synchronized hopping (CCP-12) using node.synchronized_hop_channel(current_sfn)
        when hop_schedule present; passes to medium; updates node state without conflicting
        current_channel for hop nodes. Removes dead code.

        Args:
            node_id: ID of the transmitting node.
            payload: Raw bytes to transmit.
            tx_power_dbm: Transmit power in dBm.
            position: Node position (x, y, z) in meters.
            channel: Channel from synchronized hopping (overrides
                node.current_channel where necessary).

        Returns:
            The transmission ID.
        """
        node = self._nodes.get(node_id)
        if node is not None and not node.tdma_scheduler.is_tx_allowed(self._current_time_us):
            return ""
        if node is not None and node.hop_schedule and len(node.hop_schedule) > 0:
            current_sfn = node.tdma_scheduler.clock.sfn
            channel = node.synchronized_hop_channel(current_sfn)
        previous_tx_id = self._active_transmissions.get(node_id)
        if previous_tx_id is not None:
            self._medium.end_tx(previous_tx_id)
        if node is not None:
            node.state = NodeState.TX
            if (
                not (node.hop_schedule and len(node.hop_schedule) > 0)
                and channel != node.current_channel
            ):
                node.current_channel = channel

        tx = self._medium.start_tx(
            node_id=node_id,
            payload=payload,
            tx_power_dbm=tx_power_dbm,
            position=position,
            time_us=self._current_time_us,
            channel=channel,
        )

        self._active_transmissions[node_id] = tx.id
        self._metrics.record_transmission_start(tx.id, tx.start_time_us)

        # Record per-node metrics
        if node is not None:
            packet_hash = hashlib.sha256(payload).digest()[:16].hex()
            node.metrics.record_tx(payload, packet_hash)

        # Notify observers
        self._observers.notify(
            "on_tx_start",
            sim_id=self._id,
            node_id=node_id,
            tx_id=tx.id,
            payload_len=len(payload),
            time_us=tx.start_time_us,
        )

        end_event = TxEndEvent(
            time_us=tx.end_time_us,
            node_id=node_id,
            transmission_id=tx.id,
        )
        self._event_queue.push(end_event)

        tx_log = {
            "sim_id": self._id,
            "node_id": node_id,
            "tx_id": tx.id,
            "payload_len": len(payload),
            "start_us": tx.start_time_us,
            "end_us": tx.end_time_us,
        }
        if self._debug_enabled:
            tx_log.update(
                node_state=node.state.name if node is not None else None,
                queue_size=len(self._event_queue),
                active_txs=len(self._active_transmissions),
            )
        self._debug_log("tx_start", **tx_log)

        return tx.id

    def start_receive(self, node_id: str, timeout_ms: int) -> None:
        """Start a receive operation on a node.

        Sets the node to RX_WAIT state and queues an RxTimeoutEvent.

        Args:
            node_id: ID of the receiving node.
            timeout_ms: Receive timeout in milliseconds.

        Raises:
            ValueError: If node doesn't exist or is not connected.
        """
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node '{node_id}' does not exist")
        if not node.connected:
            raise ValueError(f"Node '{node_id}' is not connected")

        node.state = NodeState.RX_WAIT

        timeout_us = self._current_time_us + (timeout_ms * 1000)
        self._pending_rx_timeouts[node_id] = timeout_us

        timeout_event = RxTimeoutEvent(
            time_us=timeout_us,
            node_id=node_id,
        )
        self._event_queue.push(timeout_event)
        self._debug_log("rx_start", sim_id=self._id, node_id=node_id, timeout_us=timeout_us)

    def enter_rx_mode(
        self,
        node_id: str,
        timeout_us: int,
        on_packet: Callable[[bytes, int, int], None],
        on_timeout: Callable[[], None],
        channel: int = 0,
    ) -> None:
        """Enter RX mode. Derives via node.synchronized_hop_channel for hop_schedule
        (CCP-12 rendezvous node.py:146). Sets current_channel only if needed.
        """
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node '{node_id}' does not exist")
        if not node.connected:
            raise ValueError(f"Node '{node_id}' is not connected")
        if node.hop_schedule and len(node.hop_schedule) > 0:
            current_sfn = node.tdma_scheduler.clock.sfn
            channel = node.synchronized_hop_channel(current_sfn)
        elif channel == 0:
            channel = node.current_channel
        node.state = NodeState.RX_WAIT
        if not (node.hop_schedule and len(node.hop_schedule) > 0):
            node.current_channel = channel
        node.rx_callbacks = (on_packet, on_timeout)
        timeout_time_us = self._current_time_us + timeout_us
        self._pending_rx_timeouts[node_id] = timeout_time_us
        timeout_event = RxTimeoutEvent(time_us=timeout_time_us, node_id=node_id)
        self._event_queue.push(timeout_event)
        self._debug_log(
            "enter_rx_mode",
            sim_id=self._id,
            node_id=node_id,
            timeout_us=timeout_time_us,
        )

    def exit_rx_mode(self, node_id: str) -> None:
        """Exit RX mode, cancel pending timeout.

        Args:
            node_id: ID of the node to exit RX mode.
        """
        node = self._nodes.get(node_id)
        if node is None:
            return

        node.state = NodeState.IDLE
        node.rx_callbacks = None
        self._pending_rx_timeouts.pop(node_id, None)
        # Remove pending RxTimeoutEvent for this node
        self._event_queue.remove_events_for_node(node_id)
        self._debug_log(
            "exit_rx_mode",
            sim_id=self._id,
            node_id=node_id,
        )

    def deliver_pending_packets(self) -> int:
        """Deliver packets to nodes in callback-based RX mode.

        All RX resolution, metrics (idempotent), collision handling, rx_success
        logging, and on_rx_success notification are unified in
        _get_rx_result_internal. This method only captures the callback and
        performs RX cleanup/state transition. Preserves exact polling vs
        callback behavior and test oracles (metrics.receptions==1,
        observer events len==1, logs emitted once).

        Returns:
            Number of packets delivered.
        """
        delivered = 0
        for node_id, node in list(self._nodes.items()):
            if node.state != NodeState.RX_WAIT or node.rx_callbacks is None:
                continue

            result = self._get_rx_result_internal(node_id)
            if result is not None:
                payload, rssi, snr, _, _ = result
                on_packet = node.rx_callbacks[0]
                # State cleanup must happen before callback (matches prior
                # behavior; prevents re-delivery or timeout firing).
                node.state = NodeState.IDLE
                node.rx_callbacks = None
                self._pending_rx_timeouts.pop(node_id, None)
                self._event_queue.remove_events_for_node(node_id)

                on_packet(payload, rssi, snr)
                delivered += 1

        return delivered

    def _get_rx_result_internal(self, node_id: str) -> tuple[bytes, int, int, str, str] | None:
        """Unified core RX logic. Uses node.synchronized_hop_channel (node.py:146)
        for medium channel when hop_schedule present (CCP-12 per
        ccp16-hop.json spec/02a-coordinated-capacity.md:120). Preserves oracles.

        - Medium candidates + chaos + latency filter + resolve_reception.
        - Collision: idempotent record_collision + log + observer (once).
        - Success: idempotent record_reception + node.record_rx + rx_success
          log (with debug fields) + on_rx_success observer.
        - Returns full 5-tuple on success or None. No node state change
          (callback path cleans up; polling path remains idempotent).
        """
        node = self._nodes.get(node_id)
        if node is None:
            return None

        if node.hop_schedule and len(node.hop_schedule) > 0:
            channel = node.synchronized_hop_channel()
        else:
            channel = node.current_channel
        candidates = self._medium.get_rx_candidates(
            rx_node_id=node_id,
            rx_position=node.position,
            time_us=self._current_time_us,
            channel=channel,
        )

        # Apply chaos rules to filter/modify candidates
        if self._chaos_engine is not None:
            filtered_candidates = []
            for candidate in candidates:
                result = self._chaos_engine.apply_all(
                    candidate=candidate,
                    rx_node_id=node_id,
                    rx_position=node.position,
                )
                if result is not None:
                    filtered_candidates.append(result)
            candidates = filtered_candidates

        # Drop candidates whose LatencyRule-added delivery delay hasn't elapsed.
        candidates = [
            c
            for c in candidates
            if c.added_latency_us == 0
            or self._current_time_us >= c.transmission.end_time_us + c.added_latency_us
        ]

        tx = self._medium.resolve_reception(candidates)
        if tx is None:
            if len(candidates) >= 2:
                tx_ids = [c.transmission.id for c in candidates]
                if self._metrics.record_collision(node_id, tx_ids):
                    self._debug_log(
                        "collision",
                        sim_id=self._id,
                        node_id=node_id,
                        time_us=self._current_time_us,
                        tx_ids=tx_ids,
                    )
                    self._observers.notify(
                        "on_collision",
                        sim_id=self._id,
                        node_id=node_id,
                        tx_ids=tx_ids,
                        time_us=self._current_time_us,
                    )
            return None

        # Record simulation-wide + per-node metrics. Idempotent for polling
        # and callback paths.
        self._metrics.record_reception(node_id, tx.id, self._current_time_us)
        packet_hash = hashlib.sha256(tx.payload).digest()[:16].hex()
        node.metrics.record_rx(tx.payload, packet_hash, from_peer=tx.source_node_id)

        for candidate in candidates:
            if candidate.transmission is tx:
                rssi = int(candidate.rssi)
                snr = int(candidate.snr)
                rx_log = {
                    "sim_id": self._id,
                    "node_id": node_id,
                    "tx_id": tx.id,
                    "payload_len": len(tx.payload),
                    "rssi": rssi,
                    "snr": snr,
                    "time_us": self._current_time_us,
                    "from_node_id": tx.source_node_id,
                    "node_state": node.state.name,
                    "queue_size": len(self._event_queue),
                    "candidate_count": len(candidates),
                    "pending_rx_timeouts": len(self._pending_rx_timeouts),
                }
                self._debug_log("rx_success", **rx_log)
                self._observers.notify(
                    "on_rx_success",
                    sim_id=self._id,
                    node_id=node_id,
                    tx_id=tx.id,
                    from_node_id=tx.source_node_id,
                    payload_len=len(tx.payload),
                    rssi=rssi,
                    snr=snr,
                    time_us=self._current_time_us,
                )
                return (
                    tx.payload,
                    rssi,
                    snr,
                    tx.id,
                    tx.source_node_id,
                )

        return None

    def get_rx_result(self, node_id: str) -> tuple[bytes, int, int] | None:
        """Polling path for RX result (used by tests/examples).

        Thin wrapper that raises on missing node (legacy contract) and
        extracts 3-tuple. All heavy lifting, metrics, logging, observers,
        and deduplication now live in _get_rx_result_internal. No duplication
        remains. Behavior identical for repeated polls (idempotent metrics,
        single log/notify per test oracle).

        Args:
            node_id: ID of the receiving node.

        Returns:
            (payload, rssi, snr) or None.

        Raises:
            ValueError: If node doesn't exist.
        """
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node '{node_id}' does not exist")

        result = self._get_rx_result_internal(node_id)
        if result is None:
            return None
        payload, rssi, snr, _, _ = result
        return payload, rssi, snr

    def get_connected_node_count(self) -> int:
        """Return the number of connected nodes.

        Returns:
            Count of nodes where connected is True.
        """
        return sum(1 for n in self._nodes.values() if n.connected)

    def _get_blocked_node_info(self) -> dict[str, int]:
        """Return detailed blocked node info for debug logging.
        Returns counts of total, connected, rx_wait, tx, idle, blocked nodes
        when debug is enabled (blocked = rx_wait count for barrier sync).
        """
        if not self._debug_enabled:
            return {}
        connected_nodes = [n for n in self._nodes.values() if n.connected]
        rx_wait = sum(1 for n in connected_nodes if n.state == NodeState.RX_WAIT)
        return {
            "total": len(self._nodes),
            "connected": len(connected_nodes),
            "rx_wait": rx_wait,
            "tx": sum(1 for n in connected_nodes if n.state == NodeState.TX),
            "idle": sum(1 for n in connected_nodes if n.state == NodeState.IDLE),
            "blocked": rx_wait,
        }

    def get_all_nodes(self) -> list[SimNode]:
        """Return all nodes in the simulation.

        Returns:
            List of all SimNode objects.
        """
        return list(self._nodes.values())

    def export_metrics(self, path: Path | str) -> None:
        """Export per-node metrics as JSON for analysis.

        Writes a JSON file containing per-node telemetry metrics including
        TX/RX counts, byte totals, unique peers seen, and packet hashes
        (32-char lowercase hex of first 16 SHA256 bytes). Matches Rust
        hetero_node.rs METRICS export for cross-impl interop.

        Args:
            path: Path to the output JSON file.
        """
        path = Path(path)
        metrics = {node_id: node.metrics.to_dict() for node_id, node in self._nodes.items()}
        path.write_text(json.dumps(metrics, indent=2))
