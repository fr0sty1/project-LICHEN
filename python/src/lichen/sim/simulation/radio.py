# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Radio operations mixin for the simulation.

This module provides the RadioMixin class that adds transmission and
reception operations to the simulation.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING, Any, NamedTuple

from lora_medium import GilbertElliottRule

from lichen.sim.events import (
    DelayedRxReadyEvent,
    Event,
    RxTimeoutEvent,
    TxEndEvent,
    TxStartDelayedEvent,
)
from lichen.sim.node import NodeState

if TYPE_CHECKING:
    from lora_medium import ChaosEngine


class _DelayedRx(NamedTuple):
    """Pre-chaos RX candidate held only until end_time_us + added_latency_us."""

    candidate: Any
    channel: int
    expire_us: int


class _GeLinkState:
    """Duck-typed Gilbert-Elliott per-link Markov bit (in_bad_state)."""

    __slots__ = ("in_bad_state",)

    def __init__(self, in_bad_state: bool = False) -> None:
        self.in_bad_state = in_bad_state


class RadioMixin:
    """Mixin providing radio transmission and reception operations.

    This mixin adds methods for starting transmissions, entering RX mode,
    and processing received packets.
    """

    # Type hints for attributes from base class
    _id: str
    _current_time_us: int
    _nodes: dict[str, Any]
    _medium: Any
    _event_queue: Any
    _pending_rx_timeouts: dict[str, int]
    _active_transmissions: dict[str, str]
    _chaos_engine: ChaosEngine | None
    _metrics: Any
    _rng: Any
    _observers: Any
    _debug_enabled: bool
    _jitter_min_us: int
    _jitter_max_us: int
    _density_aware_startup: bool
    _listen_period_us: int
    # (rx_node_id, tx_id) -> original candidate held until expire_us
    _delayed_rx: dict[tuple[str, str], _DelayedRx]
    # Fail-closed live chaos drops; blocks re-stash until the TX is gone.
    _dropped_rx: set[tuple[str, str]]
    # Gilbert-Elliott survival per (rx, tx, rule.id); True means the packet lived.
    _ge_survived: dict[tuple[str, str, str], bool]
    # Burst Markov bit per (source, dest, rule.id); survives TxEnd.
    _ge_link_states: dict[tuple[str, str, str], bool]
    # Receivers currently inside a collision overlap epoch: rx -> tx ids.
    _collision_open: dict[str, set[str]]
    # Polling RX captured at DelayedRxReady before a same-tick timeout.
    _pending_poll_rx: dict[str, tuple[bytes, int, int, str, str]]

    def start_transmission(self, node_id: str, payload: bytes, channel: int = 0) -> str:
        """Start a transmission from a node.

        Args:
            node_id: ID of the transmitting node.
            payload: Raw bytes to transmit.
            channel: Channel number (may be overridden by hop schedule).

        Returns:
            The transmission ID, or empty string if delayed.

        Raises:
            ValueError: If node doesn't exist or is not connected.
        """
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node '{node_id}' does not exist")
        if not node.connected:
            raise ValueError(f"Node '{node_id}' is not connected")
        channel = node.get_hop_channel()

        delay_us = 0
        if self._density_aware_startup and not node.started:
            listen_us = 0
            if self._listen_period_us > 0:
                listen_us = int(self._rng.uniform(0, self._listen_period_us))
            if listen_us > 0:
                delay_us = listen_us
            else:
                delay_us = self.calculate_startup_delay(node)  # type: ignore[attr-defined]
                node.started = True
            self._debug_log(  # type: ignore[attr-defined]
                "density_aware_startup_delay",
                sim_id=self._id,
                node_id=node_id,
                heard_count=len(node.heard_set),
                listen_us=listen_us,
                delay_us=delay_us,
            )
        elif self._jitter_max_us > 0:
            delay_us = self.calculate_tx_jitter()  # type: ignore[attr-defined]

        if delay_us > 0:
            delayed_event = TxStartDelayedEvent(
                time_us=self._current_time_us + delay_us,
                node_id=node_id,
                payload=payload,
                tx_power_dbm=node.tx_power_dbm,
                position=node.position,
                channel=channel,
            )
            self._event_queue.push(delayed_event)
            self._debug_log(  # type: ignore[attr-defined]
                "tx_delayed",
                sim_id=self._id,
                node_id=node_id,
                delay_us=delay_us,
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
        Integrates synchronized hopping (CCP-12) using node.get_hop_channel(current_sfn)
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
        if node is not None:
            # Radiate from the antenna at TX instant, not the listen/jitter snapshot.
            channel = node.get_hop_channel()
            position = node.position

        # Probe the medium before half-duplex teardown so a duty-cycle
        # reject cannot abort a live TX or destroy an RX window.
        tx = self._medium.start_tx(
            node_id=node_id,
            payload=payload,
            tx_power_dbm=tx_power_dbm,
            position=position,
            time_us=self._current_time_us,
            channel=channel,
        )
        if tx is None:
            return ""

        previous_tx_id = self._active_transmissions.get(node_id)
        if previous_tx_id is not None:
            self._medium.end_tx(previous_tx_id)
            self._drop_delayed_rx_for_tx(previous_tx_id)
        # Half-duplex: TX ends this node's RX window without deleting
        # TxEndEvent / TxStartDelayedEvent or other receivers' stash.
        self._pending_rx_timeouts.pop(node_id, None)
        self._cancel_rx_timeout_events(node_id)
        self._drop_delayed_rx_for_receiver(node_id)
        self._pending_poll_rx_map().pop(node_id, None)
        if node is not None:
            node.rx_callbacks = None
            node.state = NodeState.TX
            if (
                not (node.hop_schedule and len(node.hop_schedule) > 0)
                and channel != node.current_channel
            ):
                node.current_channel = channel

        self._active_transmissions[node_id] = tx.id
        self._metrics.record_transmission_start(tx.id, tx.start_time_us)

        # Compute actual airtime for duty cycle tracking
        airtime_us = tx.end_time_us - tx.start_time_us

        # Record per-node metrics with airtime for duty cycle deduction
        if node is not None:
            packet_hash = hashlib.sha256(payload).digest()[:16].hex()
            node.metrics.record_tx(payload, packet_hash, airtime_us=airtime_us)

        # Notify observers
        self._observers.notify(
            "on_tx_start",
            sim_id=self._id,
            node_id=node_id,
            tx_id=tx.id,
            payload_len=len(payload),
            time_us=tx.start_time_us,
        )

        # Notify propagation visualization observer with position and range
        max_range_m = self._medium.propagation.max_range(tx_power_dbm)
        self._observers.notify(
            "on_tx_propagation",
            sim_id=self._id,
            node_id=node_id,
            tx_id=tx.id,
            x=position[0],
            y=position[1],
            z=position[2],
            max_range_m=max_range_m,
            duration_us=airtime_us,
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
        self._debug_log("tx_start", **tx_log)  # type: ignore[attr-defined]

        # LatencyRule eligibility is end_time_us + added_us, after TxEndEvent.
        self._stash_delayed_rx_candidates(tx)
        self._record_startup_heard(tx)

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

        self._cancel_rx_timeout_events(node_id)
        self._pending_poll_rx_map().pop(node_id, None)
        node.state = NodeState.RX_WAIT

        timeout_us = self._current_time_us + (timeout_ms * 1000)
        self._pending_rx_timeouts[node_id] = timeout_us

        timeout_event = RxTimeoutEvent(
            time_us=timeout_us,
            node_id=node_id,
        )
        self._event_queue.push(timeout_event)
        self._debug_log(  # type: ignore[attr-defined]
            "rx_start", sim_id=self._id, node_id=node_id, timeout_us=timeout_us
        )

    def enter_rx_mode(
        self,
        node_id: str,
        timeout_us: int,
        on_packet: Callable[[bytes, int, int], None],
        on_timeout: Callable[[], None],
        channel: int = 0,
    ) -> None:
        """Enter RX mode. Derives via node.get_hop_channel for hop_schedule
        (CCP-12 rendezvous node.py:146). Sets current_channel only if needed.
        """
        node = self._nodes.get(node_id)
        if node is None:
            raise ValueError(f"Node '{node_id}' does not exist")
        if not node.connected:
            raise ValueError(f"Node '{node_id}' is not connected")
        # In BARRIER_SYNC mode, a node's TxEndEvent may not have fired yet even
        # though the TX has been received by others. Check if the TX has already
        # been delivered (recorded as a reception) and clear the stale entry.
        # This preserves half-duplex for physically ongoing TXs while allowing
        # bidirectional communication after logical completion.
        tx_id = self._active_transmissions.get(node_id)
        if tx_id is not None:
            # Check if this TX has been received by anyone - if so, it's done
            if self._metrics.has_any_reception_for_tx(tx_id):
                self._active_transmissions.pop(node_id, None)
                self._medium.end_tx(tx_id)
                self._drop_delayed_rx_for_tx(tx_id)
        channel = node.get_hop_channel()
        self._cancel_rx_timeout_events(node_id)
        self._pending_poll_rx_map().pop(node_id, None)
        node.state = NodeState.RX_WAIT
        if not (node.hop_schedule and len(node.hop_schedule) > 0):
            node.current_channel = channel
        node.rx_callbacks = (on_packet, on_timeout)
        timeout_time_us = self._current_time_us + timeout_us
        self._pending_rx_timeouts[node_id] = timeout_time_us
        timeout_event = RxTimeoutEvent(time_us=timeout_time_us, node_id=node_id)
        self._event_queue.push(timeout_event)
        self._debug_log(  # type: ignore[attr-defined]
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
        self._pending_poll_rx_map().pop(node_id, None)
        self._drop_delayed_rx_for_receiver(node_id)
        self._cancel_rx_timeout_events(node_id)
        self._debug_log(  # type: ignore[attr-defined]
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
                self._cancel_rx_timeout_events(node_id)

                on_packet(payload, rssi, snr)
                delivered += 1

        return delivered

    def _delayed_rx_map(self) -> dict[tuple[str, str], _DelayedRx]:
        """Return the delayed-RX stash, creating it on first use."""
        delayed: dict[tuple[str, str], _DelayedRx] | None = getattr(self, "_delayed_rx", None)
        if delayed is None:
            delayed = {}
            self._delayed_rx = delayed
        return delayed

    def _dropped_rx_set(self) -> set[tuple[str, str]]:
        """Return the live-drop tombstone set, creating it on first use."""
        dropped: set[tuple[str, str]] | None = getattr(self, "_dropped_rx", None)
        if dropped is None:
            dropped = set()
            self._dropped_rx = dropped
        return dropped

    def _ge_cache(self) -> dict[tuple[str, str, str], bool]:
        """Return the Gilbert-Elliott survival cache, creating it on first use."""
        cache: dict[tuple[str, str, str], bool] | None = getattr(self, "_ge_survived", None)
        if cache is None:
            cache = {}
            self._ge_survived = cache
        return cache

    def _ge_link_states_map(self) -> dict[tuple[str, str, str], bool]:
        """Return per-(src, dst, rule) GE burst bits, creating the map on first use."""
        states: dict[tuple[str, str, str], bool] | None = getattr(self, "_ge_link_states", None)
        if states is None:
            states = {}
            self._ge_link_states = states
        return states

    def _drop_ge_link_states_for_node(self, node_id: str) -> None:
        """Drop burst-chain entries where this node is source or destination."""
        states = self._ge_link_states_map()
        for key in list(states):
            if key[0] == node_id or key[1] == node_id:
                states.pop(key, None)

    def _collision_open_map(self) -> dict[str, set[str]]:
        """Return the open collision-epoch map, creating it on first use."""
        open_ids: dict[str, set[str]] | None = getattr(self, "_collision_open", None)
        if open_ids is None:
            open_ids = {}
            self._collision_open = open_ids
        return open_ids

    def _pending_poll_rx_map(self) -> dict[str, tuple[bytes, int, int, str, str]]:
        """Return parked polling-RX results, creating the map on first use."""
        parked: dict[str, tuple[bytes, int, int, str, str]] | None = getattr(
            self, "_pending_poll_rx", None
        )
        if parked is None:
            parked = {}
            self._pending_poll_rx = parked
        return parked

    def _drop_chaos_state_for_receiver(self, node_id: str) -> None:
        """Drop GE cache, tombstones, and collision epoch for a receiver."""
        dropped = self._dropped_rx_set()
        ge = self._ge_cache()
        for key in list(dropped):
            if key[0] == node_id:
                dropped.discard(key)
        for key in list(ge):
            if key[0] == node_id:
                ge.pop(key, None)
        self._collision_open_map().pop(node_id, None)

    def _drop_chaos_state_for_tx(self, tx_id: str) -> None:
        """Drop GE cache and tombstones for a finished or aborted TX."""
        dropped = self._dropped_rx_set()
        ge = self._ge_cache()
        for key in list(dropped):
            if key[1] == tx_id:
                dropped.discard(key)
        for key in list(ge):
            if key[1] == tx_id:
                ge.pop(key, None)

    def _prune_delayed_rx(self) -> None:
        """Drop expired, disconnected, or missing delayed-RX entries."""
        delayed = self._delayed_rx_map()
        now_us = self._current_time_us
        for key, entry in list(delayed.items()):
            rx_id, _tx_id = key
            rx_node = self._nodes.get(rx_id)
            if now_us > entry.expire_us or rx_node is None or not rx_node.connected:
                delayed.pop(key, None)

    def _cancel_rx_timeout_events(self, node_id: str) -> None:
        """Cancel RxTimeoutEvent for this node; leave TX lifecycle events."""
        self._event_queue.remove_events_for_node_of_type(node_id, RxTimeoutEvent)

    def _drop_delayed_rx_for_receiver(self, node_id: str) -> None:
        """Drop delayed-RX entries where this node is the receiver only."""
        delayed = self._delayed_rx_map()
        for key in list(delayed):
            if key[0] == node_id:
                delayed.pop(key, None)
        self._drop_chaos_state_for_receiver(node_id)

    def _drop_delayed_rx_for_node(self, node_id: str) -> None:
        """remove_node: drop inbound stash and this node's in-flight TX copies."""
        self._drop_delayed_rx_for_receiver(node_id)
        tx_id = self._active_transmissions.get(node_id)
        if tx_id is not None:
            self._drop_delayed_rx_for_tx(tx_id)

    def _drop_delayed_rx_for_tx(self, tx_id: str) -> None:
        """Drop delayed-RX entries for a superseded or aborted transmission."""
        delayed = self._delayed_rx_map()
        for key in list(delayed):
            if key[1] == tx_id:
                delayed.pop(key, None)
        self._drop_chaos_state_for_tx(tx_id)

    def _apply_delayed_chaos(
        self,
        candidate: Any,
        rx_node_id: str,
        rx_position: tuple[float, float, float],
    ) -> Any | None:
        """Re-apply chaos at eligibility, skipping Gilbert-Elliott.

        GE already drew at first hearing (stash or live poll). Re-inject
        must still honor Drop/Jam/Partition added after TxEnd, without a
        second Markov transition that can resurrect a live drop.
        """
        key = (rx_node_id, candidate.transmission.id)
        if key in self._dropped_rx_set():
            return None
        engine = self._chaos_engine
        if engine is None:
            return candidate
        current = candidate
        tx = candidate.transmission
        for rule in engine.get_rules():
            if not rule.matches(tx, rx_node_id):
                continue
            if isinstance(rule, GilbertElliottRule):
                continue
            applied = rule.apply(current, rx_position)
            if applied is None:
                self._dropped_rx_set().add(key)
                return None
            current = applied
        return current

    def _apply_live_chaos(
        self,
        candidate: Any,
        rx_node_id: str,
        rx_position: tuple[float, float, float],
    ) -> Any | None:
        """Apply chaos on the live path with a sticky GE decision.

        Gilbert-Elliott is evaluated once per (rx, tx). Other rules still
        run on every poll so Drop/Jam added during airtime take effect. A
        None result is tombstoned and cannot be restashed.
        """
        engine = self._chaos_engine
        if engine is None:
            return candidate
        key = (rx_node_id, candidate.transmission.id)
        dropped = self._dropped_rx_set()
        if key in dropped:
            return None
        current = candidate
        ge_cache = self._ge_cache()
        tx = candidate.transmission
        for rule in engine.get_rules():
            if not rule.matches(tx, rx_node_id):
                continue
            if isinstance(rule, GilbertElliottRule):
                ge_key = (rx_node_id, tx.id, rule.id)
                if ge_key in ge_cache:
                    if not ge_cache[ge_key]:
                        dropped.add(key)
                        return None
                    continue
                applied = self._apply_ge_independent(rule, current, rx_node_id, rx_position)
                ge_cache[ge_key] = applied is not None
                if applied is None:
                    dropped.add(key)
                    return None
                current = applied
                continue
            applied = rule.apply(current, rx_position)
            if applied is None:
                dropped.add(key)
                return None
            current = applied
        return current

    def _apply_ge_independent(
        self,
        rule: GilbertElliottRule,
        candidate: Any,
        rx_node_id: str,
        rx_position: tuple[float, float, float],
    ) -> Any | None:
        """Apply GE with a per-(source, dest) chain that survives across tx.id.

        GilbertElliottRule keys state by (source, tx.id), so walking every
        neighbor on one apply() would chain extra Good→Bad transitions onto
        later receivers. Radio-owned (source, dest, rule.id) bits are copied
        into a one-entry shim for this apply and written back, so each dest
        has its own burst memory. The shared rule.rng is still used; callers
        must iterate receivers in a stable order.
        """
        tx = candidate.transmission
        link_key = (tx.source_node_id, rx_node_id, rule.id)
        shim_state = _GeLinkState(self._ge_link_states_map().get(link_key, False))
        shim = replace(rule, _link_states={(tx.source_node_id, tx.id): shim_state})
        result = shim.apply(candidate, rx_position)
        self._ge_link_states_map()[link_key] = shim_state.in_bad_state
        return result

    def _stash_delayed_rx_candidates(self, tx: Any) -> None:
        """Keep LatencyRule originals until end_time_us + added_latency_us.

        Medium.get_rx_candidates only returns in-flight transmissions, and
        TxEndEvent removes the TX at end_time_us. The original (pre-chaos)
        candidate is cached so apply_all can run again at eligibility.
        Entries expire at that instant; a later poll does not replay them.
        """
        if self._chaos_engine is None:
            return
        self._prune_delayed_rx()
        delayed = self._delayed_rx_map()
        dropped = self._dropped_rx_set()
        for rx_id, rx_node in sorted(self._nodes.items()):
            if rx_id == tx.source_node_id or not rx_node.connected:
                continue
            if rx_id in self._active_transmissions:
                continue
            channel = rx_node.get_hop_channel()
            candidates = self._medium.get_rx_candidates(
                rx_node_id=rx_id,
                rx_position=rx_node.position,
                time_us=self._current_time_us,
                channel=channel,
            )
            for candidate in candidates:
                if candidate.transmission.id != tx.id:
                    continue
                key = (rx_id, tx.id)
                if key in dropped:
                    continue
                result = self._apply_live_chaos(candidate, rx_id, rx_node.position)
                if result is None or result.added_latency_us <= 0:
                    continue
                if key not in delayed:
                    expire_us = tx.end_time_us + result.added_latency_us
                    delayed[key] = _DelayedRx(
                        candidate=candidate,
                        channel=channel,
                        expire_us=expire_us,
                    )
                    self._event_queue.push(DelayedRxReadyEvent(expire_us, rx_id))

    def _consume_delayed_rx(self, node_id: str, tx_ids: list[str]) -> None:
        """Fail-closed: drop stash keys involved in this poll's resolve set."""
        delayed = self._delayed_rx_map()
        for tx_id in tx_ids:
            delayed.pop((node_id, tx_id), None)

    def _reinject_delayed_candidates(
        self,
        node_id: str,
        node: Any,
        channel: int,
        candidates: list[Any],
    ) -> list[tuple[str, str]]:
        """Re-apply chaos to stashed originals; drop on TTL/mismatch/drop.

        Returns keys injected this poll (eligible now). Those keys are
        consumed after resolve whether or not a frame is delivered.
        """
        delayed = self._delayed_rx_map()
        dropped = self._dropped_rx_set()
        present_ids = {c.transmission.id for c in candidates}
        injected: list[tuple[str, str]] = []
        if node.state == NodeState.TX or node_id in self._active_transmissions:
            return injected
        for key, entry in list(delayed.items()):
            nid, txid = key
            if nid != node_id or txid in present_ids:
                continue
            if key in dropped:
                delayed.pop(key, None)
                continue
            if self._current_time_us < entry.expire_us:
                # Not eligible yet: do not re-draw stateful chaos.
                continue
            if self._current_time_us > entry.expire_us:
                delayed.pop(key, None)
                continue
            if channel != entry.channel:
                delayed.pop(key, None)
                continue
            applied = self._apply_delayed_chaos(entry.candidate, node_id, node.position)
            if applied is None:
                delayed.pop(key, None)
                continue
            candidates.append(applied)
            present_ids.add(txid)
            injected.append(key)
        return injected

    def remove_node(self, node_id: str) -> None:
        """Remove a node and drop its delayed-RX stash."""
        self._drop_delayed_rx_for_node(node_id)
        self._drop_ge_link_states_for_node(node_id)
        self._pending_poll_rx_map().pop(node_id, None)
        # End any active transmission in the medium before removing the node
        tx_id = self._active_transmissions.get(node_id)
        if tx_id is not None:
            self._medium.end_tx(tx_id)
            self._close_collision_epoch_for_tx(tx_id)
        super().remove_node(node_id)  # type: ignore[misc]

    def _handle_event(self, event: Event) -> None:
        """Deliver delayed RX at expire before a later RxTimeout can run."""
        if isinstance(event, DelayedRxReadyEvent):
            self.deliver_pending_packets()
            self._capture_polling_rx(event.node_id)
            return
        super()._handle_event(event)  # type: ignore[misc]

    def _handle_tx_start_delayed(self, event: TxStartDelayedEvent) -> None:
        """Finish listen-before-TX, then apply log density delay."""
        node = self._nodes.get(event.node_id)
        if node is None or not node.connected:
            return
        if self._density_aware_startup and not node.started:
            extra = self.calculate_startup_delay(node)  # type: ignore[attr-defined]
            node.started = True
            if extra > 0:
                self._event_queue.push(
                    TxStartDelayedEvent(
                        time_us=self._current_time_us + extra,
                        node_id=event.node_id,
                        payload=event.payload,
                        tx_power_dbm=event.tx_power_dbm,
                        position=node.position,
                        channel=event.channel,
                    )
                )
                return
        super()._handle_tx_start_delayed(event)  # type: ignore[misc]

    def _record_startup_heard(self, tx: Any) -> None:
        """Credit in-range receivers still in listen with this transmitter."""
        if not self._density_aware_startup:
            return
        source = tx.source_node_id
        for rx_id, rx_node in self._nodes.items():
            if rx_id == source or rx_node.started or not rx_node.connected:
                continue
            channel = rx_node.get_hop_channel()
            candidates = self._medium.get_rx_candidates(
                rx_node_id=rx_id,
                rx_position=rx_node.position,
                time_us=self._current_time_us,
                channel=channel,
            )
            if any(c.transmission.id == tx.id for c in candidates):
                rx_node.heard_set.add(source)

    def _capture_polling_rx(self, node_id: str) -> None:
        """Park a polling RX result so same-tick timeout cannot drop it."""
        node = self._nodes.get(node_id)
        if node is None or node.state != NodeState.RX_WAIT or node.rx_callbacks is not None:
            return
        if node_id in self._pending_poll_rx_map():
            return
        result = self._get_rx_result_internal(node_id)
        if result is not None:
            self._pending_poll_rx_map()[node_id] = result

    def _close_collision_epoch_for_tx(self, tx_id: str) -> None:
        """Drop a finished TX from every receiver's collision epoch."""
        open_ids = self._collision_open_map()
        for rx_id in list(open_ids):
            open_ids[rx_id].discard(tx_id)
            if not open_ids[rx_id]:
                del open_ids[rx_id]

    def _handle_rx_timeout(self, event: RxTimeoutEvent) -> None:
        """RX timeout ends this receiver's window; other nodes keep their stash.

        A DelayedRxReadyEvent at the same time_us is popped first. If a
        timeout still lands here, attempt delivery before dropping stash
        so same-tick eligibility is not lost.
        """
        pending = self._pending_rx_timeouts.get(event.node_id)
        if pending is not None and event.time_us != pending:
            return
        node = self._nodes.get(event.node_id)
        if node is not None and node.state == NodeState.RX_WAIT and node.rx_callbacks is not None:
            self.deliver_pending_packets()
            node = self._nodes.get(event.node_id)
            if node is None or node.state != NodeState.RX_WAIT:
                if pending is not None and event.time_us == pending:
                    self._pending_rx_timeouts.pop(event.node_id, None)
                return
        if node is not None and node.state == NodeState.RX_WAIT and node.rx_callbacks is None:
            self._capture_polling_rx(event.node_id)
            if event.node_id in self._pending_poll_rx_map():
                # Polling success at timeout: keep the park for get_rx_result,
                # end the window, and do not notify on_rx_timeout.
                if pending is not None and event.time_us == pending:
                    self._pending_rx_timeouts.pop(event.node_id, None)
                self._drop_delayed_rx_for_receiver(event.node_id)
                node.state = NodeState.IDLE
                return
        if node is None or node.state != NodeState.RX_WAIT:
            if pending is not None and event.time_us == pending:
                self._pending_rx_timeouts.pop(event.node_id, None)
            return
        self._drop_delayed_rx_for_receiver(event.node_id)
        super()._handle_rx_timeout(event)  # type: ignore[misc]

    def _handle_tx_end(self, event: TxEndEvent) -> None:
        """Prune expired stash; drop superseded TX ghosts, keep delayed current TX."""
        self._prune_delayed_rx()
        if self._active_transmissions.get(event.node_id) != event.transmission_id:
            self._drop_delayed_rx_for_tx(event.transmission_id)
        else:
            self._drop_chaos_state_for_tx(event.transmission_id)
        self._close_collision_epoch_for_tx(event.transmission_id)
        super()._handle_tx_end(event)  # type: ignore[misc]

    def _get_rx_result_internal(self, node_id: str) -> tuple[bytes, int, int, str, str] | None:
        """Unified core RX logic. Uses node.get_hop_channel (node.py:146)
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
        # Half-duplex: an in-flight TX cannot hear overlapping frames.
        if node_id in self._active_transmissions:
            return None

        self._prune_delayed_rx()
        channel = node.get_hop_channel()
        candidates = self._medium.get_rx_candidates(
            rx_node_id=node_id,
            rx_position=node.position,
            time_us=self._current_time_us,
            channel=channel,
        )

        delayed_map = self._delayed_rx_map()
        dropped = self._dropped_rx_set()
        if self._chaos_engine is not None:
            filtered_candidates = []
            for candidate in candidates:
                result = self._apply_live_chaos(candidate, node_id, node.position)
                if result is None:
                    delayed_map.pop((node_id, candidate.transmission.id), None)
                    continue
                filtered_candidates.append(result)
                if result.added_latency_us > 0:
                    key = (node_id, result.transmission.id)
                    if key not in delayed_map and key not in dropped:
                        expire_us = result.transmission.end_time_us + result.added_latency_us
                        delayed_map[key] = _DelayedRx(
                            candidate=candidate,
                            channel=channel,
                            expire_us=expire_us,
                        )
                        self._event_queue.push(DelayedRxReadyEvent(expire_us, node_id))
            candidates = filtered_candidates

        injected = self._reinject_delayed_candidates(node_id, node, channel, candidates)

        # Drop candidates whose LatencyRule-added delivery delay hasn't elapsed.
        candidates = [
            c
            for c in candidates
            if c.added_latency_us == 0
            or self._current_time_us >= c.transmission.end_time_us + c.added_latency_us
        ]

        tx = self._medium.resolve_reception(candidates)
        if tx is None:
            self._consume_delayed_rx(node_id, [c.transmission.id for c in candidates])
            for key in injected:
                delayed_map.pop(key, None)
            open_ids = self._collision_open_map()
            if len(candidates) >= 2:
                tx_ids = [c.transmission.id for c in candidates]
                tx_id_set = set(tx_ids)
                already_rx = any(self._metrics.has_reception(node_id, cid) for cid in tx_ids)
                open_set = open_ids.get(node_id)
                same_epoch = open_set is not None and bool(open_set & tx_id_set)
                if already_rx or same_epoch:
                    if open_set is not None:
                        open_set.update(tx_id_set)
                elif self._metrics.record_collision(
                    node_id,
                    tx_ids,
                    channel=channel,
                    time_us=self._current_time_us,
                ):
                    open_ids[node_id] = tx_id_set
                    self._debug_log(  # type: ignore[attr-defined]
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
                    # Notify collision visualization with position data
                    tx_positions = []
                    for c in candidates:
                        tx_pos = self._medium._tx_positions.get(c.transmission.id)
                        if tx_pos is not None:
                            tx_positions.append(tx_pos)
                    if tx_positions:
                        self._observers.notify(
                            "on_collision_visual",
                            sim_id=self._id,
                            node_id=node_id,
                            tx_ids=tx_ids,
                            tx_positions=tx_positions,
                            time_us=self._current_time_us,
                        )
            else:
                open_ids.pop(node_id, None)
            return None

        # Record simulation-wide + per-node metrics. Idempotent for polling
        # and callback paths: NodeMetrics and observers fire once per delivery.
        self._collision_open_map().pop(node_id, None)
        self._consume_delayed_rx(node_id, [c.transmission.id for c in candidates])
        for key in injected:
            delayed_map.pop(key, None)
        first_delivery = self._metrics.record_reception(node_id, tx.id, self._current_time_us)
        if first_delivery:
            packet_hash = hashlib.sha256(tx.payload).digest()[:16].hex()
            node.metrics.record_rx(tx.payload, packet_hash, from_peer=tx.source_node_id)

            # Track heard neighbors during startup phase for density-aware startup
            if self._density_aware_startup and not node.started and tx.source_node_id is not None:
                node.heard_set.add(tx.source_node_id)

        for candidate in candidates:
            if candidate.transmission is tx:
                rssi = int(candidate.rssi)
                snr = int(candidate.snr)
                if first_delivery:
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
                    self._debug_log("rx_success", **rx_log)  # type: ignore[attr-defined]
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

        parked = self._pending_poll_rx_map().pop(node_id, None)
        if parked is not None:
            payload, rssi, snr, _, _ = parked
            return payload, rssi, snr

        result = self._get_rx_result_internal(node_id)
        if result is None:
            return None
        payload, rssi, snr, _, _ = result
        return payload, rssi, snr
