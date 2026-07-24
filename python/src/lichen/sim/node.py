# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Simulated node state tracking for the LICHEN simulator."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

from lichen.sim.metrics import NodeMetrics
from lichen.sim.tdma import TDMAScheduler, hash_32
from lichen.state_machine import StateMachine

# Type alias for RX callbacks: (on_packet, on_timeout)
# on_packet: Callable[[bytes, int, int], None] -> (payload, rssi, snr)
# on_timeout: Callable[[], None]
RxCallbacks = tuple[Callable[[bytes, int, int], None], Callable[[], None]]


class NodeState(Enum):
    """Radio state of a simulated node."""

    IDLE = auto()
    TX = auto()
    RX_WAIT = auto()


NODE_STATE_TRANSITIONS: dict[NodeState, frozenset[NodeState]] = {
    NodeState.IDLE: frozenset({NodeState.TX, NodeState.RX_WAIT}),
    NodeState.TX: frozenset({NodeState.IDLE, NodeState.TX, NodeState.RX_WAIT}),
    NodeState.RX_WAIT: frozenset({NodeState.IDLE, NodeState.TX, NodeState.RX_WAIT}),
}


@dataclass(init=False)
class SimNode:
    """State for a single simulated node in the LICHEN mesh.

    Tracks position, radio state, connection status, and hopping state.
    synchronized_hop_channel (method, derived from hop_schedule+SFN for CCP-12)
    takes priority over current_channel (CCP-9/legacy). rx_channel from
    Announce per simulation.py:713. Position mutable for mobility.
    """

    id: str
    position: tuple[float, float, float]
    tx_power_dbm: int
    pending_rx_future: asyncio.Future[None] | None = field(repr=False)
    connected: bool
    last_seen_time_us: int
    rx_callbacks: RxCallbacks | None = field(repr=False)
    metrics: NodeMetrics = field(repr=False)
    current_channel: int = 0
    seed: int = 0
    hop_schedule: tuple[int, ...] = field(default_factory=tuple, repr=False)
    tdma_scheduler: TDMAScheduler = field(repr=False, default_factory=TDMAScheduler)
    _state_machine: StateMachine[NodeState] = field(init=False, repr=False)

    def __init__(
        self,
        id: str,
        position: tuple[float, float, float] = (0.0, 0.0, 0.0),
        tx_power_dbm: int = 22,
        state: NodeState = NodeState.IDLE,
        pending_rx_future: asyncio.Future[None] | None = None,
        connected: bool = False,
        last_seen_time_us: int = 0,
        rx_callbacks: RxCallbacks | None = None,
        metrics: NodeMetrics | None = None,
        current_channel: int = 0,
        seed: int = 0,
        hop_schedule: tuple[int, ...] | None = None,
        tdma_scheduler: TDMAScheduler | None = None,
        sfn: int = 0,
        num_channels: int = 8,
    ) -> None:
        self.id = id
        self.position = position
        self.tx_power_dbm = tx_power_dbm
        self.pending_rx_future = pending_rx_future
        self.connected = connected
        self.last_seen_time_us = last_seen_time_us
        self.rx_callbacks = rx_callbacks
        self.metrics = metrics if metrics is not None else NodeMetrics()
        self.seed = seed
        self.current_channel = current_channel
        self.tdma_scheduler = tdma_scheduler if tdma_scheduler is not None else TDMAScheduler()
        if hop_schedule is not None:
            self.hop_schedule = tuple(hop_schedule)
        else:
            self.hop_schedule = self._populate_hop_schedule(seed, sfn, num_channels)
        self._state_machine = StateMachine(
            initial=state,
            transitions=NODE_STATE_TRANSITIONS,
            name=f"sim-node[{self.id}]",
        )

    @property
    def state(self) -> NodeState:
        """Return this node's radio state."""
        return self._state_machine.state

    @state.setter
    def state(self, new_state: NodeState) -> None:
        self._state_machine.transition(new_state)

    def set_position(self, x: float, y: float, z: float) -> None:
        """Update the node's position in 3D space.

        Args:
            x: X coordinate in meters.
            y: Y coordinate in meters.
            z: Z coordinate in meters (altitude).
        """
        self.position = (x, y, z)

    def disconnect(self) -> None:
        """Disconnect the node and clean up pending operations.

        Sets connected to False, cancels any pending RX future, and clears
        RX callbacks.
        """
        self.connected = False
        if self.pending_rx_future is not None and not self.pending_rx_future.done():
            self.pending_rx_future.cancel()
        self.pending_rx_future = None
        self.rx_callbacks = None

    def is_online(self) -> bool:
        """Check if the node is currently connected.

        Returns:
            True if the node is connected, False otherwise.
        """
        return self.connected

    @staticmethod
    def _populate_hop_schedule(seed: int, sfn: int, num_channels: int = 8) -> tuple[int, ...]:
        n = max(num_channels, 3)
        return tuple(
            1 + (hash_32(seed.to_bytes(8, "big") + (((sfn + i) & 0xffffffff).to_bytes(4, "little"))) % n)
            for i in range(8)
        )

    def synchronized_hop_channel(self, sfn: int | None = None) -> int:
        """Derive hop channel from hop_schedule+SFN (CCP-12) or current_channel.
        Matches spec/02a-coordinated-capacity.md:120, ccp16-hop.json:7.
        Delegates to get_hop_channel for core logic.
        """
        return self.get_hop_channel(sfn)

    def get_hop_channel(self, sfn: int | None = None) -> int:
        """Derive hop channel from hop_schedule+SFN (CCP-12) or current_channel.
        Matches spec/02a-coordinated-capacity.md:120, ccp16-hop.json:7.
        """
        if sfn is None:
            sfn = self.tdma_scheduler.clock.sfn
        if self.hop_schedule and len(self.hop_schedule) > 0:
            return self.hop_schedule[sfn % len(self.hop_schedule)]
        return self.current_channel
