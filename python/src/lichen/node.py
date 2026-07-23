# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN Node class - main integration point for protocol stack.

The Node class integrates all protocol layers:
- Radio: Physical layer (simulated or hardware)
- LinkLayer: Frame format, signing, replay protection
- Router: Hybrid routing (RPL + Announce + LOADng)
- AnnounceProcessor: Gradient building from announces

Why a single Node class: Provides clean lifecycle management (start/stop)
and coordinates the async receive loop, routing decisions, and packet flow.

Packet flow (RX):
    radio.receive() -> link.receive() -> router.route() -> deliver/forward

Packet flow (TX):
    node.send() -> router.route() -> link.send() -> radio.transmit()
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address, IPv6Network
from typing import Protocol, cast

from lichen.announce.messages import AnnounceMessage
from lichen.announce.processor import AnnounceProcessor
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity, PeerIdentity
from lichen.gradient import GradientTable
from lichen.ipv6 import make_ula
from lichen.ipv6.packet import IPv6Packet
from lichen.l2_payload import (
    L2_ROUTING_TYPE_ANNOUNCE,
    L2PayloadKind,
    classify_l2_payload,
    l2_payload_body,
    wrap_routing_payload,
    wrap_schc_payload,
)
from lichen.link.link_layer import LinkLayer, ReceiveError, RxFrame
from lichen.radio.base import Radio
from lichen.routing.router import RouteDecision, Router
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.state_machine import StateMachine

logger = logging.getLogger(__name__)


def _build_address(iid: bytes) -> IPv6Address:
    prefix = IPv6Network("fd00::/64")
    return make_ula(prefix, iid)


class MeshtasticAdapterProtocol(Protocol):
    """Lifecycle surface Node needs from an optional Meshtastic adapter."""

    async def start(self) -> None:
        """Start adapter-owned async resources."""

    async def stop(self) -> None:
        """Stop adapter-owned async resources."""


class NodeState(Enum):
    """Lifecycle state of a Node."""

    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()


NODE_STATE_TRANSITIONS: dict[NodeState, frozenset[NodeState]] = {
    NodeState.STOPPED: frozenset({NodeState.STARTING}),
    NodeState.STARTING: frozenset({NodeState.RUNNING, NodeState.STOPPING}),
    NodeState.RUNNING: frozenset({NodeState.STOPPING}),
    NodeState.STOPPING: frozenset({NodeState.STOPPED}),
}

# Maximum relay-seen cache entries before LRU eviction
RELAY_SEEN_MAX_SIZE = 128


@dataclass
class NodeConfig:
    """Configuration for a LICHEN node.

    Why a separate config: Makes construction clear and allows validation.

    Attributes:
        receive_timeout_ms: Timeout for each receive call.
            Why 1000: Balance between responsiveness and CPU usage.
        announce_interval_ms: How often to send announces.
            Why 300000: Spec section 9.4 (5 minutes).
        announce_jitter_ms: Random jitter for announces.
            Why 30000: Spec section 9.4 (0-30 seconds).
        pending_timeout_ms: How long to queue packets waiting for discovery.
            Why 5000: LOADng RREQ_WAIT_TIME is 5 seconds.
        rreq_jitter_min_ms: Minimum jitter before sending RREQ.
            Why 0: Allow immediate transmission when no contention.
        rreq_jitter_max_ms: Maximum jitter before sending RREQ.
            Why 100: LOADng spec recommends short jitter to reduce collisions.
    """

    receive_timeout_ms: int = 1000
    announce_interval_ms: int = 300_000
    announce_jitter_ms: int = 30_000
    pending_timeout_ms: int = 5_000
    rreq_jitter_min_ms: int = 0
    rreq_jitter_max_ms: int = 100


@dataclass
class Node:
    """A LICHEN mesh node integrating all protocol layers.

    Why a class: Owns all layer instances, manages lifecycle, coordinates
    async tasks for receiving, announcing, and routing.

    Attributes:
        identity: This node's cryptographic identity.
        radio: Physical layer (simulated or hardware).
        config: Node configuration.
        meshtastic: Enable Meshtastic BLE adapter (requires [meshtastic] extra).
        link: Link layer for frame signing/verification.
        gradient_table: Unified routing table.
        router: Hybrid routing decision engine.
        announce_processor: Processes incoming announces.
        peer_db: Known peers by IID (for signature verification).
        state: Current lifecycle state.
    """

    identity: Identity
    radio: Radio
    config: NodeConfig = field(default_factory=NodeConfig)
    meshtastic: bool = False

    # Protocol layers - initialized in __post_init__
    link: LinkLayer = field(init=False, repr=False)
    gradient_table: GradientTable = field(default_factory=GradientTable)
    router: Router = field(init=False, repr=False)
    announce_processor: AnnounceProcessor = field(init=False, repr=False)

    # Peer database - nodes we know about
    peer_db: dict[bytes, PeerIdentity] = field(default_factory=dict, repr=False)

    # Lifecycle state
    _state_machine: StateMachine[NodeState] = field(init=False, repr=False)
    _receive_task: asyncio.Task[None] | None = field(default=None, init=False, repr=False)
    _lifecycle_lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    # Announce scheduler - manages periodic announce transmission
    # Why separate: Single responsibility, persistence support, testability.
    _scheduler: AnnounceScheduler = field(init=False, repr=False)

    # Callbacks
    _on_receive: Callable[[bytes, PeerIdentity], None] | None = field(
        default=None, init=False, repr=False
    )
    _on_receive_owner: object | None = field(default=None, init=False, repr=False)

    # Relay dedup: SCHC payloads forwarded by this node; prevents relay loops.
    # Why OrderedDict: LRU eviction preserves recent history when cache exceeds max.
    _relay_seen: OrderedDict[bytes, None] = field(
        default_factory=OrderedDict, init=False, repr=False
    )

    # Meshtastic adapter (optional, created if meshtastic=True)
    _meshtastic_adapter: MeshtasticAdapterProtocol | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self._state_machine = StateMachine(
            initial=NodeState.STOPPED,
            transitions=NODE_STATE_TRANSITIONS,
            name=f"node[{self.identity.iid.hex()}]",
        )

        # Why initialize layers here: They depend on self.identity, self.radio.
        self.link = LinkLayer(
            radio=self.radio,
            identity=self.identity,
            peer_lookup=self._peer_lookup,
            peer_lookup_all=lambda: list(self.peer_db.values()),
        )

        self.router = Router(
            node_address=_build_address(self.identity.iid),
            gradient_table=self.gradient_table,
        )

        self.announce_processor = AnnounceProcessor(
            gradient_table=self.gradient_table,
            address_builder=_build_address,
        )

        # Why scheduler: Encapsulates announce timing, signing, sequence numbers.
        # The transmitter lambda bridges scheduler to link layer.
        self._scheduler = AnnounceScheduler(
            identity=self.identity,
            transmitter=self,  # Node implements AnnounceTransmitter
            config=SchedulerConfig(
                interval_ms=self.config.announce_interval_ms,
                jitter_ms=self.config.announce_jitter_ms,
                initial_delay_ms=5_000,  # Why 5s: Let node discover peers first.
            ),
        )

        # Meshtastic adapter: lazy import to avoid requiring bleak/betterproto
        if self.meshtastic:
            try:
                from lichen.interface.meshtastic.adapter import MeshtasticAdapter

                self._meshtastic_adapter = MeshtasticAdapter(self)
            except ImportError:
                logger.warning(
                    "meshtastic=True but adapter not available; "
                    "install with: pip install lichen[meshtastic]"
                )

    @property
    def state(self) -> NodeState:
        """Return the node lifecycle state."""
        return self._state_machine.state

    def _peer_lookup(self, hint: bytes) -> PeerIdentity | None:
        if hint and len(hint) == 8 and hint in self.peer_db:
            return self.peer_db[hint]
        return None

    def add_peer(self, peer: PeerIdentity) -> None:
        """Add a peer to the database.

        Why exposed: Caller may have out-of-band knowledge of peers.
        Also called automatically when we receive a valid announce.
        """
        self.peer_db[peer.iid] = peer
        logger.debug("added peer: %s", peer.iid.hex())

    def remove_peer(self, iid: bytes) -> None:
        """Remove a peer from the database."""
        self.peer_db.pop(iid, None)

    async def transmit_announce(self, data: bytes) -> bool:
        """Transmit announce data via link layer (AnnounceTransmitter protocol).

        Why a method on Node: Node owns the link layer. Scheduler calls this
        to actually send the announce bytes over the air.
        """
        return await self.link.send(wrap_routing_payload(data))

    def set_on_receive(self, callback: Callable[[bytes, PeerIdentity], None]) -> None:
        """Set callback for received application data.

        Why callback: Upper layers (CoAP, etc.) need to receive data.
        The callback is invoked with (payload, sender).
        """
        if self._on_receive_owner is not None and self._on_receive_owner is not self:
            raise RuntimeError("node receive callback already has an owner")
        self._on_receive = callback
        self._on_receive_owner = self

    def register_on_receive(
        self,
        owner: object,
        callback: Callable[[bytes, PeerIdentity], None],
    ) -> None:
        """Register one owner-controlled receive callback."""
        if owner is None:
            raise ValueError("node receive callback owner must not be None")
        if self._on_receive is not None:
            raise RuntimeError("node receive callback already has an owner")
        self._on_receive = callback
        self._on_receive_owner = owner

    def unregister_on_receive(self, owner: object) -> bool:
        """Clear the receive callback only when ``owner`` still controls it."""
        if owner is None:
            raise ValueError("node receive callback owner must not be None")
        if self._on_receive_owner is not owner:
            return False
        self._on_receive = None
        self._on_receive_owner = None
        return True

    async def start(self) -> None:
        """Start the node's async tasks.

        Why async: Creates background tasks that run until stop().
        """
        async with self._lifecycle_lock:
            self._state_machine.require(NodeState.STOPPED)
            self._state_machine.transition(NodeState.STARTING)
            logger.info("starting node %s", self.identity.iid.hex())
            scheduler_attempted = False
            adapter_attempted = False
            try:
                self._receive_task = asyncio.create_task(
                    self._receive_loop(),
                    name=f"node-rx-{self.identity.iid.hex()[:8]}",
                )
                await asyncio.sleep(0)
                self._raise_receive_failure()
                scheduler_attempted = True
                await self._scheduler.start()
                if self._meshtastic_adapter is not None:
                    adapter_attempted = True
                    await self._meshtastic_adapter.start()
                await asyncio.sleep(0)
                self._raise_receive_failure()
            except BaseException as primary:
                self._state_machine.transition(NodeState.STOPPING)
                await self._cleanup_started(
                    adapter=adapter_attempted,
                    scheduler=scheduler_attempted,
                )
                self._state_machine.transition(NodeState.STOPPED)
                raise primary
            self._state_machine.transition(NodeState.RUNNING)
            logger.info("node started")

    async def stop(self) -> None:
        """Stop the node's async tasks.

        Why graceful: Cancels tasks and waits for them to finish.
        """
        async with self._lifecycle_lock:
            if self.state == NodeState.STOPPED:
                return
            self._state_machine.require(NodeState.RUNNING)
            self._state_machine.transition(NodeState.STOPPING)
            logger.info("stopping node")
            error = await self._cleanup_started(
                adapter=self._meshtastic_adapter is not None,
                scheduler=True,
            )
            self._state_machine.transition(NodeState.STOPPED)
            logger.info("node stopped")
            if error is not None:
                raise error

    def _raise_receive_failure(self) -> None:
        task = self._receive_task
        if task is not None and task.done():
            task.result()

    async def _cleanup_started(
        self, *, adapter: bool, scheduler: bool
    ) -> BaseException | None:
        error: BaseException | None = None
        if adapter and self._meshtastic_adapter is not None:
            try:
                await self._meshtastic_adapter.stop()
            except BaseException as exc:
                error = exc
        if scheduler:
            try:
                await self._scheduler.stop()
            except BaseException as exc:
                if error is None:
                    error = exc
        task = self._receive_task
        self._receive_task = None
        if task is not None:
            task.cancel()
            results = await asyncio.gather(task, return_exceptions=True)
            result = results[0]
            if (
                error is None
                and isinstance(result, BaseException)
                and not isinstance(result, asyncio.CancelledError)
            ):
                error = result
        return error

    async def _receive_loop(self) -> None:
        """Continuously receive and process frames.

        Why infinite loop: Runs until cancelled by stop().
        """
        while True:
            try:
                rx = await self.link.receive(self.config.receive_timeout_ms)
                if rx is not None and not isinstance(rx, ReceiveError):
                    await self._process_received(rx)
                elif isinstance(rx, ReceiveError):
                    if rx in (ReceiveError.KEY_CHANGE, ReceiveError.REPLAY, ReceiveError.MIC_FAILED):
                        logger.warning("link RX security event: %s", rx)
                    else:
                        logger.debug("link RX rejected: %s", rx)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception("error in receive loop: %s", e)
                # Continue receiving despite errors

    async def _process_received(self, rx: RxFrame) -> None:
        """Process a received and verified frame.

        Why separate method: Keeps receive loop simple, allows testing.
        """
        payload = rx.frame.payload

        kind = classify_l2_payload(payload)
        body = l2_payload_body(payload)

        if (
            kind == L2PayloadKind.ROUTING
            and len(body) > 0
            and body[0] == L2_ROUTING_TYPE_ANNOUNCE
        ):
            await self._process_announce(body, rx.sender, rx.rssi_dbm)
            return

        # SCHC-compressed IPv6 data packet: decompress, route, relay or deliver.
        if kind != L2PayloadKind.SCHC:
            if self._on_receive:
                self._on_receive(payload, rx.sender)
            return

        try:
            ipv6_bytes = decompress_packet(body)
            packet = IPv6Packet.from_bytes(ipv6_bytes)
        except Exception:
            # Not a parseable IPv6 packet — pass raw bytes to app callback.
            if self._on_receive:
                self._on_receive(payload, rx.sender)
            return

        now_ms = int(asyncio.get_running_loop().time() * 1000)
        decision, _next_hop = self.router.route(packet, now_ms)

        if decision == RouteDecision.DELIVER_LOCAL:
            if self._on_receive:
                self._on_receive(payload, rx.sender)
        elif decision == RouteDecision.FORWARD and payload not in self._relay_seen:
            # Relay: re-broadcast SCHC bytes unchanged.  Dedup prevents loops.
            self._relay_seen[payload] = None
            if len(self._relay_seen) > RELAY_SEEN_MAX_SIZE:
                # LRU eviction: remove oldest half to preserve recent history.
                # Why half: amortizes eviction cost while keeping recent entries.
                for _ in range(RELAY_SEEN_MAX_SIZE // 2):
                    self._relay_seen.popitem(last=False)
            await self.link.send(payload)

    async def _process_announce(
        self, payload: bytes, sender: PeerIdentity, rssi_dbm: int
    ) -> None:
        """Process an announce message.

        Why async: May need to relay the announce.
        """
        try:
            announce = AnnounceMessage.from_bytes(payload)
        except Exception as e:
            logger.warning("failed to parse announce: %s", e)
            return

        # Use sender's link-local address as from_neighbor
        # Why fe80:: prefix: Link-local is the "neighbor" address.
        from_neighbor = IPv6Address(
            bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + sender.iid
        )

        # Get current time in ms (in production, use monotonic clock)
        now_ms = int(asyncio.get_running_loop().time() * 1000)

        result = self.announce_processor.process(announce, from_neighbor, now_ms)

        if result.accepted:
            # Add peer to database if new
            if result.peer:
                self.add_peer(result.peer)

            # Relay if needed
            if result.should_relay:
                await self._relay_announce(announce)

    async def _relay_announce(self, announce: AnnounceMessage) -> None:
        """Relay an announce to neighbors.

        Why separate method: Relay involves incrementing hop count and resending.
        """
        relay = self.announce_processor.get_relay_message(announce)
        if relay is None:
            return

        success = await self.link.send(wrap_routing_payload(relay.to_bytes()))
        if success:
            logger.debug("relayed announce from %s", announce.originator_iid.hex())

    async def _send_announce(self) -> None:
        """Send our own announce message.

        Why separate method: Allows testing and manual triggering.
        Delegates to scheduler for announce building (signing, seq_num).
        """
        announce = self._scheduler.build_announce()
        data = wrap_routing_payload(announce.to_bytes())
        success = await self.link.send(data)
        if success:
            logger.info("sent announce seq=%d", announce.seq_num)

    @property
    def _announce_seq(self) -> int:
        """Current announce sequence number (for backwards compatibility).

        Why property: Tests expect node._announce_seq. Delegate to scheduler.
        """
        return self._scheduler.get_seq_num()

    async def send(self, ipv6_bytes: bytes) -> bool:
        """Send a raw IPv6 datagram through the SCHC + routing stack.

        Args:
            ipv6_bytes: A complete IPv6 datagram (e.g. IPv6 + UDP + CoAP).
                        Use coap.node_channel.NodeChannel to build this from CoAP.

        Returns:
            True if forwarded to the link layer, False if routed to drop.
        """
        try:
            packet = IPv6Packet.from_bytes(ipv6_bytes)
        except Exception:
            logger.warning("send: failed to parse IPv6 packet")
            return False

        schc = compress_packet(ipv6_bytes)
        wrapped = wrap_schc_payload(schc)
        # Track what we've sent so relay dedup doesn't forward it back to us.
        self._relay_seen[wrapped] = None
        if len(self._relay_seen) > RELAY_SEEN_MAX_SIZE:
            # LRU eviction: remove oldest half to preserve recent history.
            for _ in range(RELAY_SEEN_MAX_SIZE // 2):
                self._relay_seen.popitem(last=False)

        now_ms = int(asyncio.get_running_loop().time() * 1000)
        decision, _next_hop = self.router.route(packet, now_ms)

        if decision == RouteDecision.FORWARD:
            return await self.link.send(wrapped)
        if decision == RouteDecision.DELIVER_LOCAL:
            if self._on_receive:
                self._on_receive(wrapped, PeerIdentity.from_pubkey(self.identity.pubkey))
            return True
        return False

    def scheduled_send(
        self,
        data: bytes,
        min_delay_ms: int | None = None,
        max_delay_ms: int | None = None,
    ) -> asyncio.Task[bool]:
        """Schedule a transmission after a random jitter delay.

        Why jitter: RREQ rebroadcast uses jitter to reduce collision probability
        when multiple nodes forward the same RREQ (LOADng spec).

        Args:
            data: Routing/control message body to transmit via link layer.
            min_delay_ms: Minimum delay in milliseconds. Defaults to config.rreq_jitter_min_ms.
            max_delay_ms: Maximum delay in milliseconds. Defaults to config.rreq_jitter_max_ms.

        Returns:
            The asyncio Task that will perform the delayed send.
        """
        if min_delay_ms is None:
            min_delay_ms = self.config.rreq_jitter_min_ms
        if max_delay_ms is None:
            max_delay_ms = self.config.rreq_jitter_max_ms

        delay_ms = random.randint(min_delay_ms, max_delay_ms)

        async def _delayed_send() -> bool:
            await asyncio.sleep(delay_ms / 1000)
            return await self.link.send(wrap_routing_payload(data))

        return asyncio.create_task(
            _delayed_send(),
            name=f"scheduled-send-{delay_ms}ms",
        )

    def get_status(self) -> dict[str, object]:
        """Get node status for debugging/monitoring.

        Returns:
            Dict with node state, peer count, gradient count, etc.
            Includes `uptime` and `firmware` for Rust TUI compatibility.
        """
        # ponytail: uptime from event loop time, good enough for sim
        try:
            loop = asyncio.get_running_loop()
            uptime_secs = int(loop.time())
        except RuntimeError:
            uptime_secs = 0
        return {
            "iid": self.identity.iid.hex(),
            "pubkey": self.identity.pubkey.hex()[:16] + "...",
            "state": self.state.name,
            "peers": len(self.peer_db),
            "gradients": len(self.gradient_table),
            "announce_seq": self._scheduler.get_seq_num(),
            "uptime": uptime_secs,
            "firmware": "sim-0.1.0",
        }

    def get_queue_stats(self) -> dict[str, int]:
        """Get TX queue statistics for diagnostics.

        Returns:
            Dict with queue latency and drop counters per spec/appendix-bufferbloat.md.
            Fields:
                packets_queued: Total packets pushed to queue.
                packets_dropped_deadline: Packets expired before transmission.
                packets_dropped_full: Packets rejected due to full queue (backpressure).
                max_latency_ms: Worst-case time a packet spent in queue.
                avg_latency_ms: Smoothed average queue latency (EMA).
        """
        stats = self.link.tx_queue.stats
        return {
            "packets_queued": stats.packets_queued,
            "packets_dropped_deadline": stats.packets_dropped_deadline,
            "packets_dropped_full": stats.packets_dropped_full,
            "max_latency_ms": stats.max_latency_ms,
            "avg_latency_ms": stats.avg_latency_ms,
        }

    def get_neighbors(self) -> list[dict[str, object]]:
        """Get neighbor list for CoAP /neighbors resource.

        Returns:
            List of dicts with `addr` and `rssi` keys.
        """
        # ponytail: peer_db has IIDs, convert to link-local addresses
        neighbors = []
        for iid in self.peer_db:
            addr = IPv6Address(b"\xfe\x80\x00\x00\x00\x00\x00\x00" + iid)
            neighbors.append({
                "addr": str(addr),
                "rssi": -100,  # ponytail: no per-peer RSSI tracking yet
            })
        return neighbors

    def get_config(self) -> dict[str, int]:
        """Get node config for CoAP /config resource."""
        return {
            "receive_timeout_ms": self.config.receive_timeout_ms,
            "announce_interval_ms": self.config.announce_interval_ms,
        }

    _VALID_CONFIG_KEYS = frozenset({"receive_timeout_ms", "announce_interval_ms"})

    def set_config(self, updates: Mapping[str, object]) -> None:
        """Update node config from CoAP /config PUT.

        Raises:
            ValueError: If any key in updates is not a valid config key.
        """
        unknown = set(updates.keys()) - self._VALID_CONFIG_KEYS
        if unknown:
            raise ValueError(f"unknown config keys: {sorted(unknown)}")
        receive_timeout_ms = self.config.receive_timeout_ms
        announce_interval_ms = self.config.announce_interval_ms
        if "receive_timeout_ms" in updates:
            receive_timeout_ms = int(cast(int | str, updates["receive_timeout_ms"]))
        if "announce_interval_ms" in updates:
            announce_interval_ms = int(cast(int | str, updates["announce_interval_ms"]))
        self.config.receive_timeout_ms = receive_timeout_ms
        self.config.announce_interval_ms = announce_interval_ms
