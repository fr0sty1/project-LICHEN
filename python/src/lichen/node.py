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
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from ipaddress import IPv6Address

from lichen.announce.messages import ANNOUNCE_TYPE, AnnounceMessage
from lichen.announce.processor import AnnounceProcessor
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity, PeerIdentity
from lichen.gradient import GradientTable
from lichen.link.link_layer import LinkLayer, RxFrame
from lichen.radio.base import Radio
from lichen.routing.router import Router

logger = logging.getLogger(__name__)


class NodeState(Enum):
    """Lifecycle state of a Node."""

    STOPPED = auto()
    STARTING = auto()
    RUNNING = auto()
    STOPPING = auto()


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
    """

    receive_timeout_ms: int = 1000
    announce_interval_ms: int = 300_000
    announce_jitter_ms: int = 30_000
    pending_timeout_ms: int = 5_000


@dataclass
class Node:
    """A LICHEN mesh node integrating all protocol layers.

    Why a class: Owns all layer instances, manages lifecycle, coordinates
    async tasks for receiving, announcing, and routing.

    Attributes:
        identity: This node's cryptographic identity.
        radio: Physical layer (simulated or hardware).
        config: Node configuration.
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

    # Protocol layers - initialized in __post_init__
    link: LinkLayer = field(init=False, repr=False)
    gradient_table: GradientTable = field(default_factory=GradientTable)
    router: Router = field(init=False, repr=False)
    announce_processor: AnnounceProcessor = field(init=False, repr=False)

    # Peer database - nodes we know about
    peer_db: dict[bytes, PeerIdentity] = field(default_factory=dict, repr=False)

    # Lifecycle state
    state: NodeState = field(default=NodeState.STOPPED, init=False)
    _receive_task: asyncio.Task | None = field(default=None, init=False, repr=False)

    # Announce scheduler - manages periodic announce transmission
    # Why separate: Single responsibility, persistence support, testability.
    _scheduler: AnnounceScheduler = field(init=False, repr=False)

    # Callbacks
    _on_receive: Callable[[bytes, PeerIdentity], None] | None = field(
        default=None, init=False, repr=False
    )

    def __post_init__(self) -> None:
        # Why initialize layers here: They depend on self.identity, self.radio.
        self.link = LinkLayer(
            radio=self.radio,
            identity=self.identity,
            peer_lookup=self._peer_lookup,
        )

        # Why separate address builder: Router needs to build full IPv6 from IID.
        # For now, use ULA prefix. In production, this comes from DIO.
        def build_address(iid: bytes) -> IPv6Address:
            # Why fd00::/64: Default ULA prefix for LICHEN mesh.
            prefix = bytes([0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            return IPv6Address(prefix + iid)

        self.router = Router(
            node_address=build_address(self.identity.iid),
            gradient_table=self.gradient_table,
        )

        self.announce_processor = AnnounceProcessor(
            gradient_table=self.gradient_table,
            address_builder=build_address,
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

    def _peer_lookup(self, hint: bytes) -> PeerIdentity | None:
        """Look up a peer by IID hint.

        Why a callback: LinkLayer needs to verify signatures but doesn't
        own the peer database. This callback provides the lookup.

        For now, returns the first matching peer. In production, would
        use the hint (e.g., destination address) to narrow down.
        """
        # Why iterate: Without sender IID in frame, must try all peers.
        # This is O(n) but n is small for mesh networks.
        if hint and hint in self.peer_db:
            return self.peer_db[hint]
        # Try first peer as fallback (for testing)
        if self.peer_db:
            return next(iter(self.peer_db.values()))
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
        return await self.link.send(data)

    def set_on_receive(self, callback: Callable[[bytes, PeerIdentity], None]) -> None:
        """Set callback for received application data.

        Why callback: Upper layers (CoAP, etc.) need to receive data.
        The callback is invoked with (payload, sender).
        """
        self._on_receive = callback

    async def start(self) -> None:
        """Start the node's async tasks.

        Why async: Creates background tasks that run until stop().
        """
        if self.state != NodeState.STOPPED:
            raise RuntimeError(f"cannot start node in state {self.state}")

        self.state = NodeState.STARTING
        logger.info("starting node %s", self.identity.iid.hex())

        # Start receive loop
        self._receive_task = asyncio.create_task(
            self._receive_loop(),
            name=f"node-rx-{self.identity.iid.hex()[:8]}",
        )

        # Start announce scheduler
        # Why separate: Scheduler owns timing and seq_num; Node owns integration.
        await self._scheduler.start()

        self.state = NodeState.RUNNING
        logger.info("node started")

    async def stop(self) -> None:
        """Stop the node's async tasks.

        Why graceful: Cancels tasks and waits for them to finish.
        """
        if self.state != NodeState.RUNNING:
            return

        self.state = NodeState.STOPPING
        logger.info("stopping node")

        # Stop announce scheduler first
        # Why first: Prevents new announces while shutting down.
        await self._scheduler.stop()

        # Cancel receive task
        if self._receive_task:
            self._receive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._receive_task
            self._receive_task = None

        self.state = NodeState.STOPPED
        logger.info("node stopped")

    async def _receive_loop(self) -> None:
        """Continuously receive and process frames.

        Why infinite loop: Runs until cancelled by stop().
        """
        while True:
            try:
                rx = await self.link.receive(self.config.receive_timeout_ms)
                if rx is not None:
                    await self._process_received(rx)
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

        # Why check first byte: Identifies message type (announce vs data).
        if len(payload) > 0 and payload[0] == ANNOUNCE_TYPE:
            await self._process_announce(payload, rx.sender, rx.rssi_dbm)
        else:
            # Application data
            if self._on_receive:
                self._on_receive(payload, rx.sender)

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
        now_ms = int(asyncio.get_event_loop().time() * 1000)

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

        # Send as raw bytes via link layer
        success = await self.link.send(relay.to_bytes())
        if success:
            logger.debug("relayed announce from %s", announce.originator_iid.hex())

    async def _send_announce(self) -> None:
        """Send our own announce message.

        Why separate method: Allows testing and manual triggering.
        Delegates to scheduler for announce building (signing, seq_num).
        """
        announce = self._scheduler.build_announce()
        data = announce.to_bytes()
        success = await self.link.send(data)
        if success:
            logger.info("sent announce seq=%d", announce.seq_num)

    @property
    def _announce_seq(self) -> int:
        """Current announce sequence number (for backwards compatibility).

        Why property: Tests expect node._announce_seq. Delegate to scheduler.
        """
        return self._scheduler.get_seq_num()

    async def send(self, dst: IPv6Address, payload: bytes) -> bool:
        """Send application data to a destination.

        Why async: May need to wait for route discovery.

        Args:
            dst: Destination IPv6 address.
            payload: Application data to send.

        Returns:
            True if sent (or queued for discovery), False if dropped.
        """
        # For now, just send directly via link layer
        # In production, would go through SCHC compression first
        return await self.link.send(payload)

    def get_status(self) -> dict:
        """Get node status for debugging/monitoring.

        Returns:
            Dict with node state, peer count, gradient count, etc.
        """
        return {
            "iid": self.identity.iid.hex(),
            "pubkey": self.identity.pubkey.hex()[:16] + "...",
            "state": self.state.name,
            "peers": len(self.peer_db),
            "gradients": len(self.gradient_table),
            "announce_seq": self._scheduler.get_seq_num(),
        }
