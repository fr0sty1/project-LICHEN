# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
Meshtastic adapter core state machine.

Coordinates BLE GATT service, message translation, and LICHEN node.
Thread-safe queue bridges BLE callbacks and node async tasks.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lichen.interface.meshtastic.address import iid_to_node_num
from lichen.interface.meshtastic.config_sync import (
    AckTracker,
    ConfigSync,
    build_queue_status,
)
from lichen.interface.meshtastic.proto import (
    Data,
    FromRadio,
    MeshPacket,
    NodeInfo,
    ToRadio,
)
from lichen.interface.meshtastic.translate import PortNum, Position, User

if TYPE_CHECKING:
    from lichen.node import Node

log = logging.getLogger(__name__)

# Queue size limits
MAX_QUEUE_SIZE = 64
QUEUE_WARN_THRESHOLD = 48  # 75% - log warning when reached

# Max TX queue for flow control
MAX_TX_QUEUE = 8


@dataclass
class MeshtasticAdapter:
    """Central adapter coordinating GATT, translation, and LICHEN node.

    Thread-safe: BLE callbacks run on BLE thread, node events on node task.
    The from_radio_queue is protected by a lock.

    Attributes:
        node: Reference to the LICHEN node.
        from_radio_queue: Thread-safe queue of FromRadio messages (raw bytes).
        from_num: Counter incremented on new message, notifies BLE clients.
        config_sync_pending: Config request ID awaiting response, if any.
        connected: Whether a BLE client is connected.
    """

    node: Node
    from_radio_queue: deque[bytes] = field(default_factory=deque)
    from_num: int = field(default=0)
    config_sync_pending: int | None = field(default=None)
    connected: bool = field(default=False)

    # Thread safety
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # Notify callback for BLE FromNum characteristic
    _on_from_num_changed: Callable[[], None] | None = field(default=None, repr=False)

    # Config sync state machine (initialized lazily)
    _config_sync: ConfigSync | None = field(default=None, repr=False)

    # ACK tracking for want_ack packets
    _ack_tracker: AckTracker = field(default_factory=AckTracker, repr=False)

    # Message ID counter for outgoing packets
    _next_packet_id: int = field(default=1)

    def _get_config_sync(self) -> ConfigSync:
        """Get or create config sync state machine."""
        if self._config_sync is None:
            self._config_sync = ConfigSync(adapter=self)
        return self._config_sync

    def _gen_packet_id(self) -> int:
        """Generate next packet ID."""
        pkt_id = self._next_packet_id
        self._next_packet_id = (self._next_packet_id + 1) & 0xFFFFFFFF
        if self._next_packet_id == 0:
            self._next_packet_id = 1
        return pkt_id

    def set_on_from_num_changed(self, callback: Callable[[], None] | None) -> None:
        """Set callback invoked when FromNum changes (new message queued)."""
        self._on_from_num_changed = callback

    async def start(self) -> None:
        """Start adapter-owned resources.

        BLE server startup is implemented by the GATT layer; this core adapter
        only owns in-memory state, so start is currently a no-op lifecycle hook.
        """
        log.info("Meshtastic adapter started")

    async def stop(self) -> None:
        """Stop adapter-owned resources and clear connection state."""
        self.on_disconnect()
        log.info("Meshtastic adapter stopped")

    # --- BLE events (called from BLE thread) ---

    def on_connect(self) -> None:
        """Called when a BLE client connects."""
        with self._lock:
            self.connected = True
            self.config_sync_pending = None
            self.from_radio_queue.clear()
            self.from_num = 0
        log.info("Meshtastic client connected")

    def on_disconnect(self) -> None:
        """Called when a BLE client disconnects."""
        with self._lock:
            self.connected = False
            self.config_sync_pending = None
            self.from_radio_queue.clear()
        log.info("Meshtastic client disconnected")

    def on_to_radio(self, data: bytes) -> None:
        """Called when client writes ToRadio data.

        Args:
            data: Raw protobuf bytes (ToRadio message).

        Handles:
            - want_config_id: triggers config sync
            - packet: translates and sends via node
            - disconnect: clears connection state
            - heartbeat: ignored (keepalive)
        """
        if not data:
            return

        log.debug("ToRadio received: %d bytes", len(data))

        try:
            msg = ToRadio.from_bytes(data)
        except Exception as e:
            log.warning("Failed to parse ToRadio: %s", e)
            return

        self._handle_to_radio(msg)

    def _handle_to_radio(self, msg: ToRadio) -> None:
        """Dispatch parsed ToRadio message."""
        if msg.want_config_id is not None:
            self._handle_want_config(msg.want_config_id)
        elif msg.packet is not None:
            self._handle_packet(msg.packet)
        elif msg.disconnect:
            log.info("Disconnect requested by client")
            self.on_disconnect()
        elif msg.heartbeat is not None:
            log.debug("Heartbeat received")
            # Heartbeat is just a keepalive, no response needed
        else:
            log.debug("ToRadio with no recognized payload")

    def _handle_want_config(self, config_id: int) -> None:
        """Handle want_config_id request - start config sync."""
        log.info("Config sync requested: nonce=%d", config_id)

        config_sync = self._get_config_sync()
        config_sync.start(config_id)
        self.config_sync_pending = config_id

        # Generate and queue all config messages
        while config_sync.is_active():
            msg = config_sync.next_message()
            if msg is not None:
                self.queue_from_radio(msg.to_bytes())
            else:
                break

        self.config_sync_pending = None

    def _handle_packet(self, pkt: MeshPacket) -> None:
        """Handle incoming MeshPacket from app."""
        log.debug(
            "Packet received: from=%08x to=%08x id=%08x",
            pkt.from_,
            pkt.to,
            pkt.id,
        )

        # Queue status feedback
        queue_len = len(self.from_radio_queue)
        free_slots = max(0, MAX_TX_QUEUE - queue_len)
        qs = build_queue_status(
            packet_id=pkt.id,
            free=free_slots,
            maxlen=MAX_TX_QUEUE,
            result=0,
        )
        self.queue_from_radio(qs.to_bytes())

        # Track ACK if requested
        if pkt.want_ack and pkt.id != 0:
            self._ack_tracker.track(pkt.id)

        # Dispatch based on decoded payload
        if pkt.decoded is not None:
            self._handle_data_packet(pkt)
        elif pkt.encrypted is not None:
            log.debug("Encrypted packet (not supported): %d bytes", len(pkt.encrypted))

    def _handle_data_packet(self, pkt: MeshPacket) -> None:
        """Handle decoded Data packet."""
        data = pkt.decoded
        if data is None:
            return

        portnum = data.portnum
        payload = data.payload

        if portnum == PortNum.TEXT_MESSAGE_APP:
            log.debug("Text message: %s", payload.decode("utf-8", errors="replace"))
            # TODO: Forward to LICHEN CoAP /msg/inbox
        elif portnum == PortNum.POSITION_APP:
            pos = Position.from_bytes(payload)
            log.debug("Position: lat=%s lon=%s", pos.latitude, pos.longitude)
            # TODO: Integrate with LICHEN announce
        elif portnum == PortNum.NODEINFO_APP:
            user = User.from_bytes(payload)
            log.debug("NodeInfo: id=%s name=%s", user.id, user.long_name)
        elif portnum == PortNum.ROUTING_APP:
            log.debug("Routing message: %d bytes", len(payload))
        else:
            log.debug("Unknown portnum %d: %d bytes", portnum, len(payload))

    def read_from_radio(self) -> bytes | None:
        """Read next FromRadio message from queue.

        Returns:
            Raw protobuf bytes, or None if queue empty.
        """
        with self._lock:
            if self.from_radio_queue:
                return self.from_radio_queue.popleft()
            return None

    def get_from_num(self) -> int:
        """Get current FromNum counter value."""
        with self._lock:
            return self.from_num

    # --- LICHEN node events (called from node async context) ---

    def queue_from_radio(self, data: bytes) -> bool:
        """Queue a FromRadio message and bump FromNum.

        Thread-safe. Invokes notify callback if set.
        Returns False if queue is full (backpressure signal) - does NOT drop.

        Args:
            data: Raw protobuf bytes (FromRadio message).

        Returns:
            True if queued, False if full (caller must retry or handle).
        """
        with self._lock:
            if not self.connected:
                return False
            queue_len = len(self.from_radio_queue)
            if queue_len >= MAX_QUEUE_SIZE:
                log.warning("FromRadio queue full (%d), rejecting message", queue_len)
                return False
            if queue_len >= QUEUE_WARN_THRESHOLD:
                log.warning("FromRadio queue near capacity (%d/%d)", queue_len, MAX_QUEUE_SIZE)
            self.from_radio_queue.append(data)
            self.from_num = (self.from_num + 1) & 0xFFFFFFFF

        # Notify outside lock to avoid deadlock
        if self._on_from_num_changed:
            self._on_from_num_changed()
        return True

    def on_message_received(self, payload: bytes, from_iid: bytes) -> None:
        """Called when LICHEN node receives a message.

        Translates to MeshPacket and queues as FromRadio.

        Args:
            payload: Application payload bytes.
            from_iid: Sender's IID (8 bytes).
        """
        log.debug("Message from %s: %d bytes", from_iid.hex(), len(payload))

        if not self.connected:
            return

        from_node = iid_to_node_num(from_iid)
        my_node = iid_to_node_num(self.node.identity.iid)

        # Treat as text message
        data = Data(
            portnum=PortNum.TEXT_MESSAGE_APP,
            payload=payload,
            source=from_node,
            dest=my_node,
        )
        pkt = MeshPacket(
            from_=from_node,
            to=my_node,
            id=self._gen_packet_id(),
            decoded=data,
            rx_time=int(time.time()),
            hop_limit=3,
        )
        self.queue_from_radio(FromRadio(packet=pkt).to_bytes())

    def on_peer_discovered(self, iid: bytes, pubkey: bytes) -> None:
        """Called when a new peer is discovered.

        Queues NodeInfo as FromRadio.

        Args:
            iid: Peer's IID (8 bytes).
            pubkey: Peer's public key.
        """
        log.debug("Peer discovered: %s", iid.hex())

        if not self.connected:
            return

        node_num = iid_to_node_num(iid)
        user = User(
            id=f"!{node_num:08x}",
            long_name=iid.hex(),
            short_name=iid.hex()[-4:].upper(),
            hw_model=255,  # PRIVATE_HW
        )
        node_info = NodeInfo(
            num=node_num,
            user=user.to_bytes(),
            last_heard=int(time.time()),
        )
        self.queue_from_radio(FromRadio(node_info=node_info.to_bytes()).to_bytes())

    def on_peer_position(self, iid: bytes, lat_e7: int, lon_e7: int, alt_m: int) -> None:
        """Called when a peer's position is updated.

        Queues Position as FromRadio.

        Args:
            iid: Peer's IID (8 bytes).
            lat_e7: Latitude in degrees * 1e7.
            lon_e7: Longitude in degrees * 1e7.
            alt_m: Altitude in meters.
        """
        log.debug("Peer position: %s @ (%d, %d)", iid.hex(), lat_e7, lon_e7)

        if not self.connected:
            return

        from_node = iid_to_node_num(iid)
        my_node = iid_to_node_num(self.node.identity.iid)

        # Build position protobuf
        pos = Position(
            latitude_i=lat_e7,
            longitude_i=lon_e7,
            altitude=alt_m,
            time=int(time.time()),
        )
        data = Data(
            portnum=PortNum.POSITION_APP,
            payload=pos.to_bytes(),
            source=from_node,
        )
        pkt = MeshPacket(
            from_=from_node,
            to=my_node,
            id=self._gen_packet_id(),
            decoded=data,
            rx_time=int(time.time()),
            hop_limit=3,
        )
        self.queue_from_radio(FromRadio(packet=pkt).to_bytes())


def create_adapter(node: Node) -> MeshtasticAdapter:
    """Create and wire up a Meshtastic adapter for a node.

    Call this when Meshtastic feature is enabled. The adapter subscribes
    to node events automatically.

    Args:
        node: The LICHEN node to adapt.

    Returns:
        Configured MeshtasticAdapter instance.
    """
    adapter = MeshtasticAdapter(node=node)

    # Wire up node callbacks
    # ponytail: node.set_on_receive takes (payload, sender) callback
    # We adapt to call on_message_received
    original_callback = getattr(node, "_on_receive", None)

    def on_receive(payload: bytes, sender: object) -> None:
        # Forward to original callback if any
        if original_callback:
            original_callback(payload, sender)
        # Also notify Meshtastic adapter
        iid = getattr(sender, "iid", b"\x00" * 8)
        adapter.on_message_received(payload, iid)

    node.set_on_receive(on_receive)

    log.info("Meshtastic adapter created for node %s", node.identity.iid.hex())
    return adapter
