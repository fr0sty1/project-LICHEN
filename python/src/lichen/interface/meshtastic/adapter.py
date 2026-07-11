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
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lichen.node import Node

log = logging.getLogger(__name__)

# Queue size limits
MAX_QUEUE_SIZE = 64
QUEUE_WARN_THRESHOLD = 48  # 75% - log warning when reached


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
        """
        if not data:
            return

        # ponytail: defer protobuf parsing until python-88e (betterproto) done
        # For now, just log that we received data
        log.debug("ToRadio received: %d bytes", len(data))

        # TODO: parse ToRadio, dispatch to config sync or packet handler

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
        # ponytail: defer translation until python-8ns done
        log.debug("Message from %s: %d bytes", from_iid.hex(), len(payload))

    def on_peer_discovered(self, iid: bytes, pubkey: bytes) -> None:
        """Called when a new peer is discovered.

        Queues NodeInfo as FromRadio.

        Args:
            iid: Peer's IID (8 bytes).
            pubkey: Peer's public key.
        """
        # ponytail: defer NodeInfo generation until python-8ns done
        log.debug("Peer discovered: %s", iid.hex())

    def on_peer_position(self, iid: bytes, lat_e7: int, lon_e7: int, alt_m: int) -> None:
        """Called when a peer's position is updated.

        Queues Position as FromRadio.

        Args:
            iid: Peer's IID (8 bytes).
            lat_e7: Latitude in degrees * 1e7.
            lon_e7: Longitude in degrees * 1e7.
            alt_m: Altitude in meters.
        """
        # ponytail: defer Position generation until python-8ns done
        log.debug("Peer position: %s @ (%d, %d)", iid.hex(), lat_e7, lon_e7)


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
