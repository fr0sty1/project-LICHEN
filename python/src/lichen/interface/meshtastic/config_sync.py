# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Meshtastic config sync state machine.

Handles the initial handshake when a Meshtastic app connects:
1. App sends ToRadio.want_config_id = nonce
2. Device replies with FromRadio sequence: my_info, metadata, node_info(s),
   config sections, module_config, channels, then config_complete_id = nonce

The nonce can be:
- Legacy: 69420 or 69421 (original Meshtastic protocol, now deprecated)
- Modern: Random 32-bit value from app

LICHEN nodes respond with minimal config - we present as a "PRIVATE_HW"
device with no channels, simplified config, and synthesized node info
from known LICHEN peers.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import TYPE_CHECKING

from lichen.interface.meshtastic.address import iid_to_node_num
from lichen.interface.meshtastic.proto import (
    Data,
    DeviceMetadata,
    FromRadio,
    MeshPacket,
    MyNodeInfo,
    NodeInfo,
    QueueStatus,
)
from lichen.interface.meshtastic.translate import PortNum, User

if TYPE_CHECKING:
    from lichen.interface.meshtastic.adapter import MeshtasticAdapter

log = logging.getLogger(__name__)

# Legacy nonce values (deprecated but still used by older apps)
LEGACY_NONCE_A = 69420
LEGACY_NONCE_B = 69421

# Firmware version we claim to be
FIRMWARE_VERSION = "2.5.0.lichen"

# Minimum app version we require
MIN_APP_VERSION = 30200  # 2.5.x

# Hardware model: PRIVATE_HW (255) indicates custom/private hardware
HW_MODEL_PRIVATE = 255

# Device state version
DEVICE_STATE_VERSION = 1

# Max TX queue size
MAX_TX_QUEUE = 8


class ConfigSyncState(IntEnum):
    """Config sync state machine states."""

    IDLE = auto()
    SENDING_MY_INFO = auto()
    SENDING_METADATA = auto()
    SENDING_NODE_INFO = auto()
    SENDING_CONFIG = auto()
    SENDING_MODULE_CONFIG = auto()
    SENDING_CHANNELS = auto()
    SENDING_COMPLETE = auto()
    DONE = auto()


@dataclass
class ConfigSync:
    """Config sync state machine.

    Produces FromRadio messages in response to want_config_id.

    Attributes:
        adapter: Parent adapter for accessing node state.
        config_id: Current config request nonce (None if not syncing).
        state: Current state machine state.
    """

    adapter: MeshtasticAdapter
    config_id: int | None = None
    state: ConfigSyncState = ConfigSyncState.IDLE
    _from_radio_id: int = field(default=0)
    _node_info_iter: Iterator[bytes] | None = field(default=None, repr=False)

    def _next_id(self) -> int:
        """Generate next FromRadio message ID."""
        self._from_radio_id = (self._from_radio_id + 1) & 0xFFFFFFFF
        return self._from_radio_id

    def start(self, config_id: int) -> None:
        """Start config sync with given nonce.

        Args:
            config_id: Config request nonce from ToRadio.want_config_id.
        """
        is_legacy = config_id in (LEGACY_NONCE_A, LEGACY_NONCE_B)
        log.info(
            "Config sync started: nonce=%d%s",
            config_id,
            " (legacy)" if is_legacy else "",
        )
        self.config_id = config_id
        self.state = ConfigSyncState.SENDING_MY_INFO
        self._node_info_iter = None

    def cancel(self) -> None:
        """Cancel ongoing config sync."""
        if self.config_id is not None:
            log.debug("Config sync cancelled")
        self.config_id = None
        self.state = ConfigSyncState.IDLE
        self._node_info_iter = None

    def is_active(self) -> bool:
        """Check if config sync is in progress."""
        return self.config_id is not None and self.state != ConfigSyncState.DONE

    def next_message(self) -> FromRadio | None:
        """Generate next FromRadio message in sequence.

        Returns:
            Next FromRadio, or None if sync complete or not active.
        """
        if self.config_id is None:
            return None

        while True:
            if self.state == ConfigSyncState.SENDING_MY_INFO:
                self.state = ConfigSyncState.SENDING_METADATA
                return self._build_my_info()

            elif self.state == ConfigSyncState.SENDING_METADATA:
                self.state = ConfigSyncState.SENDING_NODE_INFO
                self._node_info_iter = self._iter_node_info()
                return self._build_metadata()

            elif self.state == ConfigSyncState.SENDING_NODE_INFO:
                if self._node_info_iter is not None:
                    try:
                        node_info_bytes = next(self._node_info_iter)
                        return FromRadio(id=self._next_id(), node_info=node_info_bytes)
                    except StopIteration:
                        self._node_info_iter = None
                self.state = ConfigSyncState.SENDING_COMPLETE
                continue

            elif self.state == ConfigSyncState.SENDING_COMPLETE:
                self.state = ConfigSyncState.DONE
                return self._build_config_complete()

            return None

    def _build_my_info(self) -> FromRadio:
        """Build MyNodeInfo message."""
        node_num = iid_to_node_num(self.adapter.node.identity.iid)
        my_info = MyNodeInfo(
            my_node_num=node_num,
            reboot_count=1,
            min_app_version=MIN_APP_VERSION,
        )
        return FromRadio(id=self._next_id(), my_info=my_info)

    def _build_metadata(self) -> FromRadio:
        """Build DeviceMetadata message."""
        metadata = DeviceMetadata(
            firmware_version=FIRMWARE_VERSION,
            device_state_version=DEVICE_STATE_VERSION,
            can_shutdown=False,
            has_wifi=False,
            has_bluetooth=True,
            has_ethernet=False,
            role=0,  # CLIENT
            position_flags=0,
            hw_model=HW_MODEL_PRIVATE,
            has_remote_hardware=False,
        )
        return FromRadio(id=self._next_id(), metadata=metadata)

    def _iter_node_info(self) -> Iterator[bytes]:
        """Iterate over NodeInfo messages for known peers.

        Yields raw NodeInfo protobuf bytes.
        """
        # First, our own node info
        my_iid = self.adapter.node.identity.iid
        my_node_num = iid_to_node_num(my_iid)
        my_user = User(
            id=f"!{my_node_num:08x}",
            long_name=my_iid.hex(),
            short_name=my_iid.hex()[-4:].upper(),
            hw_model=HW_MODEL_PRIVATE,
        )
        my_node_info = NodeInfo(
            num=my_node_num,
            user=my_user.to_bytes(),
            last_heard=int(time.time()),
        )
        yield my_node_info.to_bytes()

        # Then known peers (if any)
        # LICHEN node exposes peers via get_peers() or similar
        # For now, we don't have this interface, so skip

    def _build_config_complete(self) -> FromRadio:
        """Build config_complete_id message."""
        return FromRadio(id=self._next_id(), config_complete_id=self.config_id)


@dataclass
class AckTracker:
    """Track pending ACK requests.

    When want_ack is set on outgoing packets, tracks the request_id
    so we can generate routing ACK/NAK when delivery succeeds/fails.
    """

    pending: dict[int, float] = field(default_factory=dict)  # request_id -> timestamp
    timeout_secs: float = 30.0

    def track(self, request_id: int) -> None:
        """Start tracking an ACK request."""
        self.pending[request_id] = time.monotonic()

    def complete(self, request_id: int) -> bool:
        """Mark ACK request as complete.

        Returns True if this was a tracked request.
        """
        return self.pending.pop(request_id, None) is not None

    def get_expired(self) -> list[int]:
        """Get list of expired (timed out) request IDs."""
        now = time.monotonic()
        expired = [
            req_id
            for req_id, ts in self.pending.items()
            if now - ts > self.timeout_secs
        ]
        for req_id in expired:
            del self.pending[req_id]
        return expired


def build_queue_status(
    packet_id: int = 0,
    free: int = MAX_TX_QUEUE,
    maxlen: int = MAX_TX_QUEUE,
    result: int = 0,
) -> FromRadio:
    """Build a QueueStatus FromRadio message.

    Used to provide flow control feedback to the app.

    Args:
        packet_id: ID of the packet this status refers to.
        free: Number of free queue slots.
        maxlen: Maximum queue length.
        result: Result code of last send (0 = success).

    Returns:
        FromRadio with queue_status populated.
    """
    return FromRadio(
        queue_status=QueueStatus(
            res=result,
            free=free,
            maxlen=maxlen,
            mesh_packet_id=packet_id,
        )
    )


def build_routing_ack(
    request_id: int,
    from_: int,
    to: int,
) -> FromRadio:
    """Build a routing ACK packet.

    Args:
        request_id: ID of the packet being acknowledged.
        from_: Node that sent the ACK.
        to: Node that receives the ACK.

    Returns:
        FromRadio containing routing ACK as a MeshPacket.
    """
    from lichen.interface.meshtastic.proto import Routing, RoutingError

    routing = Routing(error_reason=RoutingError.NONE)
    data = Data(
        portnum=PortNum.ROUTING_APP,
        payload=routing.to_bytes(),
        request_id=request_id,
    )
    pkt = MeshPacket(
        from_=from_,
        to=to,
        id=request_id,  # Use same ID for ACK
        decoded=data,
    )
    return FromRadio(packet=pkt)


def build_routing_nak(
    request_id: int,
    from_: int,
    to: int,
    error: int = 3,  # TIMEOUT by default
) -> FromRadio:
    """Build a routing NAK packet.

    Args:
        request_id: ID of the packet that failed.
        from_: Node that sent the NAK.
        to: Node that receives the NAK.
        error: RoutingError code.

    Returns:
        FromRadio containing routing NAK as a MeshPacket.
    """
    from lichen.interface.meshtastic.proto import Routing, RoutingError

    routing = Routing(error_reason=RoutingError(error))
    data = Data(
        portnum=PortNum.ROUTING_APP,
        payload=routing.to_bytes(),
        request_id=request_id,
    )
    pkt = MeshPacket(
        from_=from_,
        to=to,
        id=request_id,
        decoded=data,
    )
    return FromRadio(packet=pkt)
