# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Meshtastic protocol translation for LICHEN.

This package provides bidirectional translation between Meshtastic's
protobuf-based messaging and LICHEN's CoAP/announce protocols.

Submodules:
    adapter: Core state machine coordinating GATT, translation, and node
    address: IID ↔ node_num mapping
    config_sync: Config sync state machine for initial handshake
    gatt: BLE GATT service definitions and wire protocol
    proto: Manual protobuf encoding/decoding for Meshtastic messages
    translate: Message translation (text, position, nodeinfo)
"""

from lichen.interface.meshtastic.adapter import (
    MeshtasticAdapter,
    create_adapter,
)
from lichen.interface.meshtastic.address import (
    BROADCAST_NODE_NUM,
    AddressMapper,
    iid_to_node_num,
    iid_to_user_id,
    node_num_to_iid,
)
from lichen.interface.meshtastic.config_sync import (
    ConfigSync,
    ConfigSyncState,
)
from lichen.interface.meshtastic.gatt import (
    FROMNUM_UUID,
    FROMRADIO_UUID,
    SERVICE_UUID,
    TORADIO_UUID,
    GattError,
    MeshtasticGattService,
)
from lichen.interface.meshtastic.proto import (
    Data,
    FromRadio,
    MeshPacket,
    MyNodeInfo,
    NodeInfo,
    ProtoError,
    QueueStatus,
    Routing,
    RoutingError,
    ToRadio,
)
from lichen.interface.meshtastic.translate import (
    PortNum,
    Position,
    TranslationError,
    Translator,
    User,
)

__all__ = [
    # adapter
    "MeshtasticAdapter",
    "create_adapter",
    # address
    "BROADCAST_NODE_NUM",
    "AddressMapper",
    "iid_to_node_num",
    "iid_to_user_id",
    "node_num_to_iid",
    # config_sync
    "ConfigSync",
    "ConfigSyncState",
    # gatt
    "SERVICE_UUID",
    "TORADIO_UUID",
    "FROMRADIO_UUID",
    "FROMNUM_UUID",
    "GattError",
    "MeshtasticGattService",
    # proto
    "Data",
    "FromRadio",
    "MeshPacket",
    "MyNodeInfo",
    "NodeInfo",
    "ProtoError",
    "QueueStatus",
    "Routing",
    "RoutingError",
    "ToRadio",
    # translate
    "PortNum",
    "Position",
    "TranslationError",
    "Translator",
    "User",
]
