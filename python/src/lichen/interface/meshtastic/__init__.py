# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Meshtastic protocol translation for LICHEN.

This package provides bidirectional translation between Meshtastic's
protobuf-based messaging and LICHEN's CoAP/announce protocols.

Submodules:
    address: IID ↔ node_num mapping
    translate: Message translation (text, position, nodeinfo)
"""

from lichen.interface.meshtastic.address import (
    BROADCAST_NODE_NUM,
    AddressMapper,
    iid_to_node_num,
    iid_to_user_id,
    node_num_to_iid,
)
from lichen.interface.meshtastic.translate import (
    PortNum,
    TranslationError,
    Translator,
)

__all__ = [
    "BROADCAST_NODE_NUM",
    "AddressMapper",
    "PortNum",
    "TranslationError",
    "Translator",
    "iid_to_node_num",
    "iid_to_user_id",
    "node_num_to_iid",
]
