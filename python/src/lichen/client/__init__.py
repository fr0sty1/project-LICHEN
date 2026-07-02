# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Shared client model for native LICHEN applications."""

from lichen.client.ble import (
    LICHEN_LCI_PROFILE,
    NUS_LCI_PROFILE,
    BleDeviceCandidate,
    BleLciProfile,
    BlePacketTransport,
    BleTransportError,
    discover_lci_devices,
)
from lichen.client.ip_coap import (
    AiocoapResourceSubscription,
    AiocoapResourceTransport,
    CoapTransportError,
    IpCoapConfig,
)
from lichen.client.lci import (
    LciClient,
    LciClientError,
    MessageSubscription,
    ResourceSubscription,
    ResourceTransport,
)
from lichen.client.model import (
    Capabilities,
    CoapResult,
    ConfigSnapshot,
    ConnectionPhase,
    DeliveryState,
    DeviceStatus,
    Identity,
    MessageDraft,
    MessageRecord,
    Neighbor,
    RadioConfig,
    Route,
    SendResult,
)
from lichen.client.transport import PacketTransport

__all__ = [
    "Capabilities",
    "CoapResult",
    "ConfigSnapshot",
    "ConnectionPhase",
    "DeliveryState",
    "DeviceStatus",
    "Identity",
    "LICHEN_LCI_PROFILE",
    "LciClient",
    "LciClientError",
    "MessageDraft",
    "MessageRecord",
    "MessageSubscription",
    "NUS_LCI_PROFILE",
    "Neighbor",
    "PacketTransport",
    "RadioConfig",
    "ResourceSubscription",
    "ResourceTransport",
    "Route",
    "SendResult",
    "BleDeviceCandidate",
    "BleLciProfile",
    "BlePacketTransport",
    "BleTransportError",
    "AiocoapResourceSubscription",
    "AiocoapResourceTransport",
    "CoapTransportError",
    "IpCoapConfig",
    "discover_lci_devices",
]
