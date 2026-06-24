# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP application layer for LICHEN (spec section 7).

A custom aiocoap transport that carries CoAP over the LICHEN stack, plus the
node's CoAP resources.
"""

from lichen.coap.resources import (
    ConfigResource,
    NeighborsResource,
    NodeInfo,
    StaticNodeInfo,
    StatusResource,
    build_site,
)
from lichen.coap.schc_channel import SchcChannel, unwrap_coap, wrap_coap
from lichen.coap.transport import (
    DatagramChannel,
    InMemoryChannel,
    InMemoryNetwork,
    LichenRemote,
    LichenTransport,
    create_lichen_context,
)
from lichen.coap.udp_server import bind_coap_udp

__all__ = [
    "ConfigResource",
    "DatagramChannel",
    "InMemoryChannel",
    "InMemoryNetwork",
    "LichenRemote",
    "LichenTransport",
    "NeighborsResource",
    "NodeInfo",
    "SchcChannel",
    "StaticNodeInfo",
    "StatusResource",
    "bind_coap_udp",
    "build_site",
    "create_lichen_context",
    "unwrap_coap",
    "wrap_coap",
]
