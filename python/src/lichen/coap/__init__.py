# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP application layer for LICHEN (spec section 7).

A custom aiocoap transport that carries CoAP over the LICHEN stack, plus the
node's CoAP resources.

Security (spec section 8.7):
    Use SecureDatagramChannel to wrap any DatagramChannel with OSCORE protection.
    Contexts can be pre-provisioned via add_context() or established via EDHOC.
"""

from lichen.coap.resources import (
    ConfigResource,
    EdhocResource,
    MessageReceiptsResource,
    NeighborsResource,
    NodeInfo,
    StaticNodeInfo,
    StatusResource,
    build_site,
)
from lichen.coap.schc_channel import SchcChannel, unwrap_coap, wrap_coap
from lichen.coap.secure import (
    ContextGenerationError,
    EdhocPeerResolver,
    EndpointPolicyConflictError,
    ForkSafetyError,
    InMemoryOscoreContextStore,
    OscoreContextStore,
    PeerKeyConflictError,
    ReplayWindowConflictError,
    SecureDatagramChannel,
    SequenceReservation,
    SequenceReservationError,
    SqliteOscoreContextStore,
    SqliteStoreHooks,
    TofuPeerResolver,
    TransactionalOscoreContextStore,
    create_secure_channel,
    normalize_host,
    validate_endpoint_key,
)
from lichen.coap.transport import (
    DatagramChannel,
    EndpointPolicy,
    InMemoryChannel,
    InMemoryNetwork,
    LichenRemote,
    LichenTransport,
    create_lichen_context,
)
from lichen.coap.udp_server import bind_coap_udp

__all__ = [
    # Transport
    "DatagramChannel",
    "EndpointPolicy",
    "InMemoryChannel",
    "InMemoryNetwork",
    "LichenRemote",
    "LichenTransport",
    "SchcChannel",
    "create_lichen_context",
    # Security (OSCORE)
    "ContextGenerationError",
    "EdhocPeerResolver",
    "EndpointPolicyConflictError",
    "ForkSafetyError",
    "InMemoryOscoreContextStore",
    "OscoreContextStore",
    "PeerKeyConflictError",
    "ReplayWindowConflictError",
    "SequenceReservation",
    "SequenceReservationError",
    "SecureDatagramChannel",
    "SqliteOscoreContextStore",
    "SqliteStoreHooks",
    "TofuPeerResolver",
    "TransactionalOscoreContextStore",
    "create_secure_channel",
    "normalize_host",
    "validate_endpoint_key",
    # Resources
    "ConfigResource",
    "EdhocResource",
    "MessageReceiptsResource",
    "NeighborsResource",
    "NodeInfo",
    "StaticNodeInfo",
    "StatusResource",
    "build_site",
    # UDP
    "bind_coap_udp",
    # SCHC helpers
    "unwrap_coap",
    "wrap_coap",
]
