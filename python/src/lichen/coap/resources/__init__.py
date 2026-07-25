# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resources for a LICHEN node (spec section 7, RFC 6690).

Exposes ``/.well-known/core`` (resource discovery), ``/status``, ``/neighbors``,
and ``/config``. Payloads use CBOR (content-format 60), the compact encoding
appropriate for constrained LoRa links.

Also provides optional :class:`ProxyResource` compatibility support for local
transports that cannot route directly to mesh IPv6 addresses. The
authoritative LCI mesh access model remains direct IPv6 + CoAP routing through
the local node.

Observable resources (RFC 7641):

* :class:`SenMLSensorsResource` — ``/sensors`` — SenML+CBOR pack of all
  current sensor readings; clients subscribe with ``Observe: 0`` and receive
  pushed updates whenever the node calls :meth:`~SenMLSensorsResource.update`.

* :class:`SenMLLocationResource` — ``/location`` — SenML+CBOR lat/lon/alt pack;
  updated by calling :meth:`~SenMLLocationResource.update`.

* :class:`PresenceResource` — ``/presence`` — CBOR list of recently-heard
  neighbour nodes; updated by calling :meth:`~PresenceResource.seen` whenever a
  beacon arrives from a mesh peer.

* :class:`SosResource` — ``/sos`` — emergency beacon.  POST activates SOS;
  DELETE cancels; GET and Observe let any node monitor the state.

Because the integrated Node class does not exist yet, the local resources read
from an injected :class:`NodeInfo` provider rather than a live node; swap in
a node-backed provider once it lands.
"""

from lichen.coap.resources.base import (
    CBOR,
    SENML_CBOR,
    NodeInfo,
    StaticNodeInfo,
    _cbor_response,
    _ReadResource,
)
from lichen.coap.resources.cbor_validation import (
    _CBOR_MAX_ARRAY_ENTRIES,
    _CBOR_MAX_DEPTH,
    _CBOR_MAX_ENCODED_BYTES,
    _CBOR_MAX_ITEMS,
    _CBOR_MAX_MAP_ENTRIES,
    _cbor_argument,
    _CborScanBudget,
    _decode_single_cbor,
    _scan_cbor_item,
)
from lichen.coap.resources.edhoc import EdhocResource
from lichen.coap.resources.emergency import RollcallResource, SosResource
from lichen.coap.resources.keys import KeyResource
from lichen.coap.resources.messaging import (
    _MESSAGES_MAX,
    LegacyMessagesAliasResource,
    MessageReceiptsResource,
    MessagesResource,
    SentMessageDetailsResource,
    SentMessagesResource,
)
from lichen.coap.resources.node_resources import (
    ConfigResource,
    NeighborsResource,
    StatusResource,
)
from lichen.coap.resources.presence import PresenceResource
from lichen.coap.resources.proxy import ProxyResource, _is_mesh_uri
from lichen.coap.resources.resource_directory import ResourceDirectoryResource
from lichen.coap.resources.senml import (
    SenMLLocationResource,
    SenMLMetricsResource,
    SenMLSensorsResource,
)
from lichen.coap.resources.site import build_site

__all__ = [
    # Constants
    "CBOR",
    "SENML_CBOR",
    # Base classes and protocols
    "NodeInfo",
    "StaticNodeInfo",
    "_cbor_response",
    "_ReadResource",
    # CBOR validation
    "_CBOR_MAX_ARRAY_ENTRIES",
    "_CBOR_MAX_DEPTH",
    "_CBOR_MAX_ENCODED_BYTES",
    "_CBOR_MAX_ITEMS",
    "_CBOR_MAX_MAP_ENTRIES",
    "_cbor_argument",
    "_CborScanBudget",
    "_decode_single_cbor",
    "_scan_cbor_item",
    # Node resources
    "ConfigResource",
    "NeighborsResource",
    "StatusResource",
    # Proxy
    "ProxyResource",
    "_is_mesh_uri",
    # SenML resources
    "SenMLLocationResource",
    "SenMLMetricsResource",
    "SenMLSensorsResource",
    # Presence
    "PresenceResource",
    # Emergency
    "RollcallResource",
    "SosResource",
    # Messaging
    "_MESSAGES_MAX",
    "LegacyMessagesAliasResource",
    "MessageReceiptsResource",
    "MessagesResource",
    "SentMessageDetailsResource",
    "SentMessagesResource",
    # Resource Directory
    "ResourceDirectoryResource",
    # Keys
    "KeyResource",
    # EDHOC
    "EdhocResource",
    # Site builder
    "build_site",
]
