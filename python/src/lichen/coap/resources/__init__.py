# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resources for a LICHEN node (spec section 7, RFC 6690).

Exposes ``/.well-known/core`` (resource discovery), ``/status``,
``/status/neighbors``, ``/status/routes``, and ``/config``. Payloads use
CBOR (content-format 60), the compact encoding appropriate for constrained
LoRa links.

Also provides optional :class:`ProxyResource` compatibility support for local
transports that cannot route directly to mesh IPv6 addresses. The
authoritative LCI mesh access model remains direct IPv6 + CoAP routing through
the local node.

Observable resources (RFC 7641):

* :class:`SenMLSensorsResource` — ``/sensors`` — SenML+CBOR pack of all
  current sensor readings; clients subscribe with ``Observe: 0`` and receive
  pushed updates whenever the node calls :meth:`~SenMLSensorsResource.update`.

* :class:`SenMLLocationResource` — ``/sensors/location`` — observable
  SenML+CBOR position pack; updated by calling
  :meth:`~SenMLLocationResource.update`. ``/location`` remains a compatibility
  alias.

* :class:`PresenceResource` — ``/presence`` — own presence GET/PUT (status,
  activity, msg, battery, ts); updated by PUT or automatic status (spec 18.5).

* :class:`PresenceCacheResource` — ``/presence/cache`` — CBOR map of known
  neighbour presence with ``age_s``; updated by :meth:`PresenceCacheResource.record`.

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
from lichen.coap.resources.confessions import (
    CONFESSION_COOLDOWN_S,
    CONFESSION_DEFAULT_TTL,
    CONFESSION_HOURLY_MAX,
    CONFESSION_MAX_SIZE,
    CONFESSION_MAX_TTL,
    CONFESSION_STORAGE_BR,
    CONFESSION_STORAGE_LEAF,
    ConfessionsResource,
)
from lichen.coap.resources.deaddrop import (
    DEADDROP_DEFAULT_TTL,
    DEADDROP_MAX_DROP_SIZE,
    DEADDROP_MAX_TTL,
    DEADDROP_POSTS_PER_HOUR,
    DEADDROP_STORAGE_BR,
    DEADDROP_STORAGE_LEAF,
    DeadDropDetailsResource,
    DeadDropResource,
)
from lichen.coap.resources.edhoc import EdhocResource
from lichen.coap.resources.emergency import (
    CHECKIN_STATUS_VALUES,
    MAX_CHECKINS,
    CheckInResource,
    RollcallResource,
    SosResource,
)
from lichen.coap.resources.keys import KeyResource, KeyStoreResource
from lichen.coap.resources.messaging import (
    _MESSAGES_MAX,
    MESSAGES_MAX_BODY_SIZE,
    CannedMessagesResource,
    LegacyMessagesAliasResource,
    MessageReceiptsResource,
    MessagesResource,
    SentMessageDetailsResource,
    SentMessagesResource,
)
from lichen.coap.resources.node_resources import (
    ConfigResource,
    IdentityConfigResource,
    NeighborsResource,
    RadioConfigResource,
    RoutesResource,
    StatusResource,
)
from lichen.coap.resources.position import PositionCacheResource
from lichen.coap.resources.presence import PresenceCacheResource, PresenceResource
from lichen.coap.resources.proxy import ProxyResource, _is_mesh_uri
from lichen.coap.resources.rangetest import (
    DEFAULT_INTERVAL_MS,
    MAX_COUNT,
    MAX_PAYLOAD_LEN,
    RadioMetrics,
    RadioMetricsProvider,
    RangeTestResource,
    TracerouteHop,
    TracerouteResource,
)
from lichen.coap.resources.resource_directory import ResourceDirectoryResource
from lichen.coap.resources.senml import (
    PositionBeaconResource,
    SenMLLocationResource,
    SenMLMetricsResource,
    SenMLSensorsResource,
)
from lichen.coap.resources.site import (
    CongestionAwareSite,
    CongestionProvider,
    build_site,
)
from lichen.coap.resources.waypoints import (
    WaypointDetailsResource,
    WaypointsResource,
)

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
    "IdentityConfigResource",
    "NeighborsResource",
    "RadioConfigResource",
    "RoutesResource",
    "StatusResource",
    # Proxy
    "ProxyResource",
    "_is_mesh_uri",
    # SenML resources
    "PositionBeaconResource",
    "SenMLLocationResource",
    "SenMLMetricsResource",
    "SenMLSensorsResource",
    # Position
    "PositionCacheResource",
    # Presence
    "PresenceCacheResource",
    "PresenceResource",
    # Emergency
    "CHECKIN_STATUS_VALUES",
    "CheckInResource",
    "MAX_CHECKINS",
    "RollcallResource",
    "SosResource",
    # Messaging
    "_MESSAGES_MAX",
    "MESSAGES_MAX_BODY_SIZE",
    "CannedMessagesResource",
    "LegacyMessagesAliasResource",
    "MessageReceiptsResource",
    "MessagesResource",
    "SentMessageDetailsResource",
    "SentMessagesResource",
    # Resource Directory
    "ResourceDirectoryResource",
    # Keys
    "KeyResource",
    "KeyStoreResource",
    # EDHOC
    "EdhocResource",
    # Confessions
    "CONFESSION_COOLDOWN_S",
    "CONFESSION_DEFAULT_TTL",
    "CONFESSION_HOURLY_MAX",
    "CONFESSION_MAX_SIZE",
    "CONFESSION_MAX_TTL",
    "CONFESSION_STORAGE_BR",
    "CONFESSION_STORAGE_LEAF",
    "ConfessionsResource",
    # Site builder
    "build_site",
    # Congestion-aware site
    "CongestionAwareSite",
    "CongestionProvider",
    # Dead Drop
    "DEADDROP_DEFAULT_TTL",
    "DEADDROP_MAX_DROP_SIZE",
    "DEADDROP_MAX_TTL",
    "DEADDROP_POSTS_PER_HOUR",
    "DEADDROP_STORAGE_BR",
    "DEADDROP_STORAGE_LEAF",
    "DeadDropDetailsResource",
    "DeadDropResource",
    # Waypoints
    "WaypointDetailsResource",
    "WaypointsResource",
    # Range Testing
    "DEFAULT_INTERVAL_MS",
    "MAX_COUNT",
    "MAX_PAYLOAD_LEN",
    "RadioMetrics",
    "RadioMetricsProvider",
    "RangeTestResource",
    "TracerouteHop",
    "TracerouteResource",
]
