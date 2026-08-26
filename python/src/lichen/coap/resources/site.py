# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Site builder for LICHEN CoAP resources."""

from __future__ import annotations

from typing import Any, Protocol

import aiocoap
from aiocoap import Message, resource
from aiocoap.numbers.types import CON

from lichen.coap.params import (
    CongestionLevel,
    CongestionState,
    check_congestion_allows,
    congestion_service_unavailable,
)
from lichen.coap.resources.base import NodeInfo
from lichen.coap.resources.edhoc import EdhocResource
from lichen.coap.resources.emergency import CheckInResource, RollcallResource, SosResource
from lichen.coap.resources.keys import KeyResource
from lichen.coap.resources.messaging import (
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
from lichen.coap.resources.presence import PresenceResource
from lichen.coap.resources.proxy import ProxyResource
from lichen.coap.resources.resource_directory import ResourceDirectoryResource
from lichen.coap.resources.senml import (
    PositionBeaconResource,
    SenMLLocationResource,
    SenMLMetricsResource,
    SenMLSensorsResource,
)
from lichen.coap.transport import EndpointPolicy
from lichen.link.tx_queue import Priority


class CongestionProvider(Protocol):
    """Protocol for objects that provide congestion information."""

    @property
    def congestion_level(self) -> CongestionLevel:
        """Return current duty cycle congestion level."""
        ...

    @property
    def retry_after_ms(self) -> int | None:
        """Return estimated time until duty cycle budget refills (ms)."""
        ...

    def congestion_state(self) -> CongestionState:
        """Return atomic snapshot of congestion level and retry delay (r1-P3-43).

        This method provides an atomic read of both congestion_level and
        retry_after_ms to avoid race conditions when these values are read
        separately in concurrent environments.
        """
        ...


class CongestionAwareSite(resource.Site):
    """A CoAP Site that enforces congestion-based load shedding (spec 07 §10.2.3).

    When duty cycle congestion exceeds thresholds, incoming requests are rejected
    with 5.03 Service Unavailable before reaching resource handlers. This prevents
    the node from accepting work it cannot complete (response transmission would
    be blocked by duty cycle limits).

    Priority mapping per spec:
    - CON requests: Priority.URGENT (P2)
    - NON requests: Priority.NORMAL (P3)

    Load shedding rules:
    - NORMAL: all traffic allowed
    - ELEVATED: shed NORMAL/BULK priority (P3-P4), allow URGENT+ (P0-P2)
    - CRITICAL: only SOS/ROUTING (P0-P1)
    - EXHAUSTED: block all

    SECURITY: This is a denial-of-service mitigation, not an attack vector.
    The congestion check runs on the *receiving* node's local duty cycle state,
    preventing commitment to work the node cannot fulfill.
    """

    def __init__(self, congestion_provider: CongestionProvider | None = None) -> None:
        """Create a congestion-aware site.

        Args:
            congestion_provider: Object providing congestion_level and retry_after_ms.
                If None, no congestion checking is performed (always allows requests).
        """
        super().__init__()
        self._congestion_provider = congestion_provider

    async def render(self, request: Message) -> Message:
        """Check congestion before dispatching to resources.

        If congestion level blocks the request priority, returns 5.03 immediately
        without invoking the resource handler.
        """
        if self._congestion_provider is not None:
            # Use atomic read to ensure level and retry_after_ms are consistent (r1-P3-43)
            state = self._congestion_provider.congestion_state()
            # Map request type to priority per spec §10.2.3
            # CON -> URGENT (P2), NON -> NORMAL (P3)
            priority = Priority.URGENT if request.mtype == CON else Priority.NORMAL
            if not check_congestion_allows(state.level, priority):
                retry_after_s = (
                    (state.retry_after_ms + 999) // 1000
                    if state.retry_after_ms is not None
                    else None
                )
                return congestion_service_unavailable(state.level, retry_after_s)
        return await super().render(request)


def build_site(
    node_info: NodeInfo,
    *,
    pubkey: bytes | None = None,
    mesh_client: aiocoap.Context | None = None,
    neighbors_resource: NeighborsResource | None = None,
    sensors_resource: SenMLSensorsResource | None = None,
    location_resource: SenMLLocationResource | None = None,
    position_beacon_resource: PositionBeaconResource | None = None,
    position_cache_resource: PositionCacheResource | None = None,
    metrics_resource: SenMLMetricsResource | None = None,
    presence_resource: PresenceResource | None = None,
    messages_resource: MessagesResource | None = None,
    message_receipts_resource: MessageReceiptsResource | None = None,
    sos_resource: SosResource | None = None,
    rollcall_resource: RollcallResource | None = None,
    checkin_resource: CheckInResource | None = None,
    resource_directory: bool = False,
    edhoc_resource: EdhocResource | None = None,
    endpoint_policy: EndpointPolicy | None = None,
    config_allow_writes: bool = False,
    radio_config_allow_writes: bool = False,
    congestion_provider: CongestionProvider | None = None,
) -> resource.Site:
    """Build an aiocoap Site exposing the LICHEN node resources.

    Pass pre-constructed observable resources to expose ``/sensors``,
    ``/sensors/location`` (plus the historical ``/location`` alias), ``/metrics``,
    ``/presence``, ``/msg/inbox``, ``/msg/ack``, ``/sos``, ``/rollcall``, and/or
    ``/checkin`` for conference demo (messaging, presence, rollcall, check-in,
    position beacons with SenML). Callers hold references and call update()
    methods to push LCI notifications. Pass ``rollcall_resource`` to enable
    conference rollcall demo using LCI and SenML per spec 18.

    Pass ``neighbors_resource`` to hold a reference for calling
    :meth:`NeighborsResource.notify_changed` when neighbours change.

    Args:
        neighbors_resource: Optional pre-constructed NeighborsResource for
            CoAP Observe support. If None, a default resource is created.
        congestion_provider: If provided, the site will check congestion level
            before processing requests and return 5.03 Service Unavailable when
            duty cycle congestion exceeds thresholds (spec 07 §10.2.3).
    """
    site: resource.Site
    if congestion_provider is not None:
        site = CongestionAwareSite(congestion_provider)
    else:
        site = resource.Site()
    site.add_resource(
        [".well-known", "core"],
        resource.WKCResource(site.get_resources_as_linkheader),
    )
    site.add_resource(["status"], StatusResource(node_info))
    site.add_resource(
        ["status", "neighbors"],
        neighbors_resource if neighbors_resource is not None else NeighborsResource(node_info),
    )
    site.add_resource(["status", "routes"], RoutesResource(node_info))
    site.add_resource(["config"], ConfigResource(node_info, allow_writes=config_allow_writes))
    site.add_resource(
        ["config", "radio"],
        RadioConfigResource(node_info, allow_writes=radio_config_allow_writes),
    )
    site.add_resource(["config", "identity"], IdentityConfigResource(node_info))
    if mesh_client is not None:
        site.add_resource(["proxy"], ProxyResource(mesh_client))
    if sensors_resource is not None:
        site.add_resource(["sensors"], sensors_resource)
    if location_resource is not None:
        site.add_resource(["sensors", "location"], location_resource)
        # Compatibility with early Python clients, before the resource path was
        # aligned with appendix-senml F.3 and applications section 18.2.
        site.add_resource(["location"], location_resource)
    if position_beacon_resource is not None:
        site.add_resource(["pos"], position_beacon_resource)
    if position_cache_resource is not None:
        site.add_resource(["pos", "cache"], position_cache_resource)
    if metrics_resource is not None:
        site.add_resource(["metrics"], metrics_resource)
    if presence_resource is not None:
        site.add_resource(["presence"], presence_resource)
    if messages_resource is not None:

        def register_sent_detail(msg_id: str, message: dict[str, Any]) -> None:
            pass  # handled by SentMessageDetailsResource (PathCapable)

        messages_resource.set_sent_detail_registrar(register_sent_detail)
        legacy_messages = LegacyMessagesAliasResource(messages_resource)
        messages_resource.register_legacy_alias(legacy_messages)
        site.add_resource(["msg", "inbox"], messages_resource)
        site.add_resource(["msg", "sent"], SentMessagesResource(messages_resource))
        site.add_resource(["msg", "sent"], SentMessageDetailsResource(messages_resource))
        site.add_resource(["messages"], legacy_messages)
    if message_receipts_resource is not None:
        site.add_resource(["msg", "ack"], message_receipts_resource)
    if sos_resource is not None:
        site.add_resource(["sos"], sos_resource)
    if rollcall_resource is not None:
        site.add_resource(["rollcall"], rollcall_resource)
    if checkin_resource is not None:
        site.add_resource(["checkin"], checkin_resource)
    if resource_directory:

        def remove_rd_registration(reg_id: str) -> None:
            site.remove_resource(["rd", reg_id])

        site.add_resource(
            ["rd"],
            ResourceDirectoryResource(site, route_remover=remove_rd_registration),
        )
    if pubkey is not None:
        site.add_resource(["keys"], KeyResource(pubkey))
    if edhoc_resource is not None:
        if endpoint_policy is not None:
            edhoc_resource.bind_endpoint_policy(endpoint_policy)
        site.add_resource([".well-known", "edhoc"], edhoc_resource)
    return site
