# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Site builder for LICHEN CoAP resources."""

from __future__ import annotations

from typing import Any

import aiocoap
from aiocoap import resource

from lichen.coap.resources.base import NodeInfo
from lichen.coap.resources.edhoc import EdhocResource
from lichen.coap.resources.emergency import RollcallResource, SosResource
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
    NeighborsResource,
    StatusResource,
)
from lichen.coap.resources.presence import PresenceResource
from lichen.coap.resources.proxy import ProxyResource
from lichen.coap.resources.resource_directory import ResourceDirectoryResource
from lichen.coap.resources.senml import (
    SenMLLocationResource,
    SenMLMetricsResource,
    SenMLSensorsResource,
)
from lichen.coap.transport import EndpointPolicy


def build_site(
    node_info: NodeInfo,
    *,
    pubkey: bytes | None = None,
    mesh_client: aiocoap.Context | None = None,
    sensors_resource: SenMLSensorsResource | None = None,
    location_resource: SenMLLocationResource | None = None,
    metrics_resource: SenMLMetricsResource | None = None,
    presence_resource: PresenceResource | None = None,
    messages_resource: MessagesResource | None = None,
    message_receipts_resource: MessageReceiptsResource | None = None,
    sos_resource: SosResource | None = None,
    rollcall_resource: RollcallResource | None = None,
    resource_directory: bool = False,
    edhoc_resource: EdhocResource | None = None,
    endpoint_policy: EndpointPolicy | None = None,
    config_allow_writes: bool = False,
) -> resource.Site:
    """Build an aiocoap Site exposing the LICHEN node resources.

    Pass pre-constructed observable resources to expose ``/sensors``,
    ``/location``, ``/metrics``, ``/presence``, ``/msg/inbox``, ``/msg/ack``,
    ``/sos``, and/or ``/rollcall`` for conference demo (messaging, presence,
    rollcall, position beacons with SenML). Callers hold references and call
    update() methods to push LCI notifications. Pass ``rollcall_resource`` to
    enable conference rollcall demo using LCI and SenML per spec 18.
    """
    site = resource.Site()
    site.add_resource(
        [".well-known", "core"],
        resource.WKCResource(site.get_resources_as_linkheader),
    )
    site.add_resource(["status"], StatusResource(node_info))
    site.add_resource(["neighbors"], NeighborsResource(node_info))
    site.add_resource(["config"], ConfigResource(node_info, allow_writes=config_allow_writes))
    if mesh_client is not None:
        site.add_resource(["proxy"], ProxyResource(mesh_client))
    if sensors_resource is not None:
        site.add_resource(["sensors"], sensors_resource)
    if location_resource is not None:
        site.add_resource(["location"], location_resource)
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
