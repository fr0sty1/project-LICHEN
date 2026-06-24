# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP resources for a LICHEN node (spec section 7, RFC 6690).

Exposes ``/.well-known/core`` (resource discovery), ``/status``, ``/neighbors``,
and ``/config``. Payloads use CBOR (content-format 60), the compact encoding
appropriate for constrained LoRa links.

Also provides :class:`ProxyResource` — a forward proxy (RFC 7252 §5.7) that
lets a local client reach any mesh node by passing a ``Proxy-Uri`` option.

Observable resources (RFC 7641):

* :class:`SenMLSensorsResource` — ``/sensors`` — SenML+CBOR pack of all
  current sensor readings; clients subscribe with ``Observe: 0`` and receive
  pushed updates whenever the node calls :meth:`~SenMLSensorsResource.update`.

* :class:`SenMLLocationResource` — ``/location`` — SenML+CBOR lat/lon/alt pack;
  updated by calling :meth:`~SenMLLocationResource.update`.

* :class:`PresenceResource` — ``/presence`` — CBOR list of recently-heard
  neighbour nodes; updated by calling :meth:`~PresenceResource.seen` whenever a
  beacon arrives from a mesh peer.

Because the integrated Node class does not exist yet, the local resources read
from an injected :class:`NodeInfo` provider rather than a live node; swap in
a node-backed provider once it lands.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Protocol

import aiocoap
import cbor2
from aiocoap import BAD_GATEWAY, BAD_REQUEST, CHANGED, CONTENT, Message, resource
from aiocoap.numbers import ContentFormat

CBOR = ContentFormat.CBOR
SENML_CBOR = ContentFormat(112)  # application/senml+cbor (RFC 8428)


class NodeInfo(Protocol):
    """Data source backing the CoAP resources."""

    def get_status(self) -> dict[str, Any]: ...
    def get_neighbors(self) -> list[dict[str, Any]]: ...
    def get_config(self) -> dict[str, Any]: ...
    def set_config(self, updates: dict[str, Any]) -> None: ...


@dataclass
class StaticNodeInfo:
    """A simple in-memory :class:`NodeInfo` for tests and single-node sims."""

    status: dict[str, Any] = field(default_factory=dict)
    neighbors: list[dict[str, Any]] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)

    def get_status(self) -> dict[str, Any]:
        return dict(self.status)

    def get_neighbors(self) -> list[dict[str, Any]]:
        return [dict(n) for n in self.neighbors]

    def get_config(self) -> dict[str, Any]:
        return dict(self.config)

    def set_config(self, updates: dict[str, Any]) -> None:
        self.config.update(updates)


def _cbor_response(value: Any) -> Message:
    msg = Message(code=CONTENT, payload=cbor2.dumps(value))
    msg.opt.content_format = CBOR
    return msg


class _ReadResource(resource.Resource):
    """A read-only CBOR resource advertising a resource type."""

    rt = "lichen"

    def __init__(self, node_info: NodeInfo) -> None:
        super().__init__()
        self.node_info = node_info

    def get_link_description(self) -> dict[str, Any]:
        # Link-format attribute values are strings (RFC 6690).
        return {"rt": self.rt, "ct": str(int(CBOR))}


class StatusResource(_ReadResource):
    """``/status`` — node status (uptime, rank, parent, battery, ...)."""

    rt = "lichen.status"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_status())


class NeighborsResource(_ReadResource):
    """``/neighbors`` — the neighbour table."""

    rt = "lichen.neighbors"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_neighbors())


class ConfigResource(_ReadResource):
    """``/config`` — node configuration (GET to read, PUT to update)."""

    rt = "lichen.config"

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_config())

    async def render_put(self, request: Message) -> Message:
        updates = cbor2.loads(request.payload) if request.payload else {}
        if not isinstance(updates, dict):
            return Message(code=CHANGED)  # ignore non-object bodies
        self.node_info.set_config(updates)
        return Message(code=CHANGED)


class ProxyResource(resource.Resource):
    """CoAP forward proxy — relays requests with Proxy-Uri into the mesh.

    A local client (phone, desktop) sends a request to ``/proxy`` on the
    gateway with a ``Proxy-Uri`` option naming the target mesh node::

        GET coap://[gateway]/proxy
        Proxy-Uri: coap://[fd00::2]/status

    The gateway forwards the request via its mesh-side aiocoap context and
    relays the response — including any CoAP error codes from the target.
    The ``mesh_ctx`` must be a context whose transport can route to mesh nodes
    (e.g. a :class:`~lichen.coap.transport.LichenTransport` backed by a
    :class:`~lichen.coap.node_channel.NodeChannel`).

    Per RFC 7252 §5.7, the Proxy-Uri option is stripped before forwarding.
    """

    def __init__(self, mesh_ctx: aiocoap.Context, *, timeout: float = 30.0) -> None:
        super().__init__()
        self._mesh_ctx = mesh_ctx
        self._timeout = timeout

    async def render(self, request: Message) -> Message:
        target = request.opt.proxy_uri
        if not target:
            return Message(code=BAD_REQUEST)

        fwd = Message(code=request.code, uri=target, payload=request.payload)
        if request.opt.content_format is not None:
            fwd.opt.content_format = request.opt.content_format

        try:
            response = await asyncio.wait_for(
                self._mesh_ctx.request(fwd).response,
                timeout=self._timeout,
            )
        except Exception:
            return Message(code=BAD_GATEWAY)

        relay = Message(code=response.code, payload=response.payload)
        if response.opt.content_format is not None:
            relay.opt.content_format = response.opt.content_format
        return relay


class SenMLSensorsResource(resource.ObservableResource):
    """Observable ``/sensors`` — SenML+CBOR pack of all current readings.

    Callers push new readings by calling :meth:`update`; all registered CoAP
    observers receive a notification automatically (RFC 7641).

    Example::

        sensors = SenMLSensorsResource()
        site = build_site(info, sensors_resource=sensors)
        # ... later, when readings change:
        sensors.update([temperature(23.4), humidity(61.0)])
    """

    def __init__(self) -> None:
        super().__init__()
        self._records: list[Any] = []

    def update(self, records: list[Any]) -> None:
        """Replace the current readings and notify all observers.

        Args:
            records: List of :class:`~lichen.senml.codec.SenmlRecord`.
        """
        from lichen.senml.codec import pack
        self._records = records
        self._payload = pack(records)
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        from lichen.senml.codec import pack
        payload = getattr(self, "_payload", pack([]))
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = SENML_CBOR
        return msg


class SenMLLocationResource(resource.ObservableResource):
    """Observable ``/location`` — SenML+CBOR lat/lon(/alt) pack.

    Callers push position fixes by calling :meth:`update`.

    Example::

        loc = SenMLLocationResource()
        site = build_site(info, location_resource=loc)
        loc.update(lat=48.2049, lon=16.3710, alt=158.0)
    """

    def __init__(self) -> None:
        super().__init__()
        self._payload: bytes = b""

    def update(self, lat: float, lon: float, alt: float | None = None) -> None:
        """Set the current position and notify all observers.

        Args:
            lat: Latitude in decimal degrees (WGS-84).
            lon: Longitude in decimal degrees (WGS-84).
            alt: Altitude in metres above WGS-84 ellipsoid, or None to omit.
        """
        from lichen.senml.codec import pack
        from lichen.senml.profiles import location
        self._payload = pack(location(lat, lon, alt))
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=self._payload)
        msg.opt.content_format = SENML_CBOR
        return msg


class PresenceResource(resource.ObservableResource):
    """Observable ``/presence`` — CBOR list of recently-heard mesh nodes.

    Each entry is a plain dict serialised to CBOR::

        {"id": "<hex-eui64>", "rank": 256, "t": 1700000000.0}

    An optional ``"rssi"`` key (integer dBm) is included when the caller
    provides it.  Entries are keyed internally by the hex EUI-64 string so
    a later :meth:`seen` call for the same node overwrites the old entry.

    Example::

        presence = PresenceResource()
        site = build_site(info, presence_resource=presence)
        # When a beacon arrives from a neighbour:
        presence.seen(bytes.fromhex("0102030405060708"), rank=256, t=1700000000.0)
    """

    def __init__(self) -> None:
        super().__init__()
        self._peers: dict[str, dict[str, Any]] = {}

    def seen(
        self,
        eui64: bytes,
        rank: int,
        t: float,
        rssi: int | None = None,
    ) -> None:
        """Record or refresh a peer's presence and notify observers.

        Args:
            eui64: 8-byte EUI-64 identifier of the peer.
            rank:  RPL rank of the peer node.
            t:     Unix timestamp of the observation.
            rssi:  Received signal strength in dBm, or ``None`` if unknown.
        """
        entry: dict[str, Any] = {"id": eui64.hex(), "rank": rank, "t": t}
        if rssi is not None:
            entry["rssi"] = rssi
        self._peers[eui64.hex()] = entry
        self.updated_state()

    def evict(self, eui64: bytes) -> None:
        """Remove a peer from the presence table and notify observers.

        No-op if the peer is not in the table.
        """
        if self._peers.pop(eui64.hex(), None) is not None:
            self.updated_state()

    def purge_older_than(self, cutoff_t: float) -> int:
        """Remove entries with ``t < cutoff_t`` and notify if any were removed.

        Returns the number of entries evicted.
        """
        stale = [k for k, v in self._peers.items() if v["t"] < cutoff_t]
        for k in stale:
            del self._peers[k]
        if stale:
            self.updated_state()
        return len(stale)

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=cbor2.dumps(list(self._peers.values())))
        msg.opt.content_format = CBOR
        return msg


_MESSAGES_MAX = 100  # maximum inbox depth


class MessagesResource(resource.ObservableResource):
    """Observable ``/messages`` — CBOR inbox with POST-to-send.

    Each message is a CBOR map::

        {"from": "<hex-eui64>", "to": "<hex-eui64> | all", "text": "...", "t": <float>}

    **GET** returns the inbox (most recent :data:`_MESSAGES_MAX` messages, oldest
    first).  **POST** delivers a new message and notifies all observers;
    the body must be a valid CBOR map with at least ``from``, ``to``, and
    ``text`` keys.

    Callers can also inject received messages directly via :meth:`deliver`
    (used when a message arrives over the mesh rather than via CoAP POST).

    Example::

        msgs = MessagesResource()
        site = build_site(info, messages_resource=msgs)
        # A peer message arrives over the mesh:
        msgs.deliver({"from": "aabb...", "to": "all", "text": "hello", "t": 1700000000.0})
    """

    def __init__(self) -> None:
        super().__init__()
        self._inbox: list[dict[str, Any]] = []

    def deliver(self, message: dict[str, Any]) -> None:
        """Append *message* to the inbox and notify observers.

        Trims the inbox to :data:`_MESSAGES_MAX` entries (oldest dropped).
        """
        self._inbox.append(message)
        if len(self._inbox) > _MESSAGES_MAX:
            self._inbox = self._inbox[-_MESSAGES_MAX:]
        self.updated_state()

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=cbor2.dumps(self._inbox))
        msg.opt.content_format = CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            body = cbor2.loads(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(body, dict):
            return Message(code=aiocoap.BAD_REQUEST)
        required = {"from", "to", "text"}
        if not required.issubset(body.keys()):
            return Message(code=aiocoap.BAD_REQUEST)
        self.deliver(body)
        return Message(code=aiocoap.CHANGED)


def build_site(
    node_info: NodeInfo,
    *,
    mesh_client: aiocoap.Context | None = None,
    sensors_resource: SenMLSensorsResource | None = None,
    location_resource: SenMLLocationResource | None = None,
    presence_resource: PresenceResource | None = None,
    messages_resource: MessagesResource | None = None,
) -> resource.Site:
    """Build an aiocoap Site exposing the LICHEN node resources.

    Pass ``mesh_client`` to also expose a forward proxy at ``/proxy``.
    Pass pre-constructed observable resources to expose ``/sensors``,
    ``/location``, ``/presence``, and/or ``/messages``; callers hold the
    references and call ``update()`` / ``seen()`` / ``deliver()`` to push
    data to observers.
    """
    site = resource.Site()
    site.add_resource(
        [".well-known", "core"],
        resource.WKCResource(site.get_resources_as_linkheader),
    )
    site.add_resource(["status"], StatusResource(node_info))
    site.add_resource(["neighbors"], NeighborsResource(node_info))
    site.add_resource(["config"], ConfigResource(node_info))
    if mesh_client is not None:
        site.add_resource(["proxy"], ProxyResource(mesh_client))
    if sensors_resource is not None:
        site.add_resource(["sensors"], sensors_resource)
    if location_resource is not None:
        site.add_resource(["location"], location_resource)
    if presence_resource is not None:
        site.add_resource(["presence"], presence_resource)
    if messages_resource is not None:
        site.add_resource(["messages"], messages_resource)
    return site
