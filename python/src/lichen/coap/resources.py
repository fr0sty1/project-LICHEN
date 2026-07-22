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

* :class:`SosResource` — ``/sos`` — emergency beacon.  PUT activates SOS;
  DELETE cancels; GET and Observe let any node monitor the state.

Because the integrated Node class does not exist yet, the local resources read
from an injected :class:`NodeInfo` provider rather than a live node; swap in
a node-backed provider once it lands.
"""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import itertools
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlparse

import aiocoap
import cbor2
from aiocoap import (
    BAD_GATEWAY,
    BAD_REQUEST,
    CHANGED,
    CONTENT,
    CREATED,
    DELETED,
    UNAUTHORIZED,
    Message,
    resource,
)
from aiocoap.numbers import ContentFormat

CBOR = ContentFormat.CBOR
SENML_CBOR = ContentFormat(112)  # application/senml+cbor (RFC 8428)

# SECURITY: Mesh address prefixes allowed for proxy forwarding.
# IPv6 ULA (fd00::/8) is the LICHEN mesh address space.
# Link-local (fe80::/10) may be used for direct neighbor access.
_MESH_ALLOWED_PREFIXES = (
    ipaddress.IPv6Network("fd00::/8"),
    ipaddress.IPv6Network("fe80::/10"),
)


def _is_mesh_uri(uri: str) -> bool:
    """Return True if *uri* targets a mesh-allowed address.

    SECURITY: Validates that the target host is an IPv6 address within
    the mesh address space (ULA fd00::/8 or link-local fe80::/10).
    Rejects hostnames, IPv4 addresses, and non-mesh IPv6 addresses
    to prevent SSRF attacks via the proxy.
    """
    try:
        parsed = urlparse(uri)
    except Exception:
        return False
    if parsed.scheme not in ("coap", "coaps"):
        return False
    host = parsed.hostname
    if not host:
        return False
    # Strip brackets from IPv6 literal if present
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        addr = ipaddress.IPv6Address(host)
    except ValueError:
        return False  # Not a valid IPv6 address (rejects hostnames, IPv4)
    return any(addr in prefix for prefix in _MESH_ALLOWED_PREFIXES)


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
    """``/config`` — node configuration (GET to read, PUT to update).

    SECURITY: Config writes can reconfigure security features, routing
    parameters, or redirect traffic. By default, PUT is rejected with
    4.01 Unauthorized unless ``allow_writes=True``.

    In production, use OSCORE-protected transport (spec section 8.7) and
    set ``allow_writes=True`` only when the transport layer enforces
    authentication. For testing without OSCORE, explicitly enable writes.
    """

    rt = "lichen.config"

    def __init__(self, node_info: NodeInfo, *, allow_writes: bool = False) -> None:
        """Create a config resource.

        Args:
            node_info: Data source for configuration.
            allow_writes: If True, allow PUT to modify configuration.
                SECURITY: Only set True when transport-layer authentication
                (OSCORE) is enforced. Defaults to False (read-only).
        """
        super().__init__(node_info)
        self._allow_writes = allow_writes

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(self.node_info.get_config())

    async def render_put(self, request: Message) -> Message:
        # SECURITY: Reject unauthenticated writes. Config changes can disable
        # security features, alter routing, or redirect traffic (spec 8).
        if not self._allow_writes:
            return Message(code=UNAUTHORIZED)
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            updates = cbor2.loads(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        if not isinstance(updates, dict):
            return Message(code=BAD_REQUEST)
        self.node_info.set_config(updates)
        return Message(code=CHANGED)


class ProxyResource(resource.Resource):
    """Optional CoAP forward proxy for constrained local transports.

    LCI clients normally address mesh nodes directly and let the local node
    route IPv6 packets into the mesh. When direct routing is unavailable, a
    client can send a request to ``/proxy`` on the gateway with a ``Proxy-Uri``
    option naming the target mesh node::

        GET coap://[gateway]/proxy
        Proxy-Uri: coap://[fd00::2]/status

    The gateway forwards the request via its mesh-side aiocoap context and
    relays the response — including any CoAP error codes from the target.
    The ``mesh_ctx`` must be a context whose transport can route to mesh nodes
    (e.g. a :class:`~lichen.coap.transport.LichenTransport` backed by a
    :class:`~lichen.coap.node_channel.NodeChannel`).

    Per RFC 7252 section 5.7, the Proxy-Uri option is stripped before forwarding.

    SECURITY: To prevent SSRF, the proxy validates that the target URI is a
    ``coap://`` or ``coaps://`` URI with an IPv6 address in the mesh address
    space (ULA fd00::/8 or link-local fe80::/10). Requests to hostnames, IPv4
    addresses, or non-mesh IPv6 addresses are rejected with 4.00 Bad Request.
    """

    rt = "proxy"

    def __init__(self, mesh_ctx: aiocoap.Context, *, timeout: float = 30.0) -> None:
        super().__init__()
        self._mesh_ctx = mesh_ctx
        self._timeout = timeout

    async def render(self, request: Message) -> Message:
        target = request.opt.proxy_uri
        if not target:
            return Message(code=BAD_REQUEST)

        # SECURITY: Validate target is a mesh address to prevent SSRF
        if not _is_mesh_uri(target):
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
        from lichen.senml.codec import pack
        payload = getattr(self, "_payload", pack([]))
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = SENML_CBOR
        return msg


class SenMLMetricsResource(resource.ObservableResource):
    """Basic observable ``/metrics`` CoAP resource — SenML+CBOR (112)
    telemetry+battery profile (RSSI, nodecount, pps, battery, collision-rate).

    Updated via :meth:`update(**kwargs)` where kwargs match
    :func:`~lichen.senml.profiles.metrics`. Supports GET, Observe.
    """

    def __init__(self) -> None:
        """Initialize with empty payload."""
        super().__init__()
        self._payload: bytes = b""

    def update(
        self,
        rssi: int | None = None,
        nodecount: int | None = None,
        packets_per_sec: float | None = None,
        battery: float | None = None,
        collision_rate: float | None = None,
    ) -> None:
        """Update telemetry+battery readings and notify all observers."""
        from lichen.senml.codec import pack  # noqa: PLC0415
        from lichen.senml.profiles import metrics  # noqa: PLC0415
        self._payload = pack(
            metrics(
                rssi=rssi,
                nodecount=nodecount,
                packets_per_sec=packets_per_sec,
                battery=battery,
                collision_rate=collision_rate,
            ),
        )
        self.updated_state()

    async def render_get(self, request: Message) -> Message:  # noqa: D102,ARG002
        from lichen.senml.codec import pack  # noqa: PLC0415
        payload = getattr(self, "_payload", pack([]))
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = SENML_CBOR
        return msg

    def get_link_description(self) -> dict[str, Any]:
        """Link description for .well-known/core and RD."""
        return {
            "rt": "senml",
            "if": "sensor",
            "ct": str(int(SENML_CBOR)),
            "obs": None,
        }


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


class SosResource(resource.ObservableResource):
    """Observable ``/sos`` — emergency beacon (PUT to activate, DELETE to cancel).

    State is a CBOR map::

        {"active": true, "from": "<hex-eui64>", "t": <float>}  # active
        {"active": false, "from": null, "t": null}              # idle

    **PUT** activates SOS; body is optional CBOR ``{"from": "<hex>", "t": <float>}``.
    **DELETE** cancels.  **GET** and **Observe** expose the current state to all
    subscribers so neighbouring nodes can relay/escalate the alert.

    The repeating-beacon behaviour (every 30 s) is the responsibility of the
    application layer driving :meth:`retrigger`; the resource itself only
    tracks state and notifies on changes.
    """

    def __init__(self) -> None:
        super().__init__()
        self._active = False
        self._from: str | None = None
        self._t: float | None = None

    def _state_payload(self) -> bytes:
        return cbor2.dumps(
            {"active": self._active, "from": self._from, "t": self._t}
        )

    def activate(self, from_eui64: bytes, t: float) -> None:
        """Activate SOS from *from_eui64* at time *t* and notify observers."""
        self._active = True
        self._from = from_eui64.hex()
        self._t = t
        self.updated_state()

    def cancel(self) -> None:
        """Cancel an active SOS and notify observers.  No-op if already idle."""
        if self._active:
            self._active = False
            self._from = None
            self._t = None
            self.updated_state()

    def retrigger(self) -> None:
        """Re-notify observers without changing state (periodic beacon pulse)."""
        if self._active:
            self.updated_state()

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=self._state_payload())
        msg.opt.content_format = CBOR
        return msg

    async def render_put(self, request: Message) -> Message:
        t: float | None = None
        from_hex: str | None = None
        if request.payload:
            try:
                body = cbor2.loads(request.payload)
                if isinstance(body, dict):
                    from_hex = body.get("from")
                    t = body.get("t")
            except Exception:
                return Message(code=aiocoap.BAD_REQUEST)

        # SECURITY: Validate from_hex is a string before hex decoding;
        # CBOR body could contain non-string types that would raise TypeError.
        if from_hex is not None and not isinstance(from_hex, str):
            return Message(code=aiocoap.BAD_REQUEST)
        # SECURITY: Validate t is numeric; non-numeric values would violate
        # the API contract (t: float) and cause type errors in consumers.
        if t is not None and not isinstance(t, (int, float)):
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            eui64 = bytes.fromhex(from_hex) if from_hex else b"\x00" * 8
        except ValueError:
            return Message(code=aiocoap.BAD_REQUEST)
        if len(eui64) != 8:
            return Message(code=aiocoap.BAD_REQUEST)
        self.activate(eui64, t if t is not None else 0.0)
        return Message(code=aiocoap.CHANGED)

    async def render_delete(self, request: Message) -> Message:
        self.cancel()
        return Message(code=aiocoap.DELETED)


class RollcallResource(resource.ObservableResource):
    """Demo CoAP resource for conference rollcall use case per spec/12-apps.md §18.6.
    Supports POST to initiate, observable GET for status with SenML position data.
    Used by LCI-based conference demo application.
    """

    def __init__(self) -> None:
        super().__init__()
        self._rollcalls: dict[str, dict[str, Any]] = {}

    def update(
        self,
        roll_id: str,
        responded: list[dict[str, Any]] | None = None,
        missing: list[dict[str, Any]] | None = None,
    ) -> None:
        """Update rollcall state and notify observers (for demo position beacons)."""
        if roll_id not in self._rollcalls:
            self._rollcalls[roll_id] = {
                "id": roll_id,
                "started": int(time.time()),
                "timeout_s": 60,
                "responded": [],
                "missing": [],
            }
        if responded is not None:
            self._rollcalls[roll_id]["responded"] = responded
        if missing is not None:
            self._rollcalls[roll_id]["missing"] = missing
        self.updated_state()

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "rollcall", "ct": str(int(CBOR)), "obs": None}

    async def render_post(self, request: Message) -> Message:
        """POST /rollcall to initiate a roll call."""
        if not request.payload:
            return Message(code=aiocoap.BAD_REQUEST)
        try:
            data = cbor2.loads(request.payload)
        except Exception:
            return Message(code=aiocoap.BAD_REQUEST)
        if not isinstance(data, dict) or "id" not in data:
            return Message(code=aiocoap.BAD_REQUEST)
        roll_id = str(data["id"])
        self._rollcalls[roll_id] = {
            "id": roll_id,
            "started": data.get("ts", int(time.time())),
            "timeout_s": data.get("timeout_s", 60),
            "responded": [],
            "missing": [],
        }
        self.updated_state()
        return Message(code=CREATED)

    async def render_get(self, request: Message) -> Message:
        """GET /rollcall/{id} or /rollcall returns status. Uses SenML via profiles for position."""
        roll_id = None
        if request.opt.uri_path and len(request.opt.uri_path) > 1:
            roll_id = request.opt.uri_path[-1]
        if roll_id and roll_id in self._rollcalls:
            data = dict(self._rollcalls[roll_id])
            # Use SenML for position in conference demo
            from lichen.senml.codec import pack
            from lichen.senml.profiles import location
            data["position"] = pack(location(37.7749, -122.4194, 10.0))
            payload = cbor2.dumps(data)
        else:
            payload = cbor2.dumps({"rollcalls": list(self._rollcalls.values())})
        msg = Message(code=CONTENT, payload=payload)
        msg.opt.content_format = CBOR
        return msg


_MESSAGES_MAX = 100  # maximum inbox depth


class MessagesResource(resource.ObservableResource):
    """Observable ``/msg/inbox`` — CBOR inbox with POST-to-send.

    Each message is a CBOR map::

        {"from": "<addr>", "to": "<addr> | all", "body": "...", "ts": <timestamp>}

    **GET** returns the inbox (most recent :data:`_MESSAGES_MAX` messages, oldest
    first).  **POST** delivers a new message and notifies all observers;
    the body must be a valid CBOR map with a message body. Local LCI submits
    include ``to``; direct POSTs to a destination inbox MAY omit it. Legacy
    ``text``/``t`` fields are accepted and preserved for simulator compatibility.

    Callers can also inject received messages directly via :meth:`deliver`
    (used when a message arrives over the mesh rather than via CoAP POST).

    Example::

        msgs = MessagesResource()
        site = build_site(info, messages_resource=msgs)
        # A peer message arrives over the mesh:
        msgs.deliver({"from": "aabb...", "to": "all", "body": "hello", "ts": 1700000000})
    """

    def __init__(self) -> None:
        super().__init__()
        self._inbox: list[dict[str, Any]] = []
        self._sent: dict[str, dict[str, Any]] = {}
        self._sent_order: list[str] = []
        self._sent_detail_registrar: Callable[[str, dict[str, Any]], None] | None = None
        self._legacy_aliases: list[LegacyMessagesAliasResource] = []
        self._next_id = 1

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.inbox", "ct": str(int(CBOR)), "obs": None}

    def deliver(self, message: dict[str, Any]) -> None:
        """Append *message* to the inbox and notify observers.

        Trims the inbox to :data:`_MESSAGES_MAX` entries (oldest dropped).
        """
        self._inbox.append(message)
        if len(self._inbox) > _MESSAGES_MAX:
            self._inbox = self._inbox[-_MESSAGES_MAX:]
        self.updated_state()
        for alias in self._legacy_aliases:
            alias.updated_state()

    def sent_messages(self) -> list[dict[str, Any]]:
        """Return sent messages in creation order."""
        return [self._sent[msg_id] for msg_id in self._sent_order]

    def inbox(self) -> list[dict[str, Any]]:
        """Return inbox messages in delivery order."""
        return [dict(message) for message in self._inbox]

    def sent_message(self, msg_id: str) -> dict[str, Any] | None:
        """Return one sent message by ID."""
        return self._sent.get(msg_id)

    def set_sent_detail_registrar(
        self,
        registrar: Callable[[str, dict[str, Any]], None],
    ) -> None:
        """Install callback used to mount ``/msg/sent/{id}`` resources."""
        self._sent_detail_registrar = registrar

    def register_legacy_alias(self, alias: LegacyMessagesAliasResource) -> None:
        """Register a legacy observable alias that mirrors inbox updates."""
        self._legacy_aliases.append(alias)

    async def render_get(self, request: Message) -> Message:
        msg = Message(code=CONTENT, payload=cbor2.dumps({"messages": self._inbox}))
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
        if not (isinstance(body.get("body"), str) or isinstance(body.get("text"), str)):
            return Message(code=aiocoap.BAD_REQUEST)
        body = dict(body)
        body.setdefault("id", self._next_id)
        if isinstance(body["id"], int):
            self._next_id = max(self._next_id + 1, body["id"] + 1)
        else:
            self._next_id += 1
        if "body" not in body and "text" in body:
            body["body"] = body["text"]
        self.deliver(body)
        msg_id = str(body["id"])
        self._sent[msg_id] = copy.deepcopy(body)
        if msg_id not in self._sent_order:
            self._sent_order.append(msg_id)
        if len(self._sent_order) > _MESSAGES_MAX:
            oldest = self._sent_order[: len(self._sent_order) - _MESSAGES_MAX]
            self._sent_order = self._sent_order[-_MESSAGES_MAX:]
            for old_id in oldest:
                self._sent.pop(old_id, None)
        if self._sent_detail_registrar is not None:
            self._sent_detail_registrar(msg_id, body)
        msg = Message(code=aiocoap.CREATED)
        msg.opt.location_path = ("msg", "sent", msg_id)
        return msg


class SentMessagesResource(resource.Resource):
    """``/msg/sent`` collection for messages accepted through LCI."""

    def __init__(self, messages: MessagesResource) -> None:
        super().__init__()
        self._messages = messages

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.sent", "ct": str(int(CBOR))}

    async def render_get(self, request: Message) -> Message:
        return _cbor_response({"messages": self._messages.sent_messages()})


class SentMessageDetailResource(resource.Resource):
    """``/msg/sent/{id}`` detail for one accepted message."""

    def __init__(self, message: dict[str, Any]) -> None:
        super().__init__()
        self._message = dict(message)

    async def render_get(self, request: Message) -> Message:
        return _cbor_response(dict(self._message))


class MessageReceiptsResource(resource.Resource):
    """``/msg/ack`` collection for delivery/read/failure receipts."""

    VALID_STATUSES = frozenset({"delivered", "read", "failed"})

    def __init__(
        self,
        *,
        handler: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        super().__init__()
        self._handler = handler
        self._receipts: list[dict[str, Any]] = []

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "msg.ack", "ct": str(int(CBOR))}

    def receipts(self) -> list[dict[str, Any]]:
        """Return stored receipts in POST order."""
        return [dict(receipt) for receipt in self._receipts]

    async def render_post(self, request: Message) -> Message:
        if not request.payload:
            return Message(code=BAD_REQUEST)
        try:
            payload = cbor2.loads(request.payload)
        except Exception:
            return Message(code=BAD_REQUEST)
        receipt = self._normalize(payload)
        if receipt is None:
            return Message(code=BAD_REQUEST)
        self._receipts.append(receipt)
        if self._handler is not None:
            self._handler(dict(receipt))
        return Message(code=CHANGED)

    @classmethod
    def _normalize(cls, payload: Any) -> dict[str, Any] | None:
        if not isinstance(payload, dict):
            return None
        receipt_id = payload.get("id")
        status = payload.get("status")
        timestamp = payload.get("ts")
        if not _is_uint(receipt_id):
            return None
        if status not in cls.VALID_STATUSES:
            return None
        if not _is_uint(timestamp):
            return None
        return {
            "id": receipt_id,
            "status": status,
            "ts": timestamp,
        }


def _is_uint(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class LegacyMessagesAliasResource(resource.ObservableResource):
    """Legacy/demo ``/messages`` alias for older Python simulator clients."""

    def __init__(self, messages: MessagesResource) -> None:
        super().__init__()
        self._messages = messages

    def get_link_description(self) -> dict[str, Any]:
        return {"rt": "legacy.messages", "ct": str(int(CBOR)), "title": "legacy demo alias"}

    async def render_get(self, request: Message) -> Message:
        payload = {"messages": [_legacy_message_view(msg) for msg in self._messages.inbox()]}
        return _cbor_response(payload)

    async def render_post(self, request: Message) -> Message:
        return await self._messages.render_post(request)


def _legacy_message_view(message: dict[str, Any]) -> dict[str, Any]:
    legacy = dict(message)
    if "text" not in legacy and isinstance(legacy.get("body"), str):
        legacy["text"] = legacy["body"]
    return legacy


_RD_DEFAULT_LIFETIME = 86400  # seconds (RFC 9176 §7.3.1)
_rd_id_counter = itertools.count(1)


@dataclass
class _RdEntry:
    """One endpoint registration in the Resource Directory."""

    reg_id: str
    ep: str  # endpoint name (RFC 9176 §7.3.1, mandatory)
    lt: int  # lifetime in seconds
    base: str | None
    links: list[dict[str, Any]]  # decoded link descriptors


class ResourceDirectoryResource(resource.Resource):
    """``/rd`` — CoAP Resource Directory (simplified RFC 9176).

    **POST** registers an endpoint; query parameters ``ep`` (required),
    ``lt`` (optional, default 86400), ``base`` (optional), body is a CBOR
    list of link descriptor maps ``[{"href": "/sensors", "rt": "..."}]``.
    Returns ``2.01 Created`` with ``Location-Path: /rd/<id>``.

    **GET** returns all active registrations as a CBOR list.

    Individual registrations are managed via :class:`_RdRegistrationResource`
    mounted at ``/rd/<id>``; those resources are added dynamically to the site
    when a node registers.

    Example registration::

        POST coap://rd/rd?ep=node-01&lt=3600
        CBOR body: [{"href": "/sensors", "rt": "lichen.sensors"},
                    {"href": "/status",  "rt": "lichen.status"}]
    """

    def __init__(self, site: resource.Site) -> None:
        super().__init__()
        self._site = site
        self._entries: dict[str, _RdEntry] = {}  # keyed by reg_id

    def _lookup(self, ep: str | None = None) -> list[dict[str, Any]]:
        """Return registrations, optionally filtered by endpoint name."""
        rows = list(self._entries.values())
        if ep is not None:
            rows = [r for r in rows if r.ep == ep]
        return [
            {
                "id": r.reg_id,
                "ep": r.ep,
                "lt": r.lt,
                "base": r.base,
                "links": r.links,
            }
            for r in rows
        ]

    def remove_entry(self, reg_id: str) -> bool:
        """Remove a registration; returns True if it existed."""
        return self._entries.pop(reg_id, None) is not None

    async def render_get(self, request: Message) -> Message:
        ep_filter: str | None = None
        if request.opt.uri_query:
            for q in request.opt.uri_query:
                if q.startswith("ep="):
                    ep_filter = q[3:]
        msg = Message(code=CONTENT, payload=cbor2.dumps(self._lookup(ep_filter)))
        msg.opt.content_format = CBOR
        return msg

    async def render_post(self, request: Message) -> Message:
        # Parse query parameters
        ep: str | None = None
        lt: int = _RD_DEFAULT_LIFETIME
        base: str | None = None
        for q in (request.opt.uri_query or []):
            if q.startswith("ep="):
                ep = q[3:]
            elif q.startswith("lt="):
                try:
                    lt = int(q[3:])
                except ValueError:
                    return Message(code=BAD_REQUEST)
            elif q.startswith("base="):
                base = q[5:]

        if not ep:
            return Message(code=BAD_REQUEST)  # RFC 9176 §7.3.1: ep is mandatory

        links: list[dict[str, Any]] = []
        if request.payload:
            try:
                body = cbor2.loads(request.payload)
                if isinstance(body, list):
                    links = body
            except Exception:
                return Message(code=BAD_REQUEST)

        reg_id = str(next(_rd_id_counter))
        entry = _RdEntry(reg_id=reg_id, ep=ep, lt=lt, base=base, links=links)
        self._entries[reg_id] = entry

        # Mount a deletion endpoint at /rd/<id>
        self._site.add_resource(
            ["rd", reg_id],
            _RdRegistrationResource(self, reg_id),
        )

        resp = Message(code=CREATED)
        resp.opt.location_path = ("rd", reg_id)
        return resp


class _RdRegistrationResource(resource.Resource):
    """``/rd/<id>`` — per-registration management (DELETE to remove)."""

    def __init__(self, rd: ResourceDirectoryResource, reg_id: str) -> None:
        super().__init__()
        self._rd = rd
        self._reg_id = reg_id

    async def render_delete(self, request: Message) -> Message:
        self._rd.remove_entry(self._reg_id)
        return Message(code=DELETED)


class KeyResource(resource.Resource):
    """GET /key — returns this node's public key and fingerprint as CBOR.

    Response map keys:
    - ``"fingerprint"``: hex string of the first 8 bytes of the public key.
    - ``"pubkey"``: raw 32-byte public key.
    """

    def __init__(self, pubkey: bytes) -> None:
        super().__init__()
        self._pubkey = pubkey

    async def render_get(self, request: Message) -> Message:
        data = {
            "fingerprint": self._pubkey[:8].hex(),
            "pubkey": self._pubkey,
        }
        return _cbor_response(data)


class EdhocResource(resource.Resource):
    """POST /.well-known/edhoc — EDHOC key establishment (RFC 9528, spec 8.8).

    Handles the responder side of EDHOC key exchange. Messages are exchanged
    as raw bytes (not CBOR-wrapped) per RFC 9528 Section 5.3.

    Protocol flow:
        1. Client POSTs Message 1 -> Server returns Message 2
        2. Client POSTs Message 3 -> Server returns empty 2.04 Changed

    After step 2, both sides have derived the OSCORE master secret and salt.

    Usage::

        from lichen.coap.resources import EdhocResource
        from lichen.crypto.identity import Identity

        identity = Identity.generate()
        edhoc = EdhocResource(identity, context_store, peer_resolver)
        site.add_resource([".well-known", "edhoc"], edhoc)
    """

    def __init__(
        self,
        identity: Any,
        context_store: Any,
        peer_resolver: Any,
    ) -> None:
        """Create an EDHOC responder resource.

        Args:
            identity: Our cryptographic Identity for signing.
            context_store: OscoreContextStore to save derived contexts.
            peer_resolver: EdhocPeerResolver to look up/pin peer pubkeys.
        """
        super().__init__()
        self._identity = identity
        self._context_store = context_store
        self._peer_resolver = peer_resolver
        # Active EDHOC sessions keyed by (peer_host, C_I)
        self._sessions: dict[tuple[str, bytes], Any] = {}

    async def render_post(self, request: Message) -> Message:
        """Handle EDHOC POST request.

        Expects Message 1 or Message 3 in the payload. Determines which
        based on whether we have an active session for the sender.
        """
        if not request.payload:
            return Message(code=BAD_REQUEST)

        # Get peer address from remote
        peer_host = request.remote.hostinfo if request.remote else None
        if not peer_host:
            return Message(code=BAD_REQUEST)

        payload = request.payload

        active_session = None
        for (host, _), session in reversed(list(self._sessions.items())):
            if host == peer_host:
                active_session = session
                break

        if active_session is None:
            # This is Message 1 - start new session
            try:
                return await self._handle_message_1(peer_host, payload)
            except Exception:
                return Message(code=BAD_REQUEST)
        else:
            # This is Message 3 - complete handshake
            try:
                return await self._handle_message_3(
                    peer_host, payload, active_session
                )
            except Exception:
                # Clean up failed session
                self._cleanup_session(peer_host)
                return Message(code=BAD_REQUEST)

    async def _handle_message_1(self, peer_host: str, msg1: bytes) -> Message:
        """Process EDHOC Message 1 and return Message 2."""
        from lichen.crypto.edhoc import EdhocResponder

        # Get peer's public key for authentication
        # SECURITY: Reject unknown peers early rather than proceeding with a
        # dummy key. An all-zeros key is a valid Ed25519 point, so passing it
        # to crypto routines could allow attacks. TOFU would defer this check
        # to Message 3, but we currently require pre-known peers.
        peer_pubkey = await self._peer_resolver.get_peer_pubkey(peer_host)
        if peer_pubkey is None:
            return Message(code=UNAUTHORIZED)

        # Create responder and process Message 1
        responder = EdhocResponder.create(self._identity)
        msg2 = responder.process_message_1(msg1, peer_pubkey)

        # Extract C_I from Message 1 for session tracking
        # Message 1: (METHOD_CORR, SUITES_I, G_X, C_I, ?EAD_1)
        c_i = responder._c_i

        # Store session
        self._sessions[(peer_host, c_i)] = {
            "responder": responder,
            "peer_pubkey": peer_pubkey,
        }

        # Return Message 2
        response = Message(code=CHANGED, payload=msg2)
        response.opt.content_format = ContentFormat(65535)  # application/edhoc
        return response

    async def _handle_message_3(
        self, peer_host: str, msg3: bytes, session: dict[str, Any]
    ) -> Message:
        """Process EDHOC Message 3 and establish OSCORE context."""
        from lichen.crypto.oscore import MemorySecurityContext

        responder = session["responder"]
        peer_pubkey = session["peer_pubkey"]

        if peer_pubkey is None:
            # SECURITY: Defense-in-depth check. Message 1 handler now rejects
            # unknown peers early, but if a session somehow lacks a peer key,
            # fail here rather than proceeding with verification.
            self._cleanup_session(peer_host)
            return Message(code=UNAUTHORIZED)

        # Process Message 3
        responder.process_message_3(msg3, peer_pubkey)

        # Export OSCORE context
        edhoc_ctx = responder.export_oscore()
        oscore_ctx = MemorySecurityContext.from_edhoc(edhoc_ctx)

        # Store context
        self._context_store.put_sync(peer_host, oscore_ctx, peer_pubkey)

        # Pin peer if using TOFU
        # (handled by context_store.put or peer_resolver.pin_peer)

        # Clean up session
        self._cleanup_session(peer_host)

        # Return success (empty payload per RFC 9528)
        return Message(code=CHANGED)

    def _cleanup_session(self, peer_host: str) -> None:
        """Remove any active sessions for a peer."""
        to_remove = [key for key in self._sessions if key[0] == peer_host]
        for key in to_remove:
            del self._sessions[key]


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
            site.add_resource(["msg", "sent", msg_id], SentMessageDetailResource(message))

        messages_resource.set_sent_detail_registrar(register_sent_detail)
        legacy_messages = LegacyMessagesAliasResource(messages_resource)
        messages_resource.register_legacy_alias(legacy_messages)
        site.add_resource(["msg", "inbox"], messages_resource)
        site.add_resource(["msg", "sent"], SentMessagesResource(messages_resource))
        site.add_resource(["messages"], legacy_messages)
    if message_receipts_resource is not None:
        site.add_resource(["msg", "ack"], message_receipts_resource)
    if sos_resource is not None:
        site.add_resource(["sos"], sos_resource)
    if rollcall_resource is not None:
        site.add_resource(["rollcall"], rollcall_resource)
    if resource_directory:
        site.add_resource(["rd"], ResourceDirectoryResource(site))
    if pubkey is not None:
        site.add_resource(["key"], KeyResource(pubkey))
    if edhoc_resource is not None:
        site.add_resource([".well-known", "edhoc"], edhoc_resource)
    return site
