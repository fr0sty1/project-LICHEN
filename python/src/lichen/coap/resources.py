"""Basic CoAP resources for a LICHEN node (spec section 7, RFC 6690).

Exposes ``/.well-known/core`` (resource discovery), ``/status``, ``/neighbors``,
and ``/config``. Payloads use CBOR (content-format 60), the compact encoding
appropriate for constrained LoRa links.

Because the integrated Node class does not exist yet, the resources read from an
injected :class:`NodeInfo` provider rather than a live node; :func:`build_site`
wires them into an aiocoap Site. Swap in a node-backed provider once it lands.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import cbor2
from aiocoap import CHANGED, CONTENT, Message, resource
from aiocoap.numbers import ContentFormat

CBOR = ContentFormat.CBOR


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
        return _cbor_response(self.node_info.get_config())


def build_site(node_info: NodeInfo) -> resource.Site:
    """Build an aiocoap Site exposing the LICHEN node resources."""
    site = resource.Site()
    site.add_resource(
        [".well-known", "core"],
        resource.WKCResource(site.get_resources_as_linkheader),
    )
    site.add_resource(["status"], StatusResource(node_info))
    site.add_resource(["neighbors"], NeighborsResource(node_info))
    site.add_resource(["config"], ConfigResource(node_info))
    return site
