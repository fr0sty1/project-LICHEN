# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CoAP forward proxy for LCI baseline mesh access."""

from __future__ import annotations

import asyncio
import ipaddress
from urllib.parse import urlparse

import aiocoap
from aiocoap import BAD_GATEWAY, BAD_REQUEST, Message, resource

# SECURITY: Mesh address prefixes allowed for proxy forwarding.
# Native 0200::/8 is the LICHEN key-derived Yggdrasil address space.
# Link-local (fe80::/10) may be used for direct neighbor access.
_MESH_ALLOWED_PREFIXES = (
    ipaddress.IPv6Network("0200::/8"),
    ipaddress.IPv6Network("fe80::/10"),
)


def _is_mesh_uri(uri: str) -> bool:
    """Return True if *uri* targets a mesh-allowed address.

    SECURITY: Validates that the target host is an IPv6 address within
    the mesh address space (native 0200::/8 or link-local fe80::/10).
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
    try:
        addr = ipaddress.IPv6Address(host)
    except ValueError:
        return False  # Not a valid IPv6 address (rejects hostnames, IPv4)
    return any(addr in prefix for prefix in _MESH_ALLOWED_PREFIXES)


class ProxyResource(resource.Resource):
    """CoAP forward proxy for LCI baseline mesh access.

    LCI baseline clients have link-local reachability to the gateway and access
    mesh nodes through this proxy using RFC 7252 Proxy-Uri. A client sends a
    request to ``/proxy`` on the gateway with a ``Proxy-Uri`` option naming the
    target mesh node::

        GET coap://[gateway]/proxy
        Proxy-Uri: coap://[0200::1234:5678:9abc:def0]/status

    The gateway forwards the request via its mesh-side aiocoap context and
    relays the response, including any CoAP error codes from the target.
    The ``mesh_ctx`` must be a context whose transport can route to mesh nodes
    (e.g. a :class:`~lichen.coap.transport.LichenTransport` backed by a
    :class:`~lichen.coap.node_channel.NodeChannel`).

    Per RFC 7252 section 5.7, the Proxy-Uri option is stripped before forwarding.

    SECURITY: To prevent SSRF, the proxy validates that the target URI is a
    ``coap://`` or ``coaps://`` URI with an IPv6 address in the mesh address
    space (native 0200::/8 or link-local fe80::/10). Requests to hostnames, IPv4
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
        except asyncio.CancelledError:
            raise
        except Exception:
            return Message(code=BAD_GATEWAY)

        relay = Message(code=response.code, payload=response.payload)
        if response.opt.content_format is not None:
            relay.opt.content_format = response.opt.content_format
        return relay
