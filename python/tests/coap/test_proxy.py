# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the CoAP forward proxy resource (82zw)."""

from __future__ import annotations

import aiocoap
import cbor2
from aiocoap import GET, PUT, Message

from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


def _mesh_node_info() -> StaticNodeInfo:
    return StaticNodeInfo(
        status={"rank": 512, "parent": "fd00::1"},
        neighbors=[{"addr": "fd00::3", "etx": 1.2}],
        config={"tx_power_dbm": 14},
    )


async def _setup():
    """Create: mesh-node server, gateway (proxy), local client.

    Topology::

        local_client <--local_net--> gateway <--mesh_net--> mesh_node
    """
    mesh_net = InMemoryNetwork()
    local_net = InMemoryNetwork()

    # Mesh node: serves /status, /neighbors, /config
    node_info = _mesh_node_info()
    mesh_node = await create_lichen_context(
        mesh_net.channel("fd00::2"), "fd00::2", site=build_site(node_info)
    )

    # Gateway mesh-side client (used by the proxy to forward requests)
    gw_mesh_client = await create_lichen_context(
        mesh_net.channel("fd00::1"), "fd00::1"
    )

    # Gateway local server: proxy resource + its own status resource
    gw_info = StaticNodeInfo(status={"rank": 256, "role": "root"})
    gw_site = build_site(gw_info, mesh_client=gw_mesh_client)
    gateway = await create_lichen_context(
        local_net.channel("gw"), "gw", site=gw_site
    )

    # Local client
    local_client = await create_lichen_context(
        local_net.channel("client"), "client"
    )

    return local_client, gateway, mesh_node, gw_mesh_client


async def _teardown(*ctxs: aiocoap.Context) -> None:
    for ctx in ctxs:
        await ctx.shutdown()


class TestProxyForwardGet:
    async def test_proxy_get_status_from_mesh_node(self) -> None:
        """GET with Proxy-Uri retrieves the remote node's /status."""
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            msg = Message(code=GET, uri="coap://gw/proxy")
            msg.opt.proxy_uri = "coap://[fd00::2]/status"
            resp = await local_client.request(msg).response

            assert resp.code == aiocoap.CONTENT
            data = cbor2.loads(resp.payload)
            assert data["rank"] == 512
            assert data["parent"] == "fd00::1"
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)

    async def test_proxy_get_neighbors_from_mesh_node(self) -> None:
        """GET with Proxy-Uri retrieves the remote node's /neighbors."""
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            msg = Message(code=GET, uri="coap://gw/proxy")
            msg.opt.proxy_uri = "coap://[fd00::2]/neighbors"
            resp = await local_client.request(msg).response

            assert resp.code == aiocoap.CONTENT
            neighbors = cbor2.loads(resp.payload)
            assert len(neighbors) == 1
            assert neighbors[0]["addr"] == "fd00::3"
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)

    async def test_proxy_get_config_from_mesh_node(self) -> None:
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            msg = Message(code=GET, uri="coap://gw/proxy")
            msg.opt.proxy_uri = "coap://[fd00::2]/config"
            resp = await local_client.request(msg).response

            assert resp.code == aiocoap.CONTENT
            config = cbor2.loads(resp.payload)
            assert config["tx_power_dbm"] == 14
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)

    async def test_gateway_own_status_unaffected(self) -> None:
        """The gateway's own /status resource still works alongside the proxy."""
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            resp = await local_client.request(
                Message(code=GET, uri="coap://gw/status")
            ).response
            data = cbor2.loads(resp.payload)
            assert data["role"] == "root"  # gateway's own info, not mesh node's
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)


class TestProxyForwardPut:
    async def test_proxy_put_config_to_mesh_node(self) -> None:
        """PUT with Proxy-Uri updates the remote node's config."""
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            update = {"tx_power_dbm": 20}
            msg = Message(
                code=PUT,
                uri="coap://gw/proxy",
                payload=cbor2.dumps(update),
                content_format=aiocoap.numbers.ContentFormat.CBOR,
            )
            msg.opt.proxy_uri = "coap://[fd00::2]/config"
            resp = await local_client.request(msg).response

            assert resp.code == aiocoap.CHANGED
            # Confirm by reading back
            get = Message(code=GET, uri="coap://gw/proxy")
            get.opt.proxy_uri = "coap://[fd00::2]/config"
            resp2 = await local_client.request(get).response
            data = cbor2.loads(resp2.payload)
            assert data["tx_power_dbm"] == 20
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)


class TestProxyErrors:
    async def test_missing_proxy_uri_returns_bad_request(self) -> None:
        """A request to /proxy without Proxy-Uri returns 4.00 Bad Request."""
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            resp = await local_client.request(
                Message(code=GET, uri="coap://gw/proxy")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)

    async def test_unreachable_target_returns_bad_gateway(self) -> None:
        """Proxy-Uri pointing at a non-existent node returns 5.02 Bad Gateway."""
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            msg = Message(code=GET, uri="coap://gw/proxy")
            msg.opt.proxy_uri = "coap://[fd00::99]/status"  # no such node
            resp = await local_client.request(msg).response
            assert resp.code == aiocoap.BAD_GATEWAY
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)

    async def test_remote_error_is_relayed(self) -> None:
        """A CoAP error from the target is relayed back to the local client."""
        local_client, gateway, mesh_node, gw_mesh = await _setup()
        try:
            msg = Message(code=GET, uri="coap://gw/proxy")
            msg.opt.proxy_uri = "coap://[fd00::2]/nonexistent"
            resp = await local_client.request(msg).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await _teardown(local_client, gateway, mesh_node, gw_mesh)


class TestBuildSite:
    async def test_build_site_without_proxy(self) -> None:
        """build_site without mesh_client does not expose /proxy."""
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        ctx = await create_lichen_context(
            net.channel("srv"), "srv", site=build_site(info)
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/proxy")
            ).response
            assert resp.code == aiocoap.NOT_FOUND

            core = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            body = core.payload.decode()
            assert "</proxy>" not in body
            assert "</mesh>" not in body
        finally:
            await client.shutdown()
            await ctx.shutdown()

    async def test_build_site_with_proxy_exposes_proxy(self) -> None:
        """build_site with mesh_client exposes optional /proxy."""
        mesh_net = InMemoryNetwork()
        local_net = InMemoryNetwork()

        mesh_node_info = StaticNodeInfo(status={"rank": 1})
        mesh_node = await create_lichen_context(
            mesh_net.channel("fd00::2"), "fd00::2",
            site=build_site(mesh_node_info),
        )
        gw_mesh_client = await create_lichen_context(
            mesh_net.channel("fd00::1"), "fd00::1"
        )
        gw = await create_lichen_context(
            local_net.channel("gw"), "gw",
            site=build_site(StaticNodeInfo(), mesh_client=gw_mesh_client),
        )
        cli = await create_lichen_context(local_net.channel("cli"), "cli")
        try:
            msg = Message(code=GET, uri="coap://gw/proxy")
            msg.opt.proxy_uri = "coap://[fd00::2]/status"
            resp = await cli.request(msg).response
            assert resp.code == aiocoap.CONTENT
        finally:
            await cli.shutdown()
            await gw.shutdown()
            await gw_mesh_client.shutdown()
            await mesh_node.shutdown()

    async def test_build_site_with_proxy_advertises_proxy_not_mesh(self) -> None:
        """Discovery advertises optional /proxy and not a /mesh proxy alias."""
        mesh_net = InMemoryNetwork()
        local_net = InMemoryNetwork()
        gw_mesh_client = await create_lichen_context(
            mesh_net.channel("fd00::1"), "fd00::1"
        )
        gw = await create_lichen_context(
            local_net.channel("gw"), "gw",
            site=build_site(StaticNodeInfo(), mesh_client=gw_mesh_client),
        )
        cli = await create_lichen_context(local_net.channel("cli"), "cli")
        try:
            resp = await cli.request(
                Message(code=GET, uri="coap://gw/.well-known/core")
            ).response
            body = resp.payload.decode()

            assert "</proxy>" in body
            assert 'rt="proxy"' in body
            assert "</mesh>" not in body
        finally:
            await cli.shutdown()
            await gw.shutdown()
            await gw_mesh_client.shutdown()
