"""Tests for LICHEN CoAP resources (t64)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import GET, PUT, Message

from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


def _node_info() -> StaticNodeInfo:
    return StaticNodeInfo(
        status={"uptime": 1234, "rank": 512, "parent": "fe80::1", "battery": 90},
        neighbors=[{"addr": "fe80::2", "rank": 256, "etx": 1.0}],
        config={"region": "US915", "tx_power_dbm": 14},
    )


async def _client_server(node_info: StaticNodeInfo):
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=build_site(node_info)
    )
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


@pytest.mark.asyncio
async def test_status_returns_cbor() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/status")).response
        assert resp.code == aiocoap.CONTENT
        assert resp.opt.content_format == 60  # application/cbor
        assert cbor2.loads(resp.payload) == info.status
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_neighbors_returns_table() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        resp = await client.request(
            Message(code=GET, uri="coap://server/neighbors")
        ).response
        assert cbor2.loads(resp.payload) == info.neighbors
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_well_known_core_lists_resources() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        resp = await client.request(
            Message(code=GET, uri="coap://server/.well-known/core")
        ).response
        body = resp.payload.decode()
        assert "</status>" in body
        assert "</neighbors>" in body
        assert "</config>" in body
        assert 'rt="lichen.status"' in body
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_get_and_put() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/config")).response
        assert cbor2.loads(resp.payload)["region"] == "US915"

        put = Message(
            code=PUT,
            uri="coap://server/config",
            payload=cbor2.dumps({"tx_power_dbm": 20}),
        )
        put_resp = await client.request(put).response
        assert put_resp.code == aiocoap.CONTENT
        # The update is reflected, other keys preserved.
        updated = cbor2.loads(put_resp.payload)
        assert updated["tx_power_dbm"] == 20
        assert updated["region"] == "US915"
        assert info.config["tx_power_dbm"] == 20
    finally:
        await client.shutdown()
        await server.shutdown()


def test_static_node_info_is_copy_safe() -> None:
    info = StaticNodeInfo(status={"a": 1})
    snapshot = info.get_status()
    snapshot["a"] = 999
    assert info.status["a"] == 1  # get_status returns a copy
