"""Tests for the aiocoap LICHEN transport binding (3dl)."""

from __future__ import annotations

import aiocoap
import pytest
from aiocoap import GET, Message, resource

from lichen.coap.transport import (
    InMemoryNetwork,
    LichenRemote,
    create_lichen_context,
)


class _Hello(resource.Resource):
    async def render_get(self, request: Message) -> Message:
        return Message(payload=b"hello", code=aiocoap.CONTENT)


class _Echo(resource.Resource):
    async def render_post(self, request: Message) -> Message:
        return Message(payload=request.payload, code=aiocoap.CHANGED)


def test_remote_identity_and_uri() -> None:
    r = LichenRemote("node-b")
    assert r.hostinfo == "node-b"
    assert r.uri_base == "coap://node-b"
    assert r == LichenRemote("node-b")
    assert r != LichenRemote("node-c")
    assert hash(r) == hash(LichenRemote("node-b"))


@pytest.mark.asyncio
async def test_get_request_over_loopback() -> None:
    net = InMemoryNetwork()
    site = resource.Site()
    site.add_resource(["test"], _Hello())

    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        response = await client.request(
            Message(code=GET, uri="coap://server/test")
        ).response
        assert response.payload == b"hello"
        assert response.code == aiocoap.CONTENT
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_post_round_trips_payload() -> None:
    net = InMemoryNetwork()
    site = resource.Site()
    site.add_resource(["echo"], _Echo())

    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        response = await client.request(
            Message(code=aiocoap.POST, uri="coap://server/echo", payload=b"ping")
        ).response
        assert response.payload == b"ping"
        assert response.code == aiocoap.CHANGED
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_request_to_unknown_resource_returns_not_found() -> None:
    net = InMemoryNetwork()
    site = resource.Site()
    site.add_resource(["test"], _Hello())

    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        response = await client.request(
            Message(code=GET, uri="coap://server/nope")
        ).response
        assert response.code == aiocoap.NOT_FOUND
    finally:
        await client.shutdown()
        await server.shutdown()
