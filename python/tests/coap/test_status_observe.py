# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Observe /status (spec/11-lci.md 17.5.3, RFC 7641)."""

from __future__ import annotations

import asyncio
import re

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site, WKCResource

from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.resources.node_resources import StatusResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


def _info() -> StaticNodeInfo:
    return StaticNodeInfo(status={"uptime": 10, "rank": 256, "battery": 80})


@pytest.mark.asyncio
async def test_status_observe_notifies_on_change() -> None:
    info = _info()
    status = StatusResource(info)
    site = Site()
    site.add_resource(
        [".well-known", "core"],
        WKCResource(site.get_resources_as_linkheader),
    )
    site.add_resource(["status"], status)
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"),
        "server",
        site=site,
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        req = client.request(Message(code=aiocoap.GET, observe=0, uri="coap://server/status"))
        first = await req.response
        assert first.code == aiocoap.CONTENT
        assert cbor2.loads(first.payload) == info.status
        obs_iter = req.observation.__aiter__()
        info.status["battery"] = 40
        status.notify_changed()
        notification = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
        assert cbor2.loads(notification.payload)["battery"] == 40
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_status_advertises_obs() -> None:
    info = _info()
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"),
        "server",
        site=build_site(info),
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(
            Message(code=aiocoap.GET, uri="coap://server/.well-known/core")
        ).response
        body = resp.payload.decode()
        entry = re.search(r"</status>[^<]*", body)
        assert entry is not None
        assert "obs" in entry.group(0)
    finally:
        await client.shutdown()
        await server.shutdown()
