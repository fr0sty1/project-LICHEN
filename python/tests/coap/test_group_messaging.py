# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Group multicast /msg/inbox POST and /pos PUT (spec/12-apps.md 18.8.4)."""

from __future__ import annotations

import json
from pathlib import Path

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.messaging import MessagesResource
from lichen.coap.resources.senml import PositionBeaconResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.senml.codec import pack
from lichen.senml.profiles import location

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "groups_messaging.json"


@pytest.mark.asyncio
async def test_group_inbox_post_from_vector() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    case = next(v for v in document["vectors"] if v["name"] == "group_inbox_post")
    msgs = MessagesResource()
    site = Site()
    site.add_resource(["msg", "inbox"], msgs)
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("::1"), "::1")
    try:
        resp = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/msg/inbox",
                payload=cbor2.dumps(case["payload"]),
            )
        ).response
        assert str(resp.code).startswith(case["expected_code"])
        assert msgs.inbox()[0]["body"] == case["payload"]["body"]
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_group_pos_put_from_vector() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    case = next(v for v in document["vectors"] if v["name"] == "group_pos_put")
    pos = PositionBeaconResource()
    site = Site()
    site.add_resource(["pos"], pos)
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("::1"), "::1")
    try:
        payload = pack(location(lat=case["lat"], lon=case["lon"]))
        msg = Message(code=aiocoap.PUT, uri="coap://server/pos", payload=payload)
        msg.opt.content_format = case["content_format"]
        resp = await client.request(msg).response
        assert str(resp.code).startswith(case["expected_code"])
    finally:
        await client.shutdown()
        await server.shutdown()
