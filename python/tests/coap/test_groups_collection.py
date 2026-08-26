# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GET/POST /groups (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_collection import (
    GroupsCollectionResource,
    GroupsItemResource,
    group_id_from_name,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


@pytest.mark.asyncio
async def test_groups_create_and_list() -> None:
    resource = GroupsCollectionResource(owner="0200::1111")
    site = Site()
    site.add_resource(["groups"], resource)
    site.add_resource(["groups"], GroupsItemResource(resource))
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=site
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        empty = await client.request(Message(code=aiocoap.GET, uri="coap://server/groups")).response
        assert cbor2.loads(empty.payload) == {"groups": []}
        created = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups",
                payload=cbor2.dumps({"name": "Team Alpha", "encrypted": True}),
            )
        ).response
        assert created.code == aiocoap.CREATED
        body = cbor2.loads(created.payload)
        expected_id = group_id_from_name("Team Alpha")
        assert body["id"] == expected_id
        assert body["mcast"].startswith("ff35:0040:")
        assert "master_secret" in body and len(body["master_secret"]) == 32
        assert created.opt.location_path == ("groups", expected_id)
        listed = await client.request(Message(code=aiocoap.GET, uri="coap://server/groups")).response
        rows = cbor2.loads(listed.payload)
        assert rows == {
            "groups": [{"id": expected_id, "name": "Team Alpha", "members": 1}]
        }
    finally:
        await client.shutdown()
        await server.shutdown()
