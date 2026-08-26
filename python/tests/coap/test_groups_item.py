# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GET/PUT/DELETE /groups/{id} and POST /groups/{id}/key (spec 18.8)."""

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


async def _stack(owner: str = "0200::1111"):
    resource = GroupsCollectionResource(owner=owner, clock=lambda: 1716742800)
    site = Site()
    site.add_resource(["groups"], resource)
    site.add_resource(["groups"], GroupsItemResource(resource))
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    return resource, client, server


async def _create(client, *, encrypted: bool = True) -> str:
    created = await client.request(
        Message(
            code=aiocoap.POST,
            uri="coap://server/groups",
            payload=cbor2.dumps({"name": "Team Alpha", "encrypted": encrypted}),
        )
    ).response
    assert created.code == aiocoap.CREATED
    return cbor2.loads(created.payload)["id"]


@pytest.mark.asyncio
async def test_group_item_get_put_delete() -> None:
    resource, client, server = await _stack()
    try:
        group_id = await _create(client)
        assert group_id == group_id_from_name("Team Alpha")
        got = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        body = cbor2.loads(got.payload)
        assert body["id"] == group_id
        assert body["name"] == "Team Alpha"
        assert body["owner"] == "0200::1111"
        assert body["members"] == ["0200::1111"]
        assert body["admins"] == []
        assert body["created"] == 1716742800
        assert body["key_epoch"] == 1
        assert "master_secret" not in body
        put = await client.request(
            Message(
                code=aiocoap.PUT,
                uri=f"coap://server/groups/{group_id}",
                payload=cbor2.dumps({"name": "Team Alpha Renamed"}),
            )
        ).response
        assert put.code == aiocoap.CHANGED
        got = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        assert cbor2.loads(got.payload)["name"] == "Team Alpha Renamed"
        missing = await client.request(
            Message(code=aiocoap.GET, uri="coap://server/groups/no-such")
        ).response
        assert missing.code == aiocoap.NOT_FOUND
        deleted = await client.request(
            Message(code=aiocoap.DELETE, uri=f"coap://server/groups/{group_id}")
        ).response
        assert deleted.code == aiocoap.DELETED
        gone = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        assert gone.code == aiocoap.NOT_FOUND
        assert group_id not in resource.groups
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_join_key_post_and_key_metadata() -> None:
    _resource, client, server = await _stack()
    try:
        group_id = await _create(client, encrypted=True)
        meta = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}/key")
        ).response
        meta_body = cbor2.loads(meta.payload)
        assert meta_body["algorithm"] == "AES-CCM-16-64-128"
        assert "master_secret" not in meta_body
        joined = await client.request(
            Message(
                code=aiocoap.POST,
                uri=f"coap://server/groups/{group_id}/key",
                payload=cbor2.dumps({"request": "join_key", "node": "0200::3333"}),
            )
        ).response
        assert joined.code == aiocoap.CONTENT
        key = cbor2.loads(joined.payload)
        assert key["algorithm"] == "AES-CCM-16-64-128"
        assert key["key_epoch"] == 1
        assert len(key["master_secret"]) == 32
        assert len(key["master_salt"]) == 8
        got = await client.request(
            Message(code=aiocoap.GET, uri=f"coap://server/groups/{group_id}")
        ).response
        assert "0200::3333" in cbor2.loads(got.payload)["members"]
        bad = await client.request(
            Message(
                code=aiocoap.POST,
                uri=f"coap://server/groups/{group_id}/key",
                payload=cbor2.dumps({"request": "nope", "node": "0200::3333"}),
            )
        ).response
        assert bad.code == aiocoap.BAD_REQUEST
    finally:
        await client.shutdown()
        await server.shutdown()
