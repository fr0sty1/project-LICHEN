# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Membership sequences and rekey-on-removal (spec 18.8.2)."""

from __future__ import annotations

import json
from pathlib import Path

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_collection import (
    REKEY_GRACE_S,
    GroupsCollectionResource,
    GroupsItemResource,
)
from lichen.coap.resources.groups_invite import GroupsInviteResource
from lichen.coap.resources.groups_remove import GroupsRemoveResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.group_membership import GroupRoster

ROOT = Path(__file__).resolve().parents[3]
SEQ = ROOT / "test" / "vectors" / "groups_membership_sequences.json"
REKEY = ROOT / "test" / "vectors" / "groups_rekey.json"


async def _client_server(site: Site):
    net = InMemoryNetwork()
    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


@pytest.mark.asyncio
async def test_membership_protocol_sequences() -> None:
    document = json.loads(SEQ.read_text(encoding="utf-8"))
    owner = "0200::1111"
    for case in document["vectors"]:
        collection = GroupsCollectionResource(owner=owner, clock=lambda: 1716742800)
        site = Site()
        site.add_resource(["groups"], collection)
        site.add_resource(["groups"], GroupsItemResource(collection))
        site.add_resource(["groups", "invite"], GroupsInviteResource())
        client, server = await _client_server(site)
        group_id = ""
        try:
            for step in case["steps"]:
                if step["op"] == "create":
                    created = await client.request(
                        Message(
                            code=aiocoap.POST,
                            uri="coap://server/groups",
                            payload=cbor2.dumps(
                                {"name": step["name"], "encrypted": step["encrypted"]}
                            ),
                        )
                    ).response
                    assert created.code == aiocoap.CREATED
                    group_id = cbor2.loads(created.payload)["id"]
                elif step["op"] == "invite":
                    assert step["inviter_is_owner"] is True
                    assert step["role"] == "member"
                    invited = await client.request(
                        Message(
                            code=aiocoap.POST,
                            uri="coap://server/groups/invite",
                            payload=cbor2.dumps(
                                {
                                    "group_id": group_id,
                                    "group_name": "Team Alpha",
                                    "mcast": "ff35:0040::1",
                                    "inviter": owner,
                                    "role": "member",
                                    "expires": 1716829200,
                                    "signature": b"\x11",
                                }
                            ),
                        )
                    ).response
                    assert invited.code == aiocoap.CHANGED
                elif step["op"] == "join_key":
                    resp = await client.request(
                        Message(
                            code=aiocoap.POST,
                            uri=f"coap://server/groups/{group_id}/key",
                            payload=cbor2.dumps(
                                {"request": "join_key", "node": step["node"]}
                            ),
                        )
                    ).response
                    assert resp.code == aiocoap.CONTENT
                elif step["op"] == "members":
                    resp = await client.request(
                        Message(
                            code=aiocoap.GET,
                            uri=f"coap://server/groups/{group_id}/members",
                        )
                    ).response
                    body = cbor2.loads(resp.payload)
                    expected = step["expected"]
                    if expected.get("owner_is_member"):
                        assert body["owner"] in body["members"]
                    if "admins" in expected:
                        assert body["admins"] == expected["admins"]
                    if "member_count" in expected:
                        assert len(body["members"]) == expected["member_count"]
                    if "contains" in expected:
                        assert expected["contains"] in body["members"]
        finally:
            await client.shutdown()
            await server.shutdown()


@pytest.mark.asyncio
async def test_rekey_on_member_removal() -> None:
    document = json.loads(REKEY.read_text(encoding="utf-8"))
    assert document["grace_s"] == REKEY_GRACE_S
    case = document["vectors"][0]
    now = {"t": 1_716_742_800.0}
    owner = "0200::1111"
    removed = case["removed_member"]
    collection = GroupsCollectionResource(owner=owner, clock=lambda: now["t"])
    created_id = None
    site = Site()
    site.add_resource(["groups"], collection)
    site.add_resource(["groups"], GroupsItemResource(collection))
    roster = GroupRoster(owner=owner)
    remover = GroupsRemoveResource(
        roster=roster,
        node_id=removed,
        collection=collection,
    )
    site.add_resource(["groups", "remove"], remover)
    client, server = await _client_server(site)
    try:
        created = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups",
                payload=cbor2.dumps({"name": "Team Alpha", "encrypted": True}),
            )
        ).response
        created_id = cbor2.loads(created.payload)["id"]
        await client.request(
            Message(
                code=aiocoap.POST,
                uri=f"coap://server/groups/{created_id}/key",
                payload=cbor2.dumps({"request": "join_key", "node": removed}),
            )
        ).response
        item = collection.groups[created_id]
        assert item["key_epoch"] == case["initial_epoch"]
        old_epoch = item["key_epoch"]
        old_secret = item["master_secret"]
        resp = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/remove",
                payload=cbor2.dumps(
                    {
                        "group_id": created_id,
                        "removed_by": owner,
                        "reason": "no longer on team",
                        "signature": b"\x00" * 48,
                    }
                ),
            )
        ).response
        assert resp.code == aiocoap.CHANGED
        item = collection.groups[created_id]
        assert item["key_epoch"] == case["after_removal_epoch"]
        assert item["master_secret"] != old_secret
        assert removed not in item["members"]
        assert collection.epoch_accepted(created_id, old_epoch) is case[
            "old_epoch_accepted_before_grace"
        ]
        now["t"] += document["grace_s"]
        assert collection.epoch_accepted(created_id, old_epoch) is case[
            "old_epoch_accepted_after_grace"
        ]
    finally:
        await client.shutdown()
        await server.shutdown()
