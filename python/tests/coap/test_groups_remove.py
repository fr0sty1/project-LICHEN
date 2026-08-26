# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /groups/remove (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import json
from pathlib import Path

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_remove import GroupsRemoveResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.group_membership import GroupRoster

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "groups_membership.json"


@pytest.mark.asyncio
async def test_post_groups_remove_accepts_vector() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    case = next(v for v in document["vectors"] if v["kind"] == "removal")
    payload = dict(case["payload"])
    payload["signature"] = bytes.fromhex(payload.pop("signature_hex"))
    roster = GroupRoster(
        owner=payload["removed_by"],
        members=frozenset({"member"}),
    )
    resource = GroupsRemoveResource(roster=roster, node_id="member")
    site = Site()
    site.add_resource(["groups", "remove"], resource)
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=site
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/remove",
                payload=cbor2.dumps(payload),
            )
        ).response
        assert resp.code == aiocoap.CHANGED
        assert resource.accepted[0].group_id == "team-alpha"
        forbidden = GroupsRemoveResource(
            roster=GroupRoster(owner="someone-else"),
            node_id="member",
        )
        site2 = Site()
        site2.add_resource(["groups", "remove"], forbidden)
        server2 = await create_lichen_context(
            net.channel("server2"), "server2", site=site2
        )
        try:
            denied = await client.request(
                Message(
                    code=aiocoap.POST,
                    uri="coap://server2/groups/remove",
                    payload=cbor2.dumps(payload),
                )
            ).response
            assert denied.code == aiocoap.FORBIDDEN
        finally:
            await server2.shutdown()
    finally:
        await client.shutdown()
        await server.shutdown()
