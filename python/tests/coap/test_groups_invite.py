# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /groups/invite (spec/12-apps.md 18.8.2)."""

from __future__ import annotations

import json
from pathlib import Path

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.groups_invite import GroupsInviteResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "groups_membership.json"


@pytest.mark.asyncio
async def test_post_groups_invite_accepts_vector() -> None:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    case = next(v for v in document["vectors"] if v["name"] == "invite_member")
    payload = dict(case["payload"])
    payload["signature"] = bytes.fromhex(payload.pop("signature_hex"))
    resource = GroupsInviteResource()
    site = Site()
    site.add_resource(["groups", "invite"], resource)
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=site
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/invite",
                payload=cbor2.dumps(payload),
            )
        ).response
        assert resp.code == aiocoap.CHANGED
        assert len(resource.accepted) == 1
        assert resource.accepted[0].group_id == "team-alpha"
        assert resource.accepted[0].role == "member"
        bad = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/groups/invite",
                payload=cbor2.dumps({"group_id": "x", "role": "owner"}),
            )
        ).response
        assert bad.code == aiocoap.BAD_REQUEST
    finally:
        await client.shutdown()
        await server.shutdown()
