# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""POST /diag/raw/tx (spec/11-lci.md 17.5.4)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import Message
from aiocoap.resource import Site

from lichen.coap.resources.raw_tx import RawTxResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


@pytest.mark.asyncio
async def test_post_raw_tx_accepts_spec_frame() -> None:
    now = {"t": 0.0}
    resource = RawTxResource(clock=lambda: now["t"], min_interval_s=1.0)
    site = Site()
    site.add_resource(["diag", "raw", "tx"], resource)
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=site
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/diag/raw/tx",
                payload=cbor2.dumps({"frame": bytes.fromhex("c1020304"), "wait": True}),
            )
        ).response
        assert resp.code == aiocoap.CHANGED
        assert resource.last_frame == bytes.fromhex("c1020304")
        assert resource.last_wait is True
        too_soon = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/diag/raw/tx",
                payload=cbor2.dumps({"frame": bytes.fromhex("aa"), "wait": False}),
            )
        ).response
        assert too_soon.code == aiocoap.BAD_REQUEST
        now["t"] = 1.0
        again = await client.request(
            Message(
                code=aiocoap.POST,
                uri="coap://server/diag/raw/tx",
                payload=cbor2.dumps({"frame": bytes.fromhex("aa"), "wait": False}),
            )
        ).response
        assert again.code == aiocoap.CHANGED
        assert resource.last_frame == bytes.fromhex("aa")
    finally:
        await client.shutdown()
        await server.shutdown()
