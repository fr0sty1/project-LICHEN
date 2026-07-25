# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the observable /presence CoAP resource."""

from __future__ import annotations

import asyncio

import aiocoap
import cbor2
import pytest
from aiocoap import GET, Message

from lichen.coap.resources import PresenceResource, StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_EUI_A = bytes.fromhex("0102030405060708")
_EUI_B = bytes.fromhex("aabbccddeeff0011")
_T0 = 1_700_000_000.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _setup() -> tuple[aiocoap.Context, aiocoap.Context, PresenceResource]:
    net = InMemoryNetwork()
    presence = PresenceResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, presence_resource=presence)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, presence


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


class TestPresenceGet:
    async def test_empty_returns_empty_list(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60  # application/cbor
            assert cbor2.loads(resp.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_seen_peer_appears_in_get(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            entries = cbor2.loads(resp.payload)
            assert len(entries) == 1
            assert entries[0]["id"] == _EUI_A.hex()
            assert entries[0]["rank"] == 256
            assert entries[0]["t"] == pytest.approx(_T0)
            assert "rssi" not in entries[0]
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_rssi_included_when_provided(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=128, t=_T0, rssi=-85)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            entry = cbor2.loads(resp.payload)[0]
            assert entry["rssi"] == -85
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_two_peers_both_returned(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0)
            presence.seen(_EUI_B, rank=512, t=_T0 + 1.0)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            entries = cbor2.loads(resp.payload)
            ids = {e["id"] for e in entries}
            assert ids == {_EUI_A.hex(), _EUI_B.hex()}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_seen_updates_existing_entry(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0)
            presence.seen(_EUI_A, rank=128, t=_T0 + 60.0)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            entries = cbor2.loads(resp.payload)
            assert len(entries) == 1
            assert entries[0]["rank"] == 128
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_evict_removes_peer(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0)
            presence.seen(_EUI_B, rank=512, t=_T0)
            presence.evict(_EUI_A)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            entries = cbor2.loads(resp.payload)
            assert len(entries) == 1
            assert entries[0]["id"] == _EUI_B.hex()
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_evict_missing_peer_is_noop(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.evict(_EUI_A)  # not in table
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            assert cbor2.loads(resp.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_purge_older_than_removes_stale(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0)
            presence.seen(_EUI_B, rank=512, t=_T0 + 200.0)
            evicted = presence.purge_older_than(_T0 + 100.0)
            assert evicted == 1
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            entries = cbor2.loads(resp.payload)
            assert len(entries) == 1
            assert entries[0]["id"] == _EUI_B.hex()
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_purge_no_stale_returns_zero(self) -> None:
        _, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0 + 500.0)
            assert presence.purge_older_than(_T0) == 0
        finally:
            await server.shutdown()

    async def test_not_exposed_without_resource(self) -> None:
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Observe
# ---------------------------------------------------------------------------


class TestPresenceObserve:
    async def test_observe_notified_on_seen(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0)

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence"))
            first = await req.response
            assert first.code == aiocoap.CONTENT
            assert len(cbor2.loads(first.payload)) == 1

            obs_iter = req.observation.__aiter__()
            presence.seen(_EUI_B, rank=512, t=_T0 + 60.0)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            entries = cbor2.loads(note.payload)
            ids = {e["id"] for e in entries}
            assert _EUI_B.hex() in ids
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_evict(self) -> None:
        client, server, presence = await _setup()
        try:
            presence.seen(_EUI_A, rank=256, t=_T0)

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence"))
            await req.response

            obs_iter = req.observation.__aiter__()
            presence.evict(_EUI_A)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()
