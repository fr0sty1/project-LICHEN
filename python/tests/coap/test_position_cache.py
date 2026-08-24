# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the /pos/cache CoAP resource (spec 18.2.1)."""

from __future__ import annotations

import asyncio

import aiocoap
import cbor2
import pytest
from aiocoap import GET, Message

from lichen.coap.resources import PositionCacheResource, StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_NODE_A = "0200::1111"
_NODE_B = "0200::2222"
_T0 = 1_716_742_800.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _setup(
    time_source: float | None = None,
) -> tuple[aiocoap.Context, aiocoap.Context, PositionCacheResource]:
    net = InMemoryNetwork()
    now = time_source if time_source is not None else _T0 + 100.0
    cache = PositionCacheResource(time_source=lambda: now)
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, position_cache_resource=cache)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, cache


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


class TestPositionCacheGet:
    async def test_empty_returns_empty_positions_list(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60  # application/cbor
            data = cbor2.loads(resp.payload)
            assert data == {"positions": []}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_recorded_position_appears_in_get(self) -> None:
        client, server, cache = await _setup(time_source=_T0 + 45.0)
        try:
            cache.record_position(_NODE_A, lat=37.774929, lon=-122.419416, ts=_T0)
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            data = cbor2.loads(resp.payload)
            assert len(data["positions"]) == 1
            pos = data["positions"][0]
            assert pos["node"] == _NODE_A
            assert pos["lat"] == pytest.approx(37.774929)
            assert pos["lon"] == pytest.approx(-122.419416)
            assert pos["ts"] == pytest.approx(_T0)
            assert pos["age_s"] == 45
            assert "alt" not in pos
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_altitude_included_when_provided(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0, alt=10.5)
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            pos = cbor2.loads(resp.payload)["positions"][0]
            assert pos["alt"] == pytest.approx(10.5)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_two_peers_both_returned(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0)
            cache.record_position(_NODE_B, lat=38.00, lon=-121.00, ts=_T0 + 10.0)
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            data = cbor2.loads(resp.payload)
            nodes = {p["node"] for p in data["positions"]}
            assert nodes == {_NODE_A, _NODE_B}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_record_updates_existing_entry(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0)
            cache.record_position(_NODE_A, lat=38.00, lon=-121.00, ts=_T0 + 60.0)
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            data = cbor2.loads(resp.payload)
            assert len(data["positions"]) == 1
            assert data["positions"][0]["lat"] == pytest.approx(38.00)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_evict_removes_peer(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0)
            cache.record_position(_NODE_B, lat=38.00, lon=-121.00, ts=_T0)
            cache.evict(_NODE_A)
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            data = cbor2.loads(resp.payload)
            assert len(data["positions"]) == 1
            assert data["positions"][0]["node"] == _NODE_B
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_evict_missing_peer_is_noop(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.evict(_NODE_A)  # not in cache
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            assert cbor2.loads(resp.payload) == {"positions": []}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_purge_older_than_removes_stale(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0)
            cache.record_position(_NODE_B, lat=38.00, lon=-121.00, ts=_T0 + 200.0)
            evicted = cache.purge_older_than(_T0 + 100.0)
            assert evicted == 1
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            data = cbor2.loads(resp.payload)
            assert len(data["positions"]) == 1
            assert data["positions"][0]["node"] == _NODE_B
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_purge_no_stale_returns_zero(self) -> None:
        _, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0 + 500.0)
            assert cache.purge_older_than(_T0) == 0
        finally:
            await server.shutdown()

    async def test_not_exposed_without_resource(self) -> None:
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/pos/cache")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestPositionCacheValidation:
    async def test_invalid_timestamp_raises(self) -> None:
        cache = PositionCacheResource()
        with pytest.raises(ValueError, match="timestamp"):
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=-1.0)
        with pytest.raises(ValueError, match="timestamp"):
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=float("inf"))
        with pytest.raises(ValueError, match="timestamp"):
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=float("nan"))
        with pytest.raises(ValueError, match="timestamp"):
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts="bad")  # type: ignore[arg-type]

    async def test_invalid_latitude_raises(self) -> None:
        cache = PositionCacheResource()
        with pytest.raises(ValueError, match="latitude"):
            cache.record_position(_NODE_A, lat=float("inf"), lon=-122.42, ts=_T0)
        with pytest.raises(ValueError, match="latitude"):
            cache.record_position(_NODE_A, lat=float("nan"), lon=-122.42, ts=_T0)
        with pytest.raises(ValueError, match="latitude"):
            cache.record_position(_NODE_A, lat="bad", lon=-122.42, ts=_T0)  # type: ignore[arg-type]

    async def test_invalid_longitude_raises(self) -> None:
        cache = PositionCacheResource()
        with pytest.raises(ValueError, match="longitude"):
            cache.record_position(_NODE_A, lat=37.77, lon=float("inf"), ts=_T0)
        with pytest.raises(ValueError, match="longitude"):
            cache.record_position(_NODE_A, lat=37.77, lon=float("nan"), ts=_T0)

    async def test_invalid_altitude_raises(self) -> None:
        cache = PositionCacheResource()
        with pytest.raises(ValueError, match="altitude"):
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0, alt=float("inf"))
        with pytest.raises(ValueError, match="altitude"):
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0, alt=float("nan"))

    async def test_invalid_purge_cutoff_raises(self) -> None:
        cache = PositionCacheResource()
        with pytest.raises(ValueError, match="cutoff"):
            cache.purge_older_than(-1.0)
        with pytest.raises(ValueError, match="cutoff"):
            cache.purge_older_than(float("inf"))


# ---------------------------------------------------------------------------
# Observe
# ---------------------------------------------------------------------------


class TestPositionCacheObserve:
    async def test_observe_notified_on_record(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0)

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/pos/cache"))
            first = await req.response
            assert first.code == aiocoap.CONTENT
            assert len(cbor2.loads(first.payload)["positions"]) == 1

            obs_iter = req.observation.__aiter__()
            cache.record_position(_NODE_B, lat=38.00, lon=-121.00, ts=_T0 + 60.0)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            data = cbor2.loads(note.payload)
            nodes = {p["node"] for p in data["positions"]}
            assert _NODE_B in nodes
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_evict(self) -> None:
        client, server, cache = await _setup()
        try:
            cache.record_position(_NODE_A, lat=37.77, lon=-122.42, ts=_T0)

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/pos/cache"))
            await req.response

            obs_iter = req.observation.__aiter__()
            cache.evict(_NODE_A)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload) == {"positions": []}
        finally:
            await client.shutdown()
            await server.shutdown()
