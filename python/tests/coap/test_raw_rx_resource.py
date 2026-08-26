# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GET /diag/raw/rx server resource (spec/11-lci.md 17.5.4)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import GET, Message
from aiocoap.resource import Site

from lichen.client.lci import normalize_raw_rx_event, normalize_raw_rx_status
from lichen.coap.raw_diag import RawDiagTTL
from lichen.coap.resources.raw_rx import (
    DiagResource,
    RawRxEventsResource,
    RawRxResource,
    default_disabled_status,
    diag_summary,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


def _site(resource: RawRxResource) -> Site:
    site = Site()
    site.add_resource(["diag", "raw", "rx"], resource)
    return site


@pytest.mark.asyncio
async def test_get_raw_rx_disabled_matches_spec_example() -> None:
    resource = RawRxResource()
    assert resource.status_map() == default_disabled_status()
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=_site(resource)
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(
            Message(code=GET, uri="coap://server/diag/raw/rx")
        ).response
        assert resp.code == aiocoap.CONTENT
        payload = cbor2.loads(resp.payload)
        assert payload == {"enabled": False, "remaining_s": 0, "max_ttl_s": 300}
        status = normalize_raw_rx_status(payload, coap_code="2.05")
        assert status.enabled is False
        assert status.remaining_s == 0
        assert status.max_ttl_s == 300
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_get_raw_rx_reports_armed_ttl() -> None:
    now = {"t": 0.0}

    def clock() -> float:
        return now["t"]

    ttl = RawDiagTTL(clock=clock)
    ok, code = ttl.arm(enabled=True, ttl_s=60)
    assert ok is True
    assert code == "2.04 Changed"
    resource = RawRxResource(ttl)
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=_site(resource)
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(
            Message(code=GET, uri="coap://server/diag/raw/rx")
        ).response
        payload = cbor2.loads(resp.payload)
        assert payload["enabled"] is True
        assert payload["remaining_s"] == 60
        now["t"] = 60.0
        resp = await client.request(
            Message(code=GET, uri="coap://server/diag/raw/rx")
        ).response
        payload = cbor2.loads(resp.payload)
        assert payload["enabled"] is False
        assert payload["remaining_s"] == 0
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_put_raw_rx_arms_and_get_reflects() -> None:
    resource = RawRxResource()
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=_site(resource)
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        put = await client.request(
            Message(
                code=aiocoap.PUT,
                uri="coap://server/diag/raw/rx",
                payload=cbor2.dumps({"enabled": True, "ttl_s": 60, "include_payload": True}),
            )
        ).response
        assert put.code == aiocoap.CHANGED
        assert resource.include_payload is True
        got = await client.request(
            Message(code=GET, uri="coap://server/diag/raw/rx")
        ).response
        payload = cbor2.loads(got.payload)
        assert payload["enabled"] is True
        assert payload["remaining_s"] == 60
        bad = await client.request(
            Message(
                code=aiocoap.PUT,
                uri="coap://server/diag/raw/rx",
                payload=cbor2.dumps({"enabled": True}),
            )
        ).response
        assert bad.code == aiocoap.BAD_REQUEST
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_get_diag_summary() -> None:
    site = Site()
    site.add_resource(["diag"], DiagResource())
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=site
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/diag")).response
        assert resp.code == aiocoap.CONTENT
        assert cbor2.loads(resp.payload) == diag_summary()
        assert diag_summary()["raw"]["rx"] == "/diag/raw/rx"
        assert diag_summary()["raw"]["max_frame_len"] == 255
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_raw_rx_events_observe() -> None:
    import asyncio

    events = RawRxEventsResource()
    site = Site()
    site.add_resource(["diag", "raw", "rx", "events"], events)
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=site
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        req = client.request(
            Message(code=GET, observe=0, uri="coap://server/diag/raw/rx/events")
        )
        first = await req.response
        assert first.code == aiocoap.CONTENT
        assert cbor2.loads(first.payload) == {}
        obs_iter = req.observation.__aiter__()
        sample = {
            "frame": bytes.fromhex("c1020304"),
            "rssi_dbm": -85,
            "snr_db": 9,
            "uptime_ms": 3662000,
            "freq_hz": 915000000,
            "crc_ok": True,
        }
        events.publish(sample)
        notification = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
        payload = cbor2.loads(notification.payload)
        parsed = normalize_raw_rx_event(payload, coap_code="2.05")
        assert parsed.rssi_dbm == -85
        assert parsed.crc_ok is True
        assert parsed.frame == bytes.fromhex("c1020304")
    finally:
        await client.shutdown()
        await server.shutdown()
