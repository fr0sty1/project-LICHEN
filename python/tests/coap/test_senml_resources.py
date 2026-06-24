# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for observable SenML CoAP resources (/sensors, /location)."""

from __future__ import annotations

import asyncio

import aiocoap
import pytest
from aiocoap import GET, Message

from lichen.coap.resources import (
    SenMLLocationResource,
    SenMLSensorsResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.senml.codec import unpack
from lichen.senml.profiles import temperature

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _setup_with_sensors() -> tuple[
    aiocoap.Context,
    aiocoap.Context,
    SenMLSensorsResource,
    SenMLLocationResource,
]:
    net = InMemoryNetwork()
    sensors = SenMLSensorsResource()
    location = SenMLLocationResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, sensors_resource=sensors, location_resource=location)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, sensors, location


# ---------------------------------------------------------------------------
# /sensors — GET
# ---------------------------------------------------------------------------


class TestSenMLSensorsGet:
    async def test_empty_sensors_returns_empty_pack(self) -> None:
        client, server, sensors, _loc = await _setup_with_sensors()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sensors")
            ).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 112  # application/senml+cbor
            records = unpack(resp.payload)
            assert records == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_sensors_returns_current_readings(self) -> None:
        client, server, sensors, _loc = await _setup_with_sensors()
        try:
            sensors.update([temperature(22.5)])
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sensors")
            ).response
            records = unpack(resp.payload)
            assert len(records) == 1
            assert records[0].n == "temperature"
            assert records[0].v == pytest.approx(22.5)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_sensors_reflects_latest_update(self) -> None:
        client, server, sensors, _loc = await _setup_with_sensors()
        try:
            sensors.update([temperature(20.0)])
            sensors.update([temperature(25.0)])
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sensors")
            ).response
            records = unpack(resp.payload)
            assert records[0].v == pytest.approx(25.0)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_sensors_multi_record(self) -> None:
        from lichen.senml.profiles import humidity
        client, server, sensors, _loc = await _setup_with_sensors()
        try:
            sensors.update([temperature(21.0), humidity(58.0)])
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sensors")
            ).response
            records = unpack(resp.payload)
            assert len(records) == 2
            assert {r.n for r in records} == {"temperature", "rel-humidity"}
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# /sensors — Observe
# ---------------------------------------------------------------------------


class TestSenMLSensorsObserve:
    async def test_observe_receives_push_on_update(self) -> None:
        client, server, sensors, _loc = await _setup_with_sensors()
        try:
            sensors.update([temperature(20.0)])

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/sensors"))
            first_resp = await req.response
            assert first_resp.code == aiocoap.CONTENT
            assert unpack(first_resp.payload)[0].v == pytest.approx(20.0)

            # Push a new reading; the observe notification should arrive
            obs_iter = req.observation.__aiter__()
            sensors.update([temperature(30.0)])
            notification = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            records = unpack(notification.payload)
            assert records[0].v == pytest.approx(30.0)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_not_exposed_without_resource(self) -> None:
        """build_site without sensors_resource does not expose /sensors."""
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sensors")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# /location — GET
# ---------------------------------------------------------------------------


class TestSenMLLocationGet:
    async def test_location_get_lat_lon(self) -> None:
        client, server, _sensors, location = await _setup_with_sensors()
        try:
            location.update(48.2049, 16.3710)
            resp = await client.request(
                Message(code=GET, uri="coap://srv/location")
            ).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 112
            records = unpack(resp.payload)
            by_name = {r.n: r for r in records}
            assert by_name["lat"].v == pytest.approx(48.2049)
            assert by_name["lon"].v == pytest.approx(16.3710)
            assert "alt" not in by_name
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_location_get_with_altitude(self) -> None:
        client, server, _sensors, location = await _setup_with_sensors()
        try:
            location.update(-33.8688, -70.6693, alt=567.0)
            resp = await client.request(
                Message(code=GET, uri="coap://srv/location")
            ).response
            records = unpack(resp.payload)
            by_name = {r.n: r for r in records}
            assert by_name["alt"].v == pytest.approx(567.0)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_location_not_exposed_without_resource(self) -> None:
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/location")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# /location — Observe
# ---------------------------------------------------------------------------


class TestSenMLLocationObserve:
    async def test_observe_location_receives_position_update(self) -> None:
        client, server, _sensors, location = await _setup_with_sensors()
        try:
            location.update(0.0, 0.0)

            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/location")
            )
            first_resp = await req.response
            assert first_resp.code == aiocoap.CONTENT

            # Update position; observe notification should arrive
            obs_iter = req.observation.__aiter__()
            location.update(48.2049, 16.3710, alt=158.0)
            notification = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            records = unpack(notification.payload)
            by_name = {r.n: r for r in records}
            assert by_name["lat"].v == pytest.approx(48.2049)
            assert by_name["alt"].v == pytest.approx(158.0)
        finally:
            await client.shutdown()
            await server.shutdown()
