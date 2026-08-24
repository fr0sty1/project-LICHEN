# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for observable SenML CoAP resources (/sensors, /location)."""

from __future__ import annotations

import asyncio

import aiocoap
import cbor2
import pytest
from aiocoap import GET, PUT, Message

from lichen.coap.resources import (
    PositionBeaconResource,
    SenMLLocationResource,
    SenMLSensorsResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.senml.codec import pack, unpack
from lichen.senml.profiles import location, temperature

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
            resp = await client.request(Message(code=GET, uri="coap://srv/sensors")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/sensors")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/sensors")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/sensors")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/sensors")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# /location — GET
# ---------------------------------------------------------------------------


class TestSenMLLocationGet:
    async def test_empty_location_returns_empty_pack(self) -> None:
        """Before update(), /location returns valid empty SenML (not raw empty bytes)."""
        client, server, _sensors, _location = await _setup_with_sensors()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/location")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 112  # application/senml+cbor
            records = unpack(resp.payload)
            assert records == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_location_get_lat_lon(self) -> None:
        client, server, _sensors, location = await _setup_with_sensors()
        try:
            location.update(48.2049, 16.3710)
            resp = await client.request(Message(code=GET, uri="coap://srv/location")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/location")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/location")).response
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

            req = client.request(Message(code=GET, observe=0, uri="coap://srv/location"))
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


# ---------------------------------------------------------------------------
# /pos — PositionBeaconResource (PUT)
# ---------------------------------------------------------------------------


async def _setup_with_position_beacon() -> tuple[
    aiocoap.Context,
    aiocoap.Context,
    PositionBeaconResource,
]:
    """Set up client/server with a PositionBeaconResource at /pos."""
    net = InMemoryNetwork()
    pos_beacon = PositionBeaconResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, position_beacon_resource=pos_beacon)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, pos_beacon


class TestPositionBeaconPut:
    """Tests for PUT /pos — receiving position beacons."""

    async def test_put_valid_position_returns_changed(self) -> None:
        """PUT with valid SenML position data returns 2.04 Changed."""
        client, server, _beacon = await _setup_with_position_beacon()
        try:
            payload = pack(location(lat=48.2049, lon=16.3710))
            msg = Message(code=PUT, uri="coap://srv/pos", payload=payload)
            msg.opt.content_format = 112  # application/senml+cbor
            resp = await client.request(msg).response
            assert resp.code == aiocoap.CHANGED
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_with_all_fields(self) -> None:
        """PUT with full position (lat, lon, alt, speed, heading) succeeds."""
        client, server, beacon = await _setup_with_position_beacon()
        try:
            payload = pack(location(
                lat=37.7749,
                lon=-122.4194,
                alt=10.5,
                speed=1.2,
                heading=45.0,
            ))
            msg = Message(code=PUT, uri="coap://srv/pos", payload=payload)
            msg.opt.content_format = 112
            resp = await client.request(msg).response
            assert resp.code == aiocoap.CHANGED
            # Verify stored position
            positions = beacon.get_all_positions()
            assert len(positions) == 1
            pos = list(positions.values())[0]
            assert pos["lat"] == pytest.approx(37.7749)
            assert pos["lon"] == pytest.approx(-122.4194)
            assert pos["alt"] == pytest.approx(10.5)
            assert pos["speed"] == pytest.approx(1.2)
            assert pos["heading"] == pytest.approx(45.0)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_empty_payload_returns_bad_request(self) -> None:
        """PUT with empty payload returns 4.00 Bad Request."""
        client, server, _beacon = await _setup_with_position_beacon()
        try:
            msg = Message(code=PUT, uri="coap://srv/pos", payload=b"")
            msg.opt.content_format = 112
            resp = await client.request(msg).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_missing_lat_returns_bad_request(self) -> None:
        """PUT missing required lat field returns 4.00 Bad Request."""
        from lichen.senml.codec import SenmlRecord

        client, server, _beacon = await _setup_with_position_beacon()
        try:
            # Only lon, no lat
            payload = pack([SenmlRecord(n="lon", u="lon", v=16.3710)])
            msg = Message(code=PUT, uri="coap://srv/pos", payload=payload)
            msg.opt.content_format = 112
            resp = await client.request(msg).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_invalid_cbor_returns_bad_request(self) -> None:
        """PUT with invalid CBOR returns 4.00 Bad Request."""
        client, server, _beacon = await _setup_with_position_beacon()
        try:
            msg = Message(code=PUT, uri="coap://srv/pos", payload=b"\xff\xfe\xfd")
            msg.opt.content_format = 112
            resp = await client.request(msg).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_wrong_content_format_returns_bad_request(self) -> None:
        """PUT with wrong content format (not SenML+CBOR) returns 4.00."""
        client, server, _beacon = await _setup_with_position_beacon()
        try:
            payload = pack(location(lat=48.2049, lon=16.3710))
            msg = Message(code=PUT, uri="coap://srv/pos", payload=payload)
            msg.opt.content_format = 60  # application/cbor instead of senml+cbor
            resp = await client.request(msg).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_callback_invoked_on_position(self) -> None:
        """The on_position callback is invoked with sender and position."""
        received: list[tuple[str, dict]] = []

        def on_pos(sender_id: str, pos: dict) -> None:
            received.append((sender_id, pos))

        net = InMemoryNetwork()
        beacon = PositionBeaconResource(on_position=on_pos)
        info = StaticNodeInfo(status={"rank": 256})
        site = build_site(info, position_beacon_resource=beacon)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            payload = pack(location(lat=40.7128, lon=-74.0060))
            msg = Message(code=PUT, uri="coap://srv/pos", payload=payload)
            msg.opt.content_format = 112
            resp = await client.request(msg).response
            assert resp.code == aiocoap.CHANGED
            assert len(received) == 1
            sender_id, pos = received[0]
            assert pos["lat"] == pytest.approx(40.7128)
            assert pos["lon"] == pytest.approx(-74.0060)
        finally:
            await client.shutdown()
            await server.shutdown()


class TestPositionBeaconGet:
    """Tests for GET /pos — retrieving stored positions."""

    async def test_get_empty_returns_empty_dict(self) -> None:
        """GET with no stored positions returns empty CBOR map."""
        client, server, _beacon = await _setup_with_position_beacon()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/pos")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60  # application/cbor
            data = cbor2.loads(resp.payload)
            assert data == {}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_get_returns_stored_positions(self) -> None:
        """GET returns all stored positions with timestamps."""
        client, server, beacon = await _setup_with_position_beacon()
        try:
            # First PUT a position
            payload = pack(location(lat=51.5074, lon=-0.1278))
            msg = Message(code=PUT, uri="coap://srv/pos", payload=payload)
            msg.opt.content_format = 112
            await client.request(msg).response

            # Then GET
            resp = await client.request(Message(code=GET, uri="coap://srv/pos")).response
            assert resp.code == aiocoap.CONTENT
            data = cbor2.loads(resp.payload)
            assert len(data) == 1
            pos = list(data.values())[0]
            assert pos["lat"] == pytest.approx(51.5074)
            assert pos["lon"] == pytest.approx(-0.1278)
            assert "ts" in pos
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_not_exposed_without_resource(self) -> None:
        """build_site without position_beacon_resource does not expose /pos."""
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/pos")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()
