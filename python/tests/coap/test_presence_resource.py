# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the observable /presence CoAP resource (spec 18.5)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import aiocoap
import cbor2
import pytest
from aiocoap import GET, PUT, Message

from lichen.coap.resources import PresenceResource, StaticNodeInfo, build_site
from lichen.coap.resources.presence import _peer_is_local_admin
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.presence import AWAY_AFTER_S, STATIONARY_AFTER_S, Presence

_T0 = 1_716_742_800


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


async def _setup(
    clock: _Clock | None = None,
    *,
    allow_writes: bool = False,
) -> tuple[aiocoap.Context, aiocoap.Context, PresenceResource, _Clock]:
    net = InMemoryNetwork()
    clock = clock if clock is not None else _Clock(_T0)
    presence = PresenceResource(time_source=clock, allow_writes=allow_writes)
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, presence_resource=presence)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    try:
        client = await create_lichen_context(net.channel("cli"), "cli")
    except BaseException:
        await server.shutdown()
        raise
    return client, server, presence, clock


async def _setup_writable(
    clock: _Clock | None = None,
) -> tuple[aiocoap.Context, aiocoap.Context, PresenceResource, _Clock]:
    return await _setup(clock, allow_writes=True)


def _put_presence(status: str, **fields: object) -> Message:
    req = Message(
        code=PUT,
        uri="coap://srv/presence",
        payload=cbor2.dumps({"status": status, **fields}),
    )
    req.opt.content_format = 60
    return req


async def _get(client: aiocoap.Context) -> tuple[aiocoap.Message, dict]:
    resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
    return resp, cbor2.loads(resp.payload)


class TestPresenceGet:
    async def test_default_is_available(self) -> None:
        client, server, _, _ = await _setup()
        try:
            resp, body = await _get(client)
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            assert body == {"status": "available", "ts": _T0}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_not_exposed_without_resource(self) -> None:
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        try:
            client = await create_lichen_context(net.channel("cli"), "cli")
        except BaseException:
            await server.shutdown()
            raise
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/presence")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


class TestPresencePutAuth:
    async def test_put_unauthorized_by_default(self) -> None:
        client, server, presence, _ = await _setup()
        try:
            resp = await client.request(_put_presence("busy", msg="In meeting")).response
            assert resp.code == aiocoap.UNAUTHORIZED
            got = presence.get_presence()
            assert got.status == "available"
            assert got.msg is None
            _, body = await _get(client)
            assert body == {"status": "available", "ts": _T0}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_unauthorized_before_parsing(self) -> None:
        client, server, presence, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/presence", payload=b"")
            ).response
            assert resp.code == aiocoap.UNAUTHORIZED
            assert presence.get_presence().status == "available"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_get_allowed_without_writes(self) -> None:
        client, server, _, _ = await _setup()
        try:
            resp, body = await _get(client)
            assert resp.code == aiocoap.CONTENT
            assert body == {"status": "available", "ts": _T0}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_allowed_without_writes(self) -> None:
        client, server, presence, _ = await _setup()
        try:
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence"))
            first = await req.response
            assert cbor2.loads(first.payload)["status"] == "available"
            obs_iter = req.observation.__aiter__()
            presence.note_battery(40)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["battery"] == 40
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_allowed_with_allow_writes(self) -> None:
        client, server, presence, _ = await _setup_writable()
        try:
            resp = await client.request(_put_presence("busy")).response
            assert resp.code == aiocoap.CHANGED
            assert presence.get_presence().status == "busy"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_local_admin_allowed_without_allow_writes(self) -> None:
        presence = PresenceResource(time_source=_Clock(_T0), allow_writes=False)
        req = Message(code=PUT, payload=cbor2.dumps({"status": "busy", "msg": "LCI"}))
        req.opt.content_format = 60
        req.remote = SimpleNamespace(hostinfo="[::1]")
        resp = await presence.render_put(req)
        assert resp.code == aiocoap.CHANGED
        got = presence.get_presence()
        assert got.status == "busy"
        assert got.msg == "LCI"

    @pytest.mark.parametrize(
        "hostinfo",
        (
            "[::1]:49152",
            "[0:0:0:0:0:0:0:1]:65535",
            "[::1%lo0]:5683",
            "127.0.0.1:49152",
            "127.255.255.254:1",
            "127.0.0.1:0",
        ),
    )
    async def test_put_accepts_aiocoap_loopback_hostinfo(self, hostinfo: str) -> None:
        presence = PresenceResource(time_source=_Clock(_T0), allow_writes=False)
        req = _put_presence("busy")
        req.remote = SimpleNamespace(hostinfo=hostinfo)
        resp = await presence.render_put(req)
        assert resp.code == aiocoap.CHANGED

    @pytest.mark.parametrize(
        "hostinfo",
        (
            "[2001:db8::1]:49152",
            "[fe80::1%en0]:5683",
            "192.0.2.1:49152",
            "localhost:5683",
            "::1:5683",
            "[::1",
            " [::1]:49152",
            "127.0.0.1:49152:extra",
        ),
    )
    async def test_put_rejects_remote_or_malformed_hostinfo(self, hostinfo: str) -> None:
        presence = PresenceResource(time_source=_Clock(_T0), allow_writes=False)
        req = _put_presence("emergency")
        req.remote = SimpleNamespace(hostinfo=hostinfo)
        resp = await presence.render_put(req)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert presence.get_presence().status == "available"

    async def test_put_non_loopback_remote_unauthorized(self) -> None:
        presence = PresenceResource(time_source=_Clock(_T0), allow_writes=False)
        req = Message(code=PUT, payload=cbor2.dumps({"status": "emergency"}))
        req.opt.content_format = 60
        req.remote = SimpleNamespace(hostinfo="[2001:db8::1]")
        resp = await presence.render_put(req)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert presence.get_presence().status == "available"

    async def test_put_without_remote_unauthorized(self) -> None:
        presence = PresenceResource(time_source=_Clock(_T0), allow_writes=False)
        req = Message(code=PUT, payload=cbor2.dumps({"status": "busy"}))
        req.opt.content_format = 60
        resp = await presence.render_put(req)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert presence.get_presence().status == "available"


class TestLocalAdminAuthorityParsing:
    """Loopback hosts are admin in both families; everything else stays denied.

    Mirrors TestLocalAdminAuthorityParsing in test_messages_resource.py: the
    gate helper is shared with messaging (lichen_coap_is_local_admin parity,
    nlx7), so a v4-mapped form must deny even though Python's ipaddress
    unwraps ``::ffff:127.0.0.1`` to loopback. Bracketed-loopback hosts with
    non-canonical port suffixes parse per the shared RFC 3986 authority rule.
    """

    @pytest.mark.parametrize(
        ("authority", "expected"),
        [
            ("[::1]", True),
            ("[::1]:5683", True),
            ("[::1]:9999", True),
            ("::1", True),
            ("127.0.0.1", True),
            ("127.0.0.1:5683", True),
            ("[::ffff:127.0.0.1]", False),
            ("::ffff:127.0.0.1", False),
            ("fe80::5%lora_mesh", False),
            ("[fe80::5]:5683", False),
            ("[2001:db8::42]:1234", False),
            ("localhost", False),
            ("localhost:5683", False),
            ("[::1", False),
            (":5683", False),
            ("", False),
        ],
    )
    def test_authority_matrix(self, authority: str, expected: bool) -> None:
        remote: Any = SimpleNamespace(hostinfo=authority)
        assert _peer_is_local_admin(remote) is expected

    def test_missing_remote_or_hostinfo_is_not_admin(self) -> None:
        assert _peer_is_local_admin(None) is False
        assert _peer_is_local_admin(SimpleNamespace()) is False
        assert _peer_is_local_admin(SimpleNamespace(hostinfo=None)) is False

    async def test_put_denies_ipv4_mapped_loopback_remote(self) -> None:
        """The regressed case: v4-mapped loopback must not pass the write gate."""
        presence = PresenceResource(time_source=_Clock(_T0), allow_writes=False)
        req = _put_presence("emergency")
        req.remote = SimpleNamespace(hostinfo="[::ffff:127.0.0.1]")
        resp = await presence.render_put(req)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert presence.get_presence().status == "available"


class TestPresencePut:
    async def test_put_replaces_status_and_returns_changed(self) -> None:
        client, server, presence, clock = await _setup_writable()
        try:
            clock.t = _T0 + 5
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "busy", "msg": "In meeting"}),
            )
            req.opt.content_format = 60
            resp = await client.request(req).response
            assert resp.code == aiocoap.CHANGED
            got = presence.get_presence()
            assert got.status == "busy"
            assert got.msg == "In meeting"
            assert got.activity is None
            assert got.ts == _T0 + 5
            _, body = await _get(client)
            assert body == {"status": "busy", "msg": "In meeting", "ts": _T0 + 5}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_all_fields(self) -> None:
        client, server, _, _ = await _setup_writable()
        try:
            payload = Presence(
                status="available",
                ts=_T0,
                activity="moving",
                msg="On patrol",
                battery=87,
            ).to_cbor()
            req = Message(code=PUT, uri="coap://srv/presence", payload=payload)
            req.opt.content_format = 60
            resp = await client.request(req).response
            assert resp.code == aiocoap.CHANGED
            _, body = await _get(client)
            assert body["status"] == "available"
            assert body["activity"] == "moving"
            assert body["msg"] == "On patrol"
            assert body["battery"] == 87
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_rejects_empty_payload(self) -> None:
        client, server, _, _ = await _setup_writable()
        try:
            req = Message(code=PUT, uri="coap://srv/presence", payload=b"")
            resp = await client.request(req).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_rejects_unknown_status(self) -> None:
        client, server, _, _ = await _setup_writable()
        try:
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "invisible"}),
            )
            resp = await client.request(req).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_rejects_missing_status(self) -> None:
        client, server, _, _ = await _setup_writable()
        try:
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"msg": "hello"}),
            )
            resp = await client.request(req).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_rejects_unknown_field(self) -> None:
        client, server, _, _ = await _setup_writable()
        try:
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "available", "rank": 1}),
            )
            resp = await client.request(req).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_rejects_wrong_content_format(self) -> None:
        client, server, _, _ = await _setup_writable()
        try:
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "busy"}),
            )
            req.opt.content_format = 50
            resp = await client.request(req).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_rejects_trailing_cbor(self) -> None:
        client, server, _, _ = await _setup_writable()
        try:
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "busy"}) + cbor2.dumps({"status": "away"}),
            )
            resp = await client.request(req).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_cannot_clear_emergency_while_sos_active(self) -> None:
        client, server, presence, clock = await _setup_writable()
        try:
            clock.t = _T0 + 1
            presence.set_presence(Presence(status="busy", ts=_T0, msg="In meeting"))
            presence.note_sos(True)
            assert presence.get_presence().status == "emergency"

            clock.t = _T0 + 2
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "available", "msg": "all clear"}),
            )
            req.opt.content_format = 60
            resp = await client.request(req).response
            assert resp.code == aiocoap.CHANGED
            _, body = await _get(client)
            assert body["status"] == "emergency"
            assert body["msg"] == "all clear"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_battery_below_ten_sets_low_battery_without_tick(self) -> None:
        # Spec 18.5.3: PUT with battery < 10 must include low_battery=True
        client, server, _, _ = await _setup_writable()
        try:
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "busy", "battery": 9, "low_battery": True}),
            )
            req.opt.content_format = 60
            resp = await client.request(req).response
            assert resp.code == aiocoap.CHANGED
            _, body = await _get(client)
            assert body["status"] == "busy"
            assert body["battery"] == 9
            assert body["low_battery"] is True
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_during_sos_is_restored_when_sos_clears(self) -> None:
        client, server, presence, clock = await _setup_writable()
        try:
            clock.t = _T0 + 1
            presence.set_presence(Presence(status="busy", ts=_T0, msg="In meeting"))
            presence.note_sos(True)
            clock.t = _T0 + 2
            req = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "away", "msg": "headed back"}),
            )
            req.opt.content_format = 60
            resp = await client.request(req).response
            assert resp.code == aiocoap.CHANGED
            assert presence.get_presence().status == "emergency"

            clock.t = _T0 + 3
            presence.note_sos(False)
            restored = presence.get_presence()
            assert restored.status == "away"
            assert restored.msg == "headed back"
        finally:
            await client.shutdown()
            await server.shutdown()


class TestPresenceObserve:
    async def test_observe_notified_on_put(self) -> None:
        client, server, _, clock = await _setup_writable()
        try:
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence"))
            first = await req.response
            assert cbor2.loads(first.payload)["status"] == "available"

            obs_iter = req.observation.__aiter__()
            clock.t = _T0 + 10
            put = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "away"}),
            )
            put.opt.content_format = 60
            await client.request(put).response
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["status"] == "away"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_put_during_sos_stays_emergency(self) -> None:
        client, server, presence, clock = await _setup_writable()
        try:
            clock.t = _T0 + 1
            presence.note_sos(True)
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence"))
            first = await req.response
            assert cbor2.loads(first.payload)["status"] == "emergency"
            obs_iter = req.observation.__aiter__()
            clock.t = _T0 + 2
            put = Message(
                code=PUT,
                uri="coap://srv/presence",
                payload=cbor2.dumps({"status": "offline", "msg": "hiding"}),
            )
            put.opt.content_format = 60
            await client.request(put).response
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            body = cbor2.loads(note.payload)
            assert body["status"] == "emergency"
            assert body["msg"] == "hiding"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_sos_clear(self) -> None:
        client, server, presence, clock = await _setup()
        try:
            clock.t = _T0 + 1
            presence.set_presence(Presence(status="busy", ts=_T0, msg="In meeting"))
            presence.note_sos(True)
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence"))
            first = await req.response
            assert cbor2.loads(first.payload)["status"] == "emergency"
            obs_iter = req.observation.__aiter__()
            clock.t = _T0 + 2
            presence.note_sos(False)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            body = cbor2.loads(note.payload)
            assert body["status"] == "busy"
            assert body["msg"] == "In meeting"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_battery(self) -> None:
        client, server, presence, _ = await _setup()
        try:
            presence.note_battery(50)
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence"))
            first = await req.response
            assert cbor2.loads(first.payload)["battery"] == 50
            obs_iter = req.observation.__aiter__()
            presence.note_battery(40)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["battery"] == 40
        finally:
            await client.shutdown()
            await server.shutdown()


class TestPresenceAutomatic:
    async def test_gps_motion(self) -> None:
        client, server, presence, clock = await _setup()
        try:
            clock.t = _T0 + 1
            presence.note_gps(True)
            _, body = await _get(client)
            assert body["status"] == "available"
            assert body["activity"] == "moving"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_gps_stationary_after_threshold(self) -> None:
        client, server, presence, clock = await _setup()
        try:
            presence.note_gps(False, now=_T0)
            clock.t = _T0 + STATIONARY_AFTER_S + 1
            presence.tick()
            _, body = await _get(client)
            assert body["status"] == "available"
            assert body["activity"] == "stationary"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_away_after_inactivity(self) -> None:
        client, server, presence, clock = await _setup()
        try:
            clock.t = _T0 + AWAY_AFTER_S + 1
            presence.tick()
            _, body = await _get(client)
            assert body["status"] == "away"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_sos_and_restore(self) -> None:
        client, server, presence, clock = await _setup()
        try:
            clock.t = _T0 + 1
            presence.set_presence(Presence(status="busy", ts=_T0, msg="In meeting"))
            presence.note_sos(True)
            assert presence.get_presence().status == "emergency"
            clock.t = _T0 + 2
            presence.note_sos(False)
            restored = presence.get_presence()
            assert restored.status == "busy"
            assert restored.msg == "In meeting"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_low_battery_flag(self) -> None:
        client, server, presence, _ = await _setup()
        try:
            presence.note_battery(9)
            _, body = await _get(client)
            assert body["battery"] == 9
            assert body["low_battery"] is True
            presence.note_battery(20)
            _, body = await _get(client)
            assert body["battery"] == 20
            assert "low_battery" not in body
        finally:
            await client.shutdown()
            await server.shutdown()
