# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the observable /sos CoAP resource."""

from __future__ import annotations

import asyncio

import aiocoap
import cbor2
import pytest
from aiocoap import DELETE, GET, PUT, Message

from lichen.coap.resources import SosResource, StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_EUI = bytes.fromhex("0102030405060708")
_T0 = 1_700_000_000.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _setup() -> tuple[aiocoap.Context, aiocoap.Context, SosResource]:
    net = InMemoryNetwork()
    sos = SosResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, sos_resource=sos)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, sos


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


class TestSosGet:
    async def test_idle_state(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sos")
            ).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            state = cbor2.loads(resp.payload)
            assert state["active"] is False
            assert state["from"] is None
            assert state["t"] is None
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_active_after_activate(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sos")
            ).response
            state = cbor2.loads(resp.payload)
            assert state["active"] is True
            assert state["from"] == _EUI.hex()
            assert state["t"] == pytest.approx(_T0)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_idle_after_cancel(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            sos.cancel()
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sos")
            ).response
            state = cbor2.loads(resp.payload)
            assert state["active"] is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_not_exposed_without_resource(self) -> None:
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sos")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# PUT / DELETE
# ---------------------------------------------------------------------------


class TestSosPutDelete:
    async def test_put_with_body_activates(self) -> None:
        client, server, sos = await _setup()
        try:
            body = cbor2.dumps({"from": _EUI.hex(), "t": _T0})
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/sos",
                        payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.CHANGED
            assert sos._active is True
            assert sos._from == _EUI.hex()
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_no_body_is_rejected(self) -> None:
        client, server, sos = await _setup()
        try:
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/sos", payload=b"")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert sos._active is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_invalid_cbor_returns_bad_request(self) -> None:
        client, server, _ = await _setup()
        try:
            # b"\xa5\x01" is a truncated CBOR map (declares 5 entries, body cut short)
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/sos", payload=b"\xa5\x01")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_nonstring_from_returns_bad_request(self) -> None:
        """Non-string 'from' field (e.g. integer) must be rejected."""
        client, server, sos = await _setup()
        try:
            # "from" as integer instead of hex string
            body = cbor2.dumps({"from": 12345, "t": _T0})
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/sos",
                        payload=body, content_format=60)
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert sos._active is False  # should not activate
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_duplicate_cbor_keys_preserve_state_and_do_not_notify(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            sos.updated_state = notified  # type: ignore[method-assign]
            payload = (
                b"\xa3"
                + cbor2.dumps("from")
                + cbor2.dumps(_EUI.hex())
                + cbor2.dumps("t")
                + cbor2.dumps(_T0)
                + cbor2.dumps("t")
                + cbor2.dumps(_T0 + 1)
            )
            response = await client.request(
                Message(code=PUT, uri="coap://srv/sos", payload=payload)
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert (sos._active, sos._from, sos._t) == (True, _EUI.hex(), _T0)
            assert notifications == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_put_accepts_preferred_float16_timestamp(self) -> None:
        client, server, sos = await _setup()
        try:
            payload = (
                b"\xa2"
                + cbor2.dumps("from")
                + cbor2.dumps(_EUI.hex())
                + cbor2.dumps("t")
                + b"\xf9\x3e\x00"  # preferred float16 1.5
            )
            response = await client.request(
                Message(code=PUT, uri="coap://srv/sos", payload=payload)
            ).response
            assert response.code == aiocoap.CHANGED
            assert (sos._active, sos._from, sos._t) == (True, _EUI.hex(), 1.5)
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "tagged_value",
        [b"\xd8\x1c\x81\xf9\x3e\x00", b"\xd8\x1d\x00"],
    )
    async def test_put_rejects_tags_without_state_or_notification(
        self, tagged_value: bytes
    ) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            sos.updated_state = notified  # type: ignore[method-assign]
            payload = (
                b"\xa2"
                + cbor2.dumps("from")
                + cbor2.dumps(_EUI.hex())
                + cbor2.dumps("t")
                + tagged_value
            )
            response = await client.request(
                Message(code=PUT, uri="coap://srv/sos", payload=payload)
            ).response
            current = await client.request(
                Message(code=GET, uri="coap://srv/sos")
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(current.payload) == {
                "active": True,
                "from": _EUI.hex(),
                "t": _T0,
            }
            assert notifications == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "payload",
        [
            cbor2.dumps([]),
            cbor2.dumps({}),
            cbor2.dumps({"from": _EUI.hex()}),
            cbor2.dumps({"t": _T0}),
            cbor2.dumps({"from": True, "t": _T0}),
            cbor2.dumps({"from": "0102 030405060708", "t": _T0}),
            cbor2.dumps({"from": "01:02:03:04:05:06:07:08", "t": _T0}),
            cbor2.dumps({"from": _EUI.hex(), "t": True}),
            cbor2.dumps({"from": _EUI.hex(), "t": -1}),
            cbor2.dumps({"from": _EUI.hex(), "t": float("nan")}),
            cbor2.dumps({"from": _EUI.hex(), "t": float("inf")}),
            cbor2.dumps({"from": _EUI.hex(), "t": "1"}),
            cbor2.dumps({"from": _EUI.hex(), "t": _T0}) + b"trailing",
        ],
    )
    async def test_invalid_put_preserves_active_state_and_does_not_notify(
        self, payload: bytes
    ) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            sos.updated_state = notified  # type: ignore[method-assign]
            response = await client.request(
                Message(code=PUT, uri="coap://srv/sos", payload=payload)
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert (sos._active, sos._from, sos._t) == (True, _EUI.hex(), _T0)
            assert notifications == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_delete_cancels_sos(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)
            resp = await client.request(
                Message(code=DELETE, uri="coap://srv/sos")
            ).response
            assert resp.code == aiocoap.DELETED
            assert sos._active is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_delete_when_idle_is_harmless(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=DELETE, uri="coap://srv/sos")
            ).response
            assert resp.code == aiocoap.DELETED
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Observe
# ---------------------------------------------------------------------------


class TestSosObserve:
    async def test_observe_notified_on_activate(self) -> None:
        client, server, sos = await _setup()
        try:
            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/sos")
            )
            first = await req.response
            assert cbor2.loads(first.payload)["active"] is False

            obs_iter = req.observation.__aiter__()
            sos.activate(_EUI, _T0)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is True
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_cancel(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)

            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/sos")
            )
            await req.response

            obs_iter = req.observation.__aiter__()
            sos.cancel()
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is False
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_retrigger(self) -> None:
        client, server, sos = await _setup()
        try:
            sos.activate(_EUI, _T0)

            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/sos")
            )
            await req.response

            obs_iter = req.observation.__aiter__()
            sos.retrigger()
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is True
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_retrigger_noop_when_idle(self) -> None:
        _, server, sos = await _setup()
        try:
            # retrigger while idle should not call updated_state (no crash, no notification)
            sos.retrigger()
            assert sos._active is False
        finally:
            await server.shutdown()

    async def test_observe_notified_on_put(self) -> None:
        client, server, _ = await _setup()
        try:
            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/sos")
            )
            await req.response

            obs_iter = req.observation.__aiter__()
            body = cbor2.dumps({"from": _EUI.hex(), "t": _T0})
            await client.request(
                Message(code=PUT, uri="coap://srv/sos",
                        payload=body, content_format=60)
            ).response
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload)["active"] is True
        finally:
            await client.shutdown()
            await server.shutdown()
