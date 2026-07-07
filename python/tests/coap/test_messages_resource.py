# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the observable /msg/inbox CoAP resource."""

from __future__ import annotations

import asyncio

import aiocoap
import cbor2
import pytest
from aiocoap import GET, POST, Message

from lichen.coap.resources import (
    MessageReceiptsResource,
    MessagesResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_FROM = "0102030405060708"
_TO_A = "aabbccddeeff0011"
_T0 = 1_700_000_000.0

_MSG1 = {"from": _FROM, "to": "all", "text": "hello mesh", "t": _T0}
_MSG2 = {"from": _TO_A, "to": _FROM, "text": "hi back", "t": _T0 + 1.0}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _setup() -> tuple[aiocoap.Context, aiocoap.Context, MessagesResource]:
    net = InMemoryNetwork()
    msgs = MessagesResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, messages_resource=msgs)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, msgs


def _inbox(payload: bytes) -> list[dict[str, object]]:
    decoded = cbor2.loads(payload)
    assert isinstance(decoded, dict)
    messages = decoded["messages"]
    assert isinstance(messages, list)
    return messages


# ---------------------------------------------------------------------------
# GET
# ---------------------------------------------------------------------------


class TestMessagesGet:
    async def test_core_discovery_marks_canonical_and_legacy_paths(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            body = resp.payload.decode()
            assert '</msg/inbox>;rt="msg.inbox";ct="60";obs' in body
            assert '</msg/sent>;rt="msg.sent";ct="60"' in body
            assert '</messages>;rt="legacy.messages";ct="60";title="legacy demo alias"' in body
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_empty_inbox(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            assert _inbox(resp.payload) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_deliver_appears_in_get(self) -> None:
        client, server, msgs = await _setup()
        try:
            msgs.deliver(_MSG1)
            resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            inbox = _inbox(resp.payload)
            assert len(inbox) == 1
            assert inbox[0]["text"] == "hello mesh"
            assert inbox[0]["from"] == _FROM
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_multiple_messages_in_order(self) -> None:
        client, server, msgs = await _setup()
        try:
            msgs.deliver(_MSG1)
            msgs.deliver(_MSG2)
            resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            inbox = _inbox(resp.payload)
            assert len(inbox) == 2
            assert inbox[0]["text"] == "hello mesh"
            assert inbox[1]["text"] == "hi back"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_inbox_capped_at_max(self) -> None:
        from lichen.coap.resources import _MESSAGES_MAX
        client, server, msgs = await _setup()
        try:
            for i in range(_MESSAGES_MAX + 10):
                msgs.deliver({"from": _FROM, "to": "all", "text": str(i), "t": _T0 + i})
            resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            inbox = _inbox(resp.payload)
            assert len(inbox) == _MESSAGES_MAX
            # oldest messages were dropped; newest survive
            assert inbox[-1]["text"] == str(_MESSAGES_MAX + 9)
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
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_legacy_messages_alias_reads_same_inbox(self) -> None:
        client, server, msgs = await _setup()
        try:
            msgs.deliver(_MSG1)
            resp = await client.request(
                Message(code=GET, uri="coap://srv/messages")
            ).response
            inbox = _inbox(resp.payload)
            assert inbox[0]["text"] == "hello mesh"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_legacy_messages_alias_adds_text_for_lci_body_messages(self) -> None:
        client, server, msgs = await _setup()
        try:
            msgs.deliver({"from": _FROM, "to": _TO_A, "body": "body-only"})
            resp = await client.request(
                Message(code=GET, uri="coap://srv/messages")
            ).response
            inbox = _inbox(resp.payload)
            assert inbox[0]["body"] == "body-only"
            assert inbox[0]["text"] == "body-only"
        finally:
            await client.shutdown()
            await server.shutdown()


class TestMessageReceipts:
    async def test_ack_not_advertised_without_receipts_resource(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert '</msg/ack>;rt="msg.ack";ct="60"' not in resp.payload.decode()

            missing = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack", payload=cbor2.dumps({}))
            ).response
            assert missing.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_ack_advertised_and_stores_valid_receipts(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert '</msg/ack>;rt="msg.ack";ct="60"' in discovery.payload.decode()

            payload = {"id": 12345, "status": "delivered", "ts": 1_716_742_900}
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps(payload),
                    content_format=60,
                )
            ).response

            assert resp.code == aiocoap.CHANGED
            assert receipts.receipts() == [payload]
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_ack_dispatches_normalized_receipts_to_handler(self) -> None:
        dispatched: list[dict[str, object]] = []
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource(handler=dispatched.append)
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps({"id": 12345, "status": "read", "ts": 1_716_742_901}),
                    content_format=60,
                )
            ).response

            assert resp.code == aiocoap.CHANGED
            assert dispatched == [{"id": 12345, "status": "read", "ts": 1_716_742_901}]
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "payload",
        [
            b"\xff",
            cbor2.dumps([]),
            cbor2.dumps({"status": "delivered", "ts": 1}),
            cbor2.dumps({"id": True, "status": "delivered", "ts": 1}),
            cbor2.dumps({"id": -1, "status": "delivered", "ts": 1}),
            cbor2.dumps({"id": 1.5, "status": "delivered", "ts": 1}),
            cbor2.dumps({"id": "abc", "status": "delivered", "ts": 1}),
            cbor2.dumps({"id": 1, "ts": 1}),
            cbor2.dumps({"id": 1, "status": "queued", "ts": 1}),
            cbor2.dumps({"id": 1, "status": "delivered"}),
            cbor2.dumps({"id": 1, "status": "delivered", "ts": True}),
            cbor2.dumps({"id": 1, "status": "delivered", "ts": -1}),
            cbor2.dumps({"id": 1, "status": "delivered", "ts": 1.5}),
        ],
    )
    async def test_ack_rejects_invalid_payloads(self, payload: bytes) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack", payload=payload)
            ).response

            assert resp.code == aiocoap.BAD_REQUEST
            assert receipts.receipts() == []
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# POST
# ---------------------------------------------------------------------------


class TestMessagesPost:
    async def test_post_valid_legacy_message(self) -> None:
        client, server, msgs = await _setup()
        try:
            body = cbor2.dumps(_MSG1)
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=body,
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
            assert tuple(resp.opt.location_path) == ("msg", "sent", "1")
            sent_resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/sent/1")
            ).response
            assert cbor2.loads(sent_resp.payload)["body"] == "hello mesh"
            sent_collection = await client.request(
                Message(code=GET, uri="coap://srv/msg/sent")
            ).response
            assert _inbox(sent_collection.payload)[0]["body"] == "hello mesh"
            # Verify it landed in inbox
            get_resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            inbox = _inbox(get_resp.payload)
            assert len(inbox) == 1
            assert inbox[0]["text"] == "hello mesh"
            assert inbox[0]["body"] == "hello mesh"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_valid_lci_message_body(self) -> None:
        client, server, _ = await _setup()
        try:
            body = cbor2.dumps({"to": "fd00::2", "body": "hello lci", "ack": True})
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=body,
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
            get_resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            inbox = _inbox(get_resp.payload)
            assert inbox[0]["body"] == "hello lci"
            assert inbox[0]["ack"] is True
            legacy_resp = await client.request(
                Message(code=GET, uri="coap://srv/messages")
            ).response
            assert _inbox(legacy_resp.payload)[0]["text"] == "hello lci"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_empty_body_returns_bad_request(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=b"")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_invalid_cbor_returns_bad_request(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=b"\xff\xff")
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_missing_required_field_returns_bad_request(self) -> None:
        client, server, _ = await _setup()
        try:
            # Missing "text"
            body = cbor2.dumps({"from": _FROM, "to": "all"})
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=body,
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_non_map_body_returns_bad_request(self) -> None:
        client, server, _ = await _setup()
        try:
            body = cbor2.dumps(["not", "a", "map"])
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=body,
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Observe
# ---------------------------------------------------------------------------


class TestMessagesObserve:
    async def test_observe_notified_on_deliver(self) -> None:
        client, server, msgs = await _setup()
        try:
            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/msg/inbox")
            )
            first = await req.response
            assert first.code == aiocoap.CONTENT
            assert _inbox(first.payload) == []

            obs_iter = req.observation.__aiter__()
            msgs.deliver(_MSG1)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            inbox = _inbox(note.payload)
            assert len(inbox) == 1
            assert inbox[0]["text"] == "hello mesh"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_post(self) -> None:
        client, server, msgs = await _setup()
        try:
            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/msg/inbox")
            )
            await req.response

            obs_iter = req.observation.__aiter__()
            # POST from same client context triggers notification
            await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps(_MSG2),
                    content_format=60,
                )
            ).response
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            inbox = _inbox(note.payload)
            assert inbox[0]["from"] == _TO_A
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_legacy_messages_alias_observe_notified_on_deliver(self) -> None:
        client, server, msgs = await _setup()
        try:
            req = client.request(
                Message(code=GET, observe=0, uri="coap://srv/messages")
            )
            await req.response

            obs_iter = req.observation.__aiter__()
            msgs.deliver(_MSG1)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            inbox = _inbox(note.payload)
            assert inbox[0]["text"] == "hello mesh"
        finally:
            await client.shutdown()
            await server.shutdown()
