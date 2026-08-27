# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the observable /msg/inbox CoAP resource."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aiocoap
import cbor2
import pytest
from aiocoap import GET, POST, Message

from lichen.coap.resources import (
    MESSAGES_MAX_BODY_SIZE,
    CannedMessagesResource,
    MessageReceiptsResource,
    MessagesResource,
    SentMessageDetailsResource,
    SentMessagesResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.resources.messaging import DEFAULT_CANNED_MESSAGES, _peer_is_local_admin
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_FROM = "0102030405060708"
_TO_A = "aabbccddeeff0011"
_T0 = 1_700_000_000.0
# InMemoryNetwork authority for IPv6 loopback is "[::1]" (admin per LCI).
_LCI_CLIENT = "::1"
_LCI_PEER_AUTHORITY = "[::1]"
# Spec 18.1.1 `from` is IPv6 tstr without brackets/port.
_LCI_EXPECTED_FROM = "::1"
# Non-loopback OSCORE peer authority for render-level identity-binding tests.
_OSCORE_PEER_AUTHORITY = "[2001:db8::42]"
_OSCORE_EXPECTED_FROM = "2001:db8::42"

_MSG1 = {"from": _FROM, "to": "all", "text": "hello mesh", "t": _T0}
_MSG2 = {"from": _TO_A, "to": _FROM, "text": "hi back", "t": _T0 + 1.0}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _admin_post(payload: bytes) -> Message:
    """POST bound to IPv6 loopback so LCI write gates accept it."""
    request = Message(code=POST, payload=payload)
    request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
    return request


async def _setup() -> tuple[aiocoap.Context, aiocoap.Context, MessagesResource]:
    net = InMemoryNetwork()
    msgs = MessagesResource()
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, messages_resource=msgs)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
    return client, server, msgs


async def _setup_bounded(
    max_messages: int,
) -> tuple[aiocoap.Context, aiocoap.Context, MessagesResource]:
    net = InMemoryNetwork()
    msgs = MessagesResource(max_messages=max_messages)
    site = build_site(StaticNodeInfo(), messages_resource=msgs)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
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
            assert '</msg/canned>;rt="msg.canned";ct="60"' in body
            assert '</messages>;rt="legacy.messages";ct="60";title="legacy demo alias"' in body
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_empty_inbox(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            assert _inbox(resp.payload) == []
            assert cbor2.loads(resp.payload)["unread"] == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_deliver_appears_in_get(self) -> None:
        client, server, msgs = await _setup()
        try:
            msgs.deliver(_MSG1)
            resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
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
            resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
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
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_legacy_messages_alias_reads_same_inbox(self) -> None:
        client, server, msgs = await _setup()
        try:
            msgs.deliver(_MSG1)
            resp = await client.request(Message(code=GET, uri="coap://srv/messages")).response
            inbox = _inbox(resp.payload)
            assert inbox[0]["text"] == "hello mesh"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_legacy_messages_alias_adds_text_for_lci_body_messages(self) -> None:
        client, server, msgs = await _setup()
        try:
            msgs.deliver({"from": _FROM, "to": _TO_A, "body": "body-only"})
            resp = await client.request(Message(code=GET, uri="coap://srv/messages")).response
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
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
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

    @pytest.mark.parametrize(
        ("status", "timestamp"),
        [
            ("delivered", 1_716_742_900),
            ("read", 1_716_742_901),
            ("failed", 1_716_742_902),
        ],
    )
    async def test_ack_dispatches_normalized_receipts_to_handler(
        self, status: str, timestamp: int
    ) -> None:
        dispatched: list[dict[str, object]] = []
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource(handler=dispatched.append)
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps({"id": 12345, "status": status, "ts": timestamp}),
                    content_format=60,
                )
            ).response

            assert resp.code == aiocoap.CHANGED
            assert dispatched == [{"id": 12345, "status": status, "ts": timestamp}]
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_repeated_handler_failure_does_not_commit_local_receipts(self) -> None:
        calls: list[dict[str, object]] = []

        def failing_handler(receipt: dict[str, object]) -> None:
            calls.append(receipt)
            raise RuntimeError("injected handler failure")

        net = InMemoryNetwork()
        receipts = MessageReceiptsResource(handler=failing_handler)
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        payload = {"id": 7, "status": "delivered", "ts": 9}
        try:
            for _ in range(3):
                response = await client.request(
                    Message(
                        code=POST,
                        uri="coap://srv/msg/ack",
                        payload=cbor2.dumps(payload),
                    )
                ).response
                assert response.code == aiocoap.INTERNAL_SERVER_ERROR
            assert calls == [payload, payload, payload]
            assert receipts.receipts() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_successful_handler_commits_local_receipt_once(self) -> None:
        calls: list[dict[str, object]] = []
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource(handler=calls.append)
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        payload = {"id": 7, "status": "read", "ts": 9}
        try:
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps(payload),
                )
            ).response
            assert response.code == aiocoap.CHANGED
            assert calls == [payload]
            assert receipts.receipts() == [payload]
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
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack", payload=payload)
            ).response

            assert resp.code == aiocoap.BAD_REQUEST
            assert receipts.receipts() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "trailing",
        [cbor2.dumps({"extra": True}), b"trailing-junk"],
    )
    async def test_ack_rejects_trailing_cbor_without_mutation(self, trailing: bytes) -> None:
        net = InMemoryNetwork()
        dispatched: list[dict[str, object]] = []
        receipts = MessageReceiptsResource(handler=dispatched.append)
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            valid = {"id": 1, "status": "delivered", "ts": 2}
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps(valid) + trailing,
                )
            ).response

            assert response.code == aiocoap.BAD_REQUEST
            assert receipts.receipts() == []
            assert dispatched == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_ack_accepts_u64_boundaries(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            maximum = (1 << 64) - 1
            payload = {"id": maximum, "status": "delivered", "ts": maximum}
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps(payload),
                )
            ).response
            assert response.code == aiocoap.CHANGED
            assert receipts.receipts() == [payload]
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize("field", ["id", "ts"])
    async def test_ack_rejects_u64_overflow_without_mutation(self, field: str) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            payload = {"id": 1, "status": "delivered", "ts": 1}
            payload[field] = 1 << 64
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps(payload),
                )
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert receipts.receipts() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_ack_rejects_duplicate_cbor_keys_without_mutation(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            payload = (
                b"\xa4"
                + cbor2.dumps("id")
                + cbor2.dumps(1)
                + cbor2.dumps("status")
                + cbor2.dumps("delivered")
                + cbor2.dumps("ts")
                + cbor2.dumps(1)
                + cbor2.dumps("id")
                + cbor2.dumps(2)
            )
            response = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack", payload=payload)
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert receipts.receipts() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "tagged_id",
        [b"\xd8\x1c\x81\x01", b"\xd8\x1d\x00"],
    )
    async def test_ack_rejects_tags_without_mutation(self, tagged_id: bytes) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            payload = (
                b"\xa3"
                + cbor2.dumps("id")
                + tagged_id
                + cbor2.dumps("status")
                + cbor2.dumps("delivered")
                + cbor2.dumps("ts")
                + cbor2.dumps(1)
            )
            response = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack", payload=payload)
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert receipts.receipts() == []
            assert cbor2.loads(cbor2.dumps(receipts.receipts())) == []
        finally:
            await client.shutdown()
            await server.shutdown()

    def test_max_receipts_must_be_positive(self) -> None:
        for value in (0, -1, True):
            with pytest.raises(ValueError, match="positive integer"):
                MessageReceiptsResource(max_receipts=value)

    async def test_receipts_capped_at_max(self) -> None:
        from lichen.coap.resources import _MESSAGES_MAX

        receipts = MessageReceiptsResource()
        for i in range(_MESSAGES_MAX + 10):
            payload = {"id": i, "status": "delivered", "ts": i}
            resp = await receipts.render_post(_admin_post(cbor2.dumps(payload)))
            assert resp.code == aiocoap.CHANGED

        stored = receipts.receipts()
        assert len(stored) == _MESSAGES_MAX
        # oldest receipts were dropped; newest survive
        assert stored[0] == {"id": 10, "status": "delivered", "ts": 10}
        assert stored[-1] == {
            "id": _MESSAGES_MAX + 9,
            "status": "delivered",
            "ts": _MESSAGES_MAX + 9,
        }


# ---------------------------------------------------------------------------
# POST
# ---------------------------------------------------------------------------


class TestMessagesPost:
    def test_max_messages_must_be_positive(self) -> None:
        for value in (0, -1, True):
            with pytest.raises(ValueError, match="positive integer"):
                MessagesResource(max_messages=value)

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
            get_resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
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
            get_resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
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

    async def test_post_rebinds_from_to_peer_identity_not_payload(self) -> None:
        client, server, msgs = await _setup()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps(_MSG2),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
            assert msgs.inbox()[0]["from"] == _LCI_EXPECTED_FROM
            sent_collection = await client.request(
                Message(code=GET, uri="coap://srv/msg/sent")
            ).response
            assert _inbox(sent_collection.payload)[0]["from"] == _LCI_EXPECTED_FROM
            detail = await client.request(Message(code=GET, uri="coap://srv/msg/sent/1")).response
            assert cbor2.loads(detail.payload)["from"] == _LCI_EXPECTED_FROM
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_render_post_rebinds_oscore_peer_over_payload_spoof(self) -> None:
        msgs = MessagesResource()
        request = Message(code=POST, payload=cbor2.dumps({"from": _FROM, "body": "spoof"}))
        request.remote = SimpleNamespace(
            hostinfo=_OSCORE_PEER_AUTHORITY,
            oscore_context_id=b"oscore-peer-id",
        )
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.CREATED
        assert tuple(resp.opt.location_path) == ("msg", "sent", "1")
        assert msgs.inbox()[0]["from"] == _OSCORE_EXPECTED_FROM
        assert msgs.inbox()[0]["body"] == "spoof"
        assert msgs.sent_messages()[0]["from"] == _OSCORE_EXPECTED_FROM

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

    async def test_post_rejects_duplicate_cbor_keys_without_mutation(self) -> None:
        client, server, msgs = await _setup_bounded(1)
        try:
            key = cbor2.dumps("body")
            payload = b"\xa2" + key + cbor2.dumps("first") + key + cbor2.dumps("second")
            response = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=payload)
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert msgs.inbox() == []
            assert msgs.sent_messages() == []
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert "</msg/sent/" not in discovery.payload.decode()
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "payload",
        [
            b"\xa2"
            + cbor2.dumps("body")
            + cbor2.dumps("valid")
            + cbor2.dumps("extra")
            + b"\xd8\x1c\x81\xa1\x61a\x01",
            b"\xa1" + cbor2.dumps("body") + b"\xd8\x1d\x00",
        ],
    )
    async def test_post_rejects_tags_without_state_routes_or_notification(
        self, payload: bytes
    ) -> None:
        client, server, msgs = await _setup_bounded(1)
        try:
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            msgs.updated_state = notified  # type: ignore[method-assign]
            response = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=payload)
            ).response
            current = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(current.payload) == {"messages": [], "unread": 0}
            assert msgs.sent_messages() == []
            assert "</msg/sent/" not in discovery.payload.decode()
            assert notifications == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_rejects_all_cbor_resource_limit_bypasses_without_mutation(
        self,
    ) -> None:
        client, server, msgs = await _setup_bounded(1)
        try:
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            msgs.updated_state = notified  # type: ignore[method-assign]
            oversized_map = {"body": "valid"}
            oversized_map.update({f"k{index}": index for index in range(64)})
            deep_value: object = 0
            for _ in range(17):
                deep_value = [deep_value]
            indefinite_map = (
                b"\xbf"
                + cbor2.dumps("body")
                + cbor2.dumps("valid")
                + b"".join(cbor2.dumps(f"k{index}") + cbor2.dumps(index) for index in range(64))
                + b"\xff"
            )
            indefinite_array = b"\x9f" + b"\x00" * 257 + b"\xff"
            payloads = [
                cbor2.dumps(oversized_map),
                cbor2.dumps({"body": "valid", "deep": deep_value}),
                indefinite_map,
                indefinite_array,
            ]

            for payload in payloads:
                response = await client.request(
                    Message(code=POST, uri="coap://srv/msg/inbox", payload=payload)
                ).response
                assert response.code == aiocoap.BAD_REQUEST

            assert msgs.inbox() == []
            assert msgs.sent_messages() == []
            assert msgs._next_id == 1
            assert notifications == 0
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert "</msg/sent/" not in discovery.payload.decode()
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_invalid_explicit_ids_have_no_effect_or_string_collision(self) -> None:
        client, server, msgs = await _setup_bounded(2)
        try:
            seeded = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"id": 1, "body": "integer one"}),
                )
            ).response
            assert seeded.code == aiocoap.CREATED
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            msgs.updated_state = notified  # type: ignore[method-assign]
            invalid_ids = [
                -1,
                True,
                False,
                1.0,
                "1",
                b"1",
                [1],
                {"value": 1},
                1 << 64,
            ]
            for invalid_id in invalid_ids:
                response = await client.request(
                    Message(
                        code=POST,
                        uri="coap://srv/msg/inbox",
                        payload=cbor2.dumps({"id": invalid_id, "body": "rejected"}),
                    )
                ).response
                assert response.code == aiocoap.BAD_REQUEST

            inbox = msgs.inbox()
            assert len(inbox) == 1
            assert inbox[0]["id"] == 1
            assert inbox[0]["body"] == "integer one"
            sent = msgs.sent_messages()
            assert len(sent) == 1
            assert sent[0]["id"] == 1
            assert sent[0]["body"] == "integer one"
            assert msgs._next_id == 2
            assert notifications == 0
            detail = await client.request(Message(code=GET, uri="coap://srv/msg/sent/1")).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            links = discovery.payload.decode()
            assert cbor2.loads(detail.payload)["body"] == "integer one"
            assert links.count("</msg/sent/") == 1
            assert "</msg/sent/1>" in links
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_explicit_u64_boundaries_and_exhaustion(self) -> None:
        max_id = (1 << 64) - 1
        client, server, msgs = await _setup_bounded(2)
        try:
            zero = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"id": 0, "body": "zero"}),
                )
            ).response
            maximum = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"id": max_id, "body": "maximum"}),
                )
            ).response
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            msgs.updated_state = notified  # type: ignore[method-assign]
            exhausted = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"body": "must not wrap"}),
                )
            ).response

            assert tuple(zero.opt.location_path) == ("msg", "sent", "0")
            assert tuple(maximum.opt.location_path) == (
                "msg",
                "sent",
                str(max_id),
            )
            assert exhausted.code == aiocoap.SERVICE_UNAVAILABLE
            assert [message["id"] for message in msgs.inbox()] == [0, max_id]
            assert [message["id"] for message in msgs.sent_messages()] == [0, max_id]
            assert msgs._next_id == 1 << 64
            assert notifications == 0
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            links = discovery.payload.decode()
            assert "</msg/sent/0>" in links
            assert f"</msg/sent/{max_id}>" in links
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_automatic_id_uses_u64_max_once_then_fails_closed(self) -> None:
        max_id = (1 << 64) - 1
        client, server, msgs = await _setup_bounded(1)
        try:
            msgs._next_id = max_id
            maximum = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"body": "last automatic"}),
                )
            ).response
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            msgs.updated_state = notified  # type: ignore[method-assign]
            exhausted = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"body": "collision forbidden"}),
                )
            ).response

            assert tuple(maximum.opt.location_path) == (
                "msg",
                "sent",
                str(max_id),
            )
            assert exhausted.code == aiocoap.SERVICE_UNAVAILABLE
            inbox = msgs.inbox()
            assert len(inbox) == 1
            assert inbox[0]["body"] == "last automatic"
            assert inbox[0]["id"] == max_id
            sent = msgs.sent_messages()
            assert len(sent) == 1
            assert sent[0]["body"] == "last automatic"
            assert sent[0]["id"] == max_id
            assert msgs._next_id == 1 << 64
            assert notifications == 0
            detail = await client.request(
                Message(code=GET, uri=f"coap://srv/msg/sent/{max_id}")
            ).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert cbor2.loads(detail.payload)["id"] == max_id
            assert discovery.payload.decode().count("</msg/sent/") == 1
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_capacity_evicts_inbox_sent_details_and_discovery(self) -> None:
        client, server, _ = await _setup_bounded(2)
        try:
            for index in range(1, 5):
                response = await client.request(
                    Message(
                        code=POST,
                        uri="coap://srv/msg/inbox",
                        payload=cbor2.dumps({"body": f"message {index}"}),
                    )
                ).response
                assert tuple(response.opt.location_path) == ("msg", "sent", str(index))

            inbox = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            sent = await client.request(Message(code=GET, uri="coap://srv/msg/sent")).response
            assert [item["id"] for item in _inbox(inbox.payload)] == [3, 4]
            assert [item["id"] for item in _inbox(sent.payload)] == [3, 4]

            for evicted_id in ("1", "2"):
                detail = await client.request(
                    Message(code=GET, uri=f"coap://srv/msg/sent/{evicted_id}")
                ).response
                assert detail.code == aiocoap.NOT_FOUND
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            links = discovery.payload.decode()
            assert "</msg/sent/1>" not in links
            assert "</msg/sent/2>" not in links
            assert "</msg/sent/3>" in links
            assert "</msg/sent/4>" in links
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_duplicate_id_replaces_and_moves_record_without_corruption(self) -> None:
        client, server, _ = await _setup_bounded(2)
        try:
            for body in (
                {"id": 7, "body": "old"},
                {"id": 7, "body": "new"},
                {"body": "generated"},
            ):
                await client.request(
                    Message(
                        code=POST,
                        uri="coap://srv/msg/inbox",
                        payload=cbor2.dumps(body),
                    )
                ).response
            sent = await client.request(Message(code=GET, uri="coap://srv/msg/sent")).response
            inbox = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert [(item["id"], item["body"]) for item in _inbox(sent.payload)] == [
                (7, "new"),
                (8, "generated"),
            ]
            assert [(item["id"], item["body"]) for item in _inbox(inbox.payload)] == [
                (7, "new"),
                (8, "generated"),
            ]
            detail = await client.request(Message(code=GET, uri="coap://srv/msg/sent/7")).response
            assert cbor2.loads(detail.payload)["body"] == "new"
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "path",
        ["01", "-1", "not-an-id", str(1 << 64), "1/extra"],
    )
    async def test_detail_router_rejects_noncanonical_or_extra_paths(self, path: str) -> None:
        client, server, _ = await _setup_bounded(1)
        try:
            await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"id": 1, "body": "one"}),
                )
            ).response
            response = await client.request(
                Message(code=GET, uri=f"coap://srv/msg/sent/{path}")
            ).response
            assert response.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_detail_router_rejects_non_get_methods(self) -> None:
        client, server, _ = await _setup_bounded(1)
        try:
            await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"id": 1, "body": "one"}),
                )
            ).response
            response = await client.request(
                Message(code=POST, uri="coap://srv/msg/sent/1", payload=b"x")
            ).response
            assert response.code == aiocoap.METHOD_NOT_ALLOWED
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_rejects_trailing_cbor(self) -> None:
        client, server, msgs = await _setup()
        try:
            response = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"body": "valid"}) + b"trailing",
                )
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert msgs.inbox() == []
            assert msgs.sent_messages() == []
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
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/msg/inbox"))
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
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/msg/inbox"))
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
            assert inbox[0]["from"] == _LCI_EXPECTED_FROM
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_legacy_messages_alias_observe_notified_on_deliver(self) -> None:
        client, server, msgs = await _setup()
        try:
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/messages"))
            await req.response

            obs_iter = req.observation.__aiter__()
            msgs.deliver(_MSG1)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            inbox = _inbox(note.payload)
            assert inbox[0]["text"] == "hello mesh"
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Canned messages (spec 18.1.3) and unread (spec 18.1.2)
# ---------------------------------------------------------------------------


class TestCannedMessages:
    def test_default_catalog_matches_spec(self) -> None:
        msgs = MessagesResource()
        assert msgs.canned_messages() == [dict(item) for item in DEFAULT_CANNED_MESSAGES]

    def test_catalog_copies_are_independent(self) -> None:
        msgs = MessagesResource()
        catalog = msgs.canned_messages()
        catalog[0]["text"] = "mutated"
        assert msgs.canned_messages()[0]["text"] == "I'm OK"

    def test_custom_catalog_and_invalid_entries(self) -> None:
        custom = [{"id": 7, "text": "Rally now"}]
        msgs = MessagesResource(canned_messages=custom)
        assert msgs.canned_messages() == [{"id": 7, "text": "Rally now"}]
        with pytest.raises(ValueError, match="positive integer"):
            MessagesResource(max_messages=0)
        with pytest.raises(ValueError, match="canned message"):
            MessagesResource(canned_messages=[{"id": True, "text": "nope"}])
        with pytest.raises(ValueError, match="canned message"):
            MessagesResource(canned_messages=[{"id": 1, "text": 4}])  # type: ignore[list-item]
        with pytest.raises(ValueError, match="unique"):
            MessagesResource(canned_messages=[{"id": 1, "text": "a"}, {"id": 1, "text": "b"}])

    async def test_get_canned_catalog(self) -> None:
        client, server, _ = await _setup()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/msg/canned")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            decoded = cbor2.loads(resp.payload)
            assert decoded == {"messages": [dict(item) for item in DEFAULT_CANNED_MESSAGES]}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_canned_expands_body(self) -> None:
        client, server, msgs = await _setup()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"canned": 4, "ack": True}),
                    content_format=60,
                )
            ).response
            assert resp.code == aiocoap.CREATED
            assert tuple(resp.opt.location_path) == ("msg", "sent", "1")
            stored = msgs.sent_messages()[0]
            assert stored["body"] == "Emergency - send help"
            assert stored["canned"] == 4
            assert stored["ack"] is True
            inbox = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert _inbox(inbox.payload)[0]["body"] == "Emergency - send help"
            assert cbor2.loads(inbox.payload)["unread"] == 1
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_post_canned_keeps_explicit_body(self) -> None:
        client, server, msgs = await _setup()
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps({"canned": 0, "body": "override"}),
                )
            ).response
            assert resp.code == aiocoap.CREATED
            assert msgs.sent_messages()[0]["body"] == "override"
            assert msgs.sent_messages()[0]["canned"] == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "payload",
        [
            {"canned": 99, "ack": True},
            {"canned": -1},
            {"canned": True},
            {"canned": "4"},
            {"canned": 4.0},
            {"canned": 1 << 64},
        ],
    )
    async def test_post_rejects_invalid_canned_without_mutation(
        self, payload: dict[str, object]
    ) -> None:
        client, server, msgs = await _setup_bounded(1)
        try:
            notifications = 0

            def notified() -> None:
                nonlocal notifications
                notifications += 1

            msgs.updated_state = notified  # type: ignore[method-assign]
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/inbox",
                    payload=cbor2.dumps(payload),
                )
            ).response
            assert resp.code == aiocoap.BAD_REQUEST
            assert msgs.inbox() == []
            assert msgs.sent_messages() == []
            assert msgs._next_id == 1
            assert notifications == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_unread_counts_inbox_and_survives_eviction(self) -> None:
        client, server, msgs = await _setup_bounded(2)
        try:
            empty = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert cbor2.loads(empty.payload)["unread"] == 0
            msgs.deliver({"from": _FROM, "to": "all", "body": "one"})
            msgs.deliver({"from": _FROM, "to": "all", "body": "two", "read": True})
            two = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert cbor2.loads(two.payload)["unread"] == 1
            msgs.deliver({"from": _FROM, "to": "all", "body": "three"})
            three = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            decoded = cbor2.loads(three.payload)
            assert [item["body"] for item in decoded["messages"]] == ["two", "three"]
            assert decoded["unread"] == 1
        finally:
            await client.shutdown()
            await server.shutdown()


# ---------------------------------------------------------------------------
# Independent-oracle consumption of test/vectors/messaging.json
# ---------------------------------------------------------------------------


_VECTORS_PATH = Path(__file__).resolve().parents[3] / "test" / "vectors" / "messaging.json"


def _load_messaging_vectors() -> list[dict[str, Any]]:
    document = json.loads(_VECTORS_PATH.read_text(encoding="utf-8"))
    assert document["format_version"] == 2
    return list(document["vectors"])


def _vector_payload(vector: dict[str, Any]) -> bytes:
    if "payload_hex" in vector:
        return bytes.fromhex(vector["payload_hex"])
    if vector.get("payload") == "":
        return b""
    if "cbor_payload" in vector:
        return cbor2.dumps(vector["cbor_payload"])
    return b""


def _code_class(code: object) -> str:
    return str(code).split()[0]


class TestMessagingOracleVectors:
    """Drive MessagesResource against the committed messaging.json vectors."""

    @pytest.mark.parametrize(
        "vector",
        _load_messaging_vectors(),
        ids=lambda vector: vector["name"],
    )
    async def test_resource_matches_vector(self, vector: dict[str, Any]) -> None:
        msgs = MessagesResource()
        sent = SentMessagesResource(msgs)
        details = SentMessageDetailsResource(msgs)
        receipts = MessageReceiptsResource()
        canned = CannedMessagesResource(msgs)
        expected = vector["expected"]
        expected_code = expected["response_code"]
        resource = vector["resource"]
        method = vector["method"]
        precondition = vector.get("precondition") or {}
        exists = precondition.get("message_id_exists")
        if exists is True or (isinstance(exists, int) and not isinstance(exists, bool)):
            seed_id = 42 if exists is True else exists
            seeded = await msgs.render_post(
                _admin_post(cbor2.dumps({"id": seed_id, "body": "seed"}))
            )
            assert seeded.code == aiocoap.CREATED

        payload = _vector_payload(vector)
        if resource == "/msg/inbox" and method == "POST":
            resp = await msgs.render_post(_admin_post(payload))
        elif resource == "/msg/inbox" and method == "GET":
            resp = await msgs.render_get(Message(code=GET))
        elif resource == "/msg/sent" and method == "GET":
            resp = await sent.render_get(Message(code=GET))
        elif resource.startswith("/msg/sent/") and method == "GET":
            req = Message(code=GET)
            req.opt.uri_path = (resource.rsplit("/", 1)[1],)
            resp = await details.render_get(req)
        elif resource == "/msg/ack" and method == "POST":
            resp = await receipts.render_post(_admin_post(payload))
        elif resource == "/msg/canned" and method == "GET":
            resp = await canned.render_get(Message(code=GET))
        else:
            pytest.fail(f"unhandled vector {vector['name']}: {method} {resource}")

        assert _code_class(resp.code) == expected_code.split()[0], (
            f"{vector['name']}: got {resp.code}, expected {expected_code}"
        )

        if expected.get("message_stored"):
            assert msgs.sent_messages()
        if expected.get("receipt_stored"):
            assert receipts.receipts()
        assigned = expected.get("assigned_id")
        if assigned is not None:
            assert tuple(resp.opt.location_path) == ("msg", "sent", str(assigned))
        location = expected.get("location_path")
        if isinstance(location, str):
            actual = "/" + "/".join(resp.opt.location_path)
            if "{id}" in location:
                assert actual.startswith("/msg/sent/")
                assert resp.opt.location_path[-1].isdecimal()
            else:
                assert actual == location
        if method == "POST" and resource == "/msg/inbox" and expected_code.startswith("2."):
            cbor_payload = vector.get("cbor_payload")
            if isinstance(cbor_payload, dict) and "canned" in cbor_payload:
                canned_id = cbor_payload["canned"]
                text = next(
                    item["text"] for item in DEFAULT_CANNED_MESSAGES if item["id"] == canned_id
                )
                assert msgs.sent_messages()[-1]["body"] == text
        if method == "GET" and expected_code.startswith("2."):
            decoded = cbor2.loads(resp.payload)
            assert resp.opt.content_format == 60
            if resource == "/msg/inbox":
                assert isinstance(decoded["messages"], list)
                assert decoded["unread"] == msgs.unread_count()
            elif resource == "/msg/sent":
                assert isinstance(decoded["messages"], list)
            else:
                for field in expected.get("fields_present") or ():
                    assert field in decoded
        if expected.get("error") and expected_code.startswith("4."):
            assert msgs.inbox() == [] or resource != "/msg/inbox" or exists
            if resource == "/msg/ack":
                assert receipts.receipts() == []


# ---------------------------------------------------------------------------
# Local-admin authority parsing (loopback parity, fmml)
# ---------------------------------------------------------------------------


class TestLocalAdminAuthorityParsing:
    """Loopback hosts are admin in both families; everything else stays denied."""

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
    def test_authority_matrix(self, authority: str | None, expected: bool) -> None:
        remote: Any = SimpleNamespace(hostinfo=authority)
        assert _peer_is_local_admin(remote) is expected

    def test_missing_remote_or_hostinfo_is_not_admin(self) -> None:
        assert _peer_is_local_admin(None) is False
        assert _peer_is_local_admin(SimpleNamespace()) is False
        assert _peer_is_local_admin(SimpleNamespace(hostinfo=None)) is False

    async def test_render_post_rejects_ipv4_admin_without_ipv6_from(self) -> None:
        msgs = MessagesResource()
        request = Message(code=POST, payload=cbor2.dumps({"body": "local"}))
        request.remote = SimpleNamespace(hostinfo="127.0.0.1")
        resp = await msgs.render_post(request)
        # IPv4 loopback passes the local-admin gate (_peer_is_local_admin),
        # but spec 18.1.1 requires from as the sender IPv6 tstr bound to the
        # transport peer. A non-IPv6 peer cannot produce an honest from, so
        # the post is rejected rather than stored sender-less (bead 6wrg).
        assert resp.code == aiocoap.BAD_REQUEST
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []

    async def test_render_post_grants_bracketed_ipv6_with_port_admin(self) -> None:
        msgs = MessagesResource()
        request = Message(code=POST, payload=cbor2.dumps({"body": "custom port"}))
        request.remote = SimpleNamespace(hostinfo="[::1]:9999")
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.CREATED


# ---------------------------------------------------------------------------
# Gate/identity agreement (umsd): no sender-less records via render-level calls
# ---------------------------------------------------------------------------


class TestGateRequiresRemoteIdentity:
    """OSCORE identity alone never passes: binding source and gate agree."""

    async def test_render_post_rejects_oscore_identity_without_remote_hostinfo(
        self,
    ) -> None:
        msgs = MessagesResource()
        request = Message(code=POST, payload=cbor2.dumps({"body": "ghost"}))
        request.oscore_context_id = b"oscore-peer-id"
        request.remote = SimpleNamespace()
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []
        assert msgs._next_id == 1

    async def test_render_post_rejects_oscore_identity_with_remote_none(self) -> None:
        msgs = MessagesResource()
        request = Message(code=POST, payload=cbor2.dumps({"body": "ghost"}))
        request.oscore_context_id = b"oscore-peer-id"
        request.remote = None
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert msgs.inbox() == []

    async def test_receipts_reject_oscore_identity_without_remote_hostinfo(self) -> None:
        receipts = MessageReceiptsResource()
        request = Message(code=POST, payload=cbor2.dumps({"id": 1, "status": "read", "ts": 2}))
        request.oscore_context_id = b"oscore-peer-id"
        request.remote = SimpleNamespace()
        resp = await receipts.render_post(request)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert receipts.receipts() == []


# ---------------------------------------------------------------------------
# Sent-archive policy (xd6j): recording follows inbox rules, direct writes admin
# ---------------------------------------------------------------------------


class TestSentArchivePolicy:
    """Indirect _sent population follows /msg/inbox auth; direct POST stays admin-only."""

    async def test_authenticated_non_admin_inbox_post_records_sent_copy(self) -> None:
        msgs = MessagesResource()
        request = Message(code=POST, payload=cbor2.dumps({"body": "peer copy"}))
        request.remote = SimpleNamespace(
            hostinfo=_OSCORE_PEER_AUTHORITY,
            oscore_context_id=b"oscore-peer-id",
        )
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.CREATED
        assert [m["from"] for m in msgs.sent_messages()] == [_OSCORE_EXPECTED_FROM]

    async def test_direct_sent_post_by_authenticated_non_admin_is_unauthorized(self) -> None:
        msgs = MessagesResource()
        sent = SentMessagesResource(msgs)
        request = Message(code=POST, payload=cbor2.dumps({"body": "fabricated"}))
        request.remote = SimpleNamespace(
            hostinfo=_OSCORE_PEER_AUTHORITY,
            oscore_context_id=b"oscore-peer-id",
        )
        resp = await sent.render_post(request)
        assert resp.code == aiocoap.UNAUTHORIZED
        assert msgs.sent_messages() == []
        assert msgs.inbox() == []

    async def test_direct_sent_post_by_loopback_admin_succeeds(self) -> None:
        msgs = MessagesResource()
        sent = SentMessagesResource(msgs)
        resp = await sent.render_post(_admin_post(cbor2.dumps({"body": "archived"})))
        assert resp.code == aiocoap.CREATED
        assert tuple(resp.opt.location_path) == ("msg", "sent", "1")
        # POST /msg/sent stores to sent archive only, NOT inbox (firmware contract).
        assert msgs.inbox() == []
        assert msgs.sent_messages()[0]["body"] == "archived"


# ---------------------------------------------------------------------------
# Body/text size cap (96tj), mirroring DEADDROP_MAX_DROP_SIZE semantics
# ---------------------------------------------------------------------------


class TestMessageBodySizeCap:
    """Oversize payloads get 4.13 before decode; expanded bodies get 4.00."""

    async def test_oversize_payload_returns_entity_too_large_without_mutation(self) -> None:
        client, server, msgs = await _setup_bounded(1)
        try:
            oversized = cbor2.dumps({"body": "x" * 4096})
            assert len(oversized) > MESSAGES_MAX_BODY_SIZE
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=oversized)
            ).response
            assert resp.code == aiocoap.REQUEST_ENTITY_TOO_LARGE

            raw_resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=b"x" * 1025)
            ).response
            assert raw_resp.code == aiocoap.REQUEST_ENTITY_TOO_LARGE

            current = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert cbor2.loads(current.payload) == {"messages": [], "unread": 0}
            assert msgs.sent_messages() == []
            assert msgs._next_id == 1
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_largest_encodable_body_under_cap_is_accepted(self) -> None:
        max_body_text = ""
        for size in range(1, MESSAGES_MAX_BODY_SIZE + 1):
            if len(cbor2.dumps({"body": "x" * size})) <= MESSAGES_MAX_BODY_SIZE:
                max_body_text = "x" * size
        client, server, msgs = await _setup()
        try:
            payload = cbor2.dumps({"body": max_body_text})
            assert len(payload) <= MESSAGES_MAX_BODY_SIZE
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=payload)
            ).response
            assert resp.code == aiocoap.CREATED
            assert msgs.inbox()[0]["body"] == max_body_text
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_canned_text_exactly_at_byte_cap_posts_created(self) -> None:
        """Exact 1024-byte canned text is constructible and posts CREATED."""
        text = "y" * MESSAGES_MAX_BODY_SIZE
        assert len(text.encode("utf-8")) == MESSAGES_MAX_BODY_SIZE
        msgs = MessagesResource(canned_messages=[{"id": 0, "text": text}])
        resp = await msgs.render_post(_admin_post(cbor2.dumps({"canned": 0})))
        assert resp.code == aiocoap.CREATED
        assert msgs.inbox()[0]["body"] == text
        assert msgs.sent_messages()[0]["body"] == text

    def test_canned_entry_one_byte_over_cap_rejected_at_construction(self) -> None:
        """Oversized catalog entries fail fast instead of being unpostable."""
        text = "y" * (MESSAGES_MAX_BODY_SIZE + 1)
        with pytest.raises(ValueError, match="at most"):
            MessagesResource(canned_messages=[{"id": 0, "text": text}])

    async def test_canned_expansion_over_cap_returns_bad_request_without_mutation(self) -> None:
        """Defense-in-depth: the post-expansion byte check still rejects 1025."""
        msgs = MessagesResource()
        # The constructor now guarantees catalog texts fit the cap; inject
        # directly to verify the runtime guard stays fail-closed if that
        # invariant is ever violated.
        msgs._canned_text[9] = "y" * (MESSAGES_MAX_BODY_SIZE + 1)
        resp = await msgs.render_post(_admin_post(cbor2.dumps({"canned": 9})))
        assert resp.code == aiocoap.BAD_REQUEST
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []

    async def test_multibyte_body_under_byte_cap_accepted(self) -> None:
        emoji = "\U0001f600"  # 4 UTF-8 bytes, 1 character
        body = emoji * 253  # 253 chars, 1012 bytes
        assert len(body) == 253
        assert len(body.encode("utf-8")) == 1012 <= MESSAGES_MAX_BODY_SIZE
        payload = cbor2.dumps({"body": body})
        assert len(payload) <= MESSAGES_MAX_BODY_SIZE
        client, server, msgs = await _setup()
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=payload)
            ).response
            assert resp.code == aiocoap.CREATED
            assert msgs.inbox()[0]["body"] == body
        finally:
            await client.shutdown()
            await server.shutdown()

    def test_canned_multibyte_over_byte_cap_rejected_at_construction(self) -> None:
        cjk = "\u4e00"  # 3 UTF-8 bytes, 1 character
        text = cjk * 400  # 400 chars (passes the old char count) but 1200 bytes
        assert len(text) <= MESSAGES_MAX_BODY_SIZE
        assert len(text.encode("utf-8")) > MESSAGES_MAX_BODY_SIZE
        with pytest.raises(ValueError, match="at most"):
            MessagesResource(canned_messages=[{"id": 0, "text": text}])

    async def test_text_field_byte_cap_parity(self) -> None:
        emoji = "\U0001f600"
        text = emoji * 253  # 253 chars, 1012 bytes
        assert len(text.encode("utf-8")) <= MESSAGES_MAX_BODY_SIZE
        msgs = MessagesResource()
        request = Message(code=POST, payload=cbor2.dumps({"text": text}))
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.CREATED
        assert msgs.inbox()[0]["body"] == text

        # Over-cap text cannot reach the expanded-body check: the raw
        # pre-decode gate bounds decoded field bytes, so 4.13 wins.
        over = "\u4e00" * 400  # 1200 bytes
        assert len(over.encode("utf-8")) > MESSAGES_MAX_BODY_SIZE
        payload = cbor2.dumps({"text": over})
        assert len(payload) > MESSAGES_MAX_BODY_SIZE
        msgs = MessagesResource()
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.REQUEST_ENTITY_TOO_LARGE
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []


# ---------------------------------------------------------------------------
# Content-Format Validation (Spec 18.1.2 / 18.1.3)
# ---------------------------------------------------------------------------


class TestContentFormatValidation:
    """Verify POST endpoints reject non-CBOR Content-Format per spec."""

    async def test_inbox_post_rejects_wrong_content_format(self) -> None:
        """POST /msg/inbox with Content-Format != 60 returns 4.00 without mutation."""
        msgs = MessagesResource()
        payload = cbor2.dumps({"body": "test"})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        # text/plain (0) is not CBOR
        request.opt.content_format = 0
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.BAD_REQUEST
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []
        assert msgs._next_id == 1

    async def test_inbox_post_rejects_senml_cbor_content_format(self) -> None:
        """POST /msg/inbox with Content-Format 112 (SenML+CBOR) returns 4.00."""
        msgs = MessagesResource()
        payload = cbor2.dumps({"body": "test"})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        request.opt.content_format = 112  # application/senml+cbor
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.BAD_REQUEST
        assert msgs.inbox() == []
        assert msgs._next_id == 1

    async def test_inbox_post_accepts_missing_content_format(self) -> None:
        """POST /msg/inbox with no Content-Format is accepted as CBOR per RFC 7252."""
        msgs = MessagesResource()
        payload = cbor2.dumps({"body": "test"})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        # No content_format set (None)
        assert request.opt.content_format is None
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.CREATED
        assert len(msgs.inbox()) == 1

    async def test_inbox_post_accepts_explicit_cbor_content_format(self) -> None:
        """POST /msg/inbox with Content-Format 60 (application/cbor) is accepted."""
        msgs = MessagesResource()
        payload = cbor2.dumps({"body": "test"})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        request.opt.content_format = 60  # application/cbor
        resp = await msgs.render_post(request)
        assert resp.code == aiocoap.CREATED
        assert len(msgs.inbox()) == 1

    async def test_sent_post_rejects_wrong_content_format(self) -> None:
        """POST /msg/sent with Content-Format != 60 returns 4.00 without mutation."""
        msgs = MessagesResource()
        sent_resource = SentMessagesResource(msgs)
        payload = cbor2.dumps({"body": "test"})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        request.opt.content_format = 0  # text/plain
        resp = await sent_resource.render_post(request)
        assert resp.code == aiocoap.BAD_REQUEST
        assert msgs.sent_messages() == []
        assert msgs._next_id == 1

    async def test_sent_post_accepts_missing_content_format(self) -> None:
        """POST /msg/sent with no Content-Format is accepted as CBOR."""
        msgs = MessagesResource()
        sent_resource = SentMessagesResource(msgs)
        payload = cbor2.dumps({"body": "test"})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        assert request.opt.content_format is None
        resp = await sent_resource.render_post(request)
        assert resp.code == aiocoap.CREATED

    async def test_ack_post_rejects_wrong_content_format(self) -> None:
        """POST /msg/ack with Content-Format != 60 returns 4.00 without mutation."""
        receipts = MessageReceiptsResource()
        payload = cbor2.dumps({"id": 1, "status": "delivered", "ts": 1700000000})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        request.opt.content_format = 0  # text/plain
        resp = await receipts.render_post(request)
        assert resp.code == aiocoap.BAD_REQUEST
        assert receipts.receipts() == []

    async def test_ack_post_accepts_missing_content_format(self) -> None:
        """POST /msg/ack with no Content-Format is accepted as CBOR."""
        receipts = MessageReceiptsResource()
        payload = cbor2.dumps({"id": 1, "status": "delivered", "ts": 1700000000})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        assert request.opt.content_format is None
        resp = await receipts.render_post(request)
        assert resp.code == aiocoap.CHANGED
        assert len(receipts.receipts()) == 1

    async def test_legacy_messages_alias_inherits_content_format_check(self) -> None:
        """POST /messages with wrong Content-Format returns 4.00 via delegation."""
        from lichen.coap.resources.messaging import LegacyMessagesAliasResource

        msgs = MessagesResource()
        alias = LegacyMessagesAliasResource(msgs)
        payload = cbor2.dumps({"body": "test"})
        request = Message(code=POST, payload=payload)
        request.remote = SimpleNamespace(hostinfo=_LCI_PEER_AUTHORITY)
        request.opt.content_format = 0  # text/plain
        resp = await alias.render_post(request)
        assert resp.code == aiocoap.BAD_REQUEST
        assert msgs.inbox() == []
        assert msgs._next_id == 1
