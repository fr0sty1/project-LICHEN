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


async def _setup_bounded(
    max_messages: int,
) -> tuple[aiocoap.Context, aiocoap.Context, MessagesResource]:
    net = InMemoryNetwork()
    msgs = MessagesResource(max_messages=max_messages)
    site = build_site(StaticNodeInfo(), messages_resource=msgs)
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

    async def test_repeated_handler_failure_does_not_commit_local_receipts(self) -> None:
        calls: list[dict[str, object]] = []

        def failing_handler(receipt: dict[str, object]) -> None:
            calls.append(receipt)
            raise RuntimeError("injected handler failure")

        net = InMemoryNetwork()
        receipts = MessageReceiptsResource(handler=failing_handler)
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
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
        client = await create_lichen_context(net.channel("cli"), "cli")
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

    @pytest.mark.parametrize(
        "trailing",
        [cbor2.dumps({"extra": True}), b"trailing-junk"],
    )
    async def test_ack_rejects_trailing_cbor_without_mutation(
        self, trailing: bytes
    ) -> None:
        net = InMemoryNetwork()
        dispatched: list[dict[str, object]] = []
        receipts = MessageReceiptsResource(handler=dispatched.append)
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
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
        client = await create_lichen_context(net.channel("cli"), "cli")
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
        client = await create_lichen_context(net.channel("cli"), "cli")
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
        client = await create_lichen_context(net.channel("cli"), "cli")
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
        client = await create_lichen_context(net.channel("cli"), "cli")
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
            current = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            discovery = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert response.code == aiocoap.BAD_REQUEST
            assert cbor2.loads(current.payload) == {"messages": []}
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
                + b"".join(
                    cbor2.dumps(f"k{index}") + cbor2.dumps(index)
                    for index in range(64)
                )
                + b"\xff"
            )
            indefinite_array = b"\x9f" + b"\x00" * 257 + b"\xff"
            total_items = cbor2.dumps({
                "body": "valid",
                "items": [[0, 0, 0] for _ in range(256)],
            })
            oversized_bytes = cbor2.dumps({"body": "x" * 4096})
            payloads = [
                cbor2.dumps(oversized_map),
                cbor2.dumps({"body": "valid", "deep": deep_value}),
                indefinite_map,
                indefinite_array,
                total_items,
                oversized_bytes,
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

            assert msgs.inbox() == [{"id": 1, "body": "integer one"}]
            assert msgs.sent_messages() == [{"id": 1, "body": "integer one"}]
            assert msgs._next_id == 2
            assert notifications == 0
            detail = await client.request(
                Message(code=GET, uri="coap://srv/msg/sent/1")
            ).response
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
            assert msgs.inbox() == [{"body": "last automatic", "id": max_id}]
            assert msgs.sent_messages() == [{"body": "last automatic", "id": max_id}]
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

            inbox = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            sent = await client.request(
                Message(code=GET, uri="coap://srv/msg/sent")
            ).response
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
            sent = await client.request(
                Message(code=GET, uri="coap://srv/msg/sent")
            ).response
            inbox = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            assert [(item["id"], item["body"]) for item in _inbox(sent.payload)] == [
                (7, "new"),
                (8, "generated"),
            ]
            assert [(item["id"], item["body"]) for item in _inbox(inbox.payload)] == [
                (7, "new"),
                (8, "generated"),
            ]
            detail = await client.request(
                Message(code=GET, uri="coap://srv/msg/sent/7")
            ).response
            assert cbor2.loads(detail.payload)["body"] == "new"
        finally:
            await client.shutdown()
            await server.shutdown()

    @pytest.mark.parametrize(
        "path",
        ["01", "-1", "not-an-id", str(1 << 64), "1/extra"],
    )
    async def test_detail_router_rejects_noncanonical_or_extra_paths(
        self, path: str
    ) -> None:
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
