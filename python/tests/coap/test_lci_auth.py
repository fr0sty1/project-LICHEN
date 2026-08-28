# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LICHEN CoAP LCI authorization (is_local_admin, transport scope, OSCORE).

Covers the authorization patterns for all mutating resources per spec/11-lci.md
section 17.6.3 Access Control and project-LICHEN-6mij.3.

Resources tested:
- /config PUT - requires is_local_admin (only write)
- /msg/inbox POST - requires is_local_admin or OSCORE peer
- /msg/sent POST - requires is_local_admin
- /msg/ack POST - requires is_local_admin
- /sensors/location POST - requires is_local_admin (LCI interface check)
- /deaddrop POST - requires is_local_admin or OSCORE peer
- /keys PUT/DELETE - requires is_local_admin
"""

from __future__ import annotations

from types import SimpleNamespace

import cbor2
import pytest
from aiocoap import (
    BAD_REQUEST,
    CHANGED,
    CONTENT,
    CREATED,
    GET,
    METHOD_NOT_ALLOWED,
    NOT_FOUND,
    POST,
    PUT,
    UNAUTHORIZED,
    Message,
)

from lichen.coap.resources import (
    MessageReceiptsResource,
    MessagesResource,
    SenMLLocationResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_LCI_CLIENT = "::1"
_MESH_CLIENT = "cli"
_INBOX_PAYLOAD = cbor2.dumps({"body": "hello", "to": "all"})
_ACK_PAYLOAD = cbor2.dumps({"id": 1, "status": "delivered", "ts": 2})
_PIN_ID = (1 << 64) - 1


def _remote(hostinfo: str) -> SimpleNamespace:
    return SimpleNamespace(hostinfo=hostinfo)


def _post(
    payload: bytes,
    *,
    hostinfo: str | None = None,
    oscore_context_id: str | None = None,
    oscore_protected: bool | None = None,
    oscore_option: bytes | None = None,
) -> Message:
    request = Message(code=POST, payload=payload)
    if hostinfo is not None:
        request.remote = _remote(hostinfo)
    if oscore_context_id is not None:
        request.oscore_context_id = oscore_context_id
    if oscore_protected is not None:
        request.oscore_protected = oscore_protected
    if oscore_option is not None:
        request.opt.oscore = oscore_option
    return request


@pytest.fixture
def node_info() -> StaticNodeInfo:
    return StaticNodeInfo(
        status={"uptime": 1234, "rank": 512},
        neighbors=[{"addr": "fe80::2", "rank": 256}],
        config={"region": "US915", "tx_power_dbm": 14},
    )


class TestConfigAuth:
    """PUT /config must be blocked without allow_writes."""

    async def test_config_get_is_public(self, node_info: StaticNodeInfo) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(node_info),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/config")).response
            assert resp.code == CONTENT
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_config_put_unauthorized_by_default(self, node_info: StaticNodeInfo) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(node_info),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(
                    code=PUT, uri="coap://srv/config", payload=cbor2.dumps({"tx_power_dbm": 20})
                )
            ).response
            assert resp.code == UNAUTHORIZED
            assert node_info.config["tx_power_dbm"] == 14
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_config_put_allowed_with_explicit_flag(self, node_info: StaticNodeInfo) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(node_info, config_allow_writes=True),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(
                    code=PUT, uri="coap://srv/config", payload=cbor2.dumps({"tx_power_dbm": 20})
                )
            ).response
            assert resp.code == CHANGED
            assert node_info.config["tx_power_dbm"] == 20
        finally:
            await client.shutdown()
            await server.shutdown()


class TestMessagesAuth:
    """POST /msg/inbox, /messages, /msg/ack require OSCORE or local admin."""

    async def test_msg_inbox_post_creates_message_from_loopback(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=_INBOX_PAYLOAD)
            ).response
            assert resp.code == CREATED
            assert len(msgs.inbox()) == 1
            assert len(msgs.sent_messages()) == 1
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_inbox_get_is_public(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_MESH_CLIENT), _MESH_CLIENT)
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/msg/inbox")).response
            assert resp.code == CONTENT
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_sent_mesh_post_is_unauthorized(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_MESH_CLIENT), _MESH_CLIENT)
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/sent",
                    payload=cbor2.dumps({"body": "test"}),
                )
            ).response
            assert resp.code == UNAUTHORIZED
            assert msgs.sent_messages() == []
            assert msgs.inbox() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_ack_post_accepts_valid_receipt_from_loopback(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack", payload=_ACK_PAYLOAD)
            ).response
            assert resp.code == CHANGED
            assert receipts.receipts() == [{"id": 1, "status": "delivered", "ts": 2}]
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_ack_rejects_invalid_receipt_from_loopback(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/msg/ack",
                    payload=cbor2.dumps({"id": 1, "status": "unknown", "ts": 2}),
                )
            ).response
            assert resp.code == BAD_REQUEST
            assert receipts.receipts() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_inbox_mesh_peer_unauthorized_does_not_mutate(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_MESH_CLIENT), _MESH_CLIENT)
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox", payload=_INBOX_PAYLOAD)
            ).response
            assert resp.code == UNAUTHORIZED
            assert msgs.inbox() == []
            assert msgs.sent_messages() == []
            assert msgs._next_id == 1
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_messages_alias_mesh_peer_unauthorized_does_not_mutate(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_MESH_CLIENT), _MESH_CLIENT)
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/messages", payload=_INBOX_PAYLOAD)
            ).response
            assert resp.code == UNAUTHORIZED
            assert msgs.inbox() == []
            assert msgs.sent_messages() == []
            assert msgs._next_id == 1
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_ack_mesh_peer_unauthorized_does_not_mutate(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_MESH_CLIENT), _MESH_CLIENT)
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack", payload=_ACK_PAYLOAD)
            ).response
            assert resp.code == UNAUTHORIZED
            assert receipts.receipts() == []
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_messages_alias_loopback_succeeds(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel(_LCI_CLIENT), _LCI_CLIENT)
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/messages", payload=_INBOX_PAYLOAD)
            ).response
            assert resp.code == CREATED
            assert len(msgs.inbox()) == 1
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_inbox_oscore_mesh_peer_succeeds(self) -> None:
        msgs = MessagesResource()
        resp = await msgs.render_post(
            _post(_INBOX_PAYLOAD, hostinfo="[fe80::2]", oscore_context_id="peer-a")
        )
        assert resp.code == CREATED
        assert len(msgs.inbox()) == 1
        assert len(msgs.sent_messages()) == 1

    async def test_ack_oscore_mesh_peer_succeeds(self) -> None:
        receipts = MessageReceiptsResource()
        resp = await receipts.render_post(
            _post(_ACK_PAYLOAD, hostinfo="[fe80::2]", oscore_context_id="peer-a")
        )
        assert resp.code == CHANGED
        assert receipts.receipts() == [{"id": 1, "status": "delivered", "ts": 2}]

    async def test_inbox_oscore_identity_on_remote_succeeds(self) -> None:
        msgs = MessagesResource()
        request = Message(code=POST, payload=_INBOX_PAYLOAD)
        request.remote = SimpleNamespace(hostinfo="[fe80::2]", oscore_context_id="peer-b")
        resp = await msgs.render_post(request)
        assert resp.code == CREATED
        assert len(msgs.inbox()) == 1

    async def test_inbox_oscore_durable_context_object_succeeds(self) -> None:
        class _Ctx:
            def durable_context_id(self) -> str:
                return "durable-peer"

        msgs = MessagesResource()
        request = _post(_INBOX_PAYLOAD, hostinfo="[fe80::2]")
        request.oscore_context = _Ctx()
        resp = await msgs.render_post(request)
        assert resp.code == CREATED
        assert len(msgs.inbox()) == 1

    async def test_spoofed_oscore_option_does_not_authorize_inbox(self) -> None:
        msgs = MessagesResource()
        resp = await msgs.render_post(
            _post(_INBOX_PAYLOAD, hostinfo="[fe80::2]", oscore_option=b"\x00")
        )
        assert resp.code == UNAUTHORIZED
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []
        assert msgs._next_id == 1

    async def test_oscore_protected_flag_without_identity_is_unauthorized(self) -> None:
        msgs = MessagesResource()
        receipts = MessageReceiptsResource()
        inbox = await msgs.render_post(
            _post(_INBOX_PAYLOAD, hostinfo="[fe80::2]", oscore_protected=True)
        )
        ack = await receipts.render_post(
            _post(_ACK_PAYLOAD, hostinfo="[fe80::2]", oscore_protected=True)
        )
        assert inbox.code == UNAUTHORIZED
        assert ack.code == UNAUTHORIZED
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []
        assert msgs._next_id == 1
        assert receipts.receipts() == []

    async def test_empty_oscore_context_id_is_unauthorized(self) -> None:
        msgs = MessagesResource()
        resp = await msgs.render_post(
            _post(_INBOX_PAYLOAD, hostinfo="[fe80::2]", oscore_context_id="")
        )
        assert resp.code == UNAUTHORIZED
        assert msgs.inbox() == []
        assert msgs._next_id == 1

    async def test_mesh_pinning_id_does_not_advance_next_id(self) -> None:
        msgs = MessagesResource()
        pin = await msgs.render_post(
            _post(
                cbor2.dumps({"body": "pin", "id": _PIN_ID}),
                hostinfo="[fe80::2]",
            )
        )
        assert pin.code == UNAUTHORIZED
        assert msgs.inbox() == []
        assert msgs.sent_messages() == []
        assert msgs._next_id == 1
        created = await msgs.render_post(_post(_INBOX_PAYLOAD, hostinfo="[::1]"))
        assert created.code == CREATED
        assert tuple(created.opt.location_path) == ("msg", "sent", "1")
        assert msgs._next_id == 2

    async def test_unauthenticated_empty_inbox_post_is_unauthorized(self) -> None:
        msgs = MessagesResource()
        resp = await msgs.render_post(_post(b"", hostinfo="[fe80::2]"))
        assert resp.code == UNAUTHORIZED
        assert msgs.inbox() == []
        assert msgs._next_id == 1

    async def test_unauthenticated_read_true_does_not_hide_unread(self) -> None:
        msgs = MessagesResource()
        payload = cbor2.dumps({"body": "secret", "read": True, "id": 9})
        resp = await msgs.render_post(_post(payload, hostinfo="[fe80::2]"))
        assert resp.code == UNAUTHORIZED
        assert msgs.inbox() == []
        assert msgs.unread_count() == 0
        assert msgs._next_id == 1


class TestSensorsLocationAuth:
    """POST /sensors/location is not exposed in Python (C-only), verify no handler."""

    async def test_sensors_location_not_exposed(self) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(StaticNodeInfo()),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/sensors/location")
            ).response
            assert resp.code == NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


class TestKeysAuth:
    """/keys resource in Python is read-only (GET only)."""

    async def test_keys_get_returns_pubkey(self) -> None:
        net = InMemoryNetwork()
        pubkey = bytes(32)
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(StaticNodeInfo(), pubkey=pubkey),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/keys")).response
            assert resp.code == CONTENT
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_keys_put_on_root_returns_method_not_allowed(self) -> None:
        """PUT on /keys root (without IID) returns METHOD_NOT_ALLOWED.

        PUT is only allowed on individual keys (/keys/{iid}), not the collection.
        """
        from aiocoap import METHOD_NOT_ALLOWED

        net = InMemoryNetwork()
        pubkey = bytes(32)
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(StaticNodeInfo(), pubkey=pubkey),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=PUT, uri="coap://srv/keys")).response
            assert resp.code == METHOD_NOT_ALLOWED
        finally:
            await client.shutdown()
            await server.shutdown()


class TestObservableAuth:
    """Observable resources are read-only (GET only)."""

    async def test_sensors_get_public(self) -> None:
        net = InMemoryNetwork()
        sensors = SenMLLocationResource()
        site = build_site(StaticNodeInfo(), location_resource=sensors)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/location")).response
            assert resp.code == CONTENT
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_sensors_location_no_post(self) -> None:
        net = InMemoryNetwork()
        sensors = SenMLLocationResource()
        site = build_site(StaticNodeInfo(), location_resource=sensors)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/location",
                    payload=cbor2.dumps({"lat": 47.6, "lon": -122.3}),
                )
            ).response
            # Resource exists but does not support POST - METHOD_NOT_ALLOWED is correct
            assert resp.code == METHOD_NOT_ALLOWED
        finally:
            await client.shutdown()
            await server.shutdown()


class TestDeaddropAuth:
    """/deaddrop is not exposed in Python (C-only), verify no handler."""

    async def test_deaddrop_not_exposed(self) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(StaticNodeInfo()),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(
                    code=POST,
                    uri="coap://srv/deaddrop",
                    payload=cbor2.dumps({"recipient": "node123"}),
                )
            ).response
            assert resp.code == NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


class TestWellKnownCoreAuth:
    """.well-known/core is public."""

    async def test_well_known_core_is_public(self, node_info: StaticNodeInfo) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"),
            "srv",
            site=build_site(node_info),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/.well-known/core")
            ).response
            assert resp.code == CONTENT
            body = resp.payload.decode()
            assert "</status>" in body
            assert "</config>" in body
            assert "</status/neighbors>" in body
        finally:
            await client.shutdown()
            await server.shutdown()
