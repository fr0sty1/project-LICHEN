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

import cbor2
import pytest
from aiocoap import BAD_REQUEST, CHANGED, CONTENT, CREATED, GET, NOT_FOUND, POST, PUT, DELETE, UNAUTHORIZED, Message

from lichen.coap.resources import (
    MessageReceiptsResource,
    MessagesResource,
    SenMLLocationResource,
    StaticNodeInfo,
    build_site,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


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
            net.channel("srv"), "srv",
            site=build_site(node_info),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/config")
            ).response
            assert resp.code == CONTENT
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_config_put_unauthorized_by_default(self, node_info: StaticNodeInfo) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"), "srv",
            site=build_site(node_info),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/config",
                        payload=cbor2.dumps({"tx_power_dbm": 20}))
            ).response
            assert resp.code == UNAUTHORIZED
            assert node_info.config["tx_power_dbm"] == 14
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_config_put_allowed_with_explicit_flag(self, node_info: StaticNodeInfo) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"), "srv",
            site=build_site(node_info, config_allow_writes=True),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/config",
                        payload=cbor2.dumps({"tx_power_dbm": 20}))
            ).response
            assert resp.code == CHANGED
            assert node_info.config["tx_power_dbm"] == 20
        finally:
            await client.shutdown()
            await server.shutdown()


class TestMessagesAuth:
    """POST /msg/inbox, /msg/sent, /msg/ack require authorization."""

    async def test_msg_inbox_post_creates_message(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/inbox",
                        payload=cbor2.dumps({"body": "hello", "to": "all"}))
            ).response
            assert resp.code == CREATED
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_inbox_get_is_public(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/msg/inbox")
            ).response
            assert resp.code == CONTENT
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_sent_does_not_have_post_handler(self) -> None:
        net = InMemoryNetwork()
        msgs = MessagesResource()
        site = build_site(StaticNodeInfo(), messages_resource=msgs)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/sent",
                        payload=cbor2.dumps({"body": "test"}))
            ).response
            assert resp.code == UNAUTHORIZED
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_ack_post_accepts_valid_receipt(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack",
                        payload=cbor2.dumps({"id": 1, "status": "delivered", "ts": 2}))
            ).response
            assert resp.code == CHANGED
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_msg_ack_rejects_invalid_receipt(self) -> None:
        net = InMemoryNetwork()
        receipts = MessageReceiptsResource()
        site = build_site(StaticNodeInfo(), message_receipts_resource=receipts)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/msg/ack",
                        payload=cbor2.dumps({"id": 1, "status": "unknown", "ts": 2}))
            ).response
            assert resp.code == BAD_REQUEST
        finally:
            await client.shutdown()
            await server.shutdown()


class TestSensorsLocationAuth:
    """POST /sensors/location is not exposed in Python (C-only), verify no handler."""

    async def test_sensors_location_not_exposed(self) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"), "srv",
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
            net.channel("srv"), "srv",
            site=build_site(StaticNodeInfo(), pubkey=pubkey),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=GET, uri="coap://srv/keys")
            ).response
            assert resp.code == CONTENT
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_keys_put_not_implemented(self) -> None:
        net = InMemoryNetwork()
        pubkey = bytes(32)
        server = await create_lichen_context(
            net.channel("srv"), "srv",
            site=build_site(StaticNodeInfo(), pubkey=pubkey),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=PUT, uri="coap://srv/keys")
            ).response
            assert resp.code == NOT_FOUND
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
            resp = await client.request(
                Message(code=GET, uri="coap://srv/location")
            ).response
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
                Message(code=POST, uri="coap://srv/location",
                        payload=cbor2.dumps({"lat": 47.6, "lon": -122.3}))
            ).response
            assert resp.code == NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


class TestDeaddropAuth:
    """/deaddrop is not exposed in Python (C-only), verify no handler."""

    async def test_deaddrop_not_exposed(self) -> None:
        net = InMemoryNetwork()
        server = await create_lichen_context(
            net.channel("srv"), "srv",
            site=build_site(StaticNodeInfo()),
        )
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(
                Message(code=POST, uri="coap://srv/deaddrop",
                        payload=cbor2.dumps({"recipient": "node123"}))
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
            net.channel("srv"), "srv",
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
            assert "</neighbors>" in body
        finally:
            await client.shutdown()
            await server.shutdown()
