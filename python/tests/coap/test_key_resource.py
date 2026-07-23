# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the /keys CoAP resource (rt="keystore")."""

from __future__ import annotations

import cbor2
import pytest
from aiocoap import GET, Message
from aiocoap.numbers.codes import Code

from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

_FAKE_PUBKEY = bytes(range(32))


async def _client_server(pubkey: bytes):
    info = StaticNodeInfo()
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=build_site(info, pubkey=pubkey)
    )
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


@pytest.mark.asyncio
async def test_key_returns_200() -> None:
    client, server = await _client_server(_FAKE_PUBKEY)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/keys")).response
        assert resp.code == Code.CONTENT
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_key_is_cbor() -> None:
    client, server = await _client_server(_FAKE_PUBKEY)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/keys")).response
        assert resp.opt.content_format == 60
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_key_fingerprint_is_first_8_bytes_hex() -> None:
    client, server = await _client_server(_FAKE_PUBKEY)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/keys")).response
        body = cbor2.loads(resp.payload)
        assert body["fingerprint"] == _FAKE_PUBKEY[:8].hex()
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_key_pubkey_is_raw_bytes() -> None:
    client, server = await _client_server(_FAKE_PUBKEY)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/keys")).response
        body = cbor2.loads(resp.payload)
        assert body["pubkey"] == _FAKE_PUBKEY
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_key_not_exposed_without_pubkey() -> None:
    info = StaticNodeInfo()
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"), "server", site=build_site(info)
    )
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/keys")).response
        assert resp.code == Code.NOT_FOUND
    finally:
        await client.shutdown()
        await server.shutdown()
