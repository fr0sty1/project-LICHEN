# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LICHEN CoAP resources (t64)."""

from __future__ import annotations

import aiocoap
import cbor2
import pytest
from aiocoap import GET, PUT, Message

from lichen.coap.resources import (
    _CBOR_MAX_ARRAY_ENTRIES,
    _CBOR_MAX_DEPTH,
    _CBOR_MAX_ENCODED_BYTES,
    _CBOR_MAX_MAP_ENTRIES,
    StaticNodeInfo,
    _decode_single_cbor,
    build_site,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context


def _node_info() -> StaticNodeInfo:
    return StaticNodeInfo(
        status={"uptime": 1234, "rank": 512, "parent": "fe80::1", "battery": 90},
        neighbors=[{"addr": "fe80::2", "rank": 256, "etx": 1.0}],
        config={"region": "US915", "tx_power_dbm": 14},
    )


def test_cbor_mutation_limits_accept_boundaries() -> None:
    map_value = {index: index for index in range(_CBOR_MAX_MAP_ENTRIES)}
    array_value = list(range(_CBOR_MAX_ARRAY_ENTRIES))
    nested = b"\x00"
    nested_value: object = 0
    for _ in range(_CBOR_MAX_DEPTH):
        nested = b"\x81" + nested
        nested_value = [nested_value]
    byte_string = b"\x59\x0f\xfd" + b"x" * (_CBOR_MAX_ENCODED_BYTES - 3)

    assert _decode_single_cbor(cbor2.dumps(map_value)) == map_value
    assert _decode_single_cbor(cbor2.dumps(array_value)) == array_value
    assert _decode_single_cbor(nested) == nested_value
    assert len(byte_string) == _CBOR_MAX_ENCODED_BYTES
    assert len(_decode_single_cbor(byte_string)) == _CBOR_MAX_ENCODED_BYTES - 3


@pytest.mark.parametrize(
    "payload",
    [
        cbor2.dumps({index: index for index in range(_CBOR_MAX_MAP_ENTRIES + 1)}),
        b"\xb9\xff\xff",
        b"\x81" * (_CBOR_MAX_DEPTH + 1) + b"\x00",
        b"\x9f" + b"\x00" * (_CBOR_MAX_ARRAY_ENTRIES + 1) + b"\xff",
        b"\xbf"
        + b"".join(
            cbor2.dumps(index) + cbor2.dumps(index)
            for index in range(_CBOR_MAX_MAP_ENTRIES + 1)
        )
        + b"\xff",
        b"\x99\x01\x00" + b"\x83\x00\x00\x00" * 256,
        b"\x59\x0f\xfe" + b"x" * (_CBOR_MAX_ENCODED_BYTES - 2),
    ],
)
def test_cbor_mutation_limits_reject_excess(payload: bytes) -> None:
    with pytest.raises(ValueError):
        _decode_single_cbor(payload)


def test_cbor_scanner_accepts_valid_untagged_indefinite_containers() -> None:
    assert _decode_single_cbor(b"\x9f\x01\x02\xff") == [1, 2]
    assert _decode_single_cbor(b"\xbf\x61a\x01\xff") == {"a": 1}


@pytest.mark.parametrize(
    "payload",
    [
        b"\xd8\x1c\x81\x01",  # tag 28 shared list
        b"\xd8\x1c\xa1\x61a\x01",  # tag 28 shared map
        b"\xd8\x1d\x00",  # tag 29 shared reference
        b"\x81\xd8\x1c\x81\x01",  # nested tag 28
        b"\xa1\x61a\xd8\x1d\x00",  # nested tag 29
    ],
)
def test_cbor_scanner_rejects_standalone_and_nested_tags(payload: bytes) -> None:
    with pytest.raises(ValueError, match="tags are not allowed"):
        _decode_single_cbor(payload)


async def _client_server(node_info: StaticNodeInfo, *, allow_config_write: bool = False):
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"),
        "server",
        site=build_site(node_info, allow_config_write=allow_config_write),
    )
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


@pytest.mark.asyncio
async def test_status_returns_cbor() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/status")).response
        assert resp.code == aiocoap.CONTENT
        assert resp.opt.content_format == 60  # application/cbor
        assert cbor2.loads(resp.payload) == info.status
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_neighbors_returns_table() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        resp = await client.request(
            Message(code=GET, uri="coap://server/neighbors")
        ).response
        assert cbor2.loads(resp.payload) == info.neighbors
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_well_known_core_lists_resources() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        resp = await client.request(
            Message(code=GET, uri="coap://server/.well-known/core")
        ).response
        body = resp.payload.decode()
        assert "</status>" in body
        assert "</neighbors>" in body
        assert "</config>" in body
        assert 'rt="lichen.status"' in body
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_get_and_put() -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        resp = await client.request(Message(code=GET, uri="coap://server/config")).response
        assert cbor2.loads(resp.payload)["region"] == "US915"

        put = Message(
            code=PUT,
            uri="coap://server/config",
            payload=cbor2.dumps({"tx_power_dbm": 20}),
        )
        put_resp = await client.request(put).response
        assert put_resp.code == aiocoap.CHANGED
        # Verify the update is reflected by reading back.
        get_resp = await client.request(Message(code=GET, uri="coap://server/config")).response
        updated = cbor2.loads(get_resp.payload)
        assert updated["tx_power_dbm"] == 20
        assert updated["region"] == "US915"
        assert info.config["tx_power_dbm"] == 20
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_put_is_unauthorized_by_default_before_parsing() -> None:
    info = _node_info()
    client, server = await _client_server(info)
    try:
        put = Message(code=PUT, uri="coap://server/config", payload=b"")
        resp = await client.request(put).response
        assert resp.code == aiocoap.UNAUTHORIZED
        # Config should remain unchanged
        assert info.config["tx_power_dbm"] == 14
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_put_invalid_cbor_returns_bad_request() -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        put = Message(code=PUT, uri="coap://server/config", payload=b"\xff\xfe\xfd")
        resp = await client.request(put).response
        assert resp.code == aiocoap.BAD_REQUEST
        # Config should remain unchanged
        assert info.config["tx_power_dbm"] == 14
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_put_non_dict_cbor_returns_bad_request() -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        # Send a CBOR list instead of a dict
        put = Message(
            code=PUT,
            uri="coap://server/config",
            payload=cbor2.dumps([1, 2, 3]),
        )
        resp = await client.request(put).response
        assert resp.code == aiocoap.BAD_REQUEST
        # Config should remain unchanged
        assert info.config["tx_power_dbm"] == 14
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_put_is_atomic_and_rejects_unknown_fields() -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        valid = Message(
            code=PUT,
            uri="coap://server/config",
            payload=cbor2.dumps({"tx_power_dbm": 20}),
        )
        assert (await client.request(valid).response).code == aiocoap.CHANGED

        invalid = Message(
            code=PUT,
            uri="coap://server/config",
            payload=cbor2.dumps({"tx_power_dbm": 30, "unknown": 1}),
        )
        assert (await client.request(invalid).response).code == aiocoap.BAD_REQUEST
        assert info.config == {"region": "US915", "tx_power_dbm": 20}
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_put_rejects_trailing_cbor_without_mutation() -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        payload = cbor2.dumps({"tx_power_dbm": 20}) + b"trailing"
        response = await client.request(
            Message(code=PUT, uri="coap://server/config", payload=payload)
        ).response
        assert response.code == aiocoap.BAD_REQUEST
        assert info.config["tx_power_dbm"] == 14
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_put_rejects_duplicate_cbor_keys_without_mutation() -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        key = cbor2.dumps("tx_power_dbm")
        payload = b"\xa2" + key + cbor2.dumps(20) + key + cbor2.dumps(21)
        response = await client.request(
            Message(code=PUT, uri="coap://server/config", payload=payload)
        ).response
        assert response.code == aiocoap.BAD_REQUEST
        assert info.config["tx_power_dbm"] == 14
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_config_put_accepts_canonical_map_with_float16() -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        key = cbor2.dumps("tx_power_dbm")
        payload = b"\xa1" + key + b"\xf9\x3e\x00"  # preferred float16 1.5
        response = await client.request(
            Message(code=PUT, uri="coap://server/config", payload=payload)
        ).response
        assert response.code == aiocoap.CHANGED
        assert info.config["tx_power_dbm"] == 1.5

        canonical = cbor2.dumps(
            {"tx_power_dbm": 20, "region": "EU868"},
            canonical=True,
        )
        canonical_response = await client.request(
            Message(code=PUT, uri="coap://server/config", payload=canonical)
        ).response
        assert canonical_response.code == aiocoap.CHANGED
        assert info.config == {"region": "EU868", "tx_power_dbm": 20}
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tagged_value",
    [b"\xd8\x1c\x81\x14", b"\xd8\x1d\x00"],
)
async def test_config_put_rejects_tags_and_remains_serializable(
    tagged_value: bytes,
) -> None:
    info = _node_info()
    client, server = await _client_server(info, allow_config_write=True)
    try:
        payload = b"\xa1" + cbor2.dumps("tx_power_dbm") + tagged_value
        response = await client.request(
            Message(code=PUT, uri="coap://server/config", payload=payload)
        ).response
        current = await client.request(
            Message(code=GET, uri="coap://server/config")
        ).response
        assert response.code == aiocoap.BAD_REQUEST
        assert cbor2.loads(current.payload) == info.config
        assert info.config["tx_power_dbm"] == 14
    finally:
        await client.shutdown()
        await server.shutdown()


def test_static_node_info_is_copy_safe() -> None:
    info = StaticNodeInfo(status={"a": 1})
    snapshot = info.get_status()
    snapshot["a"] = 999
    assert info.status["a"] == 1  # get_status returns a copy
