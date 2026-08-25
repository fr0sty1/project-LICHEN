# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume ``test/vectors/lci_radio_config.json`` via /config/radio.

Every GET vector's bytes are the exact payload emitted by
:class:`~lichen.coap.resources.node_resources.RadioConfigResource`; every PUT
vector's bytes are the exact request body (``cbor2.dumps`` of the update map).
Error vectors reflect verified rejection behavior: 4.01 when writes are
disabled, 4.00 for empty or non-map bodies and for unknown keys (atomic, no
mutation). The spec example pins CBOR float64 encoding of ``freq_mhz``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cbor2
import pytest
from aiocoap import GET, PUT, Message
from aiocoap.numbers import ContentFormat

from lichen.coap.resources import StaticNodeInfo, build_site
from lichen.coap.resources.node_resources import RadioConfigResource
from lichen.coap.transport import InMemoryNetwork, create_lichen_context

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
DOC: dict[str, Any] = json.loads((VECTORS_DIR / "lci_radio_config.json").read_text())
VECTORS = DOC["vectors"]

GET_VECTORS = [v for v in VECTORS if v["op"] == "get"]
PUT_OK = [v for v in VECTORS if v["op"] == "put" and v["expected"]["code"] == "2.04"]
PUT_ERRORS = [v for v in VECTORS if v["op"] == "put" and v["expected"]["code"] != "2.04"]

EXPECTED_COUNTS = {"get": 7, "put_changed": 1, "put_error": 4}

RADIO_PATH = "/config/radio"


def _body(vec: dict[str, Any]) -> bytes:
    if "wire_hex" in vec:
        return bytes.fromhex(vec["wire_hex"])
    return bytes.fromhex(vec["encoded_hex"])


async def _stack(info: StaticNodeInfo, *, allow_writes: bool) -> tuple[Any, Any]:
    net = InMemoryNetwork()
    server = await create_lichen_context(
        net.channel("server"),
        "server",
        site=build_site(info, radio_config_allow_writes=allow_writes),
    )
    client = await create_lichen_context(net.channel("client"), "client")
    return client, server


@pytest.mark.parametrize("vector", GET_VECTORS, ids=lambda v: v["name"])
def test_get_reencodes_byte_exact(vector: dict[str, Any]) -> None:
    """Generator oracle: canonical re-encode of the pinned map is byte-identical."""
    assert cbor2.dumps(vector["input"]) == bytes.fromhex(vector["encoded_hex"])
    decoded = cbor2.loads(bytes.fromhex(vector["encoded_hex"]))
    assert decoded == vector["input"]


@pytest.mark.parametrize("vector", GET_VECTORS, ids=lambda v: v["name"])
async def test_get_resource_emits_pinned_bytes(vector: dict[str, Any]) -> None:
    resource = RadioConfigResource(StaticNodeInfo(radio_config=dict(vector["input"])))
    response = await resource.render_get(Message(code=GET))
    assert response.payload == bytes.fromhex(vector["encoded_hex"]), vector["name"]
    assert int(response.opt.content_format) == vector["content_format"] == 60


def test_spec_example_float_is_cbor_float64() -> None:
    """906.875 MHz must occupy the 9-byte float64 encoding, not float16/32."""
    vec = next(v for v in VECTORS if v["name"] == "get_spec_example_radio")
    wire = bytes.fromhex(vec["encoded_hex"])
    freq_index = wire.index(cbor2.dumps("freq_mhz")) + len(cbor2.dumps("freq_mhz"))
    assert wire[freq_index] == 0xFB  # CBOR major 7, additional info 27 (float64)
    assert cbor2.loads(wire[freq_index : freq_index + 9]) == 906.875


@pytest.mark.parametrize("vector", PUT_OK, ids=lambda v: v["name"])
async def test_put_merge_over_stack(vector: dict[str, Any]) -> None:
    info = StaticNodeInfo(radio_config=dict(vector["initial_config"]))
    client, server = await _stack(info, allow_writes=True)
    try:
        put = Message(code=PUT, uri=f"coap://server{RADIO_PATH}", payload=_body(vector))
        put.opt.content_format = ContentFormat.CBOR
        response = await client.request(put).response
        assert response.code.dotted == vector["expected"]["code"] == "2.04"

        current = await client.request(Message(code=GET, uri=f"coap://server{RADIO_PATH}")).response
        assert cbor2.loads(current.payload) == vector["expected"]["resulting_config"]
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.parametrize("vector", PUT_ERRORS, ids=lambda v: v["name"])
async def test_put_rejections_match_real_codes(vector: dict[str, Any]) -> None:
    initial = vector.get("initial_config", {})
    info = StaticNodeInfo(radio_config=dict(initial))
    client, server = await _stack(info, allow_writes=vector["writes_enabled"])
    try:
        put = Message(code=PUT, uri=f"coap://server{RADIO_PATH}", payload=_body(vector))
        put.opt.content_format = ContentFormat.CBOR
        response = await client.request(put).response
        assert response.code.dotted == vector["expected"]["code"], vector["name"]

        current = await client.request(Message(code=GET, uri=f"coap://server{RADIO_PATH}")).response
        expected_state = vector["expected"].get("resulting_config", initial)
        assert cbor2.loads(current.payload) == expected_state, f"{vector['name']}: state drift"
    finally:
        await client.shutdown()
        await server.shutdown()


class TestAllVectorsAccountedFor:
    def test_vector_count_matches_expectation(self) -> None:
        counts = {
            "get": len(GET_VECTORS),
            "put_changed": len(PUT_OK),
            "put_error": len(PUT_ERRORS),
        }
        assert counts == EXPECTED_COUNTS
        assert sum(counts.values()) == len(VECTORS)
