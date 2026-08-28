# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume test/vectors/coap_block.json via the LICHEN CoAP engine (aiocoap).

Option-value integers are independently derived from RFC 7959 section 2.2
(val = (NUM << 4) | (M << 3) | SZX). This module drives aiocoap's BlockOption
and Message codec; reject cases that aiocoap accepts (empty uint, SZX=7 BERT,
4-byte uint) are covered by rust/lichen-coap.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from aiocoap import Message
from aiocoap.optiontypes import BlockOption
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

_VECTORS_PATH = Path(__file__).resolve().parents[3] / "test" / "vectors" / "coap_block.json"
_SCHEMA_PATH = _VECTORS_PATH.with_name("coap_block.schema.json")


def _document() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_VECTORS_PATH.read_text(encoding="utf-8")))


def _schema() -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(_SCHEMA_PATH.read_text(encoding="utf-8")))


def _rfc7959_pack(num: int, more: bool, szx: int) -> bytes:
    """Independent RFC 7959 section 2.2 packing (not lichen-coap)."""
    value = (num << 4) | ((1 if more else 0) << 3) | szx
    if value <= 0xFF:
        return bytes([value])
    if value <= 0xFFFF:
        return value.to_bytes(2, "big")
    return value.to_bytes(3, "big")


def test_schema_accepts_document() -> None:
    schema = _schema()
    document = _document()
    Draft7Validator.check_schema(schema)
    errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda e: e.path)
    assert not errors, [error.message for error in errors]
    assert document["format_version"] == 2
    assert document["name"] == "coap_block"


def test_option_value_accept_matches_rfc_and_aiocoap() -> None:
    document = _document()
    seen = 0
    for vector in document["vectors"]:
        if vector["kind"] != "option_value" or vector["expected"] != "accept":
            continue
        packed = bytes.fromhex(vector["encoded_hex"])
        assert packed == _rfc7959_pack(vector["num"], vector["more"], vector["szx"])
        assert vector["size"] == 2 ** (vector["szx"] + 4)

        option_number = 27 if vector["option"] == "Block1" else 23
        parsed = BlockOption(option_number)
        parsed.decode(packed)
        assert parsed.value.block_number == vector["num"]
        assert bool(parsed.value.more) is vector["more"]
        assert parsed.value.size_exponent == vector["szx"]
        assert parsed.value.size == vector["size"]
        # aiocoap uses RFC 7252 empty-uint for value 0; LICHEN rust writes 0x00.
        if packed != b"\x00":
            assert parsed.encode() == packed
        seen += 1
    assert seen >= 10


def test_coap_message_vectors_decode_on_aiocoap() -> None:
    document = _document()
    seen = 0
    for vector in document["vectors"]:
        if vector["kind"] != "coap_message":
            continue
        message = Message.decode(bytes.fromhex(vector["encoded"]))
        assert int(message.mtype) == vector["mtype"]
        assert int(message.code) == vector["code"]
        assert message.mid == vector["mid"]
        if "uri_path" in vector:
            assert list(message.opt.uri_path) == vector["uri_path"]
        if "payload_hex" in vector:
            assert message.payload == bytes.fromhex(vector["payload_hex"])
        if "block1" in vector:
            block = message.opt.block1
            assert block is not None
            assert block.block_number == vector["block1"]["num"]
            assert bool(block.more) is vector["block1"]["more"]
            assert block.size_exponent == vector["block1"]["szx"]
        if "block2" in vector:
            block = message.opt.block2
            assert block is not None
            assert block.block_number == vector["block2"]["num"]
            assert bool(block.more) is vector["block2"]["more"]
            assert block.size_exponent == vector["block2"]["szx"]
        seen += 1
    assert seen == 3
