# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Validate the Python implementation against the committed cross-language vectors.

These guard against drift between the reference implementation and the JSON
vectors that the Rust/C implementations validate against (test/vectors/, issue
ajr / gate ijj). If a vector changes intentionally, regenerate with
``PYTHONPATH=python/src python3 test/vectors/generate.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.schnorr48 import verify as schnorr_verify
from lichen.link.frame import AddrMode, LichenFrame, MicLength
from lichen.schc.headers import compress_packet, decompress_packet

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"

sys.path.insert(0, str(VECTORS_DIR))
from generate import meshtastic_app_compat_vectors  # noqa: E402


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


def test_vectors_directory_exists() -> None:
    assert VECTORS_DIR.is_dir(), f"missing {VECTORS_DIR}"
    assert (VECTORS_DIR / "schema.json").is_file()


def _schc_cases():
    doc = _load("schc_compression.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


def _frame_cases():
    doc = _load("link_frame.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


def _meshtastic_cases():
    doc = _load("meshtastic_app_compat.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _schc_cases())
def test_schc_vector(name: str, vector: dict) -> None:
    packet = bytes.fromhex(vector["packet"])
    compressed = bytes.fromhex(vector["compressed"])
    assert compress_packet(packet) == compressed, f"compress drift: {name}"
    assert decompress_packet(compressed) == packet, f"decompress drift: {name}"
    assert compressed[0] == vector["rule_id"]


@pytest.mark.parametrize("name,vector", _frame_cases())
def test_frame_vector(name: str, vector: dict) -> None:
    f = vector["fields"]
    frame = LichenFrame(
        epoch=f["epoch"],
        seqnum=f["seqnum"],
        dst_addr=bytes.fromhex(f["dst_addr"]),
        payload=bytes.fromhex(f["payload"]),
        mic=bytes.fromhex(f["mic"]),
        addr_mode=AddrMode(f["addr_mode"]),
        mic_length=MicLength(f["mic_length"]),
        signature_present=f["signature_present"],
        encrypted=f["encrypted"],
    )
    encoded = bytes.fromhex(vector["encoded"])
    assert frame.to_bytes() == encoded, f"encode drift: {name}"

    decoded = LichenFrame.from_bytes(encoded)
    assert decoded.epoch == f["epoch"]
    assert decoded.seqnum == f["seqnum"]
    assert decoded.dst_addr == bytes.fromhex(f["dst_addr"])
    assert decoded.payload == bytes.fromhex(f["payload"])
    assert decoded.mic == bytes.fromhex(f["mic"])
    assert int(decoded.addr_mode) == f["addr_mode"]
    assert int(decoded.mic_length) == f["mic_length"]
    assert decoded.signature_present == f["signature_present"]
    assert decoded.encrypted == f["encrypted"]


def test_all_schc_rules_covered() -> None:
    rule_ids = {v["rule_id"] for _, v in _schc_cases()}
    assert {0, 1, 2, 3, 4} <= rule_ids  # every whole-packet rule has a vector


def test_meshtastic_app_compat_vectors_match_generator() -> None:
    doc = _load("meshtastic_app_compat.json")
    assert doc["vectors"] == meshtastic_app_compat_vectors()


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def _read_fields(data: bytes) -> list[tuple[int, int, object]]:
    offset = 0
    fields = []
    while offset < len(data):
        key, offset = _read_varint(data, offset)
        field = key >> 3
        wire_type = key & 0x07
        if wire_type == 0:
            value, offset = _read_varint(data, offset)
        elif wire_type == 2:
            length, offset = _read_varint(data, offset)
            value = data[offset:offset + length]
            offset += length
        elif wire_type == 5:
            value = int.from_bytes(data[offset:offset + 4], "little")
            offset += 4
        else:
            raise AssertionError(f"unsupported wire type {wire_type}")
        fields.append((field, wire_type, value))
    return fields


def _one_field(data: bytes, field: int, wire_type: int) -> object:
    matches = [value for f, wt, value in _read_fields(data) if f == field and wt == wire_type]
    assert len(matches) == 1
    return matches[0]


def _assert_mesh_packet(data: bytes, decoded: dict) -> None:
    fields = _read_fields(data)
    by_field = {field: (wire_type, value) for field, wire_type, value in fields}
    packet = decoded["packet"]

    if "from" in packet:
        assert by_field[1] == (5, packet["from"])
    if "to" in packet:
        assert by_field[2] == (5, packet["to"])
    assert by_field[6] == (5, packet["id"])
    if packet.get("want_ack"):
        assert by_field[10] == (0, 1)

    decoded_data = by_field[4][1]
    assert by_field[4][0] == 2
    _assert_data(decoded_data, packet["decoded"])


def _assert_data(data: bytes, decoded: dict) -> None:
    fields = _read_fields(data)
    by_field = {field: (wire_type, value) for field, wire_type, value in fields}
    portnums = {
        "TEXT_MESSAGE_APP": 1,
        "ROUTING_APP": 5,
        "PRIVATE_APP": 256,
    }
    assert by_field[1] == (0, portnums[decoded["portnum"]])
    if "payload_utf8" in decoded:
        assert by_field[2] == (2, decoded["payload_utf8"].encode())
    if "routing_error_reason" in decoded:
        routing = by_field[2][1]
        assert by_field[2][0] == 2
        assert decoded["routing_error_reason"] == "NO_ROUTE"
        assert _one_field(routing, 3, 0) == 1
    if "request_id" in decoded:
        assert by_field[6] == (5, decoded["request_id"])


@pytest.mark.parametrize("name,vector", _meshtastic_cases())
def test_meshtastic_app_compat_vector_wire_schema(name: str, vector: dict) -> None:
    encoded = bytes.fromhex(vector["encoded"])
    expect = vector["expect"]

    if expect.get("reject"):
        if "invalid_stream_framing" in vector["message"]:
            assert encoded.startswith(bytes.fromhex("94c3")), name
        if vector["message"] == "oversized":
            assert len(encoded) == expect["max_to_radio_bytes"] + 1
        return

    assert not encoded.startswith(bytes.fromhex("94c3")), name
    assert vector["transport"]["framing"] == "one raw serialized protobuf per GATT value"

    if vector["message"] == "heartbeat":
        heartbeat = _one_field(encoded, 7, 2)
        assert heartbeat == b""
    elif vector["message"] == "want_config_id":
        nonce = vector["decoded"]["want_config_id"]
        assert _one_field(encoded, 3, 0) == nonce
        terminal = bytes.fromhex(expect["terminal_from_radio"])
        assert _one_field(terminal, 7, 0) == nonce
    elif vector["protobuf"] == "ToRadio":
        mesh_packet = _one_field(encoded, 1, 2)
        _assert_mesh_packet(mesh_packet, vector["decoded"])
    elif vector["protobuf"] == "FromRadio":
        assert _one_field(encoded, 1, 0) == expect["from_radio_id"]
        mesh_packet = _one_field(encoded, 2, 2)
        _assert_mesh_packet(mesh_packet, vector["decoded"])


def _schnorr_cases():
    doc = _load("schnorr48.json")
    return [(v["description"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("desc,vector", _schnorr_cases())
def test_schnorr_vector(desc: str, vector: dict) -> None:
    pubkey = bytes.fromhex(vector["public_key"])
    msg = bytes.fromhex(vector["message"]) if vector["message"] else b""
    sig = bytes.fromhex(vector["signature"])
    result = schnorr_verify(pubkey, msg, sig)
    expected = vector["valid"]
    assert result == expected, (
        f"{'valid sig rejected' if expected else 'invalid sig accepted'}: {desc}"
    )
    if expected and "seed" in vector:
        identity = Identity.from_seed(bytes.fromhex(vector["seed"]))
        computed = schnorr_sign(identity.privkey, identity.pubkey, msg)
        assert computed == sig, f"sign() output mismatch: {desc}"
