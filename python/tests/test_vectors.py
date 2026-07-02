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
from jsonschema import Draft7Validator

from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.schnorr48 import verify as schnorr_verify
from lichen.link.frame import AddrMode, LichenFrame, MicLength
from lichen.schc.headers import compress_packet, decompress_packet

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"

sys.path.insert(0, str(VECTORS_DIR))
from generate import meshcore_app_compat_vectors, meshtastic_app_compat_vectors  # noqa: E402

CONFIG_SECTION_EXPECTATIONS = [
    ("device", 1, [(1, 0), (7, 900)]),
    ("position", 2, [(3, 0), (5, 0), (7, 0), (13, 2)]),
    ("power", 3, [(1, 0), (4, 0)]),
    ("network", 4, [(1, 0), (6, 0), (11, 0)]),
    ("display", 5, [(1, 0), (6, 0), (8, 0)]),
    (
        "lora",
        6,
        [(1, 1), (2, 0), (7, 1), (8, 3), (9, 1), (10, 14), (11, 0), (104, 1)],
    ),
    ("bluetooth", 7, [(1, 1), (2, 2)]),
    ("security", 8, [(5, 0), (6, 0), (8, 0)]),
    ("device_ui", 10, [(1, 0), (2, 1), (3, 0)]),
]


def _load(name: str) -> dict:
    return json.loads((VECTORS_DIR / name).read_text())


def test_vectors_directory_exists() -> None:
    assert VECTORS_DIR.is_dir(), f"missing {VECTORS_DIR}"
    assert (VECTORS_DIR / "schema.json").is_file()


@pytest.mark.parametrize(
    "filename",
    [
        "schc_compression.json",
        "link_frame.json",
        "meshtastic_app_compat.json",
        "meshcore_app_compat.json",
    ],
)
def test_vector_file_schema(filename: str) -> None:
    schema = _load("schema.json")
    doc = _load(filename)
    errors = sorted(Draft7Validator(schema).iter_errors(doc), key=lambda e: e.path)
    assert not errors, [error.message for error in errors]


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


def _meshcore_cases():
    doc = _load("meshcore_app_compat.json")
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


def test_meshcore_app_compat_vectors_match_generator() -> None:
    doc = _load("meshcore_app_compat.json")
    assert doc["vectors"] == meshcore_app_compat_vectors()


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


def _assert_queue_status(data: bytes, decoded: dict) -> None:
    fields = _read_fields(data)
    by_field = {field: (wire_type, value) for field, wire_type, value in fields}
    if "res" in decoded:
        assert by_field[1] == (0, decoded["res"])
    assert by_field[2] == (0, decoded["free"])
    assert by_field[3] == (0, decoded["maxlen"])
    if "mesh_packet_id" in decoded:
        assert by_field[4] == (0, decoded["mesh_packet_id"])


def _assert_module_config(data: bytes, decoded: dict) -> None:
    fields = _read_fields(data)
    assert [field for field, _, _ in fields] == [6]
    telemetry = _one_field(data, 6, 2)
    telemetry_fields = _read_fields(telemetry)
    assert [(field, wire_type) for field, wire_type, _ in telemetry_fields] == [
        (1, 0),
        (2, 0),
        (14, 0),
    ]

    values = decoded["moduleConfig"]["telemetry"]
    by_field = {field: value for field, _, value in telemetry_fields}
    assert by_field[1] == values["device_update_interval"]
    assert by_field[2] == values["environment_update_interval"]
    assert by_field[14] == int(values["device_telemetry_enabled"])


def _assert_region_presets(data: bytes, decoded: dict) -> None:
    fields = _read_fields(data)
    assert [(field, wire_type) for field, wire_type, _ in fields] == [(1, 2), (2, 2)]

    values = decoded["region_presets"]
    assert len(values["preset_groups"]) == 1
    assert len(values["region_groups"]) == 1

    preset_group = _one_field(data, 1, 2)
    preset_fields = _read_fields(preset_group)
    assert [(field, wire_type) for field, wire_type, _ in preset_fields] == [
        (1, 0),
        (2, 0),
    ]
    preset_values = values["preset_groups"][0]
    modem_presets = {"LONG_FAST": 0}
    assert preset_fields[0][2] == modem_presets[preset_values["presets"][0]]
    assert preset_fields[1][2] == modem_presets[preset_values["default_preset"]]

    region_group = _one_field(data, 2, 2)
    region_fields = _read_fields(region_group)
    assert [(field, wire_type) for field, wire_type, _ in region_fields] == [
        (1, 0),
        (2, 0),
    ]
    region_values = values["region_groups"][0]
    regions = {"US": 1}
    assert region_fields[0][2] == regions[region_values["region"]]
    assert region_fields[1][2] == region_values["group_index"]


def _assert_config_section(data: bytes, decoded: dict, expect: dict) -> None:
    fields = _read_fields(data)
    assert len(fields) == 1
    section = expect["config_section"]
    canonical = {
        name: {"section": name, "oneof_field": oneof, "fields": [
            {"field": field, "wire_type": "varint", "value": value}
            for field, value in expected_fields
        ]}
        for name, oneof, expected_fields in CONFIG_SECTION_EXPECTATIONS
    }[section["section"]]
    assert {key: section[key] for key in ("section", "oneof_field", "fields")} == canonical
    assert fields[0][0] == section["oneof_field"]
    assert fields[0][1] == 2

    inner = fields[0][2]
    assert isinstance(inner, bytes)
    inner_fields = _read_fields(inner)
    assert [(field, wire_type) for field, wire_type, _ in inner_fields] == [
        (field["field"], 0) for field in section["fields"]
    ]

    values = {field: value for field, _, value in inner_fields}
    for field in section["fields"]:
        assert field["wire_type"] == "varint"
        assert values[field["field"]] == field["value"]

    config = decoded["config"]
    assert config["section"] == section["section"]
    assert config["oneof_field"] == section["oneof_field"]
    assert config["fields"] == section["fields"]


def _assert_config_sequence(expect: dict) -> None:
    sequence = expect["from_radio_sequence"]
    if "config" not in sequence:
        return
    assert "config_sections" in expect
    section_names = [section["section"] for section in expect["config_sections"]]
    assert [item for item in sequence if item == "config"] == ["config"] * len(section_names)
    assert section_names == [name for name, _, _ in CONFIG_SECTION_EXPECTATIONS]
    assert [section["oneof_field"] for section in expect["config_sections"]] == [
        oneof for _, oneof, _ in CONFIG_SECTION_EXPECTATIONS
    ]
    for section in expect["config_sections"]:
        _assert_config_section(bytes.fromhex(section["payload"]), {"config": section}, {
            "config_section": section
        })


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

    if vector["protobuf"] == "Empty":
        assert encoded == b""
        assert expect["queue_drained"] is True
        assert expect["no_from_num_increment"] is True
        return

    assert not encoded.startswith(bytes.fromhex("94c3")), name
    assert vector["transport"]["framing"] == "one raw serialized protobuf per GATT value"

    if vector["protobuf"] == "FromNum":
        assert len(encoded) == 4
        assert int.from_bytes(encoded, "little") == vector["decoded"]["from_num"]
        assert expect["byte_order"] == "little-endian"
        assert expect["read_until_empty"] is True
    elif vector["message"] == "heartbeat":
        heartbeat = _one_field(encoded, 7, 2)
        assert heartbeat == b""
    elif vector["message"] == "want_config_id":
        nonce = vector["decoded"]["want_config_id"]
        assert _one_field(encoded, 3, 0) == nonce
        terminal = bytes.fromhex(expect["terminal_from_radio"])
        assert _one_field(terminal, 7, 0) == nonce
        _assert_config_sequence(expect)
    elif vector["protobuf"] == "ToRadio":
        mesh_packet = _one_field(encoded, 1, 2)
        _assert_mesh_packet(mesh_packet, vector["decoded"])
    elif vector["protobuf"] == "FromRadio":
        if vector["message"] == "queueStatus":
            assert not [value for f, wt, value in _read_fields(encoded) if f == 1 and wt == 0]
            queue_status = _one_field(encoded, 11, 2)
            _assert_queue_status(queue_status, vector["decoded"]["queueStatus"])
        elif vector["message"] in ("config", "moduleConfig", "region_presets"):
            payload = bytes.fromhex(vector["payload"])
            assert _one_field(encoded, expect["from_radio_field"], 2) == payload
            if vector["message"] == "config":
                _assert_config_section(payload, vector["decoded"], expect)
            elif vector["message"] == "moduleConfig":
                _assert_module_config(payload, vector["decoded"])
            else:
                _assert_region_presets(payload, vector["decoded"])
        else:
            assert _one_field(encoded, 1, 0) == expect["from_radio_id"]
            mesh_packet = _one_field(encoded, 2, 2)
            _assert_mesh_packet(mesh_packet, vector["decoded"])


@pytest.mark.parametrize("name,vector", _meshcore_cases())
def test_meshcore_app_compat_vector_wire_schema(name: str, vector: dict) -> None:
    encoded = bytes.fromhex(vector["encoded"])
    expect = vector["expect"]

    if vector["transport"]["name"] == "serial":
        assert len(encoded) >= 4, name
        assert encoded[0] in (0x3C, 0x3E), name
        inner_len = int.from_bytes(encoded[1:3], "little")
        assert inner_len == len(encoded) - 3, name
        assert encoded[3:].hex() == expect["inner_frame"], name
        return

    assert vector["transport"]["name"] == "ble-nus"
    assert not encoded.startswith(bytes.fromhex("94c3")), name
    assert encoded, name

    if vector["frame"] == "command" and "responses" in expect:
        for response_hex in expect["responses"]:
            response = bytes.fromhex(response_hex)
            assert response, name
            if response[0] == 0x01:
                assert len(response) == 2, name
    elif vector["frame"] in ("response", "push"):
        if vector["decoded"].get("response") == "CHANNEL_MSG_RECV_V3":
            assert encoded[0] == 0x11, name
            assert encoded[5] == 0xFF, name
            assert int.from_bytes(encoded[7:11], "little") == vector["decoded"]["id"]
            assert encoded[11:] == vector["decoded"]["payload_utf8"].encode()
        elif vector["decoded"].get("push") == "SEND_CONFIRMED":
            assert encoded[0] == 0x82, name
            assert int.from_bytes(encoded[1:5], "little") == vector["decoded"]["request_id"]
            assert encoded[5] == vector["decoded"]["error_reason"]
            assert encoded[6] == int(vector["decoded"]["has_error_reason"])
        elif vector["decoded"].get("push") == "MSG_WAITING":
            assert encoded == b"\x83", name
    elif "response_prefix" in expect:
        prefix = bytes.fromhex(expect["response_prefix"])
        assert prefix, name
        assert expect["response_len"] >= len(prefix), name


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
