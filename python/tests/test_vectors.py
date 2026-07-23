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

from lichen.announce.coords import decode_coords, encode_coords
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.schnorr48 import verify as schnorr_verify
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength
from lichen.rpl.dao import RplTarget, TransitInformation
from lichen.rpl.messages import DAO, DIO, DIS, DAOAck, _parse_options
from lichen.schc.headers import compress_packet, decompress_packet

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"

sys.path.insert(0, str(VECTORS_DIR))
from generate import (  # noqa: E402
    announce_coords_vectors,
    l2_payload_vectors,
    meshcore_app_compat_vectors,
    meshtastic_app_compat_vectors,
)

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
        "l2_payload.json",
        "link_frame.json",
        "announce_coords.json",
        "ccp16.json",
        "meshtastic_app_compat.json",
        "meshcore_app_compat.json",
        "rpl_messages.json",
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


def _l2_payload_cases():
    doc = _load("l2_payload.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


def _meshtastic_cases():
    doc = _load("meshtastic_app_compat.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


def _announce_coords_cases():
    doc = _load("announce_coords.json")
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


@pytest.mark.parametrize("name,vector", _l2_payload_cases())
def test_l2_payload_vector(name: str, vector: dict) -> None:
    wrapped = bytes.fromhex(vector["wrapped"])
    body = bytes.fromhex(vector["body"])
    assert wrapped[0] == vector["dispatch"], f"dispatch drift: {name}"
    assert l2_payload_body(wrapped) == body, f"body drift: {name}"

    expected = {
        "schc": L2PayloadKind.SCHC,
        "routing": L2PayloadKind.ROUTING,
        "unknown": L2PayloadKind.UNKNOWN,
    }[vector["kind"]]
    assert classify_l2_payload(wrapped) is expected, f"classify drift: {name}"


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
    if vector.get("expect", {}).get("error"):
        with pytest.raises(FrameError):
            LichenFrame.from_bytes(encoded)
        with pytest.raises(FrameError):
            frame.to_bytes()
        return
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


@pytest.mark.parametrize("name,vector", _announce_coords_cases())
def test_announce_coords_vector(name: str, vector: dict) -> None:
    encoded = bytes.fromhex(vector["encoded"])
    assert encode_coords(vector["latitude_degrees"], vector["longitude_degrees"]) == encoded

    decoded = decode_coords(encoded)
    assert decoded is not None, f"decode drift: {name}"
    assert abs(decoded[0] - vector["latitude_degrees"]) < 1e-7
    assert abs(decoded[1] - vector["longitude_degrees"]) < 1e-7

    assert int.from_bytes(encoded[1:5], "big", signed=True) == vector["latitude_e7"]
    assert int.from_bytes(encoded[5:9], "big", signed=True) == vector["longitude_e7"]


def test_all_schc_rules_covered() -> None:
    rule_ids = {v["rule_id"] for _, v in _schc_cases()}
    assert {0, 1, 2, 3, 4} <= rule_ids  # every whole-packet rule has a vector


def test_announce_coords_vectors_match_generator() -> None:
    doc = _load("announce_coords.json")
    assert doc["vectors"] == announce_coords_vectors()


def test_l2_payload_vectors_match_generator() -> None:
    doc = _load("l2_payload.json")
    assert doc["vectors"] == l2_payload_vectors()


def test_meshtastic_app_compat_vectors_match_generator() -> None:
    doc = _load("meshtastic_app_compat.json")
    assert doc["vectors"] == meshtastic_app_compat_vectors()


def test_meshcore_app_compat_vectors_match_generator() -> None:
    doc = _load("meshcore_app_compat.json")
    assert doc["vectors"] == meshcore_app_compat_vectors()


def _ccp15_cases():
    doc = _load("ccp16.json")
    assert doc["format_version"] == 2
    return [(v.get("name") or v.get("description", "unnamed"), v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp15_cases())
def test_ccp15_sf_ema_load_factor_hash32_logic(name: str, vector: dict) -> None:
    i = vector["input"]
    o = vector["output"]
    eui = bytes.fromhex(i["eui64"])
    h = 0x811c9dc5
    for b in eui + i["epoch"].to_bytes(4, "little"):
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    assert h == o["hash_32"]
    snr_ema = i.get("snr_ema", i["snr_db"])
    load_factor = i.get("load_factor", 0.0)
    if i["density"] > 8 or snr_ema < 0 or load_factor > 0.8:
        sf = 11
    elif i["density"] < 5 and snr_ema > 8.0:
        sf = 9
    elif i["density"] > 20 or snr_ema < -5.0:
        sf = 12
    else:
        sf = 10
    assert sf == o["sf"]
    ch = 0 if i["density"] > 8 else ((h % 3) + 1)
    assert ch == o["select_channel"]
    assert ch == o["channel"]
    assert i["now"] == o.get("now", i["now"])


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
        "POSITION_APP": 3,
        "ROUTING_APP": 5,
        "PRIVATE_APP": 256,
    }
    assert by_field[1] == (0, portnums[decoded["portnum"]])
    if "payload_utf8" in decoded:
        assert by_field[2] == (2, decoded["payload_utf8"].encode())
    if "position" in decoded:
        assert by_field[2][0] == 2
        _assert_position(by_field[2][1], decoded["position"])
    if "routing_error_reason" in decoded:
        routing = by_field[2][1]
        assert by_field[2][0] == 2
        assert decoded["routing_error_reason"] == "NO_ROUTE"
        assert _one_field(routing, 3, 0) == 1
    if "request_id" in decoded:
        assert by_field[6] == (5, decoded["request_id"])


def _signed32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000


def _assert_position(data: bytes, decoded: dict) -> None:
    fields = _read_fields(data)
    by_field = {field: (wire_type, value) for field, wire_type, value in fields}
    expected = {
        "latitude_i": (1, 5, lambda value: _signed32(value)),
        "longitude_i": (2, 5, lambda value: _signed32(value)),
        "altitude": (3, 0, int),
        "time": (4, 5, int),
        "location_source": (5, 0, int),
        "altitude_source": (6, 0, int),
        "timestamp": (7, 5, int),
        "gps_accuracy": (14, 0, int),
        "sats_in_view": (19, 0, int),
        "precision_bits": (23, 0, int),
    }

    for name, (field, wire_type, convert) in expected.items():
        if name not in decoded:
            continue
        assert field in by_field, name
        assert by_field[field][0] == wire_type, name
        assert convert(by_field[field][1]) == decoded[name]


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


def _rpl_messages_cases():
    doc = _load("rpl_messages.json")
    assert doc["format_version"] == 1
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _rpl_messages_cases())
def test_rpl_messages_vector(name: str, vector: dict) -> None:
    """Validate RPL message encode/decode against cross-implementation vectors."""
    from ipaddress import IPv6Address

    encoded = bytes.fromhex(vector["encoded"])
    msg_type = vector["type"]

    if msg_type == "dio":
        fields = vector["fields"]
        # Decode
        dio = DIO.from_bytes(encoded)
        assert dio.rpl_instance_id == fields["rpl_instance_id"], f"{name}: rpl_instance_id"
        assert dio.version == fields["version"], f"{name}: version"
        assert dio.rank == fields["rank"], f"{name}: rank"
        assert dio.grounded == fields["grounded"], f"{name}: grounded"
        assert dio.mode_of_operation == fields["mode_of_operation"], f"{name}: mop"
        assert dio.preference == fields["preference"], f"{name}: preference"
        assert dio.dtsn == fields["dtsn"], f"{name}: dtsn"
        assert str(dio.dodag_id) == fields["dodag_id"], f"{name}: dodag_id"
        # Encode round-trip
        rebuilt = DIO(
            rpl_instance_id=fields["rpl_instance_id"],
            version=fields["version"],
            rank=fields["rank"],
            grounded=fields["grounded"],
            mode_of_operation=fields["mode_of_operation"],
            preference=fields["preference"],
            dtsn=fields["dtsn"],
            flags=fields["flags"],
            dodag_id=fields["dodag_id"],
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"

    elif msg_type == "dao":
        fields = vector["fields"]
        dao = DAO.from_bytes(encoded)
        assert dao.rpl_instance_id == fields["rpl_instance_id"], f"{name}: rpl_instance_id"
        assert dao.ack_requested == fields["ack_requested"], f"{name}: ack_requested"
        assert dao.dao_sequence == fields["dao_sequence"], f"{name}: dao_sequence"
        dodag_str = str(dao.dodag_id) if dao.dodag_id else None
        assert dodag_str == fields["dodag_id"], f"{name}: dodag_id"
        rebuilt = DAO(
            rpl_instance_id=fields["rpl_instance_id"],
            ack_requested=fields["ack_requested"],
            flags=fields["flags"],
            dao_sequence=fields["dao_sequence"],
            dodag_id=fields["dodag_id"],
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"

    elif msg_type == "dao_ack":
        fields = vector["fields"]
        ack = DAOAck.from_bytes(encoded)
        assert ack.rpl_instance_id == fields["rpl_instance_id"], f"{name}: rpl_instance_id"
        assert ack.dao_sequence == fields["dao_sequence"], f"{name}: dao_sequence"
        assert ack.status == fields["status"], f"{name}: status"
        dodag_str = str(ack.dodag_id) if ack.dodag_id else None
        assert dodag_str == fields["dodag_id"], f"{name}: dodag_id"
        rebuilt = DAOAck(
            rpl_instance_id=fields["rpl_instance_id"],
            flags=fields["flags"],
            dao_sequence=fields["dao_sequence"],
            status=fields["status"],
            dodag_id=fields["dodag_id"],
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"

    elif msg_type == "dis":
        fields = vector["fields"]
        dis = DIS.from_bytes(encoded)
        assert dis.flags == fields["flags"], f"{name}: flags"
        assert dis.reserved == fields["reserved"], f"{name}: reserved"
        rebuilt = DIS(flags=fields["flags"], reserved=fields["reserved"])
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"

    elif msg_type == "option":
        opt_type = vector["option_type"]
        fields = vector["fields"]
        if opt_type == 5:  # RPL Target
            from lichen.rpl.messages import RplOption
            opt = RplOption(5, encoded[2 : 2 + encoded[1]])
            target = RplTarget.from_option(opt)
            assert target.prefix_length == fields["prefix_length"], f"{name}: prefix_length"
            assert target.target == IPv6Address(fields["prefix"]), f"{name}: prefix"
        elif opt_type == 6:  # Transit Information
            from lichen.rpl.messages import RplOption
            opt = RplOption(6, encoded[2 : 2 + encoded[1]])
            ti = TransitInformation.from_option(opt)
            assert ti.path_control == fields["path_control"], f"{name}: path_control"
            assert ti.path_sequence == fields["path_sequence"], f"{name}: path_sequence"
            assert ti.path_lifetime == fields["path_lifetime"], f"{name}: path_lifetime"
            expected_parent = (
                IPv6Address(fields["parent_address"])
                if fields["parent_address"] is not None
                else None
            )
            assert ti.parent_address == expected_parent, f"{name}: parent"
            assert ti.to_option().to_bytes() == encoded, f"{name}: encode"

    elif msg_type == "dio_with_options":
        fields = vector["fields"]
        dio = DIO.from_bytes(encoded)
        assert dio.rpl_instance_id == fields["rpl_instance_id"], f"{name}: rpl_instance_id"
        assert len(dio.options) == len(fields["options"]), f"{name}: options count"
        for i, opt in enumerate(dio.options):
            assert opt.type == fields["options"][i]["type"], f"{name}: option {i} type"

    elif msg_type == "dao_with_options":
        fields = vector["fields"]
        dao = DAO.from_bytes(encoded)
        assert dao.rpl_instance_id == fields["rpl_instance_id"], f"{name}: rpl_instance_id"
        assert dao.dao_sequence == fields["dao_sequence"], f"{name}: dao_sequence"
        assert len(dao.options) == len(fields["options"]), f"{name}: options count"
        for i, opt in enumerate(dao.options):
            assert opt.type == fields["options"][i]["type"], f"{name}: option {i} type"

    elif msg_type == "option_chain":
        options = _parse_options(encoded)
        expected = vector["options"]
        assert len(options) == len(expected), f"{name}: options count"
        for i, opt in enumerate(options):
            assert opt.type == expected[i]["type"], f"{name}: option {i} type"
