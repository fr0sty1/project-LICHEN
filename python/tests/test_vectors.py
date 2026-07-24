# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Validate the Python implementation against the committed cross-language vectors.

These guard against drift between the reference implementation and the JSON
vectors that the Rust/C implementations validate against (test/vectors/, issue
ajr / gate ijj). If a vector changes intentionally, regenerate with
``PYTHONPATH=python/src python3 test/vectors/generate.py``.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zlib
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from lichen.announce.coords import decode_coords, encode_coords
from lichen.crypto.identity import Identity
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.schnorr48 import verify as schnorr_verify
from lichen.ipv6.icmpv6 import Icmpv6Error, Icmpv6Message, handle_icmpv6
from lichen.ipv6.packet import IPv6Packet, NextHeader, PacketError
from lichen.ipv6.udp import UdpDatagram, UdpError
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength
from lichen.rpl.dao import RplTarget, TransitInformation
from lichen.rpl.messages import DAO, DIO, DIS, DAOAck, _parse_options
from lichen.ipv6.packet import IPv6Header, IPv6Packet, PacketError
from lichen.ipv6.icmpv6 import Icmpv6Error, Icmpv6Message, handle_icmpv6
from lichen.ipv6.udp import UdpDatagram, UdpError
from lichen.schc.fragment import (
    MAX_PACKET_SIZE,
    Ack,
    Fragment,
    FragmentError,
    FragmentSender,
    ack_request,
    receiver_abort,
    sender_abort,
)
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.reassembly import FragmentReceiver
from lichen.sim.propagation import PropagationModel, link_budget


def _db_to_linear(dbm: float) -> float:
    return 10.0 ** (dbm / 10.0)


def _linear_to_db(linear: float) -> float:
    if linear <= 1e-15:
        return -float("inf")
    import math
    return 10.0 * math.log10(linear)

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"

sys.path.insert(0, str(VECTORS_DIR))
from generate import (  # noqa: E402
    _hop_hash,
    announce_coords_vectors,
    ccp9_vectors,
    edhoc_vectors,
    frame_vectors,
    hash_32,
    l2_payload_vectors,
    meshcore_app_compat_vectors,
    meshtastic_app_compat_vectors,
)
from generate_rpl_route_state import build_document as build_route_state_document  # noqa: E402

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
        "ccp9.json",
        "l2_payload.json",
        "ipv6_malformed.json",
        "propagation.json",
    ],
)
def test_vector_file_schema(filename: str) -> None:
    schema = _load("schema.json")
    doc = _load(filename)
    errors = sorted(Draft7Validator(schema).iter_errors(doc), key=lambda e: e.path)
    assert not errors, [error.message for error in errors]


def _schc_cases():
    doc = _load("schc_compression.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"] if v.get("category") != "malformed"]



def _fragmentation_cases():
    doc = _load("schc_fragmentation.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _expand_vector_bytes(value: str | dict) -> bytes:
    if isinstance(value, str):
        return bytes.fromhex(value)
    output = bytearray()
    for part in value["parts"]:
        if isinstance(part, str):
            output.extend(bytes.fromhex(part))
        else:
            output.extend(bytes.fromhex(part["repeat_byte"]) * part["count"])
    return bytes(output)


def _frame_cases():
    doc = _load("link_frame.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _l2_payload_cases():
    doc = _load("l2_payload.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _meshtastic_cases():
    doc = _load("meshtastic_app_compat.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _announce_coords_cases():
    doc = _load("announce_coords.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _meshcore_cases():
    doc = _load("meshcore_app_compat.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _ipv6_malformed_cases():
    doc = _load("ipv6_malformed.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc.get("vectors", doc)]


@pytest.mark.parametrize("name,vector", _ipv6_malformed_cases())
def test_ipv6_malformed_vector(name: str, vector: dict) -> None:
    wire = bytes.fromhex(vector["wire"])
    e = vector["expect_error"]
    if e == "packet_version":
        with pytest.raises(PacketError):
            IPv6Header.from_bytes(wire)
    elif e == "icmpv6_too_short":
        with pytest.raises((PacketError, Icmpv6Error)):
            IPv6Packet.from_bytes(wire)
    elif e == "invalid_checksum":
        p = IPv6Packet.from_bytes(wire)
        assert handle_icmpv6(p) is None
    elif e == "bad_type":
        p = IPv6Packet.from_bytes(wire)
        assert handle_icmpv6(p) is None
    elif e == "bad_udp_length":
        with pytest.raises(UdpError):
            UdpDatagram.from_bytes(wire[40:])
    elif e == "invalid_source":
        p = IPv6Packet.from_bytes(wire)
        assert handle_icmpv6(p) is None


@pytest.mark.parametrize("name,vector", _schc_cases())
def test_schc_vector(name: str, vector: dict) -> None:
    packet = bytes.fromhex(vector["packet"])
    compressed = bytes.fromhex(vector["compressed"])
    assert compress_packet(packet) == compressed, f"compress drift: {name}"
    assert decompress_packet(compressed) == packet, f"decompress drift: {name}"
    assert compressed[0] == vector["rule_id"]


def test_schc_fragmentation_vector_coverage() -> None:
    cases = _fragmentation_cases()
    assert len({name for name, _ in cases}) == len(cases)
    assert {vector["category"] for _, vector in cases} == {
        "recovery",
        "retry_exhaustion",
        "window_transition",
        "controls",
        "capacity",
        "malformed",
    }


@pytest.mark.parametrize("name,vector", _fragmentation_cases())
def test_schc_fragmentation_vector_integrity(name: str, vector: dict) -> None:
    category = vector["category"]
    if "packet" in vector:
        packet = _expand_vector_bytes(vector["packet"])
        assert len(packet) == vector["packet_length"], name
        assert hashlib.sha256(packet).hexdigest() == vector["packet_sha256"], name
        if "rcs" in vector:
            assert (zlib.crc32(packet + b"\x00") & 0xFFFF_FFFF).to_bytes(4, "big").hex() == vector[
                "rcs"
            ], name

    if category in ("recovery", "window_transition"):
        fragment_names = {fragment["name"] for fragment in vector["fragments"]}
        assert vector["loss"]["drop_fragment"] in fragment_names
        assert vector.get("fragment_count", len(vector["fragments"])) >= len(vector["fragments"])
        if category == "window_transition":
            assert len(vector["fragments"]) == vector["fragment_count"]
            assert [fragment["tile_ordinal"] for fragment in vector["fragments"]] == list(
                range(vector["fragment_count"])
            )
        if "retransmission" in vector["loss"]:
            dropped = next(
                fragment
                for fragment in vector["fragments"]
                if fragment["name"] == vector["loss"]["drop_fragment"]
            )
            assert _expand_vector_bytes(vector["loss"]["retransmission"]) == _expand_vector_bytes(
                dropped["wire"]
            )
        for fragment in vector["fragments"]:
            wire = _expand_vector_bytes(fragment["wire"])
            assert wire[0] == vector["rule_id"], fragment["name"]
            assert wire[1] >> 7 == fragment["window"], fragment["name"]
            assert (wire[1] >> 1) & 0x3F == fragment["fcn"], fragment["name"]
            assert wire[-1] & 1 == 0, fragment["name"]
            if fragment["kind"] in ("regular", "all0"):
                assert len(wire) == 189, fragment["name"]
            else:
                assert 7 <= len(wire) <= 193, fragment["name"]

        ack_failure = _expand_vector_bytes(vector["loss"]["ack_failure"])
        ack_success = _expand_vector_bytes(vector["loss"]["ack_success"])
        assert (ack_failure[1] >> 6) & 1 == 0
        assert (ack_success[1] >> 6) & 1 == 1

    if category == "controls":
        control_sets = (
            (0x78, vector["controls"]["rule_78"]),
            (0x79, vector["controls"]["rule_79"]),
        )
        for rule, controls in control_sets:
            for wire_hex in controls.values():
                assert bytes.fromhex(wire_hex)[0] == rule
            assert controls["sender_abort"] == f"{rule:02x}fe"
            assert controls["receiver_abort"] == f"{rule:02x}ffff"

    if category == "retry_exhaustion":
        assert vector["attempts_before"] == 4
        assert _expand_vector_bytes(vector["trigger"])[0] == vector["rule_id"]
        expected_message = _expand_vector_bytes(vector["expected_message"])
        assert expected_message[0] == vector["rule_id"]
        assert expected_message.hex() in ("78fe", "78ffff")
        assert vector["expect_status"] == "aborted"

    if category == "malformed":
        assert _expand_vector_bytes(vector["wire"])
        assert vector["expect_error"]


@pytest.mark.parametrize("name,vector", _fragmentation_cases())
def test_schc_fragmentation_production_conformance(name: str, vector: dict) -> None:
    category = vector["category"]
    if category in ("recovery", "window_transition"):
        packet = _expand_vector_bytes(vector["packet"])
        sender = FragmentSender(packet, vector["rule_id"], MAX_PACKET_SIZE)
        fragments = sender.all_fragments()
        for expected in vector["fragments"]:
            ordinal = expected["tile_ordinal"]
            wire = _expand_vector_bytes(expected["wire"])
            assert fragments[ordinal].to_bytes() == wire, f"{name}: {expected['name']}"
            assert Fragment.from_bytes(wire) == fragments[ordinal]
        sender.start()
        failure = _expand_vector_bytes(vector["loss"]["ack_failure"])
        expected_messages = [
            _expand_vector_bytes(vector["loss"]["retransmission"]),
            _expand_vector_bytes(vector["loss"]["ack_req"]),
        ]
        assert sender.handle_ack_bytes(failure) == expected_messages
        receiver = FragmentReceiver(max_size=len(packet))
        if category == "recovery":
            result = None
            for expected in vector["fragments"]:
                result = receiver.receive_bytes(_expand_vector_bytes(expected["wire"]))
            assert result is not None
            assert result.response == _expand_vector_bytes(vector["loss"]["ack_success"])
            assert result.reassembled == packet

            receiver = FragmentReceiver(max_size=len(packet))
            for expected in vector["fragments"]:
                if expected["name"] != vector["loss"]["drop_fragment"]:
                    result = receiver.receive_bytes(_expand_vector_bytes(expected["wire"]))
            assert result is not None
            assert result.response == failure
            assert receiver.receive_bytes(expected_messages[0]).response is None
            result = receiver.receive_bytes(_expand_vector_bytes(vector["loss"]["ack_req"]))
            assert result.response == _expand_vector_bytes(vector["loss"]["ack_success"])
            assert result.reassembled == packet
        else:
            result = None
            for expected in vector["fragments"]:
                if expected["name"] != vector["loss"]["drop_fragment"]:
                    result = receiver.receive_bytes(_expand_vector_bytes(expected["wire"]))
            assert result is not None
            assert result.response == failure
            assert receiver.receive_bytes(expected_messages[0]).response is None
            result = receiver.receive_bytes(_expand_vector_bytes(vector["loss"]["ack_req"]))
            assert result.response == _expand_vector_bytes(vector["loss"]["ack_success"])
            assert result.reassembled == packet
        return

    if category == "controls":
        control_sets = (
            (0x78, vector["controls"]["rule_78"]),
            (0x79, vector["controls"]["rule_79"]),
        )
        for rule, controls in control_sets:
            assert Ack(rule, 0, complete=True).to_bytes() == bytes.fromhex(
                controls["ack_success_w0"]
            )
            assert Ack(rule, 1, complete=True).to_bytes() == bytes.fromhex(
                controls["ack_success_w1"]
            )
            assert ack_request(rule, 0) == bytes.fromhex(controls["ack_req_w0"])
            assert ack_request(rule, 1) == bytes.fromhex(controls["ack_req_w1"])
            assert sender_abort(rule) == bytes.fromhex(controls["sender_abort"])
            assert receiver_abort(rule) == bytes.fromhex(controls["receiver_abort"])
        return

    if category == "retry_exhaustion":
        if name == "sender_retry_exhaustion":
            sender = FragmentSender(b"x", vector["rule_id"])
            sender.start()
            sender.attempts = vector["attempts_before"]
            assert sender.timeout() == _expand_vector_bytes(vector["expected_message"])
            assert sender.status == vector["expect_status"]
        else:
            receiver = FragmentReceiver()
            receiver.attempts = vector["attempts_before"]
            result = receiver.receive_bytes(_expand_vector_bytes(vector["trigger"]))
            assert result.response == _expand_vector_bytes(vector["expected_message"])
            assert result.aborted
        return

    if category == "capacity":
        packet = _expand_vector_bytes(vector["packet"])
        if vector["expect_status"] == "ok":
            limit = max(1281, len(packet))
            sender = FragmentSender(packet, receiver_limit=limit)
            assert sender.fragment_count == vector["fragment_count"]
            fragments = []
            tiles = [packet[i : i + 187] for i in range(0, len(packet), 187)]
            for ordinal, tile in enumerate(tiles):
                final = ordinal == len(tiles) - 1
                fragments.append(
                    Fragment(
                        0x78,
                        ordinal // 63,
                        63 if final else 62 - ordinal % 63,
                        tile,
                        bytes.fromhex(vector["rcs"]) if final else b"",
                    )
                )
            receiver = FragmentReceiver() if len(packet) <= 1281 else FragmentReceiver(len(packet))
            result = None
            for fragment in fragments:
                result = receiver.receive(fragment)
            assert result is not None
            expected_ack = bytes.fromhex("7840" if vector["fragment_count"] <= 63 else "78c0")
            assert result.response == expected_ack
            assert result.reassembled == packet
        else:
            with pytest.raises(FragmentError):
                FragmentSender(packet, receiver_limit=MAX_PACKET_SIZE)
        return

    wire = _expand_vector_bytes(vector["wire"])
    result = FragmentReceiver().receive_bytes(wire)
    assert result.response == bytes.fromhex("78ffff")
    assert result.aborted
    if name == "unassigned_bitmap_bit":
        with pytest.raises(FragmentError):
            Ack.from_bytes(wire, assigned_fcns=vector["assigned_fcns"])
    elif name.startswith("ack_success") or name == "malformed_control":
        with pytest.raises(FragmentError):
            Ack.from_bytes(wire)
    else:
        with pytest.raises(FragmentError):
            Fragment.from_bytes(wire)


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


def test_frame_vectors_match_generator() -> None:
    doc = _load("link_frame.json")
    assert doc["vectors"] == frame_vectors()


def test_meshtastic_app_compat_vectors_match_generator() -> None:
    doc = _load("meshtastic_app_compat.json")
    assert doc["vectors"] == meshtastic_app_compat_vectors()


def test_meshcore_app_compat_vectors_match_generator() -> None:
    doc = _load("meshcore_app_compat.json")
    assert doc["vectors"] == meshcore_app_compat_vectors()


def test_edhoc_vectors_match_generator() -> None:
    doc = _load("edhoc.json")
    assert doc["vectors"] == edhoc_vectors()


def test_ccp9_vectors_match_generator() -> None:
    doc = _load("ccp9.json")
    assert doc["vectors"] == ccp9_vectors()


def test_ccp_tdma_vectors_independent_oracle() -> None:
    doc = _load("ccp_tdma.json")
    for v in doc["vectors"]:
        if "eui64_hex" in v:
            eui = bytes.fromhex(v["eui64_hex"])
            n_slots = v.get("n_slots", 8)
            epoch = v.get("epoch", 0)
            data = eui + epoch.to_bytes(4, "little")
            h = hash_32(data)
            computed = h % n_slots
            assert computed == v["expected_slot"], f"{v['name']}: slot {computed} != {v['expected_slot']}"
        elif "local_beacon_rx_ms" in v:
            correction_ms = abs(v["local_beacon_rx_ms"] - v["expected_beacon_ms"])
            assert correction_ms == v["expected_correction_ms"], f"{v['name']}: correction {correction_ms} != {v['expected_correction_ms']}"
        elif "slot_start_ms" in v:
                t = v["current_ms"]
                start = v["slot_start_ms"]
                dur = v.get("slot_duration_ms", 250)
                g = v.get("guard_ms", 50)
                in_guard = t < start or t > (start + dur)
                expected_in_guard = v.get("expected_in_guard", False)
                assert in_guard == expected_in_guard, f"{v['name']}: guard mismatch (in_guard={in_guard} != expected={expected_in_guard})"
        else:
            raise AssertionError(f"Unknown vector type: {v.get('name', '?')}")


def _ccp16_cases():
    doc = _load("ccp16.json")
    assert doc["format_version"] == 2
    return [(v["description"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("desc,vector", _ccp16_cases())
def test_ccp16_sf_ema_load_factor_hash32_logic(desc: str, vector: dict) -> None:
    i = vector.get("input", vector)
    o = vector.get("output", vector)
    eui_hex = i.get("eui64") or i.get("eui64_hex", "")
    if isinstance(eui_hex, (int, float)):
        eui = int(eui_hex).to_bytes(8, "big")
    else:
        eui = bytes.fromhex(str(eui_hex).replace("0x", ""))
    epoch = i.get("epoch", 0)
    h = _hop_hash(eui, epoch)
    assert h == o.get("hash_32", o.get("expected_hash", h))
    snr_ema = i.get("snr_ema", i.get("snr_db", 5.0))
    load_factor = i.get("load_factor", 0.0)
    if i["density"] > 20 or snr_ema < -5.0:
        sf = 12
    elif i["density"] > 8 or snr_ema < 0 or load_factor > 0.8:
        sf = 11
    elif i["density"] < 5 and snr_ema > 8.0:
        sf = 9
    else:
        sf = 10
    assert sf == o.get("sf", 10)
    n = i.get("n_channels", 3)
    ch = 0 if i["density"] > 8 else (1 + (h % n))
    assert ch == o.get("select_channel", o.get("expected_channel", o.get("channel", ch)))
    assert ch == o.get("channel", ch)
    now = i.get("now", 0)
    assert now == o.get("now", now)


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
            value = data[offset : offset + length]
            offset += length
        elif wire_type == 5:
            value = int.from_bytes(data[offset : offset + 4], "little")
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
        name: {
            "section": name,
            "oneof_field": oneof,
            "fields": [
                {"field": field, "wire_type": "varint", "value": value}
                for field, value in expected_fields
            ],
        }
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
        _assert_config_section(
            bytes.fromhex(section["payload"]), {"config": section}, {"config_section": section}
        )


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
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _dao_origin_signature_cases():
    doc = _load("dao_origin_signature.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _dao_base_context(wire: bytes, vector: dict) -> tuple[str | None, str | None]:
    if len(wire) < 4:
        return "malformed_dao", "structural"
    if wire[1] & 0x3F:
        return "unsupported_flags", "structural"
    if wire[2] != 0:
        return "nonzero_reserved", "structural"
    offset = 20 if wire[1] & 0x40 else 4
    if len(wire) < offset:
        return "malformed_dao", "structural"
    if wire[0] != vector["effective_instance_id"]:
        return "instance_mismatch", "context"
    if wire[1] & 0x40 and wire[4:20] != bytes.fromhex(vector["active_dodag_id"]):
        return "dodag_mismatch", "context"
    return None, None


def _dao_structure(wire: bytes) -> tuple[str | None, list[tuple[int, bytes]], int | None]:
    offset = 20 if wire[1] & 0x40 else 4
    options = []
    origin_offset = None
    while offset < len(wire):
        start = offset
        if wire[offset] == 0:
            if origin_offset is not None:
                return "nonterminal_option", options, origin_offset
            options.append((0, b""))
            offset += 1
            continue
        if offset + 2 > len(wire):
            return "truncated", options, origin_offset
        option_type = wire[offset]
        length = wire[offset + 1]
        end = offset + 2 + length
        if end > len(wire):
            return "truncated", options, origin_offset
        data = wire[offset + 2:end]
        if option_type == 0x12:
            if length != 56:
                return "bad_option_length", options, origin_offset
            if origin_offset is not None:
                return "duplicate_option", options, origin_offset
            if int.from_bytes(data[:8], "big") == 0:
                return "zero_sequence", options, start
            origin_offset = start
        elif option_type not in {1, 5, 6}:
            return "unknown_option", options, origin_offset
        elif option_type == 5 and length != 18 or option_type == 6 and length != 20:
            return "bad_option_length", options, origin_offset
        if origin_offset is not None and option_type != 0x12:
            return "nonterminal_option", options, origin_offset
        options.append((option_type, data))
        offset = end
    if origin_offset is None:
        return "missing_signature", options, None
    return None, options, origin_offset


def _dao_semantics(options: list[tuple[int, bytes]], source: bytes) -> str | None:
    targets = [(data[1], data[2:]) for option_type, data in options if option_type == 5]
    transits = [data for option_type, data in options if option_type == 6]
    if not targets:
        return "missing_target"
    if not transits:
        return "missing_transit"
    if len(targets) > 1:
        return "duplicate_target" if len(set(targets)) == 1 else "multiple_target"
    if targets[0][0] != 128:
        return "non128_target"
    if targets[0][1] != source:
        return "target_mismatch"
    if any(data[0] != 0 for data in transits):
        return "unsupported_transit_e"
    if len({(data[2], data[3]) for data in transits}) != 1:
        return "inconsistent_transit"
    return None


def _assert_dao_relations(vector: dict) -> None:
    source = bytes.fromhex(vector["source_ipv6"])
    dodag = bytes.fromhex(vector["effective_dodag_id"])
    unsigned = bytes.fromhex(vector["unsigned_dao"])
    option = bytes.fromhex(vector["signature_option"])
    sequence = vector["sequence"]
    digest = hashlib.sha512(
        b"LICHEN-DAO-ORIGIN-v1" + source + dodag + sequence.to_bytes(8, "big") + unsigned
    ).digest()
    assert digest.hex() == vector["digest"]
    assert len(option) == 58 and option[0] == 0x12
    assert int.from_bytes(option[2:10], "big") == sequence
    coverage = vector["coverage"]
    signed = bytes.fromhex(vector["signed_dao"])
    offset = vector["option_offset"]
    if coverage in {"duplicate_option", "replay_structural"}:
        assert signed == unsigned + option + option
    elif coverage == "nonterminal_option":
        assert signed == unsigned[:offset] + option + unsigned[offset:]
    elif coverage in {"missing_signature", "malformed_base", "truncated_dodag"}:
        assert signed == unsigned
    elif coverage == "truncated_option":
        assert signed == unsigned + option[:-1]
    else:
        assert offset == len(unsigned)
        assert signed == unsigned + option


@pytest.mark.parametrize("name,vector", _dao_origin_signature_cases())
def test_dao_origin_signature_vector(name: str, vector: dict) -> None:
    """Secondary oracle: no production Python DAO-origin codec currently exists."""
    _assert_dao_relations(vector)
    source = bytes.fromhex(vector["source_ipv6"])
    dodag = bytes.fromhex(vector["effective_dodag_id"])
    unsigned = bytes.fromhex(vector["unsigned_dao"])
    option = bytes.fromhex(vector["signature_option"])
    signed = bytes.fromhex(vector["signed_dao"])
    public_key = bytes.fromhex(vector["public_key"])
    sequence = vector["sequence"]
    expected_digest = hashlib.sha512(
        b"LICHEN-DAO-ORIGIN-v1" + source + dodag + sequence.to_bytes(8, "big") + unsigned
    ).digest()
    signature_valid = schnorr_verify(public_key, expected_digest, option[10:])
    assert signature_valid is vector["expected"]["signature_valid"]
    if signature_valid:
        identity = Identity.from_seed(bytes.fromhex(vector["signing_seed"]))
        assert identity.pubkey == public_key
        assert schnorr_sign(identity.privkey, identity.pubkey, expected_digest) == option[10:]

    iid = bytearray(hashlib.sha256(public_key).digest()[:8])
    iid[0] &= 0xFD
    iid_matches = source[8:] == bytes(iid)
    base_reason, base_stage = _dao_base_context(signed, vector)
    structural_reason, options, _ = (None, [], None)
    base_length = 20 if len(signed) >= 2 and signed[1] & 0x40 else 4
    if len(signed) >= base_length:
        structural_reason, options, _ = _dao_structure(signed)
    structurally_valid = base_stage != "structural" and structural_reason is None
    assert structurally_valid is vector["expected"]["envelope_valid"]
    prior = vector["prior"]
    if prior is not None:
        prior_source = bytes.fromhex(prior["source_ipv6"])
        prior_signed = bytes.fromhex(prior["signed_dao"])
        prior_option = prior_signed[-58:]
        prior_unsigned = prior_signed[:-58]
        prior_sequence = prior["sequence"]
        prior_dodag = prior_unsigned[4:20] if prior_unsigned[1] & 0x40 else dodag
        prior_digest = hashlib.sha512(
            b"LICHEN-DAO-ORIGIN-v1"
            + prior_source
            + prior_dodag
            + prior_sequence.to_bytes(8, "big")
            + prior_unsigned
        ).digest()
        assert prior_option[:2] == b"\x12\x38"
        assert int.from_bytes(prior_option[2:10], "big") == prior_sequence
        assert schnorr_verify(public_key, prior_digest, prior_option[10:])
        prior_iid = prior_source[8:]
        assert prior_iid == source[8:] == bytes(iid)
    if base_reason is not None:
        reason, stage = base_reason, base_stage
    elif structural_reason is not None:
        reason, stage = structural_reason, "structural"
    elif not vector["key_available"]:
        reason, stage = "unknown_key", "identity"
    elif not iid_matches:
        reason, stage = "iid_mismatch", "identity"
    elif not signature_valid:
        reason, stage = "invalid_signature", "identity"
    elif prior is not None and sequence < prior["sequence"]:
        reason, stage = "replay", "replay"
    elif prior is not None and sequence == prior["sequence"]:
        if signed != bytes.fromhex(prior["signed_dao"]):
            reason, stage = "sequence_conflict", "replay"
        elif prior["route_present"]:
            reason, stage = "idempotent", "replay"
        else:
            semantic_reason = _dao_semantics(options, source)
            assert semantic_reason is None
            reason, stage = "reconciled", "semantic"
    else:
        semantic_reason = _dao_semantics(options, source)
        if semantic_reason is not None:
            reason, stage = semantic_reason, "semantic"
        else:
            reason, stage = "accepted", "applied"
    assert vector["expected"]["reason"] == reason
    assert vector["expected"]["decision_stage"] == stage
    assert vector["expected"]["accepted"] is (reason in {"accepted", "idempotent", "reconciled"})
    assert vector["expected"]["route_changed"] is (reason in {"accepted", "reconciled"})
    assert vector["expected"]["replay_persisted"] is (reason == "accepted")


def test_dao_origin_signature_coverage_and_dodag_rules() -> None:
    vectors = [vector for _, vector in _dao_origin_signature_cases()]
    coverage = {vector["coverage"] for vector in vectors}
    assert len(vectors) == len(coverage) == 50
    assert {
        "d1", "d0_effective_dodag", "identical_retransmission", "reconcile_after_crash",
        "replay_target_mismatch", "replay_malformed_semantics", "replay_structural",
        "missing_signature", "zero_sequence", "bad_option_length", "truncated_option",
        "malformed_base", "truncated_dodag", "unsupported_flags", "nonzero_reserved",
        "d1_active_dodag_mismatch", "missing_target", "missing_transit", "duplicate_target",
        "inconsistent_transit_sequence", "inconsistent_transit_lifetime",
        "unsupported_transit_e", "cross_prefix_equal", "cross_prefix_lower",
        "fresh_cross_prefix_target", "multiple_distinct_targets", "replay_non128_target",
        "context_malformed_option",
    } <= coverage
    for vector in vectors:
        unsigned = bytes.fromhex(vector["unsigned_dao"])
        if len(unsigned) >= 20 and unsigned[1] & 0x40:
            assert unsigned[4:20].hex() == vector["effective_dodag_id"]
        if vector["expected"]["reason"] == "accepted":
            assert _dao_semantics(
                _dao_structure(bytes.fromhex(vector["signed_dao"]))[1],
                bytes.fromhex(vector["source_ipv6"]),
            ) is None


def test_dao_origin_signature_schema_is_closed_and_relational() -> None:
    schema = _load("schema.json")
    original = _load("dao_origin_signature.json")
    validator = Draft7Validator(schema)

    def rejected(mutator) -> None:
        document = json.loads(json.dumps(original))
        mutator(document)
        assert list(validator.iter_errors(document))

    rejected(lambda document: document.update(unexpected=True))
    rejected(lambda document: document.pop("oracle_provenance"))
    rejected(lambda document: document.pop("vector_type"))
    rejected(lambda document: document.update(vector_type="other"))
    rejected(lambda document: document["vectors"][0].update(unexpected=True))

    changed_description = json.loads(json.dumps(original))
    changed_description["description"] = "Not used as a schema discriminator."
    assert not list(validator.iter_errors(changed_description))


def test_dao_origin_signature_relational_corruptions_fail() -> None:
    vector = _load("dao_origin_signature.json")["vectors"][0]
    for mutate in (
        lambda item: item.update(sequence=item["sequence"] + 1),
        lambda item: item.update(digest="00" * 64),
        lambda item: item.update(signature_option=item["signature_option"][:4] + "00" * 56),
        lambda item: item.update(signed_dao=item["signed_dao"][:-2]),
        lambda item: item.update(option_offset=item["option_offset"] - 1),
    ):
        corrupted = json.loads(json.dumps(vector))
        mutate(corrupted)
        with pytest.raises(AssertionError):
            _assert_dao_relations(corrupted)


def test_rpl_route_state_generation_is_deterministic() -> None:
    document = _load("rpl_route_state.json")
    assert document == build_route_state_document()


@pytest.mark.parametrize("name,vector", _rpl_messages_cases())
def test_rpl_messages_vector(name: str, vector: dict) -> None:
    """Validate RPL message encode/decode against cross-implementation vectors."""
    from ipaddress import IPv6Address

    if vector.get("type") == "malformed":
        wire = bytes.fromhex(vector["wire"])
        expect_error = vector["expect_error"]
        if expect_error == "checksum_failure":
            p = IPv6Packet.from_bytes(wire)
            s = p.header.src_addr
            d = p.header.dst_addr
            if p.header.next_header == NextHeader.ICMPV6:
                assert not Icmpv6Message.verify_checksum(s, d, p.payload)
                assert handle_icmpv6(p) is None
            else:
                assert not UdpDatagram.verify_checksum(s, d, p.payload)
        elif expect_error == "truncation":
            with pytest.raises((PacketError, Icmpv6Error, UdpError)):
                IPv6Packet.from_bytes(wire)
        return

    encoded = bytes.fromhex(vector["encoded"])
    msg_type = vector["type"]

    if msg_type == "dio":
        fields = vector["fields"]
        dio = DIO.from_bytes(encoded)
        assert dio.rpl_instance_id == fields["rpl_instance_id"], f"{name}: rpl_instance_id"
        assert dio.version == fields["version"], f"{name}: version"
        assert dio.rank == fields["rank"], f"{name}: rank"
        assert dio.grounded == fields["grounded"], f"{name}: grounded"
        assert dio.mode_of_operation == fields["mode_of_operation"], f"{name}: mop"
        assert dio.preference == fields["preference"], f"{name}: preference"
        assert dio.dtsn == fields["dtsn"], f"{name}: dtsn"
        assert str(dio.dodag_id) == fields["dodag_id"], f"{name}: dodag_id"
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


def _propagation_cases():
    doc = _load("propagation.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _propagation_cases())
def test_propagation_vector(name: str, vector: dict) -> None:
    if "expected_path_loss_db" in vector:
        model = PropagationModel(
            pl0_dbm=vector["pl0_dbm"],
            d0_m=vector["d0_m"],
            n=vector["n"],
        )
        pl = model.path_loss(vector["distance_m"])
        assert pl == pytest.approx(vector["expected_path_loss_db"], abs=vector.get("tolerance_db", 0.001))

    if "expected_rx_power_dbm" in vector and "tx_power_dbm" in vector and "expected_link_margin_db" not in vector:
        model = PropagationModel(
            pl0_dbm=vector["pl0_dbm"],
            d0_m=vector["d0_m"],
            n=vector["n"],
        )
        rx = model.received_power(vector["tx_power_dbm"], vector["distance_m"])
        assert rx == pytest.approx(vector["expected_rx_power_dbm"], abs=vector.get("tolerance_db", 0.001))

    if "expected_snr_db" in vector and "noise_floor_dbm" in vector and "expected_link_margin_db" not in vector:
        model = PropagationModel(
            pl0_dbm=vector["pl0_dbm"],
            d0_m=vector["d0_m"],
            n=vector["n"],
            noise_floor_dbm=vector["noise_floor_dbm"],
        )
        snr = model.snr(vector["tx_power_dbm"], vector["distance_m"])
        assert snr == pytest.approx(vector["expected_snr_db"], abs=vector.get("tolerance_db", 0.001))

    if "expected_max_range_m" in vector:
        model = PropagationModel(
            pl0_dbm=vector["pl0_dbm"],
            d0_m=vector["d0_m"],
            n=vector["n"],
        )
        r = model.max_range(
            vector["tx_power_dbm"],
            sensitivity_dbm=vector["sensitivity_dbm"],
        )
        assert r == pytest.approx(vector["expected_max_range_m"], rel=vector.get("tolerance_relative", 0.01))

    if "expected_link_margin_db" in vector:
        budget = link_budget(
            tx_power_dbm=vector["tx_power_dbm"],
            tx_antenna_gain_dbi=vector["tx_antenna_gain_dbi"],
            rx_antenna_gain_dbi=vector["rx_antenna_gain_dbi"],
            cable_loss_db=vector["cable_loss_db"],
            distance_m=vector["distance_m"],
            n=vector.get("n", 2.7),
            pl0_dbm=vector.get("pl0_dbm", 32.44),
            d0_m=vector.get("d0_m", 1.0),
        )
        assert budget["rx_power_dbm"] == pytest.approx(vector["expected_rx_power_dbm"], abs=vector.get("tolerance_db", 0.01))
        assert budget["link_margin_db"] == pytest.approx(vector["expected_link_margin_db"], abs=vector.get("tolerance_db", 0.01))
        assert budget["snr_db"] == pytest.approx(vector["expected_snr_db"], abs=vector.get("tolerance_db", 0.01))

    if "expected_sinr_db" in vector:
        model = PropagationModel(noise_floor_dbm=vector["noise_floor_dbm"])
        interferers = [_db_to_linear(vector["interferer_rssi_dbm"])]
        # Convert the desired signal RSSI back to a received_power equivalent
        sinr_val = model.sinr(0.0, 1.0, interferers)
        signal_linear = _db_to_linear(vector["signal_rssi_dbm"])
        noise_linear = _db_to_linear(vector["noise_floor_dbm"])
        total_noise = noise_linear + sum(interferers)
        expected_sinr = _linear_to_db(signal_linear / total_noise) if total_noise > 0 else float("inf")
        assert sinr_val == pytest.approx(expected_sinr, abs=vector.get("tolerance_db", 0.1))
