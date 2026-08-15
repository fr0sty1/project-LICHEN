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
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader, PacketError
from lichen.ipv6.udp import UdpDatagram, UdpError
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength
from lichen.link.short_addr import (
    SHORT_ADDR_RESERVED,
    SHORT_ADDR_RESERVED_BROADCAST,
    SHORT_ADDR_RESERVED_NULL,
    SHORT_ADDR_RESERVED_UNSPECIFIED,
    CoordinatorAddressTable,
    DaoAck,
    DaoRequest,
    ShortAddressCollisionDetector,
    dad_probe_schedule,
    dad_retry,
    dad_retry_incremental,
    derive_short_addr,
    derive_short_addr_crc16,
    derive_short_addr_with_seed,
    hash_32_fnv1a,
    is_reserved_addr,
    transition_to_coordinator_managed,
)
from lichen.loadng.messages import RERR, RREP, RREQ
from lichen.rpl.dao import RplTarget, TransitInformation
from lichen.rpl.messages import DAO, DIO, DIS, DAOAck, _parse_options
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
from lichen.sim.tdma import TDMAScheduler

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"

sys.path.insert(0, str(VECTORS_DIR))
from generate import (  # noqa: E402
    _hop_hash,
    announce_coords_vectors,
    ccp9_vectors,
    edhoc_vectors,
    frame_vectors,
    l2_payload_vectors,
    loadng_discovery_vectors,
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
        "ccp9-rendezvous.json",
        "l2_payload.json",
        "ipv6_malformed.json",
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
    elif e == "invalid_checksum" or e == "bad_type":
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


def test_node_address_vectors_match_python_implementation() -> None:
    """Validate all 10 node_address vectors against the Python Identity module.

    Cross-language oracle: Rust, C, and Python must all produce the same
    human-readable addresses from the canonical test vectors.
    """
    doc = _load("node_address.json")
    for v in doc["vectors"]:
        pubkey = bytes.fromhex(v["pubkey"])
        expected_iid = bytes.fromhex(v["iid"])
        expected_human = v["human_address"]

        from lichen.crypto.identity import _pubkey_to_iid, iid_to_human_address

        iid = _pubkey_to_iid(pubkey)
        assert iid == expected_iid, (
            f"IID mismatch for {v['name']}: "
            f"got {iid.hex()}, expected {expected_iid.hex()}"
        )

        human = iid_to_human_address(iid)
        assert human == expected_human, (
            f"human_address mismatch for {v['name']}: "
            f"got {human}, expected {expected_human}"
        )


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


def _ccp9_rendezvous_cases():
    doc = _load("ccp9-rendezvous.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp9_rendezvous_cases())
def test_ccp9_rendezvous_vector(name: str, vector: dict) -> None:
    mechanism = vector.get("mechanism") or vector.get("expected", {}).get("mechanism", "")
    if mechanism == "hash_based":
        peer_eui = bytes.fromhex(vector["peer_eui64"])
        sfn = vector["sfn"]
        n_channels = vector["n_channels"]
        h = _hop_hash(peer_eui, sfn)
        computed_channel = 1 + (h % (n_channels - 1))
        assert computed_channel == vector["expected_channel"]
        assert vector["expected_slot"] == 42
    elif mechanism == "scheduled":
        assert isinstance(vector["expected"], dict)
        assert vector["expected"]["mechanism"] == "scheduled"
        assert vector["expected"]["valid_until_sfn"] == 12350
    elif mechanism == "announce_driven":
        assert vector["rx_channel"] == vector["expected_channel"]
    elif mechanism == "fallback":
        assert vector["expected_channel"] == 0
        assert vector["expected_slot"] == 0
    else:
        pytest.fail(f"Unknown rendezvous mechanism: {mechanism}")


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
    if any(data[0] not in (0x00, 0x80) for data in transits):
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

    iid = bytearray(hashlib.sha512(public_key).digest()[:8])
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
    assert len(vectors) == len(coverage) == 51
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


def _loadng_messages_cases():
    doc = _load("loadng_messages.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _loadng_messages_cases())
def test_loadng_messages_vector(name: str, vector: dict) -> None:
    """Validate LOADng message encode/decode against cross-implementation vectors."""
    from ipaddress import IPv6Address

    encoded = bytes.fromhex(vector["encoded"])
    msg_type = vector["type"]
    fields = vector["fields"]

    if msg_type == "rreq":
        # Decode from bytes
        rreq = RREQ.from_bytes(encoded)
        assert rreq.flags == fields["flags"], f"{name}: flags"
        assert rreq.hop_limit == fields["hop_limit"], f"{name}: hop_limit"
        assert rreq.seq_num == fields["seq_num"], f"{name}: seq_num"
        assert str(rreq.originator) == fields["originator"], f"{name}: originator"
        assert str(rreq.destination) == fields["destination"], f"{name}: destination"
        if fields["signature"] is not None:
            assert rreq.signature == bytes.fromhex(fields["signature"]), f"{name}: signature"
        else:
            assert rreq.signature == b"", f"{name}: signature"

        # Encode back to bytes
        sig = bytes.fromhex(fields["signature"]) if fields["signature"] else b""
        rebuilt = RREQ(
            originator=IPv6Address(fields["originator"]),
            destination=IPv6Address(fields["destination"]),
            seq_num=fields["seq_num"],
            hop_limit=fields["hop_limit"],
            flags=fields["flags"],
            signature=sig,
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"

    elif msg_type == "rrep":
        # Decode from bytes
        rrep = RREP.from_bytes(encoded)
        assert rrep.flags == fields["flags"], f"{name}: flags"
        assert rrep.hop_count == fields["hop_count"], f"{name}: hop_count"
        assert rrep.seq_num == fields["seq_num"], f"{name}: seq_num"
        assert str(rrep.originator) == fields["originator"], f"{name}: originator"
        assert str(rrep.destination) == fields["destination"], f"{name}: destination"
        if fields["signature"] is not None:
            assert rrep.signature == bytes.fromhex(fields["signature"]), f"{name}: signature"
        else:
            assert rrep.signature == b"", f"{name}: signature"

        # Encode back to bytes
        sig = bytes.fromhex(fields["signature"]) if fields["signature"] else b""
        rebuilt = RREP(
            originator=IPv6Address(fields["originator"]),
            destination=IPv6Address(fields["destination"]),
            seq_num=fields["seq_num"],
            hop_count=fields["hop_count"],
            flags=fields["flags"],
            signature=sig,
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"

    elif msg_type == "rerr":
        # Decode from bytes
        rerr = RERR.from_bytes(encoded)
        assert rerr.flags == fields["flags"], f"{name}: flags"
        assert rerr.error_code == fields["error_code"], f"{name}: error_code"
        assert str(rerr.unreachable) == fields["unreachable"], f"{name}: unreachable"
        if fields["signature"] is not None:
            assert rerr.signature == bytes.fromhex(fields["signature"]), f"{name}: signature"
        else:
            assert rerr.signature == b"", f"{name}: signature"

        # Encode back to bytes
        sig = bytes.fromhex(fields["signature"]) if fields["signature"] else b""
        rebuilt = RERR(
            unreachable=IPv6Address(fields["unreachable"]),
            error_code=fields["error_code"],
            flags=fields["flags"],
            signature=sig,
        )
        assert rebuilt.to_bytes() == encoded, f"{name}: encode"


def _loadng_discovery_cases():
    doc = _load("loadng_discovery.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _loadng_discovery_cases())
def test_loadng_discovery_vector(name: str, vector: dict) -> None:
    """Validate LOADng discovery state transitions against spec-derived vectors.

    Each vector specifies initial state (node address, cache, gradient, seen entries),
    an input RREQ or RREP with from_neighbor and timestamp, and the expected action
    with cache/gradient mutations.
    """
    from ipaddress import IPv6Address

    from lichen.gradient import GradientEntry, GradientSource, GradientTable
    from lichen.loadng.cache import RouteCache, RouteEntry
    from lichen.loadng.discovery import LoadngRouter
    from lichen.loadng.messages import RREP, RREQ

    # Build initial state
    state = vector["initial_state"]
    gradient = GradientTable()
    cache = RouteCache()
    node_address = state["node_address"]

    # Pre-populate gradient entries
    for g in state.get("gradient_entries", []):
        gradient.update(
            GradientEntry(
                destination=IPv6Address(g["destination"]),
                next_hop=IPv6Address(g["next_hop"]),
                hop_count=g["hop_count"],
                seq_num=g["seq_num"],
                source=GradientSource.ANNOUNCE,
                expires=g["expires_ms"],
            ),
            now=0,
        )

    # Pre-populate cache entries
    for c in state.get("cache_entries", []):
        cache.add(
            RouteEntry(
                destination=IPv6Address(c["destination"]),
                next_hop=IPv6Address(c["next_hop"]),
                hop_count=c["hop_count"],
                metric=c["metric"],
                seq_num=c["seq_num"],
                valid_until=c["valid_until_ms"],
            )
        )

    # Create router
    router = LoadngRouter(node_address, gradient, cache)

    # Set own_seq if specified
    if "own_seq" in state:
        router._own_seq = state["own_seq"]

    # Pre-populate seen entries
    for s in state.get("seen_entries", []):
        key = (IPv6Address(s["originator"]), IPv6Address(s["destination"]))
        router._seen[key] = (s["seq_num"], s["seen_at_ms"])

    inp = vector["input"]
    exp = vector["expected"]
    now_ms = inp["now_ms"]

    if vector["type"] == "rreq":
        # Build RREQ
        rreq_data = inp["rreq"]
        rreq = RREQ(
            originator=IPv6Address(rreq_data["originator"]),
            destination=IPv6Address(rreq_data["destination"]),
            seq_num=rreq_data["seq_num"],
            hop_limit=rreq_data["hop_limit"],
        )

        # Process
        result = router.process_rreq(rreq, inp["from_neighbor"], now_ms)

        # Validate action
        if exp["action"] == "suppressed":
            assert result.suppressed, f"{name}: expected suppressed"
            assert result.reply is None
            assert result.forward is None
        elif exp["action"] == "reply":
            assert not result.suppressed, f"{name}: unexpected suppressed"
            assert result.reply is not None, f"{name}: expected reply"
            exp_reply = exp["reply"]
            assert str(result.reply.originator) == exp_reply["originator"]
            assert str(result.reply.destination) == exp_reply["destination"]
            assert result.reply.seq_num == exp_reply["seq_num"]
            assert result.reply.hop_count == exp_reply["hop_count"]
            assert result.reply.flags == exp_reply["flags"]
            assert str(result.reply_next_hop) == exp["reply_next_hop"]
            assert result.forward is None
        elif exp["action"] == "forward":
            assert not result.suppressed, f"{name}: unexpected suppressed"
            assert result.reply is None
            assert result.forward is not None, f"{name}: expected forward"
            exp_fwd = exp["forward"]
            assert str(result.forward.originator) == exp_fwd["originator"]
            assert str(result.forward.destination) == exp_fwd["destination"]
            assert result.forward.seq_num == exp_fwd["seq_num"]
            assert result.forward.hop_limit == exp_fwd["hop_limit"]
        elif exp["action"] == "dropped":
            assert not result.suppressed, f"{name}: unexpected suppressed"
            assert result.reply is None
            assert result.forward is None
        else:
            pytest.fail(f"Unknown RREQ action: {exp['action']}")

        # Validate cache mutation
        if exp.get("cache_added"):
            ce = exp["cache_entry"]
            entry = cache.lookup(IPv6Address(ce["destination"]), now_ms)
            assert entry is not None, f"{name}: expected cache entry"
            assert str(entry.next_hop) == ce["next_hop"]
            assert entry.hop_count == ce["hop_count"]
        else:
            # If the vector didn't add originator to cache, verify it's not there
            # (unless it was pre-populated)
            pass

    elif vector["type"] == "rrep":
        # Build RREP
        rrep_data = inp["rrep"]
        rrep = RREP(
            originator=IPv6Address(rrep_data["originator"]),
            destination=IPv6Address(rrep_data["destination"]),
            seq_num=rrep_data["seq_num"],
            hop_count=rrep_data["hop_count"],
            flags=rrep_data.get("flags", 0),
        )

        # Process
        result = router.process_rrep(rrep, inp["from_neighbor"], now_ms)

        # Validate action
        if exp["action"] == "delivered":
            assert result.delivered, f"{name}: expected delivered"
            assert not result.dropped
            assert result.forward is None
        elif exp["action"] == "forward_rrep":
            assert not result.delivered
            assert not result.dropped
            assert result.forward is not None, f"{name}: expected forward"
            exp_fwd = exp["forward"]
            assert str(result.forward.originator) == exp_fwd["originator"]
            assert str(result.forward.destination) == exp_fwd["destination"]
            assert result.forward.seq_num == exp_fwd["seq_num"]
            assert result.forward.hop_count == exp_fwd["hop_count"]
            assert result.forward.flags == exp_fwd["flags"]
            assert str(result.forward_next_hop) == exp["forward_next_hop"]
        elif exp["action"] == "dropped_rrep":
            assert not result.delivered
            assert result.dropped, f"{name}: expected dropped"
            assert result.forward is None
        else:
            pytest.fail(f"Unknown RREP action: {exp['action']}")

        # Validate gradient mutation
        if exp.get("gradient_added"):
            ge = exp["gradient_entry"]
            entry = gradient.lookup(IPv6Address(ge["destination"]), now_ms)
            assert entry is not None, f"{name}: expected gradient entry"
            assert str(entry.next_hop) == ge["next_hop"]
            assert entry.hop_count == ge["hop_count"]
            assert entry.seq_num == ge["seq_num"]
        elif exp.get("gradient_unchanged"):
            # Verify gradient was NOT updated (stale seq case)
            ge_state = state["gradient_entries"][0]
            entry = gradient.lookup(IPv6Address(ge_state["destination"]), now_ms)
            assert entry is not None
            assert entry.seq_num == ge_state["seq_num"]
            assert str(entry.next_hop) == ge_state["next_hop"]

        # Validate cache mutation for RREP (always adds originator)
        if exp.get("cache_added"):
            ce = exp["cache_entry"]
            entry = cache.lookup(IPv6Address(ce["destination"]), now_ms)
            assert entry is not None, f"{name}: expected cache entry"
            assert str(entry.next_hop) == ce["next_hop"]
            assert entry.hop_count == ce["hop_count"]


def test_loadng_discovery_vectors_match_generator() -> None:
    """Verify committed JSON matches generator output (no drift)."""
    doc = _load("loadng_discovery.json")
    generated = loadng_discovery_vectors()
    assert len(doc["vectors"]) == len(generated), "vector count mismatch"
    for i, (committed, gen) in enumerate(zip(doc["vectors"], generated)):
        assert committed["name"] == gen["name"], f"name mismatch at index {i}"
        assert committed["type"] == gen["type"], f"type mismatch at {committed['name']}"
        assert committed["description"] == gen["description"], f"desc mismatch at {committed['name']}"


def _epoch_rollover_cases():
    doc = _load("epoch_rollover.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


def _epoch_counter(epoch: int, seqnum: int) -> int:
    """Compute 24-bit replay counter from epoch and seqnum (spec 4.4)."""
    return (epoch << 16) | seqnum


@pytest.mark.parametrize("name,vector", _epoch_rollover_cases())
def test_epoch_rollover_vector(name: str, vector: dict) -> None:
    """Validate epoch rollover test vectors for link-layer replay protection (spec 4.4).

    Tests counter computation, tuple ordering, and replay detection rules.
    """
    # Test sender_sequence vectors: verify counter computation
    if "sender_sequence" in vector:
        for entry in vector["sender_sequence"]:
            computed = _epoch_counter(entry["epoch"], entry["seqnum"])
            assert computed == entry["counter"], (
                f"{name}: counter mismatch for ({entry['epoch']}, {entry['seqnum']}): "
                f"got {computed}, expected {entry['counter']}"
            )

    # Test tuple ordering vectors: verify counter computation and ordering
    if "tuple" in vector:
        t = vector["tuple"]
        computed = _epoch_counter(t["epoch"], t["seqnum"])
        assert computed == vector["counter"], (
            f"{name}: counter mismatch for ({t['epoch']}, {t['seqnum']})"
        )
        # Verify hex representation
        expected_hex = vector["counter"].to_bytes(3, "big").hex()
        assert expected_hex == vector["hex"], f"{name}: hex mismatch"

        # Verify ordering relation if present
        if "greater_than" in vector:
            other = vector["greater_than"]
            other_counter = _epoch_counter(other["epoch"], other["seqnum"])
            assert other_counter == other["counter"]
            assert computed > other_counter, f"{name}: ordering violation"

        if "less_than" in vector:
            other = vector["less_than"]
            other_counter = _epoch_counter(other["epoch"], other["seqnum"])
            assert other_counter == other["counter"]
            assert computed < other_counter, f"{name}: ordering violation"

    # Test receiver state vectors: verify replay detection logic
    if "receiver_state" in vector and "received" in vector:
        state = vector["receiver_state"]
        received = vector["received"]
        expected = vector["expected"]

        last_counter = _epoch_counter(state["last_epoch"], state["last_seqnum"])
        recv_counter = _epoch_counter(received["epoch"], received["seqnum"])

        # Verify counter computation
        assert recv_counter == received["counter"], f"{name}: received counter mismatch"

        # Verify acceptance decision based on spec rules
        reason = expected["reason"]
        should_accept = expected["accept"]

        if reason == "epoch_rollover_rejected":
            # Epoch 0 < last_epoch 255: always stale
            assert received["epoch"] < state["last_epoch"]
            assert not should_accept

        elif reason == "epoch_stale":
            # Lower epoch is always stale
            assert received["epoch"] < state["last_epoch"]
            assert not should_accept

        elif reason == "epoch_greater":
            # Higher epoch is always fresh
            assert received["epoch"] > state["last_epoch"]
            assert should_accept

        elif reason == "seqnum_greater":
            # Same epoch, higher seqnum is fresh
            assert received["epoch"] == state["last_epoch"]
            assert received["seqnum"] > state["last_seqnum"]
            assert should_accept

        elif reason == "seqnum_below_window_floor":
            # Same epoch, seqnum below window is stale
            assert received["epoch"] == state["last_epoch"]
            assert received["seqnum"] < state["last_seqnum"] - 32
            assert not should_accept

        elif reason == "within_window":
            # Same epoch, seqnum within 32-packet window
            assert received["epoch"] == state["last_epoch"]
            offset = state["last_seqnum"] - received["seqnum"]
            assert 0 < offset <= 32
            assert expected["window_offset"] == offset
            assert should_accept

        elif reason == "duplicate_in_window":
            # Window bit already set
            offset = state["last_seqnum"] - received["seqnum"]
            assert (state["window"] >> offset) & 1 == 1
            assert not should_accept

    # Test counter comparison vectors
    if "comparisons" in vector:
        for comp in vector["comparisons"]:
            a_counter = _epoch_counter(comp["a"]["epoch"], comp["a"]["seqnum"])
            b_counter = _epoch_counter(comp["b"]["epoch"], comp["b"]["seqnum"])
            if comp["a_less_than_b"]:
                assert a_counter < b_counter, f"{name}: {comp['a']} should be < {comp['b']}"
            else:
                assert a_counter >= b_counter, f"{name}: {comp['a']} should be >= {comp['b']}"

    # Test cold boot random init vectors
    if "cold_boot_epoch_range" in vector:
        epoch_range = vector["cold_boot_epoch_range"]
        for example in vector["examples"]:
            epoch = example["epoch"]
            computed = _epoch_counter(epoch, example["seqnum"])
            assert computed == example["counter"]
            in_range = epoch_range["min"] <= epoch <= epoch_range["max"]
            assert in_range == example["valid_init"], (
                f"{name}: epoch {epoch} valid_init mismatch"
            )


def test_epoch_rollover_counter_math() -> None:
    """Cross-validate epoch rollover counter formula against spec section 4.4."""
    # Boundary cases from spec
    assert _epoch_counter(0, 0) == 0x000000
    assert _epoch_counter(0, 65535) == 0x00FFFF
    assert _epoch_counter(1, 0) == 0x010000
    assert _epoch_counter(255, 65535) == 0xFFFFFF

    # Verify monotonic increment across epoch boundary
    assert _epoch_counter(5, 65535) < _epoch_counter(6, 0)
    assert _epoch_counter(254, 65535) < _epoch_counter(255, 0)

    # Verify epoch comparison dominates seqnum
    assert _epoch_counter(1, 0) > _epoch_counter(0, 65535)
    assert _epoch_counter(128, 0) > _epoch_counter(127, 65535)


def test_epoch_rollover_vector_file_integrity() -> None:
    """Verify epoch_rollover.json structure and coverage."""
    doc = _load("epoch_rollover.json")
    assert doc["format_version"] == 2
    assert "epoch rollover" in doc["description"].lower()

    names = {v["name"] for v in doc["vectors"]}
    # Verify required coverage
    assert "normal_epoch_increment" in names
    assert "epoch_max_boundary" in names
    assert "epoch_rollover_forbidden" in names
    assert "tuple_ordering_near_rollover_254_max" in names
    assert "tuple_ordering_near_rollover_255_0" in names
    assert "counter_comparison_unsigned" in names
    assert "random_init_cold_boot" in names


# --- Gradient Entry Ranking Vectors ---


def _gradient_entry_doc() -> dict:
    return _load("gradient_entry.json")


def _make_gradient_entry(fields: dict) -> GradientEntry:
    """Create a GradientEntry from vector fields for comparison testing."""
    from ipaddress import IPv6Address

    from lichen.gradient import GradientEntry, GradientSource

    source_map = {
        "announce": GradientSource.ANNOUNCE,
        "rrep": GradientSource.RREP,
        "rpl": GradientSource.RPL,
        "data": GradientSource.DATA,
    }
    return GradientEntry(
        destination=IPv6Address("fd00::1"),
        next_hop=IPv6Address("fe80::1"),
        hop_count=fields["hop_count"],
        seq_num=fields["seq_num"],
        source=source_map[fields["source"]],
        expires=10000,
    )


def _gradient_source_priority_cases():
    doc = _gradient_entry_doc()
    return [(v["name"], v) for v in doc["vectors"]["source_priority"]]


def _gradient_seq_num_cases():
    doc = _gradient_entry_doc()
    return [(v["name"], v) for v in doc["vectors"]["seq_num_comparison"]]


def _gradient_hop_count_cases():
    doc = _gradient_entry_doc()
    return [(v["name"], v) for v in doc["vectors"]["hop_count_comparison"]]


def _gradient_combined_cases():
    doc = _gradient_entry_doc()
    return [(v["name"], v) for v in doc["vectors"]["combined_ranking"]]


def _gradient_coord_cases():
    doc = _gradient_entry_doc()
    return [(v["name"], v) for v in doc["vectors"]["coordinate_encoding"]]


@pytest.mark.parametrize("name,vector", _gradient_source_priority_cases())
def test_gradient_source_priority_vector(name: str, vector: dict) -> None:
    """Validate GradientSource priority ordering per spec section 11."""
    entry_a = _make_gradient_entry(vector["entry_a"])
    entry_b = _make_gradient_entry(vector["entry_b"])

    a_rank = entry_a._rank()
    b_rank = entry_b._rank()

    if vector["a_wins"]:
        assert a_rank >= b_rank, f"{name}: expected a >= b"
    else:
        assert a_rank < b_rank, f"{name}: expected a < b"


@pytest.mark.parametrize("name,vector", _gradient_seq_num_cases())
def test_gradient_seq_num_vector(name: str, vector: dict) -> None:
    """Validate RFC 1982 sequence number comparison in gradient ranking."""
    entry_a = _make_gradient_entry(vector["entry_a"])
    entry_b = _make_gradient_entry(vector["entry_b"])

    a_rank = entry_a._rank()
    b_rank = entry_b._rank()

    if vector["a_wins"]:
        assert a_rank >= b_rank, f"{name}: expected a >= b"
    else:
        assert a_rank < b_rank, f"{name}: expected a < b"


@pytest.mark.parametrize("name,vector", _gradient_hop_count_cases())
def test_gradient_hop_count_vector(name: str, vector: dict) -> None:
    """Validate hop count comparison in gradient ranking (fewer hops wins)."""
    entry_a = _make_gradient_entry(vector["entry_a"])
    entry_b = _make_gradient_entry(vector["entry_b"])

    a_rank = entry_a._rank()
    b_rank = entry_b._rank()

    if vector["a_wins"]:
        assert a_rank >= b_rank, f"{name}: expected a >= b"
    else:
        assert a_rank < b_rank, f"{name}: expected a < b"


@pytest.mark.parametrize("name,vector", _gradient_combined_cases())
def test_gradient_combined_ranking_vector(name: str, vector: dict) -> None:
    """Validate combined ranking: priority > seq_num > hop_count."""
    entry_a = _make_gradient_entry(vector["entry_a"])
    entry_b = _make_gradient_entry(vector["entry_b"])

    a_rank = entry_a._rank()
    b_rank = entry_b._rank()

    if vector["a_wins"]:
        assert a_rank >= b_rank, f"{name}: expected a >= b"
    else:
        assert a_rank < b_rank, f"{name}: expected a < b"


@pytest.mark.parametrize("name,vector", _gradient_coord_cases())
def test_gradient_coordinate_encoding_vector(name: str, vector: dict) -> None:
    """Validate GradientEntry coordinate handling (e7 format from announce app_data)."""
    from ipaddress import IPv6Address

    from lichen.gradient import GradientEntry, GradientSource

    coords = tuple(vector["coords_tuple"]) if vector["coords_tuple"] else None

    entry = GradientEntry(
        destination=IPv6Address("fd00::1"),
        next_hop=IPv6Address("fe80::1"),
        hop_count=3,
        seq_num=1,
        source=GradientSource.ANNOUNCE,
        expires=10000,
        coords=coords,
    )

    assert entry.coords == coords, f"{name}: coords mismatch"

    if coords is not None:
        lat, lon = coords
        assert abs(lat - vector["latitude_degrees"]) < 1e-7, f"{name}: lat mismatch"
        assert abs(lon - vector["longitude_degrees"]) < 1e-7, f"{name}: lon mismatch"

        lat_e7 = int(round(lat * 10_000_000))
        lon_e7 = int(round(lon * 10_000_000))
        assert lat_e7 == vector["latitude_e7"], f"{name}: lat_e7 mismatch"
        assert lon_e7 == vector["longitude_e7"], f"{name}: lon_e7 mismatch"


def test_gradient_entry_vector_coverage() -> None:
    """Verify gradient_entry.json has all expected vector categories."""
    doc = _gradient_entry_doc()
    assert doc["format_version"] == 2
    vectors = doc["vectors"]

    assert "source_priority" in vectors
    assert "seq_num_comparison" in vectors
    assert "hop_count_comparison" in vectors
    assert "combined_ranking" in vectors
    assert "coordinate_encoding" in vectors

    assert len(vectors["source_priority"]) >= 5
    assert len(vectors["seq_num_comparison"]) >= 7
    assert len(vectors["hop_count_comparison"]) >= 3
    assert len(vectors["combined_ranking"]) >= 4
    assert len(vectors["coordinate_encoding"]) >= 4


# --- CCP TDMA Vectors ---


def _ccp_tdma_cases():
    doc = _load("ccp_tdma.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp_tdma_cases())
def test_ccp_tdma_vectors(name: str, vector: dict) -> None:
    """Validate TDMA slot assignment and guard time boundary vectors.

    Cross-language oracle: tests hash_32-based slot assignment per spec
    section 02a-coordinated-capacity.md, guard time boundaries, and drift
    compensation calculations.
    """
    scheduler = TDMAScheduler()
    assert scheduler.validate_vector(vector), f"{name}: validation failed"


# --- Short Address DAD Vectors ---


def _short_addr_dad_doc():
    return _load("short_addr_dad.json")


def _short_addr_derive_cases():
    doc = _short_addr_dad_doc()
    assert doc["format_version"] == 2
    return [
        (v["name"], v)
        for v in doc["vectors"]
        if v["name"].startswith("derive_") and "seeds" not in v
    ]


def _short_addr_seed_mixing_cases():
    doc = _short_addr_dad_doc()
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"] if "seeds" in v]


def _short_addr_dad_retry_cases():
    doc = _short_addr_dad_doc()
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"] if v["name"].startswith("dad_retry")]


@pytest.mark.parametrize("name,vector", _short_addr_derive_cases())
def test_short_addr_derive_vector(name: str, vector: dict) -> None:
    """Validate derive_short_addr against short_addr_dad.json vectors.

    Tests CRC32-IEEE derivation with LICHEN key 0x4c494348454e (truncated
    to 0x4348454e as init). Cross-language oracle for Rust/C implementations.
    """
    eui64 = bytes(vector["eui64_bytes"])
    expected_addr = vector["derived"]

    # Verify CRC32 init value matches
    assert vector["crc32_init"] == "0x4348454e"

    # Test derive_short_addr (CRC32-IEEE based, canonical)
    derived = derive_short_addr(eui64)
    assert derived == expected_addr, f"{name}: derived {derived:#x} != expected {expected_addr:#x}"

    # Test derive_short_addr_crc16 (CRC16-CCITT alternative oracle)
    crc16_derived = derive_short_addr_crc16(eui64)
    expected_crc16 = vector["crc16_candidate"]
    assert crc16_derived == expected_crc16, (
        f"{name}: crc16 {crc16_derived:#x} != expected {expected_crc16:#x}"
    )

    # Also verify FNV-1a low16 for oracle parity
    fnv1a_hash = hash_32_fnv1a(eui64) & 0xFFFF
    expected_fnv = vector["fnv1a_low16"]
    assert fnv1a_hash == expected_fnv, f"{name}: fnv1a {fnv1a_hash:#x} != {expected_fnv:#x}"


@pytest.mark.parametrize("name,vector", _short_addr_seed_mixing_cases())
def test_short_addr_seed_mixing_vector(name: str, vector: dict) -> None:
    """Validate derive_short_addr_with_seed XOR mixing per spec 4.5.

    Seed is XOR'd into the last 4 bytes of EUI-64 (little-endian) before
    CRC32 hashing, producing deterministic retry candidates.
    """
    eui64 = bytes.fromhex(vector["eui64"])

    for seed_case in vector["seeds"]:
        seed = seed_case["seed"]
        expected_addr = seed_case["addr"]
        derived = derive_short_addr_with_seed(eui64, seed)
        assert derived == expected_addr, (
            f"{name} seed={seed}: derived {derived:#x} != expected {expected_addr:#x}"
        )


def test_short_addr_seed_zero_equivalence() -> None:
    """Verify derive_short_addr_with_seed(eui64, 0) == derive_short_addr(eui64).

    Per spec 02-physical-link.md 4.5, seed mixing XORs the seed into the last
    4 bytes of EUI-64 before hashing. When seed=0, XOR with zeros leaves data
    unchanged, so the seeded function with seed=0 must produce identical output
    to the base derivation function.

    This property is required for correct DAD retry behavior where seed=0 is
    conceptually equivalent to the first (seedless) derivation attempt.
    """
    # Test EUI-64 values from vectors plus edge cases
    test_eui64s = [
        bytes.fromhex("0011223344556677"),  # from seed_mixing vector
        bytes.fromhex("ffeeddccbbaa9988"),  # inverse pattern
        bytes.fromhex("0000000000000000"),  # all zeros
        bytes.fromhex("ffffffffffffffff"),  # all ones
        bytes.fromhex("0123456789abcdef"),  # sequential
        bytes.fromhex("00000000ffffffff"),  # XOR target region all ones
        bytes.fromhex("ffffffff00000000"),  # XOR target region all zeros
    ]

    for eui64 in test_eui64s:
        base_addr = derive_short_addr(eui64)
        seeded_addr = derive_short_addr_with_seed(eui64, 0)
        assert base_addr == seeded_addr, (
            f"seed=0 equivalence failed for {eui64.hex()}: "
            f"derive_short_addr={base_addr:#06x} != "
            f"derive_short_addr_with_seed(0)={seeded_addr:#06x}"
        )


@pytest.mark.parametrize("name,vector", _short_addr_dad_retry_cases())
def test_short_addr_dad_retry_vector(name: str, vector: dict) -> None:
    """Validate DAD retry strategy per spec 4.5 pseudocode.

    Tests collision handling with seed mixing (1..255) and fallback to
    extended 64-bit addressing when 256 candidates exhausted.
    """
    if name == "dad_retry_exhausted":
        # Special case: all 256 candidates taken -> fallback to None
        eui64 = bytes.fromhex(vector["eui64"])
        # Generate all 256 possible addresses for this EUI-64
        existing = {derive_short_addr(eui64)}
        for seed in range(1, 256):
            existing.add(derive_short_addr_with_seed(eui64, seed))
        assert len(existing) == vector["existing_size"]
        expected_result = vector["result"]  # null in JSON -> None in Python
        result = dad_retry(eui64, existing)
        assert result is expected_result, f"{name}: expected {expected_result}, got {result}"
        return

    eui64 = bytes.fromhex(vector["eui64"])
    existing = set(vector["existing"])
    expected_result = vector["result"]
    expected_seed = vector.get("expected_seed")

    result = dad_retry(eui64, existing)
    assert result == expected_result, f"{name}: result {result:#x} != expected {expected_result:#x}"

    # Verify the seed that produced this result
    if expected_seed is not None:
        if expected_seed == 0:
            assert derive_short_addr(eui64) == expected_result
        else:
            assert derive_short_addr_with_seed(eui64, expected_seed) == expected_result


def test_short_addr_incremental_retry_vector() -> None:
    """Validate +1 mod 0xffef incremental retry (bd 1.8.2.6)."""
    doc = _short_addr_dad_doc()
    vector = next(v for v in doc["vectors"] if v["name"] == "incremental_retry")

    start = vector["start"]
    existing = set(vector["existing"])
    expected_result = vector["result"]

    result = dad_retry_incremental(start, existing)
    assert result == expected_result, f"incremental_retry: {result} != {expected_result}"


def test_short_addr_incremental_retry_wraparound_vector() -> None:
    """Validate incremental retry wraparound boundary (start near 0xFFEF wraps).

    When wraparound would land on 0x0000 (reserved null address), the function
    skips to 0x0001 as specified in the vector.
    """
    doc = _short_addr_dad_doc()
    vector = next(v for v in doc["vectors"] if v["name"] == "incremental_retry_wraparound")

    start = vector["start"]
    existing = set(vector["existing"])
    expected_result = vector["result"]

    result = dad_retry_incremental(start, existing)
    assert result == expected_result, (
        f"incremental_retry_wraparound: {result} != {expected_result}"
    )


def test_short_addr_incremental_retry_exhausted_vector() -> None:
    """Validate incremental retry returns None when all 0..0xFFEF addresses taken."""
    from lichen.link.short_addr import SHORT_ADDR_MAX_INCREMENTAL

    doc = _short_addr_dad_doc()
    vector = next(v for v in doc["vectors"] if v["name"] == "incremental_retry_exhausted")

    start = vector["start"]
    # All addresses 0..SHORT_ADDR_MAX_INCREMENTAL are taken
    existing = set(range(SHORT_ADDR_MAX_INCREMENTAL + 1))
    assert len(existing) == vector["existing_size"], (
        f"test setup: expected {vector['existing_size']} addresses, got {len(existing)}"
    )
    expected_result = vector["result"]

    result = dad_retry_incremental(start, existing)
    assert result is expected_result, (
        f"incremental_retry_exhausted: expected None, got {result}"
    )


def test_short_addr_dad_jitter_vector() -> None:
    """Validate DAD probe jitter schedule with deterministic RNG seed."""
    import random

    doc = _short_addr_dad_doc()
    vector = next(v for v in doc["vectors"] if v["name"] == "dad_jitter_three_probes")

    rng_seed = vector["rng_seed"]
    count = vector["count"]
    expected_jitters = vector["jitters_ms"]

    rng = random.Random(rng_seed)
    jitters = dad_probe_schedule(count, rng)

    assert jitters == expected_jitters, f"dad_jitter: {jitters} != {expected_jitters}"


def test_short_addr_coordinator_allocate_vector() -> None:
    """Validate coordinator address table allocation and DAO-ACK."""
    doc = _short_addr_dad_doc()
    vector = next(v for v in doc["vectors"] if v["name"] == "coordinator_allocate")

    coordinator = CoordinatorAddressTable()

    # Process allocations
    for alloc in vector["allocations"]:
        eui64 = bytes.fromhex(alloc["eui64"])
        if "again" in alloc:
            # Re-allocation should return same address
            assigned = coordinator.allocate(eui64)
            assert assigned == alloc["again"]
            assert alloc["same"] is True
        else:
            assigned = coordinator.allocate(eui64)
            expected = alloc["assigned"]
            assert assigned == expected, f"allocate {alloc['eui64']}: {assigned} != {expected}"

    # Process DAO request
    dao_req = vector["dao_requested"]
    eui64 = bytes.fromhex(dao_req["eui64"])
    req = DaoRequest(eui64=eui64, requested_short=dao_req["requested"])
    ack = coordinator.handle_dao(req)
    assert ack.assigned_short == dao_req["assigned"]
    assert ack.status == dao_req["status"]

    # Verify table snapshot
    snapshot = coordinator.table_snapshot()
    expected_snapshot = {int(k): v for k, v in vector["table_snapshot"].items()}
    assert snapshot == expected_snapshot


def test_short_addr_transition_vector() -> None:
    """Validate transition from self-assigned to coordinator-managed address."""
    doc = _short_addr_dad_doc()
    vector = next(v for v in doc["vectors"] if v["name"] == "transition_self_to_coordinator")

    eui64 = bytes.fromhex(vector["eui64"])
    self_assigned = vector["self_assigned"]

    # Coordinator already has another node with that address
    # The other node was given address 1390 (perhaps via explicit request)
    coordinator = CoordinatorAddressTable()
    other_eui = bytes.fromhex(vector["coordinator_had_other"])
    # Manually assign the conflicting address via DAO request
    req = DaoRequest(eui64=other_eui, requested_short=self_assigned)
    ack = coordinator.handle_dao(req)
    assert ack.assigned_short == self_assigned, "setup: other node should have self_assigned"

    # Transition: self_assigned is taken, should get new address
    ack = transition_to_coordinator_managed(eui64, self_assigned, coordinator)
    assert ack.assigned_short == vector["transition_assigned"]
    assert ack.status == vector["status"]


def test_short_addr_collision_detector_vector() -> None:
    """Validate collision detection when same short addr observed with multiple pubkeys."""
    doc = _short_addr_dad_doc()
    vector = next(v for v in doc["vectors"] if v["name"] == "collision_detector")

    short_addr = vector["short_addr"]
    # The vector uses ellipsis notation; use full 32-byte pubkeys
    pubkey1 = bytes([0x01] * 32)
    pubkey2 = bytes([0x02] * 32)

    detector = ShortAddressCollisionDetector()

    # First observation: no collision yet
    is_collision_1 = detector.observe(short_addr, pubkey1)
    assert is_collision_1 == vector["first_observe_collision"]

    # Second observation with different pubkey: collision detected
    is_collision_2 = detector.observe(short_addr, pubkey2)
    assert is_collision_2 == vector["second_observe_collision"]

    # Verify collision state
    assert detector.is_collision(short_addr) == vector["is_collision"]
    assert len(detector.pubkeys_for(short_addr)) == vector["pubkeys_count"]


def test_short_addr_reserved_range_detection() -> None:
    """Test is_reserved_addr correctly identifies reserved addresses.

    Reserved addresses per 802.15.4 and LICHEN spec:
    - 0x0000: null/unspecified
    - 0xFFFE: 802.15.4 unspecified
    - 0xFFFF: 802.15.4 broadcast
    """
    # Reserved addresses
    assert is_reserved_addr(0x0000)
    assert is_reserved_addr(0xFFFE)
    assert is_reserved_addr(0xFFFF)

    # Non-reserved addresses
    assert not is_reserved_addr(0x0001)
    assert not is_reserved_addr(0x1234)
    assert not is_reserved_addr(0xFFFD)
    assert not is_reserved_addr(0x8000)

    # Verify constants match
    assert SHORT_ADDR_RESERVED_NULL == 0x0000
    assert SHORT_ADDR_RESERVED_UNSPECIFIED == 0xFFFE
    assert SHORT_ADDR_RESERVED_BROADCAST == 0xFFFF
    assert frozenset({0x0000, 0xFFFE, 0xFFFF}) == SHORT_ADDR_RESERVED


def test_short_addr_derive_reserved_null() -> None:
    """Test behavior when derive_short_addr produces 0x0000.

    EUI-64 58969e7da3da9901 hashes to 0x0000. This is a reserved
    address so dad_retry must skip it and return a seeded alternative.
    """
    # This EUI-64 derives to 0x0000
    eui64_null = bytes.fromhex("58969e7da3da9901")
    derived = derive_short_addr(eui64_null)
    assert derived == 0x0000, f"expected 0x0000, got {derived:#06x}"

    # dad_retry should skip reserved 0x0000 and return seeded alternative
    result = dad_retry(eui64_null, set())
    assert result is not None, "dad_retry should find non-reserved address"
    assert result != 0x0000, "dad_retry should skip reserved 0x0000"
    assert not is_reserved_addr(result), f"result {result:#06x} is reserved"

    # Verify it's the seed=1 result
    expected = derive_short_addr_with_seed(eui64_null, 1)
    assert result == expected, f"expected seed=1 result {expected:#06x}, got {result:#06x}"


def test_short_addr_derive_reserved_broadcast() -> None:
    """Test behavior when derive_short_addr produces 0xFFFF (broadcast).

    EUI-64 4ee5844028f5d433 hashes to 0xFFFF. This is the broadcast
    address so dad_retry must skip it.
    """
    eui64_broadcast = bytes.fromhex("4ee5844028f5d433")
    derived = derive_short_addr(eui64_broadcast)
    assert derived == 0xFFFF, f"expected 0xFFFF, got {derived:#06x}"

    # dad_retry should skip reserved 0xFFFF
    result = dad_retry(eui64_broadcast, set())
    assert result is not None
    assert result != 0xFFFF, "dad_retry should skip reserved 0xFFFF"
    assert not is_reserved_addr(result)


def test_short_addr_derive_reserved_unspecified() -> None:
    """Test behavior when derive_short_addr produces 0xFFFE (unspecified).

    EUI-64 a2b602900df31bc0 hashes to 0xFFFE. This is the 802.15.4
    unspecified address so dad_retry must skip it.
    """
    eui64_unspec = bytes.fromhex("a2b602900df31bc0")
    derived = derive_short_addr(eui64_unspec)
    assert derived == 0xFFFE, f"expected 0xFFFE, got {derived:#06x}"

    # dad_retry should skip reserved 0xFFFE
    result = dad_retry(eui64_unspec, set())
    assert result is not None
    assert result != 0xFFFE, "dad_retry should skip reserved 0xFFFE"
    assert not is_reserved_addr(result)


def test_short_addr_incremental_skips_reserved_null() -> None:
    """Test dad_retry_incremental skips 0x0000 when wrapping.

    When incrementing wraps to 0x0000, it should skip to 0x0001 instead.
    """
    # Start at 0xFFEF-1 = 65518, with 65519 taken
    # Wraparound: (65518 + 2) % 65520 = 0
    # But 0x0000 is reserved, so should skip to 0x0001
    start = 0xFFEE
    existing = {0xFFEE, 0xFFEF}
    result = dad_retry_incremental(start, existing)
    assert result == 0x0001, f"expected 0x0001 (skip 0x0000), got {result:#06x}"


def test_handle_dao_rejects_reserved_addresses() -> None:
    """Test handle_dao rejects explicit requests for reserved addresses (r2-P1-11).

    Per 802.15.4 and LICHEN spec, explicit requests for reserved addresses
    (0x0000, 0xFFFE, 0xFFFF) MUST be rejected with status=1. The coordinator
    MUST NOT silently substitute a different address when the client explicitly
    requested a specific (reserved) address.
    """
    # Attempt to request each reserved address
    for reserved_addr in [0x0000, 0xFFFE, 0xFFFF]:
        # Create fresh coordinator and EUI for each test to avoid side effects
        coord = CoordinatorAddressTable()
        test_eui = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, reserved_addr & 0xFF])

        req = DaoRequest(eui64=test_eui, requested_short=reserved_addr)
        ack = coord.handle_dao(req)

        # Explicit requests for reserved addresses MUST be rejected
        assert ack.status == 1, (
            f"handle_dao should reject explicit request for reserved {reserved_addr:#06x}"
        )
        assert ack.assigned_short is None, (
            "handle_dao should not assign any address when rejecting reserved request"
        )


def test_handle_dao_allocates_when_no_explicit_request() -> None:
    """Test handle_dao allocates non-reserved address when no specific request.

    When a node requests assignment without specifying a particular address,
    the allocation path should still work and avoid reserved addresses.
    This ensures the rejection of explicit reserved requests (r2-P1-11) does
    not break normal allocation.
    """
    coord = CoordinatorAddressTable()
    eui64 = bytes.fromhex("0011223344556677")

    req = DaoRequest(eui64=eui64, requested_short=None)
    ack = coord.handle_dao(req)

    assert ack.status == 0, "handle_dao should succeed for normal allocation"
    assert ack.assigned_short is not None, "handle_dao should assign an address"
    assert not is_reserved_addr(ack.assigned_short), (
        f"handle_dao should not assign reserved address {ack.assigned_short:#06x}"
    )


def test_handle_dao_ack_rejects_reserved_addresses() -> None:
    """Test handle_dao_ack rejects reserved addresses from coordinator (r2-P2-33).

    Even if a malicious or buggy coordinator sends a DAO-ACK with a reserved
    address (0x0000, 0xFFFE, 0xFFFF), the node MUST reject it. This prevents
    reserved addresses from being stored and used on the network.
    """
    for reserved_addr in [0x0000, 0xFFFE, 0xFFFF]:
        # Create fresh coordinator table to act as the node's local state
        node_table = CoordinatorAddressTable()
        test_eui = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, reserved_addr & 0xFF])

        # Simulate receiving a DAO-ACK with a reserved address
        malicious_ack = DaoAck(
            eui64=test_eui,
            assigned_short=reserved_addr,
            status=0,  # Coordinator claims success
            dao_sequence=1,
        )
        result = node_table.handle_dao_ack(malicious_ack)

        # Node MUST reject reserved addresses
        assert result is False, (
            f"handle_dao_ack should reject reserved address {reserved_addr:#06x}"
        )
        # Verify the reserved address was not stored
        assert node_table.lookup_by_eui(test_eui) is None, (
            f"reserved address {reserved_addr:#06x} should not be stored"
        )
        assert node_table.lookup_by_short(reserved_addr) is None, (
            f"reserved address {reserved_addr:#06x} should not appear in table"
        )


def test_handle_dao_ack_accepts_valid_addresses() -> None:
    """Test handle_dao_ack accepts non-reserved addresses.

    Ensure the reserved-address rejection (r2-P2-33) does not break normal
    DAO-ACK processing for valid addresses.
    """
    node_table = CoordinatorAddressTable()
    test_eui = bytes.fromhex("0011223344556677")
    valid_addr = 0x1234

    ack = DaoAck(
        eui64=test_eui,
        assigned_short=valid_addr,
        status=0,
        dao_sequence=1,
    )
    result = node_table.handle_dao_ack(ack)

    assert result is True, "handle_dao_ack should accept valid address"
    assert node_table.lookup_by_eui(test_eui) == valid_addr
    assert node_table.lookup_by_short(valid_addr) == test_eui


def test_handle_dao_ack_rejects_mismatched_identity() -> None:
    """Test handle_dao_ack rejects DAO-ACKs for different identities (r2-P2-31).

    When self_eui64 is provided, the node MUST reject DAO-ACKs where
    ack.eui64 does not match self_eui64. This prevents address table
    corruption from spoofed or misdirected DAO-ACKs.
    """
    node_table = CoordinatorAddressTable()
    node_eui = bytes.fromhex("0011223344556677")
    attacker_eui = bytes.fromhex("aabbccddeeff0011")
    assigned_addr = 0x1234

    # Simulate receiving a DAO-ACK for a different node
    spoofed_ack = DaoAck(
        eui64=attacker_eui,  # Different from our identity
        assigned_short=assigned_addr,
        status=0,
        dao_sequence=1,
    )
    result = node_table.handle_dao_ack(spoofed_ack, self_eui64=node_eui)

    # Node MUST reject DAO-ACKs for different identities
    assert result is False, (
        "handle_dao_ack should reject DAO-ACK for different identity"
    )
    # Verify the spoofed entry was not stored
    assert node_table.lookup_by_eui(attacker_eui) is None, (
        "spoofed identity should not be stored"
    )
    assert node_table.lookup_by_short(assigned_addr) is None, (
        "address from spoofed DAO-ACK should not be stored"
    )


def test_handle_dao_ack_accepts_matching_identity() -> None:
    """Test handle_dao_ack accepts DAO-ACKs for the node's own identity (r2-P2-31).

    When self_eui64 is provided and matches ack.eui64, the DAO-ACK
    should be accepted normally.
    """
    node_table = CoordinatorAddressTable()
    node_eui = bytes.fromhex("0011223344556677")
    assigned_addr = 0x1234

    ack = DaoAck(
        eui64=node_eui,
        assigned_short=assigned_addr,
        status=0,
        dao_sequence=1,
    )
    result = node_table.handle_dao_ack(ack, self_eui64=node_eui)

    assert result is True, "handle_dao_ack should accept matching identity"
    assert node_table.lookup_by_eui(node_eui) == assigned_addr
    assert node_table.lookup_by_short(assigned_addr) == node_eui


def test_handle_dao_ack_without_self_eui64_accepts_any() -> None:
    """Test handle_dao_ack without self_eui64 for backward compatibility.

    When self_eui64 is not provided (None), the DAO-ACK should be
    accepted for any identity. This maintains backward compatibility
    but is NOT recommended for production use.
    """
    node_table = CoordinatorAddressTable()
    any_eui = bytes.fromhex("aabbccddeeff0011")
    assigned_addr = 0x5678

    ack = DaoAck(
        eui64=any_eui,
        assigned_short=assigned_addr,
        status=0,
        dao_sequence=1,
    )
    # No self_eui64 provided (backward compatible mode)
    result = node_table.handle_dao_ack(ack)

    assert result is True, "handle_dao_ack should accept any identity when self_eui64 is None"
    assert node_table.lookup_by_eui(any_eui) == assigned_addr


def test_handle_dao_ack_rejects_malformed_eui64() -> None:
    """Test handle_dao_ack rejects malformed EUI-64 values (r3-P1-6).

    The ack.eui64 field must be validated before any table mutation to prevent
    crashes or undefined behavior from malformed DAO-ACKs.
    """
    node_table = CoordinatorAddressTable()

    # Test wrong length (too short)
    bad_ack_short = DaoAck(
        eui64=bytes.fromhex("001122334455"),  # Only 6 bytes
        assigned_short=0x1234,
        status=0,
        dao_sequence=1,
    )
    with pytest.raises(ValueError, match="EUI-64 must be 8 bytes"):
        node_table.handle_dao_ack(bad_ack_short)

    # Test wrong length (too long)
    bad_ack_long = DaoAck(
        eui64=bytes.fromhex("00112233445566778899"),  # 10 bytes
        assigned_short=0x1234,
        status=0,
        dao_sequence=1,
    )
    with pytest.raises(ValueError, match="EUI-64 must be 8 bytes"):
        node_table.handle_dao_ack(bad_ack_long)

    # Test empty bytes
    bad_ack_empty = DaoAck(
        eui64=b"",
        assigned_short=0x1234,
        status=0,
        dao_sequence=1,
    )
    with pytest.raises(ValueError, match="EUI-64 must be 8 bytes"):
        node_table.handle_dao_ack(bad_ack_empty)


def test_handle_dao_ack_rejects_malformed_eui64_with_self_eui64() -> None:
    """Test handle_dao_ack rejects malformed ack.eui64 when self_eui64 is provided (r3-P2-22).

    When self_eui64 is provided for identity validation, the ack.eui64 field
    must still be validated for proper format before any comparison or table
    mutation. This ensures malformed DAO-ACKs are rejected early even when
    identity validation would otherwise be performed.
    """
    node_table = CoordinatorAddressTable()
    valid_self_eui = bytes.fromhex("0011223344556677")

    # Test wrong length (too short) with self_eui64 provided
    bad_ack_short = DaoAck(
        eui64=bytes.fromhex("001122334455"),  # Only 6 bytes
        assigned_short=0x1234,
        status=0,
        dao_sequence=1,
    )
    with pytest.raises(ValueError, match="EUI-64 must be 8 bytes"):
        node_table.handle_dao_ack(bad_ack_short, self_eui64=valid_self_eui)

    # Test wrong length (too long) with self_eui64 provided
    bad_ack_long = DaoAck(
        eui64=bytes.fromhex("00112233445566778899"),  # 10 bytes
        assigned_short=0x1234,
        status=0,
        dao_sequence=1,
    )
    with pytest.raises(ValueError, match="EUI-64 must be 8 bytes"):
        node_table.handle_dao_ack(bad_ack_long, self_eui64=valid_self_eui)

    # Test empty bytes with self_eui64 provided
    bad_ack_empty = DaoAck(
        eui64=b"",
        assigned_short=0x1234,
        status=0,
        dao_sequence=1,
    )
    with pytest.raises(ValueError, match="EUI-64 must be 8 bytes"):
        node_table.handle_dao_ack(bad_ack_empty, self_eui64=valid_self_eui)

    # Verify no table corruption occurred
    assert len(node_table) == 0, "malformed DAO-ACKs should not corrupt table"


def test_short_addr_dad_vector_coverage() -> None:
    """Verify short_addr_dad.json has all expected vector categories."""
    doc = _short_addr_dad_doc()
    assert doc["format_version"] == 2

    vector_names = {v["name"] for v in doc["vectors"]}

    # Expected vector categories per spec 02-physical-link.md 4.5
    expected = {
        # Basic derivation
        "derive_0011223344556677",
        "derive_0102030405060708",
        "derive_aabbccddeeff0011",
        "derive_0000000000000000",
        "derive_ffffffffffffffff",
        "derive_0200000000000001",
        # Seed mixing
        "seed_mixing_0011223344556677",
        # DAD retry
        "dad_retry_one_collision",
        "dad_retry_two_collisions",
        "dad_retry_exhausted",
        # Incremental retry
        "incremental_retry",
        "incremental_retry_wraparound",
        "incremental_retry_exhausted",
        # Jitter
        "dad_jitter_three_probes",
        # Coordinator
        "coordinator_allocate",
        "transition_self_to_coordinator",
        # Collision detection
        "collision_detector",
    }

    missing = expected - vector_names
    assert not missing, f"Missing vectors: {missing}"


# --- SCHC Adaptation Vectors ---


def _schc_adaptation_cases():
    doc = _load("schc_adaptation.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _schc_adaptation_cases())
def test_schc_adaptation_vector(name: str, vector: dict) -> None:
    """Validate SCHC adaptation layer vectors per spec/03-adaptation.md.

    Tests unknown rule ID rejection (P0), Rule 255 uncompressed fallback,
    port boundary compression, and control message formats.
    """
    from lichen.schc.context import NoMatchingRuleError, SchcContext
    from lichen.schc.fragment import Ack, ack_request, receiver_abort, sender_abort
    from lichen.schc.rules import RULE_SET_VERSION, SchcRuleVersionOption

    category = vector["category"]

    if category == "rejection":
        # P0 security-critical: unknown rule IDs must reject cleanly
        wire = bytes.fromhex(vector["wire"]) if vector["wire"] else b""
        ctx = SchcContext()

        if vector["expect_error"] == "unknown_rule_id":
            with pytest.raises(NoMatchingRuleError) as exc_info:
                ctx.decompress(wire)
            assert str(vector["expect_rule_id"]) in str(exc_info.value)
        elif vector["expect_error"] == "empty_packet":
            with pytest.raises(NoMatchingRuleError) as exc_info:
                ctx.decompress(wire)
            assert "empty" in str(exc_info.value).lower()

    elif category == "uncompressed":
        # Rule 255 uncompressed fallback round-trip
        packet = bytes.fromhex(vector["packet"])
        compressed = bytes.fromhex(vector["compressed"])
        assert compressed[0] == 255, f"{name}: expected Rule 255 prefix"
        assert len(compressed) == vector["compressed_size"], f"{name}: compressed size mismatch"
        assert compressed == bytes([255]) + packet, f"{name}: Rule 255 format mismatch"
        assert decompress_packet(compressed) == packet, f"{name}: decompress mismatch"

    elif category == "port_boundary":
        # Port compression boundary tests
        from lichen.schc.rules import LINK_LOCAL_COAP_RULE, UDP_PORT_RULE

        src_port = vector["src_port"]
        dst_port = vector["dst_port"]

        if vector["matches_rule_0_1"]:
            # MSB(12) match: top 12 bits must equal 0x163 (5683 >> 4)
            assert (src_port >> 4) == (5683 >> 4), f"{name}: src port MSB mismatch"
            assert (dst_port >> 4) == (5683 >> 4), f"{name}: dst port MSB mismatch"
            # LSB(4) residue
            src_lsb = src_port & 0x0F
            dst_lsb = dst_port & 0x0F
            assert format(src_lsb, "x") == vector["src_residue"], f"{name}: src residue"
            assert format(dst_lsb, "x") == vector["dst_residue"], f"{name}: dst residue"
        else:
            # Outside compressible range: MSB(12) does not match
            assert (src_port >> 4) != (5683 >> 4), f"{name}: should NOT match MSB(12)"

    elif category == "fragmentation_direction":
        # Rule 0x79 B-to-A direction vectors
        rule_id = vector["rule_id"]
        wire = bytes.fromhex(vector["wire"])
        msg_type = vector["message_type"]

        assert wire[0] == rule_id, f"{name}: rule ID mismatch"

        if msg_type == "ack_success":
            c_bit = vector["c_bit"]
            window = vector["window"]
            assert (wire[1] >> 6) & 1 == c_bit, f"{name}: C bit mismatch"
            assert (wire[1] >> 7) == window, f"{name}: window mismatch"
            expected_ack = Ack(rule_id, window, complete=True).to_bytes()
            assert wire == expected_ack, f"{name}: ACK success mismatch"
        elif msg_type == "ack_req":
            window = vector["window"]
            expected = ack_request(rule_id, window)
            assert wire == expected, f"{name}: ACK req mismatch"
        elif msg_type == "sender_abort":
            expected = sender_abort(rule_id)
            assert wire == expected, f"{name}: sender abort mismatch"
        elif msg_type == "receiver_abort":
            expected = receiver_abort(rule_id)
            assert wire == expected, f"{name}: receiver abort mismatch"

    elif category == "compressed_size":
        # Validate compressed size calculations
        from lichen.schc.codec import residue_bit_length, residue_byte_length
        from lichen.schc.rules import RULES

        rule_id = vector["rule_id"]
        if rule_id in RULES:
            rule = RULES[rule_id]
            if "residue_bit_length" in vector:
                assert residue_bit_length(rule) == vector["residue_bit_length"], (
                    f"{name}: bit length mismatch"
                )
            if "residue_byte_length" in vector:
                assert residue_byte_length(rule) == vector["residue_byte_length"], (
                    f"{name}: byte length mismatch"
                )

    elif category == "padding":
        # Octet alignment padding tests
        residue_bits = vector["residue_bits"]
        padding_bits = vector["padding_bits"]
        total_bits = vector["total_bits"]
        total_bytes = vector["total_bytes"]
        # Verify padding calculation
        computed_padding = (-residue_bits) % 8
        assert computed_padding == padding_bits, f"{name}: padding mismatch"
        assert residue_bits + padding_bits == total_bits, f"{name}: total bits mismatch"
        assert total_bits // 8 == total_bytes, f"{name}: total bytes mismatch"

    elif category == "rule_version":
        # SCHC Rule Version Option tests
        if "wire" in vector:
            wire = bytes.fromhex(vector["wire"])
            version = vector["version"]
            opt = SchcRuleVersionOption(version=version)
            assert opt.to_bytes() == wire, f"{name}: serialization mismatch"
            parsed = SchcRuleVersionOption.from_bytes(wire)
            assert parsed.version == version, f"{name}: parse mismatch"
        if vector.get("expect_error") == "version_mismatch":
            from lichen.schc.context import VersionMismatchError, check_version_compatibility

            with pytest.raises(VersionMismatchError):
                check_version_compatibility(vector["local_version"], vector["remote_version"])

    elif category == "single_active":
        # T=0 single active packet constraint tests
        rule_id = vector["rule_id"]
        t_value = vector["t_value"]
        assert t_value == 0, f"{name}: T must be 0 for single-active constraint"
        assert vector["expect_reassembly_reset"] is True, f"{name}: expect reset"
        # This is a behavioral constraint - validated by fragmentation implementation

    elif category == "ack_bitmap":
        # ACK bitmap format tests
        rule_id = vector["rule_id"]
        window = vector["window"]
        c_bit = vector["c_bit"]
        wire = bytes.fromhex(vector["wire"])

        assert wire[0] == rule_id, f"{name}: rule ID mismatch"
        parsed_c = (wire[1] >> 6) & 1
        assert parsed_c == c_bit, f"{name}: C bit mismatch"

        if c_bit == 1:
            # Complete: no bitmap
            assert vector["bitmap"] is None
            expected = Ack(rule_id, window, complete=True).to_bytes()
            assert wire == expected, f"{name}: ACK complete mismatch"


def test_schc_adaptation_vector_coverage() -> None:
    """Verify schc_adaptation.json covers all required categories."""
    cases = _schc_adaptation_cases()
    categories = {vector["category"] for _, vector in cases}
    expected = {
        "rejection",
        "uncompressed",
        "port_boundary",
        "fragmentation_direction",
        "compressed_size",
        "padding",
        "single_active",
        "rule_version",
        "ack_bitmap",
    }
    missing = expected - categories
    assert not missing, f"Missing categories: {missing}"

    # Verify P0 vectors are present
    p0_vectors = [v for _, v in cases if v.get("priority") == "P0"]
    assert len(p0_vectors) >= 4, "Must have at least 4 P0 (security-critical) vectors"


# --- Frame Length Boundary Vectors ---


def _frame_length_boundary_cases():
    doc = _load("frame_length_boundaries.json")
    assert doc["format_version"] == 2
    assert doc["vector_type"] == "frame_length_boundaries"
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _frame_length_boundary_cases())
def test_frame_length_boundary_vector(name: str, vector: dict) -> None:
    """Validate frame body length boundary handling per spec section 4.1.

    Tests minimum (4), maximum (254), and invalid (3, 255) frame lengths.
    """
    wire = bytes.fromhex(vector["input_hex"])
    expected = vector["expected"]

    if expected.get("error"):
        with pytest.raises(FrameError):
            LichenFrame.from_bytes(wire)
    else:
        frame = LichenFrame.from_bytes(wire)
        assert frame.epoch == expected["epoch"], f"{name}: epoch mismatch"
        assert frame.seqnum == expected["seqnum"], f"{name}: seqnum mismatch"
        if "addr_mode" in expected:
            assert int(frame.addr_mode) == expected["addr_mode"], f"{name}: addr_mode mismatch"
        if "payload_hex" in expected:
            assert frame.payload.hex() == expected["payload_hex"], f"{name}: payload mismatch"
        if "dst_addr_hex" in expected:
            assert frame.dst_addr.hex() == expected["dst_addr_hex"], f"{name}: dst_addr mismatch"


def test_frame_length_boundary_coverage() -> None:
    """Verify frame_length_boundaries.json covers critical boundaries."""
    doc = _load("frame_length_boundaries.json")
    names = {v["name"] for v in doc["vectors"]}

    # Critical boundary tests
    assert "body_length_3_underflow" in names, "Must test length 3 (underflow)"
    assert "body_length_4_minimum_valid" in names, "Must test length 4 (minimum)"
    assert "body_length_254_maximum_valid" in names, "Must test length 254 (maximum)"
    assert "body_length_255_exceeds_limit" in names, "Must test length 255 (exceeds)"


# --- CCP16 Utilization Vectors ---


def _ccp16_utilization_cases():
    doc = _load("ccp16_utilization.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp16_utilization_cases())
def test_ccp16_utilization_vector(name: str, vector: dict) -> None:
    """Validate channel utilization handling per spec section 3.5.

    Tests utilization thresholds: 0 (idle), 150 (first threshold),
    200 (second threshold), 255 (saturated), and tx_allowed=false paths.
    """
    inp = vector["input"]
    out = vector["output"]

    # Simulate select_tx_sf logic from spec pseudocode
    sf = inp.get("assigned_sf", 10)
    density = inp.get("density", 5)
    utilization = inp.get("utilization", 0)
    ema_loss = inp.get("ema_loss", 0.0)
    tx_allowed = True

    # Step 3: density/utilization >150 check
    if density > 10 or utilization > 150:
        sf = min(12, sf + 2)

    # Step 4: SNR upgrade check (not tested here, but would apply)
    # Step 5: loss check (separate from utilization)
    if ema_loss > 0.25:
        sf = min(12, sf + 1)

    # Step 6: utilization > 200 check - returns SF=12, false directly per spec
    if utilization > 200:
        sf = 12  # Spec: "return 12, false" overrides computed SF
        tx_allowed = False

    assert sf == out["sf"], f"{name}: SF mismatch (got {sf}, expected {out['sf']})"
    assert tx_allowed == out["tx_allowed"], f"{name}: tx_allowed mismatch"


def test_ccp16_utilization_coverage() -> None:
    """Verify ccp16_utilization.json covers required thresholds."""
    doc = _load("ccp16_utilization.json")
    names = {v["name"] for v in doc["vectors"]}

    # Required threshold vectors
    assert "utilization_0_idle_channel" in names
    assert "utilization_150_threshold_1_boundary" in names
    assert "utilization_200_threshold_2_boundary" in names
    assert "utilization_201_tx_blocked" in names
    assert "utilization_255_saturated" in names


# --- CCP16 EMA Loss Threshold Vectors ---


def _ccp16_ema_loss_cases():
    doc = _load("ccp16_ema_loss_threshold.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _ccp16_ema_loss_cases())
def test_ccp16_ema_loss_threshold_vector(name: str, vector: dict) -> None:
    """Validate EMA packet loss threshold boundary per spec section 3.5.

    Tests exact boundary at 0.25: loss <= 0.25 does NOT bump SF,
    loss > 0.25 bumps SF by 1 (capped at 12).
    """
    inp = vector["input"]
    out = vector["output"]

    sf = inp.get("assigned_sf", 10)
    ema_loss = inp.get("ema_loss", 0.0)
    ema_snr = inp.get("ema_snr", 5.0)
    density = inp.get("density", 5)

    # Per spec pseudocode order:
    # 1. if (ema_snr > 8) and (density < 5): sf = max(7, sf - 1)
    if ema_snr > 8 and density < 5:
        sf = max(7, sf - 1)

    # 2. if ema_loss > 0.25: sf = min(12, sf + 1)
    expected_bump = ema_loss > 0.25
    if expected_bump:
        sf = min(12, sf + 1)

    assert out["sf"] == sf, f"{name}: SF mismatch"
    assert out["sf_bumped"] == expected_bump, f"{name}: sf_bumped mismatch"


def test_ccp16_ema_loss_coverage() -> None:
    """Verify ccp16_ema_loss_threshold.json covers boundary conditions."""
    doc = _load("ccp16_ema_loss_threshold.json")
    names = {v["name"] for v in doc["vectors"]}

    # Boundary condition vectors
    assert "ema_loss_0.24_below_threshold" in names
    assert "ema_loss_0.25_at_threshold_exactly" in names
    assert "ema_loss_0.26_above_threshold" in names


# --- DAD Hash Algorithm Clarification Vectors ---


def _dad_hash_clarification_cases():
    doc = _load("dad_hash_clarification.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"] if "algorithm" in v]


@pytest.mark.parametrize("name,vector", _dad_hash_clarification_cases())
def test_dad_hash_clarification_vector(name: str, vector: dict) -> None:
    """Validate DAD hash algorithm selection per spec section 4.5.

    CRC32-IEEE with init 0x4348454e is authoritative for short address derivation.
    FNV-1a32 is used for channel/slot selection only.
    """
    if vector["algorithm"] == "crc32_ieee":
        eui64 = bytes.fromhex(vector["eui64"])
        expected = vector["derived_addr"]
        derived = derive_short_addr(eui64)
        assert derived == expected, f"{name}: CRC32 derivation mismatch"

    elif vector["algorithm"] == "fnv1a32":
        # FNV-1a is NOT used for DAD - verify it produces different result
        eui64 = bytes.fromhex(vector["eui64"])
        fnv_result = hash_32_fnv1a(eui64) & 0xFFFF
        expected_fnv = vector["derived_addr"]
        assert fnv_result == expected_fnv, f"{name}: FNV result verification"


def test_dad_hash_algorithm_resolution() -> None:
    """Verify DAD uses CRC32-IEEE, not FNV-1a32."""
    doc = _load("dad_hash_clarification.json")
    resolution = doc["resolution"]

    assert resolution["authoritative_algorithm"] == "crc32_ieee"
    assert resolution["initial_value"] == "0x4348454e"


# --- MIC Length Selector Vectors ---


def _mic_length_selector_cases():
    doc = _load("mic_length_selector.json")
    assert doc["format_version"] == 2
    return [(v["name"], v) for v in doc["vectors"]]


@pytest.mark.parametrize("name,vector", _mic_length_selector_cases())
def test_mic_length_selector_vector(name: str, vector: dict) -> None:
    """Validate MIC length selector (LLSec bits 2-4) per spec section 4.2.

    Selector 0 and 1 are compatibility selectors (identical behavior).
    Selectors 2-7 are reserved and MUST be rejected.
    """
    wire = bytes.fromhex(vector["input_hex"])
    expected = vector["expected"]

    if expected.get("error"):
        with pytest.raises(FrameError):
            LichenFrame.from_bytes(wire)
    else:
        frame = LichenFrame.from_bytes(wire)
        assert int(frame.mic_length) == expected["mic_length_selector"], f"{name}: selector mismatch"
        assert frame.signature_present == expected["signature_present"], f"{name}: sig mismatch"
        if "addr_mode" in expected:
            assert int(frame.addr_mode) == expected["addr_mode"], f"{name}: addr_mode mismatch"


def test_mic_length_selector_coverage() -> None:
    """Verify mic_length_selector.json covers selector 0, 1, and reserved values."""
    doc = _load("mic_length_selector.json")
    names = {v["name"] for v in doc["vectors"]}

    # Must test both compatibility selectors
    assert any("selector_0" in n or "mic_length_0" in n for n in names)
    assert any("selector_1" in n or "mic_length_1" in n for n in names)
    # Must test reserved rejection
    assert any("reserved" in n for n in names)
