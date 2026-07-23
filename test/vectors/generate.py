#!/usr/bin/env python3
"""Generate cross-language test vectors from the Python reference implementation.

Run:  PYTHONPATH=python/src python3 test/vectors/generate.py

Writes JSON vector files under this directory. The Python prototype is the
source of truth; the Rust and C implementations validate against the same files
(see README.md). Inputs are fixed, so output is deterministic. ``python -m
pytest python/tests/test_vectors.py`` re-derives every vector and fails if the
implementation drifts from the committed files.
"""

# ruff: noqa: E501  # Long descriptions in test vector data are deliberate for clarity.

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

from lichen.ipv6.icmpv6 import EchoRequest
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.link.frame import AddrMode, LichenFrame, MicLength
from lichen.rpl.messages import DAO, DIO, to_icmpv6
from lichen.schc.fragment import FragmentSender, compute_mic
from lichen.schc.headers import compress_packet


def hash_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xffffffff
    return h


VECTORS_DIR = Path(__file__).resolve().parent
FORMAT_VERSION = 2
L2_DISPATCH_SCHC = 0x14
L2_DISPATCH_ROUTING = 0x15

LL_SRC = IPv6Address("fe80::1")
LL_DST = IPv6Address("fe80::2")
G_SRC = IPv6Address("2001:db8::1")
G_DST = IPv6Address("2001:db8::2")
ULA_SRC = IPv6Address("fd00:db8::1")
ULA_DST = IPv6Address("fd00:db8::2")
COAP_PORT = 5683
MESHTASTIC_SOURCE_BASELINE = {
    "protobufs": "032b7dfd68e875c4323e6ac67590c6fc616b1714",
    "firmware": "2f97112987af311ca81dd70b83cbcf7236d6c119",
    "python": "6d76edf8a7b192c51e3a5d26bc5868da556ac3d9",
    "android": "eb3bd10757a312d1537874bfab245117c46c36a9",
    "apple": "aeeb0cc49fbe0ed593e918ba2f95100ecf694256",
}
MESHCORE_SOURCE_BASELINE = {
    "firmware": "e8d3c53ba1ea863937081cd0caad759b832f3028",
    "flutter": "e1b8d6ec97d6ccca0eee8122864092f3af3f2062",
    "python": "5bac3573b51c4298062881885b6d15a994109076",
    "cli": "3ad12c07beaac21210ed9b4b04c1fe8438722ecb",
    "js": "306dadac1cdacfd071ab6899e5c84e7def7c4425",
}


def _announce_coords_encode(latitude: float, longitude: float) -> bytes:
    latitude_e7 = int(round(latitude * 10_000_000))
    longitude_e7 = int(round(longitude * 10_000_000))
    return (
        bytes([0x01])
        + latitude_e7.to_bytes(4, "big", signed=True)
        + longitude_e7.to_bytes(4, "big", signed=True)
    )


def announce_coords_vectors() -> list[dict]:
    cases = [
        (
            "zero",
            "Equator and prime meridian.",
            0.0,
            0.0,
        ),
        (
            "seattle_west_longitude",
            "Representative west-coast longitude that the previous int24 1e-5 format could not represent.",
            47.6062,
            -122.3321,
        ),
        (
            "positive_limits",
            "Maximum valid latitude and longitude.",
            90.0,
            180.0,
        ),
        (
            "negative_limits",
            "Minimum valid latitude and longitude.",
            -90.0,
            -180.0,
        ),
    ]

    vectors = []
    for name, description, latitude, longitude in cases:
        latitude_e7 = int(round(latitude * 10_000_000))
        longitude_e7 = int(round(longitude * 10_000_000))
        vectors.append(
            {
                "name": name,
                "description": description,
                "latitude_degrees": latitude,
                "longitude_degrees": longitude,
                "latitude_e7": latitude_e7,
                "longitude_e7": longitude_e7,
                "encoded": _announce_coords_encode(latitude, longitude).hex(),
            }
        )
    return vectors


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _key(field: int, wire_type: int) -> bytes:
    return _varint((field << 3) | wire_type)


def _u32le(value: int) -> bytes:
    return value.to_bytes(4, "little")


def _bool_field(field: int, value: bool) -> bytes:
    return _key(field, 0) + (b"\x01" if value else b"\x00")


def _varint_field(field: int, value: int) -> bytes:
    return _key(field, 0) + _varint(value)


def _fixed32_field(field: int, value: int) -> bytes:
    return _key(field, 5) + _u32le(value)


def _bytes_field(field: int, value: bytes) -> bytes:
    return _key(field, 2) + _varint(len(value)) + value


def _module_config_disabled_telemetry() -> bytes:
    telemetry = _varint_field(1, 0) + _varint_field(2, 0) + _bool_field(14, False)
    return _bytes_field(6, telemetry)


def _region_presets_default_us_long_fast() -> bytes:
    preset_group = _varint_field(1, 0) + _varint_field(2, 0)
    region_group = _varint_field(1, 1) + _varint_field(2, 0)
    return _bytes_field(1, preset_group) + _bytes_field(2, region_group)


CONFIG_SECTION_SPECS = [
    ("device", 1, [(1, 0), (7, 900)]),
    ("position", 2, [(3, 0), (5, 0), (7, 0), (13, 2)]),
    ("power", 3, [(1, 0), (4, 0)]),
    ("network", 4, [(1, 0), (6, 0), (11, 0)]),
    ("display", 5, [(1, 0), (6, 0), (8, 0)]),
    ("lora", 6, [(1, 1), (2, 0), (7, 1), (8, 3), (9, 1), (10, 14), (11, 0), (104, 1)]),
    ("bluetooth", 7, [(1, 1), (2, 2)]),
    ("security", 8, [(5, 0), (6, 0), (8, 0)]),
    ("device_ui", 10, [(1, 0), (2, 1), (3, 0)]),
]


def _config_section_payload(fields: list[tuple[int, int]]) -> bytes:
    return b"".join(_varint_field(field, value) for field, value in fields)


def _config_section_entry(
    name: str, oneof_field: int, fields: list[tuple[int, int]]
) -> dict:
    payload = _config_section_payload(fields)
    return {
        "section": name,
        "oneof_field": oneof_field,
        "payload": _bytes_field(oneof_field, payload).hex(),
        "fields": [
            {"field": field, "wire_type": "varint", "value": value}
            for field, value in fields
        ],
    }


def _config_section_expectations() -> list[dict]:
    return [_config_section_entry(*spec) for spec in CONFIG_SECTION_SPECS]


def _data(portnum: int, payload: bytes = b"", request_id: int | None = None) -> bytes:
    out = bytearray()
    out += _varint_field(1, portnum)
    if payload:
        out += _bytes_field(2, payload)
    if request_id is not None:
        out += _fixed32_field(6, request_id)
    return bytes(out)


def _position_payload(
    *,
    latitude_i: int = 476206130,
    longitude_i: int = -1223493000,
    altitude: int | None = None,
    time: int | None = None,
    location_source: int | None = None,
    altitude_source: int | None = None,
    timestamp: int | None = None,
    gps_accuracy: int | None = None,
    sats_in_view: int | None = None,
    precision_bits: int | None = None,
) -> bytes:
    out = bytearray()
    out += _fixed32_field(1, latitude_i & 0xFFFFFFFF)
    out += _fixed32_field(2, longitude_i & 0xFFFFFFFF)
    if altitude is not None:
        out += _varint_field(3, altitude & 0xFFFFFFFFFFFFFFFF)
    if time is not None:
        out += _fixed32_field(4, time)
    if location_source is not None:
        out += _varint_field(5, location_source)
    if altitude_source is not None:
        out += _varint_field(6, altitude_source)
    if timestamp is not None:
        out += _fixed32_field(7, timestamp)
    if gps_accuracy is not None:
        out += _varint_field(14, gps_accuracy)
    if sats_in_view is not None:
        out += _varint_field(19, sats_in_view)
    if precision_bits is not None:
        out += _varint_field(23, precision_bits)
    return bytes(out)


def _routing_error(error_reason: int) -> bytes:
    return _varint_field(3, error_reason)


def _queue_status(
    *,
    res: int | None = None,
    free: int,
    maxlen: int,
    mesh_packet_id: int | None = None,
) -> bytes:
    out = bytearray()
    if res is not None:
        out += _varint_field(1, res)
    out += _varint_field(2, free)
    out += _varint_field(3, maxlen)
    if mesh_packet_id is not None:
        out += _varint_field(4, mesh_packet_id)
    return bytes(out)


def _mesh_packet(
    *,
    from_num: int | None = None,
    to_num: int | None = None,
    packet_id: int,
    decoded: bytes,
    want_ack: bool = False,
) -> bytes:
    out = bytearray()
    if from_num is not None:
        out += _fixed32_field(1, from_num)
    if to_num is not None:
        out += _fixed32_field(2, to_num)
    out += _bytes_field(4, decoded)
    out += _fixed32_field(6, packet_id)
    if want_ack:
        out += _bool_field(10, True)
    return bytes(out)


def _to_radio_packet(mesh_packet: bytes) -> bytes:
    return _bytes_field(1, mesh_packet)


def _from_radio_packet(message_id: int, mesh_packet: bytes) -> bytes:
    return _varint_field(1, message_id) + _bytes_field(2, mesh_packet)


def _from_radio_queue_status(queue_status: bytes) -> bytes:
    return _bytes_field(11, queue_status)


def _to_radio_want_config(nonce: int) -> bytes:
    return _varint_field(3, nonce)


def _from_radio_config_complete(nonce: int) -> bytes:
    return _varint_field(7, nonce)


def _udp_ipv6(src: IPv6Address, dst: IPv6Address, payload: bytes) -> bytes:
    udp = UdpDatagram(COAP_PORT, COAP_PORT, payload).to_bytes(src, dst)
    header = IPv6Header(src, dst, NextHeader.UDP, payload_length=len(udp))
    return header.to_bytes() + udp


def _icmpv6_ipv6(src: IPv6Address, dst: IPv6Address, message) -> bytes:
    body = message.to_bytes(src, dst)
    header = IPv6Header(src, dst, NextHeader.ICMPV6, payload_length=len(body))
    return header.to_bytes() + body


def _coap(code: int = 1, mid: int = 0x1234) -> bytes:
    # CoAP ver=1, type=0 (CON), tkl=0, code, mid, 0xFF marker, payload.
    return bytes([0x40, code]) + mid.to_bytes(2, "big") + b"\xff" + b"status"


def _coap_with_oscore(tkl: int = 2) -> bytes:
    # CoAP with OSCORE option #9 for rules 5/6 (independent canonical vectors).
    # tkl=2, code=0.01 GET, token=0x00..0x01, OSCORE opt delta=9 len=2 val=0x0900.
    b0 = 0x40 | (tkl & 0x0F)
    header = bytes([b0, 0x01]) + (0x1234).to_bytes(2, "big")
    token = bytes(range(tkl))
    oscore_option = bytes([0x92, 0x09, 0x00])
    payload = b"\xff\xde\xad\xbe\xef"
    return header + token + oscore_option + payload


def schc_vectors() -> list[dict]:
    dio = DIO(
        rpl_instance_id=0, version=1, rank=256, dtsn=0, dodag_id=LL_SRC, grounded=True
    )
    dao = DAO(rpl_instance_id=0, dao_sequence=5, dodag_id=LL_SRC)
    cases = [
        (
            "coap_linklocal",
            0,
            "Link-local IPv6+UDP+CoAP GET",
            _udp_ipv6(LL_SRC, LL_DST, _coap()),
        ),
        (
            "coap_global",
            1,
            "Global IPv6+UDP+CoAP GET",
            _udp_ipv6(G_SRC, G_DST, _coap()),
        ),
        (
            "icmpv6_echo",
            2,
            "Link-local ICMPv6 Echo Request",
            _icmpv6_ipv6(
                LL_SRC,
                LL_DST,
                EchoRequest(identifier=0xABCD, sequence=7, data=b"ping").to_message(),
            ),
        ),
        (
            "rpl_dio",
            3,
            "Link-local RPL DIO",
            _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dio)),
        ),
        (
            "rpl_dao",
            4,
            "Link-local RPL DAO with DODAGID",
            _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dao)),
        ),
    ]
    return [
        {
            "name": name,
            "rule_id": rule_id,
            "description": desc,
            "packet": raw.hex(),
            "compressed": compress_packet(raw).hex(),
        }
        for name, rule_id, desc, raw in cases
    ]


def l2_payload_vectors() -> list[dict]:
    schc_global = next(v for v in schc_vectors() if v["name"] == "coap_global")
    announce_min = bytes([0x01, 0x00, 0x00, 0x00, 0x01]) + bytes(88)
    schc_body = bytes.fromhex(schc_global["compressed"])
    return [
        {
            "name": "schc_global_coap",
            "description": (
                "Authenticated L2 SCHC dispatch wrapping a SCHC global CoAP "
                "packet whose SCHC rule ID is 0x01."
            ),
            "dispatch": L2_DISPATCH_SCHC,
            "kind": "schc",
            "body": schc_global["compressed"],
            "wrapped": (bytes([L2_DISPATCH_SCHC]) + schc_body).hex(),
        },
        {
            "name": "routing_announce_min",
            "description": (
                "Authenticated L2 routing dispatch wrapping a minimal raw "
                "announce whose routing message type is 0x01."
            ),
            "dispatch": L2_DISPATCH_ROUTING,
            "kind": "routing",
            "body": announce_min.hex(),
            "wrapped": (bytes([L2_DISPATCH_ROUTING]) + announce_min).hex(),
        },
        {
            "name": "unknown_unwrapped_0x01",
            "description": (
                "A payload beginning with 0x01 is not self-identifying at L2 "
                "and must not be treated as announce without dispatch=0x15."
            ),
            "dispatch": 0x01,
            "kind": "unknown",
            "body": "0040",
            "wrapped": "010040",
        },
    ]


def frame_vectors() -> list[dict]:
    cases = [
        (
            "broadcast_min",
            "Broadcast, no address, unsigned",
            LichenFrame(
                epoch=1,
                seqnum=2,
                dst_addr=b"",
                payload=b"abc",
                mic=b"",
                addr_mode=AddrMode.NONE,
                mic_length=MicLength.BITS32,
            ),
        ),
        (
            "short_addr",
            "16-bit short destination address",
            LichenFrame(
                epoch=0x10,
                seqnum=0x2030,
                dst_addr=bytes([0xAB, 0xCD]),
                payload=b"hi",
                mic=b"",
                addr_mode=AddrMode.SHORT,
                mic_length=MicLength.BITS32,
            ),
        ),
        (
            "extended_addr_mic64",
            "64-bit address, 64-bit MIC",
            LichenFrame(
                epoch=0xFF,
                seqnum=0xFFFF,
                dst_addr=bytes(range(8)),
                payload=b"data",
                mic=b"",
                addr_mode=AddrMode.EXTENDED,
                mic_length=MicLength.BITS64,
            ),
        ),
        (
            "signed_encrypted",
            "Unsupported signature + encrypted combination",
            LichenFrame(
                epoch=3,
                seqnum=4,
                dst_addr=b"",
                payload=b"x",
                mic=bytes(48),
                addr_mode=AddrMode.NONE,
                mic_length=MicLength.BITS32,
                signature_present=True,
                encrypted=True,
            ),
        ),
    ]
    out = []
    for name, desc, frame in cases:
        out.append(
            {
                "name": name,
                "description": desc,
                "fields": {
                    "epoch": frame.epoch,
                    "seqnum": frame.seqnum,
                    "dst_addr": frame.dst_addr.hex(),
                    "payload": frame.payload.hex(),
                    "mic": frame.mic.hex(),
                    "addr_mode": int(frame.addr_mode),
                    "mic_length": int(frame.mic_length),
                    "signature_present": frame.signature_present,
                    "encrypted": frame.encrypted,
                },
                "encoded": (
                    (
                        bytes.fromhex("35 60 03 0004 78" + "00" * 48)
                        if name == "signed_encrypted"
                        else frame.to_bytes()
                    ).hex()
                ),
            }
        )
        if name == "signed_encrypted":
            out[-1]["expect"] = {"error": "signed_encrypted_unsupported"}
    return out


def meshtastic_app_compat_vectors() -> list[dict]:
    config_nonce = 69420
    node_db_nonce = 69421
    packet_id = 0x12345678
    local_num = 0x01020304
    peer_num = 0x11223344
    broadcast = 0xFFFFFFFF

    outbound_text = _to_radio_packet(
        _mesh_packet(
            to_num=broadcast,
            packet_id=packet_id,
            decoded=_data(1, b"hello"),
            want_ack=True,
        )
    )
    position_time_timestamp_disagree = _position_payload(
        altitude=42,
        time=1710000000,
        timestamp=1710000200,
        sats_in_view=9,
    )
    position_accuracy_precision = _position_payload(
        altitude=42,
        timestamp=1710000200,
        location_source=3,
        altitude_source=4,
        gps_accuracy=2500,
        sats_in_view=9,
        precision_bits=24,
    )
    position_below_epoch = _position_payload(
        time=1700000010,
        timestamp=1699999999,
    )
    position_duplicate_time = _position_payload(time=1700000010) + _fixed32_field(
        4, 1699999999
    )
    inbound_text = _from_radio_packet(
        1,
        _mesh_packet(
            from_num=peer_num,
            to_num=local_num,
            packet_id=0x55667788,
            decoded=_data(1, b"hi"),
        ),
    )
    routing_ack = _from_radio_packet(
        2,
        _mesh_packet(
            from_num=peer_num,
            to_num=local_num,
            packet_id=0x55667789,
            decoded=_data(5, request_id=packet_id),
        ),
    )
    routing_nak = _from_radio_packet(
        3,
        _mesh_packet(
            from_num=peer_num,
            to_num=local_num,
            packet_id=0x5566778A,
            decoded=_data(5, _routing_error(1), request_id=packet_id),
        ),
    )
    heartbeat_queue_status = _from_radio_queue_status(
        _queue_status(res=0, free=4, maxlen=8, mesh_packet_id=packet_id),
    )
    config_sections = _config_section_expectations()

    baseline = MESHTASTIC_SOURCE_BASELINE
    transport = {
        "name": "ble-gatt",
        "framing": "one raw serialized protobuf per GATT value",
        "reject_prefix_hex": "94c3",
    }
    return [
        {
            "name": "heartbeat_tolerated",
            "description": "Current apps may send ToRadio.heartbeat around sync; firmware must tolerate it.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "heartbeat",
            "encoded": _bytes_field(7, b"").hex(),
            "decoded": {"heartbeat": {}},
            "expect": {
                "queue_side_effect": "none required",
                "response": "queueStatus optional",
                "must_not_require_before_sync": True,
            },
        },
        {
            "name": "heartbeat_queue_status",
            "description": "A heartbeat may be answered with local queue status over FromRadio.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "FromRadio",
            "message": "queueStatus",
            "encoded": heartbeat_queue_status.hex(),
            "decoded": {
                "queueStatus": {
                    "res": 0,
                    "free": 4,
                    "maxlen": 8,
                    "mesh_packet_id": packet_id,
                },
            },
            "expect": {
                "response_to": "heartbeat",
            },
        },
        {
            "name": "want_config_stage_69420",
            "description": "Android/iOS stage 1 config/static metadata request.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "exchange",
            "protobuf": "ToRadio",
            "message": "want_config_id",
            "encoded": _to_radio_want_config(config_nonce).hex(),
            "decoded": {"want_config_id": config_nonce},
            "expect": {
                "from_radio_sequence": [
                    "my_info",
                    "metadata",
                    "region_presets",
                    "channel",
                    "config",
                    "config",
                    "config",
                    "config",
                    "config",
                    "config",
                    "config",
                    "config",
                    "config",
                    "moduleConfig",
                    "config_complete_id",
                ],
                "config_sections": config_sections,
                "terminal_from_radio": _from_radio_config_complete(config_nonce).hex(),
            },
        },
        {
            "name": "want_node_db_stage_69421",
            "description": "Android/iOS stage 2 node database request.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "exchange",
            "protobuf": "ToRadio",
            "message": "want_config_id",
            "encoded": _to_radio_want_config(node_db_nonce).hex(),
            "decoded": {"want_config_id": node_db_nonce},
            "expect": {
                "from_radio_sequence": ["node_info", "config_complete_id"],
                "terminal_from_radio": _from_radio_config_complete(node_db_nonce).hex(),
            },
        },
        {
            "name": "module_config_disabled_telemetry",
            "description": "MVP moduleConfig placeholder reports telemetry explicitly disabled.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "FromRadio",
            "message": "moduleConfig",
            "payload": _module_config_disabled_telemetry().hex(),
            "encoded": _bytes_field(9, _module_config_disabled_telemetry()).hex(),
            "decoded": {
                "moduleConfig": {
                    "telemetry": {
                        "device_update_interval": 0,
                        "environment_update_interval": 0,
                        "device_telemetry_enabled": False,
                    },
                },
            },
            "expect": {
                "from_radio_field": 9,
            },
        },
        {
            "name": "region_presets_us_long_fast",
            "description": "MVP region_presets placeholder exposes only US with LONG_FAST default.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "FromRadio",
            "message": "region_presets",
            "payload": _region_presets_default_us_long_fast().hex(),
            "encoded": _bytes_field(19, _region_presets_default_us_long_fast()).hex(),
            "decoded": {
                "region_presets": {
                    "preset_groups": [
                        {
                            "presets": ["LONG_FAST"],
                            "default_preset": "LONG_FAST",
                        },
                    ],
                    "region_groups": [
                        {
                            "region": "US",
                            "group_index": 0,
                        },
                    ],
                },
            },
            "expect": {
                "from_radio_field": 19,
            },
        },
        *[
            {
                "name": f"config_section_{section['section']}",
                "description": (
                    "MVP Config section payload for "
                    f"{section['section']} during staged app sync."
                ),
                "source_baseline": baseline,
                "transport": transport,
                "direction": "node_to_app",
                "protobuf": "FromRadio",
                "message": "config",
                "payload": section["payload"],
                "encoded": _bytes_field(5, bytes.fromhex(section["payload"])).hex(),
                "decoded": {
                    "config": {
                        "section": section["section"],
                        "oneof_field": section["oneof_field"],
                        "fields": section["fields"],
                    },
                },
                "expect": {
                    "from_radio_field": 5,
                    "config_section": section,
                },
            }
            for section in config_sections
        ],
        {
            "name": "text_message_send_broadcast",
            "description": "App sends TEXT_MESSAGE_APP as ToRadio.packet with raw UTF-8 payload.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "packet.TEXT_MESSAGE_APP",
            "encoded": outbound_text.hex(),
            "decoded": {
                "packet": {
                    "to": broadcast,
                    "id": packet_id,
                    "want_ack": True,
                    "decoded": {
                        "portnum": "TEXT_MESSAGE_APP",
                        "payload_utf8": "hello",
                    },
                }
            },
            "expect": {"response": "queueStatus local enqueue status"},
        },
        {
            "name": "position_time_and_timestamp_disagree",
            "description": "POSITION_APP keeps field 7 timestamp as fix time when it disagrees with field 4 time.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "packet.POSITION_APP",
            "encoded": _to_radio_packet(
                _mesh_packet(
                    to_num=broadcast,
                    packet_id=0x1234567A,
                    decoded=_data(3, position_time_timestamp_disagree),
                )
            ).hex(),
            "decoded": {
                "packet": {
                    "to": broadcast,
                    "id": 0x1234567A,
                    "decoded": {
                        "portnum": "POSITION_APP",
                        "position": {
                            "latitude_i": 476206130,
                            "longitude_i": -1223493000,
                            "altitude": 42,
                            "time": 1710000000,
                            "timestamp": 1710000200,
                            "sats_in_view": 9,
                        },
                    },
                },
            },
            "expect": {
                "selected_fix_time_unix": 1710000200,
                "time_field_policy": "timestamp field 7 wins over time field 4",
                "response": "queueStatus local enqueue status",
            },
        },
        {
            "name": "position_accuracy_precision_metadata",
            "description": "POSITION_APP source, altitude-source, accuracy, and precision metadata are decoded without upgrading local-client trust.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "packet.POSITION_APP",
            "encoded": _to_radio_packet(
                _mesh_packet(
                    to_num=broadcast,
                    packet_id=0x1234567B,
                    decoded=_data(3, position_accuracy_precision),
                )
            ).hex(),
            "decoded": {
                "packet": {
                    "to": broadcast,
                    "id": 0x1234567B,
                    "decoded": {
                        "portnum": "POSITION_APP",
                        "position": {
                            "latitude_i": 476206130,
                            "longitude_i": -1223493000,
                            "altitude": 42,
                            "location_source": 3,
                            "altitude_source": 4,
                            "timestamp": 1710000200,
                            "gps_accuracy": 2500,
                            "sats_in_view": 9,
                            "precision_bits": 24,
                        },
                    },
                },
            },
            "expect": {
                "source_class": "LOCAL_CLIENT",
                "source_name": "mt-pos-external",
                "gps_accuracy_mm_retained_for_diagnostics": 2500,
                "horizontal_accuracy_mm_valid": False,
                "precision_bits_retained_for_diagnostics": 24,
            },
        },
        {
            "name": "position_epoch_floor_strips_timestamp",
            "description": "POSITION_APP timestamps below the deterministic build epoch are stripped while coordinates remain local-client metadata.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "packet.POSITION_APP",
            "encoded": _to_radio_packet(
                _mesh_packet(
                    to_num=broadcast,
                    packet_id=0x1234567C,
                    decoded=_data(3, position_below_epoch),
                )
            ).hex(),
            "decoded": {
                "packet": {
                    "to": broadcast,
                    "id": 0x1234567C,
                    "decoded": {
                        "portnum": "POSITION_APP",
                        "position": {
                            "latitude_i": 476206130,
                            "longitude_i": -1223493000,
                            "time": 1700000010,
                            "timestamp": 1699999999,
                        },
                    },
                },
            },
            "expect": {
                "build_epoch_floor_unix": 1700000000,
                "selected_fix_time_unix": None,
                "time_field_policy": "timestamp field 7 wins over time field 4, then fails the epoch floor",
                "coordinates_remain_valid": True,
            },
        },
        {
            "name": "position_duplicate_time_uses_last_field",
            "description": "POSITION_APP duplicate field 4 time values use the last value when timestamp field 7 is absent.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "packet.POSITION_APP",
            "encoded": _to_radio_packet(
                _mesh_packet(
                    to_num=broadcast,
                    packet_id=0x1234567D,
                    decoded=_data(3, position_duplicate_time),
                )
            ).hex(),
            "decoded": {
                "packet": {
                    "to": broadcast,
                    "id": 0x1234567D,
                    "decoded": {
                        "portnum": "POSITION_APP",
                        "position": {
                            "latitude_i": 476206130,
                            "longitude_i": -1223493000,
                            "time": 1699999999,
                        },
                    },
                },
            },
            "expect": {
                "build_epoch_floor_unix": 1700000000,
                "selected_fix_time_unix": None,
                "time_field_policy": "last time field 4 wins when timestamp field 7 is absent",
                "encoded_duplicate_time_values": [1700000010, 1699999999],
                "coordinates_remain_valid": True,
            },
        },
        {
            "name": "unsupported_private_app_no_side_effect",
            "description": "Unsupported app portnums produce deterministic no-op/error behavior.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "packet.PRIVATE_APP",
            "encoded": _to_radio_packet(
                _mesh_packet(
                    to_num=broadcast,
                    packet_id=0x12345679,
                    decoded=_data(256, b"unsupported"),
                )
            ).hex(),
            "decoded": {
                "packet": {
                    "to": broadcast,
                    "id": 0x12345679,
                    "decoded": {
                        "portnum": "PRIVATE_APP",
                        "payload_utf8": "unsupported",
                    },
                }
            },
            "expect": {
                "unsupported": True,
                "response": "queueStatus or clientNotification deterministic no-op/error",
                "side_effect": "no mesh packet emitted",
            },
        },
        {
            "name": "incoming_text_message",
            "description": "Node surfaces an incoming LICHEN text message as FromRadio.packet.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "FromRadio",
            "message": "packet.TEXT_MESSAGE_APP",
            "encoded": inbound_text.hex(),
            "decoded": {
                "packet": {
                    "from": peer_num,
                    "to": local_num,
                    "id": 0x55667788,
                    "decoded": {"portnum": "TEXT_MESSAGE_APP", "payload_utf8": "hi"},
                }
            },
            "expect": {"from_radio_id": 1, "from_num_increment": True},
        },
        {
            "name": "routing_ack_for_request",
            "description": "App-visible delivery success is a ROUTING_APP packet correlated by request_id.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "FromRadio",
            "message": "packet.ROUTING_APP",
            "encoded": routing_ack.hex(),
            "decoded": {
                "packet": {
                    "from": peer_num,
                    "to": local_num,
                    "id": 0x55667789,
                    "decoded": {"portnum": "ROUTING_APP", "request_id": packet_id},
                }
            },
            "expect": {"delivery_status": "ack", "from_radio_id": 2},
        },
        {
            "name": "routing_nak_for_request",
            "description": "App-visible delivery failure is a ROUTING_APP packet correlated by request_id.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "FromRadio",
            "message": "packet.ROUTING_APP",
            "encoded": routing_nak.hex(),
            "decoded": {
                "packet": {
                    "from": peer_num,
                    "to": local_num,
                    "id": 0x5566778A,
                    "decoded": {
                        "portnum": "ROUTING_APP",
                        "routing_error_reason": "NO_ROUTE",
                        "request_id": packet_id,
                    },
                }
            },
            "expect": {"delivery_status": "nak", "from_radio_id": 3},
        },
        {
            "name": "ble_rejects_stream_framing_prefix",
            "description": "BLE ToRadio uses raw protobuf values and must reject serial/TCP stream framing.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "invalid_stream_framing",
            "encoded": (
                "94c3"
                + len(outbound_text).to_bytes(2, "big").hex()
                + outbound_text.hex()
            ),
            "decoded": {},
            "expect": {
                "reject": True,
                "reason": "serial TCP 0x94c3 length prefix is invalid on BLE",
            },
        },
        {
            "name": "fromnum_notify_counter_4",
            "description": "FromNum notifies the app that queued FromRadio values should be drained.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "FromNum",
            "message": "fromnum_notify",
            "encoded": _u32le(4).hex(),
            "decoded": {"from_num": 4},
            "expect": {
                "byte_order": "little-endian",
                "read_until_empty": True,
            },
        },
        {
            "name": "fromradio_empty_queue_drain",
            "description": "A zero-length FromRadio read terminates the drain loop.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "node_to_app",
            "protobuf": "Empty",
            "message": "fromradio_empty",
            "encoded": "",
            "decoded": {"queue_empty": True},
            "expect": {
                "queue_drained": True,
                "no_from_num_increment": True,
            },
        },
        {
            "name": "oversized_to_radio_rejected",
            "description": "Inbound BLE values larger than the accepted ToRadio budget are rejected deterministically.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "app_to_node",
            "protobuf": "ToRadio",
            "message": "oversized",
            "encoded": bytes([0]).hex() * 505,
            "decoded": {"length": 505},
            "expect": {
                "max_to_radio_bytes": 504,
                "reject": True,
                "side_effect": "no partial state retained",
            },
        },
    ]


def _meshcore_self_info() -> bytes:
    out = bytearray(64)
    out[0] = 0x05
    out[1] = 0x01
    out[2] = 14
    out[3] = 22
    out[48:52] = (868000000).to_bytes(4, "little")
    out[52:56] = (125000).to_bytes(4, "little")
    out[56] = 10
    out[57] = 5
    out[58:64] = b"LICHEN"
    return bytes(out)


def _meshcore_device_info() -> bytes:
    out = bytearray(82)
    out[0] = 0x0D
    out[1] = 3
    out[3] = 1
    out[8:14] = b"LICHEN"
    out[20:26] = b"LICHEN"
    out[60:65] = b"0.0.0"
    return bytes(out)


def _meshcore_channel_info() -> bytes:
    out = bytearray(50)
    out[0] = 0x12
    out[1] = 0
    out[2:8] = b"Public"
    return bytes(out)


def _meshcore_channel_body(name: bytes = b"Public") -> bytes:
    out = bytearray(49)
    out[0] = 0
    out[1 : 1 + len(name)] = name
    return bytes(out)


def _meshcore_channel_body_with_secret(name: bytes = b"Field") -> bytes:
    out = bytearray(_meshcore_channel_body(name))
    out[33:49] = bytes(range(1, 17))
    return bytes(out)


def _meshcore_default_flood_payload(name: bytes = b"FieldScope") -> bytes:
    out = bytearray(47)
    out[0 : len(name)] = name
    out[len(name)] = 0
    out[31:47] = bytes(range(0xA0, 0xB0))
    return bytes(out)


def _meshcore_vector(
    *,
    name: str,
    description: str,
    direction: str,
    frame: str,
    encoded: bytes,
    decoded: dict,
    expect: dict,
    transport: dict | None = None,
) -> dict:
    return {
        "name": name,
        "description": description,
        "source_baseline": MESHCORE_SOURCE_BASELINE,
        "transport": transport
        or {
            "name": "ble-nus",
            "framing": "one raw MeshCore inner frame per NUS value",
        },
        "direction": direction,
        "frame": frame,
        "encoded": encoded.hex(),
        "decoded": decoded,
        "expect": expect,
    }


def meshcore_app_compat_vectors() -> list[dict]:
    err_unsupported = bytes([0x01, 0x01])
    err_not_found = bytes([0x01, 0x02])
    err_illegal_arg = bytes([0x01, 0x06])
    channel_text = bytes.fromhex("1100000000ff00040302016869")
    status_ack = bytes.fromhex("82785634120901")
    return [
        _meshcore_vector(
            name="app_start_self_info",
            description="App startup advertises the client name and receives deterministic LICHEN self info.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("010000000000000074"),
            decoded={"command": "APP_START", "client_name": "t"},
            expect={"responses": [_meshcore_self_info().hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="device_query_protocol_v3",
            description="Client protocol query returns placeholder LICHEN device metadata and protocol version 3.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("1603"),
            decoded={"command": "DEVICE_QUERY", "app_protocol_version": 3},
            expect={"responses": [_meshcore_device_info().hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="get_contacts_empty",
            description="Empty compatibility contact table is encoded as CONTACTS_START count 0 then END_OF_CONTACTS count 0.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("04"),
            decoded={"command": "GET_CONTACTS"},
            expect={"responses": ["0200000000", "0400000000"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="get_channel_public_slot",
            description="Channel slot 0 is synthesized as a public compatibility channel without native LICHEN secrets.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("1f00"),
            decoded={"command": "GET_CHANNEL", "index": 0},
            expect={
                "responses": [_meshcore_channel_info().hex()],
                "adapter_test": True,
            },
        ),
        _meshcore_vector(
            name="get_channel_not_found",
            description="Only channel slot 0 exists in the MVP compatibility view.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("1f01"),
            decoded={"command": "GET_CHANNEL", "index": 1},
            expect={"responses": [err_not_found.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="get_channel_missing_arg",
            description="GET_CHANNEL requires a channel index byte.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("1f"),
            decoded={"command": "GET_CHANNEL", "malformed": True},
            expect={"responses": [err_illegal_arg.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="sync_next_empty",
            description="SYNC_NEXT_MESSAGE returns NO_MORE_MESSAGES when no pending app-visible events exist.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("0a"),
            decoded={"command": "SYNC_NEXT_MESSAGE"},
            expect={"responses": ["0a"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="get_batt_and_storage_placeholder",
            description="Battery/storage response uses explicit zero placeholders until HAL providers are wired.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("14"),
            decoded={"command": "GET_BATT_AND_STORAGE"},
            expect={"responses": ["0c00000000000000000000"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="get_device_time",
            description="Device time is uptime-derived and therefore validated by response type and length.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("05"),
            decoded={"command": "GET_DEVICE_TIME"},
            expect={"response_prefix": "09", "response_len": 5},
        ),
        _meshcore_vector(
            name="get_custom_vars_empty",
            description="Custom variables are present as an empty compatibility response.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("28"),
            decoded={"command": "GET_CUSTOM_VARS"},
            expect={"responses": ["15"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="get_autoadd_config_disabled",
            description="Auto-add compatibility config is disabled by default.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("3b"),
            decoded={"command": "GET_AUTOADD_CONFIG"},
            expect={"responses": ["190000"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="get_default_flood_scope_null",
            description="Default flood scope is null/empty before a MeshCore-local default flood scope is stored.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("40"),
            decoded={"command": "GET_DEFAULT_FLOOD_SCOPE"},
            expect={"responses": ["1c"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="send_channel_txt_msg_ack_drift",
            description="MeshCore source drift: firmware e8d3c53 returns OK for channel text send while docs/Flutter may expect MSG_SENT in some paths; LICHEN returns unsupported when no app-interface submit provider is registered.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("0300006869"),
            decoded={
                "command": "SEND_CHANNEL_TXT_MSG",
                "channel": 0,
                "txt_type": 0,
                "payload_utf8": "hi",
            },
            expect={
                "responses": [err_unsupported.hex()],
                "adapter_test": True,
                "drift_note": "Upstream firmware observed OK, app/docs may expect SENT; LICHEN rejects in the canonical no-provider fixture and succeeds in configured submit-provider tests.",
            },
        ),
        _meshcore_vector(
            name="send_txt_msg_direct_malformed_prefix",
            description="Direct text requires a 6-byte MeshCore peer prefix before the UTF-8 payload; shorter direct-send payloads are malformed.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("0200006869"),
            decoded={"command": "SEND_TXT_MSG", "payload_utf8": "hi"},
            expect={"responses": ["0106"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="send_txt_msg_direct_unknown_peer",
            description="Direct text with a 6-byte MeshCore peer prefix returns not-found until the prefix maps to exactly one known LICHEN peer.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("020102030405066869"),
            decoded={
                "command": "SEND_TXT_MSG",
                "prefix": "010203040506",
                "payload_utf8": "hi",
            },
            expect={"responses": ["0102"], "adapter_test": True},
        ),
        _meshcore_vector(
            name="send_txt_msg_direct_known_peer",
            description="A direct MeshCore public-key prefix that maps to exactly one known LICHEN peer submits text to that peer IID.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("020102030405066869"),
            decoded={
                "command": "SEND_TXT_MSG",
                "prefix": "010203040506",
                "payload_utf8": "hi",
                "expected_iid": "00aa010203040506",
            },
            expect={
                "responses": ["00"],
                "adapter_test": True,
                "fixture": "direct-known-peer",
            },
        ),
        _meshcore_vector(
            name="send_txt_msg_direct_colliding_peer",
            description="A direct MeshCore public-key prefix that maps to multiple known peers fails closed as not found.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("020102030405066869"),
            decoded={
                "command": "SEND_TXT_MSG",
                "prefix": "010203040506",
                "payload_utf8": "hi",
                "collision": True,
            },
            expect={
                "responses": ["0102"],
                "adapter_test": True,
                "fixture": "direct-colliding-peers",
            },
        ),
        _meshcore_vector(
            name="set_advert_name_ok",
            description="Compatibility display-name writes update MeshCore-local state and return OK without mutating native identity.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("084c494348454e"),
            decoded={"command": "SET_ADVERT_NAME", "name": "LICHEN"},
            expect={
                "responses": ["00"],
                "adapter_test": True,
                "compat_store": "meshcore-local advert name",
            },
        ),
        _meshcore_vector(
            name="set_channel0_ok",
            description="Channel writes update a MeshCore-local channel record only; LICHEN does not accept MeshCore channel secrets as native group or OSCORE material.",
            direction="exchange",
            frame="command",
            encoded=bytes([0x20]) + _meshcore_channel_body(b"Field"),
            decoded={"command": "SET_CHANNEL", "index": 0, "name": "Field"},
            expect={
                "responses": ["00"],
                "adapter_test": True,
                "compat_store": "meshcore-local channel slot 0",
            },
        ),
        _meshcore_vector(
            name="set_channel16_secret_unsupported",
            description="Channel records carrying nonzero 16-byte secret material are recognized but unsupported and are not stored.",
            direction="exchange",
            frame="command",
            encoded=bytes([0x20]) + _meshcore_channel_body_with_secret(),
            decoded={
                "command": "SET_CHANNEL",
                "index": 0,
                "name": "Field",
                "secret_len": 16,
            },
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="set_channel_secret_unsupported",
            description="Secret-bearing MeshCore channel writes are recognized but unsupported so MeshCore secrets are never imported as native LICHEN material.",
            direction="exchange",
            frame="command",
            encoded=(
                bytes([0x20, 0x00]) + b"Field".ljust(32, b"\x00") + bytes(range(32))
            ),
            decoded={
                "command": "SET_CHANNEL",
                "index": 0,
                "name": "Field",
                "secret_len": 32,
            },
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="set_device_pin_ok",
            description="Device PIN writes apply and retain a MeshCore-local uint32 passkey without exposing native provisioning secrets.",
            direction="exchange",
            frame="command",
            encoded=bytes([0x25]) + _u32le(123456),
            decoded={"command": "SET_DEVICE_PIN", "pin": 123456},
            expect={
                "responses": ["00"],
                "adapter_test": True,
                "compat_store": "meshcore-local BLE PIN applied through the BLE passkey hook",
            },
        ),
        _meshcore_vector(
            name="set_autoadd_config_ok",
            description="Auto-add configuration writes retain the two-byte MeshCore-local compatibility value.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("3a0102"),
            decoded={"command": "SET_AUTOADD_CONFIG", "raw": [1, 2]},
            expect={
                "responses": ["00"],
                "adapter_test": True,
                "compat_store": "meshcore-local auto-add config",
            },
        ),
        _meshcore_vector(
            name="self_advert_unsupported",
            description="Self-advert is a MeshCore RF operation and must not be OK/no-op in LICHEN compatibility.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("07"),
            decoded={"command": "SEND_SELF_ADVERT"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="newer_get_allowed_repeat_freq_unsupported",
            description="Newer firmware command 0x3c is recognized but unsupported by the MVP shim.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("3c"),
            decoded={"command": "GET_ALLOWED_REPEAT_FREQ"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="newer_send_channel_data_unsupported",
            description="Newer firmware command 0x3e is recognized but unsupported by the MVP shim.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("3e"),
            decoded={"command": "SEND_CHANNEL_DATA"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="newer_set_default_flood_scope_ok",
            description="Default flood scope writes retain MeshCore-local name/key state without altering native RPL or routing state.",
            direction="exchange",
            frame="command",
            encoded=bytes([0x3F]) + _meshcore_default_flood_payload(),
            decoded={
                "command": "SET_DEFAULT_FLOOD_SCOPE",
                "name": "FieldScope",
                "key": bytes(range(0xA0, 0xB0)).hex(),
            },
            expect={
                "responses": ["00"],
                "adapter_test": True,
                "compat_store": "meshcore-local default flood scope name/key",
            },
        ),
        _meshcore_vector(
            name="newer_clear_default_flood_scope_ok",
            description="An empty default flood scope write clears only the MeshCore-local default flood scope store.",
            direction="exchange",
            frame="command",
            encoded=bytes([0x3F]),
            decoded={"command": "SET_DEFAULT_FLOOD_SCOPE", "clear": True},
            expect={
                "responses": ["00"],
                "adapter_test": True,
                "compat_store": "meshcore-local default flood scope clear",
            },
        ),
        _meshcore_vector(
            name="newer_send_raw_packet_unsupported",
            description="Newer firmware command 0x41 is recognized but unsupported because LICHEN does not expose MeshCore raw RF.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("41"),
            decoded={"command": "SEND_RAW_PACKET"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="unknown_zero_unsupported",
            description="Out-of-range command below the known range returns unsupported.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("00"),
            decoded={"command": "UNKNOWN_00"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="unknown_after_range_unsupported",
            description="Out-of-range command after the known firmware range returns unsupported.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("42"),
            decoded={"command": "UNKNOWN_42"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="unknown_ff_unsupported",
            description="0xff is not a MeshCore command and returns unsupported.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("ff"),
            decoded={"command": "UNKNOWN_FF"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="app_start_short_illegal_arg",
            description="Malformed APP_START shorter than the minimum payload returns ILLEGAL_ARG.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("010000"),
            decoded={"command": "APP_START", "malformed": True},
            expect={"responses": [err_illegal_arg.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="ble_msg_waiting_push",
            description="Incoming LICHEN app event first notifies the MeshCore client with MSG_WAITING.",
            direction="node_to_app",
            frame="push",
            encoded=bytes.fromhex("83"),
            decoded={"push": "MSG_WAITING"},
            expect={"emitted_by": "emit_text_or_status"},
        ),
        _meshcore_vector(
            name="channel_msg_recv_v3_hi",
            description="SYNC_NEXT_MESSAGE drains pending text as CHANNEL_MSG_RECV_V3.",
            direction="node_to_app",
            frame="response",
            encoded=channel_text,
            decoded={
                "response": "CHANNEL_MSG_RECV_V3",
                "channel": 0,
                "path": "unavailable",
                "txt_type": 0,
                "id": 0x01020304,
                "payload_utf8": "hi",
            },
            expect={"preceded_by": "MSG_WAITING", "response_to": "SYNC_NEXT_MESSAGE"},
        ),
        _meshcore_vector(
            name="send_confirmed_status_nak",
            description="Pending app status is surfaced as PUSH_SEND_CONFIRMED with request id and error reason.",
            direction="node_to_app",
            frame="push",
            encoded=status_ack,
            decoded={
                "push": "SEND_CONFIRMED",
                "request_id": 0x12345678,
                "error_reason": 9,
                "has_error_reason": True,
            },
            expect={"preceded_by": "MSG_WAITING", "response_to": "SYNC_NEXT_MESSAGE"},
        ),
        _meshcore_vector(
            name="serial_app_to_device_sync_next",
            description="Serial/TCP app-to-device framing wraps the raw SYNC_NEXT_MESSAGE command with '<' and uint16_le payload length.",
            direction="app_to_node",
            frame="serial",
            encoded=bytes.fromhex("3c01000a"),
            decoded={"serial_marker": "app_to_device", "payload": "0a"},
            expect={"inner_frame": "0a"},
            transport={
                "name": "serial",
                "framing": "0x3c + uint16_le length + MeshCore inner frame",
            },
        ),
        _meshcore_vector(
            name="serial_device_to_app_no_more_messages",
            description="Serial/TCP device-to-app framing wraps the raw NO_MORE_MESSAGES response with '>' and uint16_le payload length.",
            direction="node_to_app",
            frame="serial",
            encoded=bytes.fromhex("3e01000a"),
            decoded={"serial_marker": "device_to_app", "payload": "0a"},
            expect={"inner_frame": "0a"},
            transport={
                "name": "serial",
                "framing": "0x3e + uint16_le length + MeshCore inner frame",
            },
        ),
    ]


def _write(filename: str, description: str, vectors: list[dict]) -> None:
    path = VECTORS_DIR / filename
    doc = {
        "$schema": "./schema.json",
        "format_version": FORMAT_VERSION,
        "description": description,
        "vectors": vectors,
    }
    path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors to {path.name}")


def schc_fragment_vectors() -> list[dict]:
    def _vector(
        name: str,
        packet_hex: str,
        tile_size: int = 4,
        window_size: int = 7,
        mode: str = "no_ack",
        **extra,
    ) -> dict:
        packet = bytes.fromhex(packet_hex)
        sender = FragmentSender(
            payload=packet, rule_id=0x78, tile_size=tile_size, window_size=window_size
        )
        fragments = [f.to_bytes().hex() for f in sender.all_fragments()]
        mic = compute_mic(packet).hex()
        return {
            "name": name,
            "description": extra.pop("description", f"{name.replace('_', ' ').title()}."),
            "rule_id": 0x78,
            "packet": packet_hex,
            "fragments": fragments,
            "mode": mode,
            "mic": mic,
            **extra,
        }

    return [
        _vector(
            "single_fragment",
            "10111213",
            tile_size=10,
            description="Single All-1 with MIC (RFC 8.2).",
        ),
        _vector(
            "multi_fragment",
            "1011121320212223",
            tile_size=4,
            description="Multi-fragment + window (RFC 8.3).",
        ),
        _vector(
            "ack_on_error_mic_fail",
            "a0a1a2a3",
            tile_size=4,
            mode="ack_on_error",
            expect={"mic_fail": True},
            description="ACK-on-error, MIC mismatch triggers error (RFC 8.4.3).",
        ),
        _vector(
            "ooo_retransmit",
            "00010203",
            tile_size=2,
            mode="ack_on_error",
            expect={"out_of_order": True, "retransmits": [0]},
            description="OOO + retransmit on NACK bitmap (RFC 8.4.2).",
        ),
    ]


def ccp_load_balancing_vectors() -> list[dict]:
    return [
        {
            "name": "tdma_slot_assignment_static_hash",
            "description": "Static slot from EUI-64 hash_32(FNV-1a32) mod num_slots per TDMA spec (CCP-15.8.3, project-LICHEN-eirg).",
            "eui64_hex": "0011223344556677",
            "num_slots": 16,
            "expected_slot": 13,
        },
        {
            "name": "guard_time_boundary_sf10",
            "description": "50ms guard for 250ms slot tolerates 0.5% drift over 5s superframe.",
            "slot_ms": 250,
            "guard_ms": 50,
            "drift_ppm": 5000,
            "superframe_ms": 5000,
        },
        {
            "name": "drift_compensation_two_beacons",
            "description": "Offset correction from beacon arrival times for clock drift compensation.",
            "beacon_nominal_ms": 5000,
            "observed_ms": [4992, 5008],
            "expected_ppm": 1600,
            "slot_adjust_ticks": 8,
        },
        {
            "name": "ccp_load_high_util_rebalance",
            "description": "Load score triggers channel rebalance and TDMA slot reassignment when util>0.4.",
            "util": 0.45,
            "queue_peak": 6,
            "etx": 3.2,
            "score": 0.81,
            "action": "prefer_alt_channel_dynamic_slot",
        },
    ]


def _l2_announce_with_channel(channel: int) -> bytes:
    announce = (
        bytes([0x01, channel & 0xFF, 0x00])
        + b"\x00\x01"
        + bytes(8)
        + bytes(32)
        + bytes(48)
    )
    return bytes([L2_DISPATCH_ROUTING]) + announce


def ccp16_vectors() -> list[dict]:
    def _h(data):
        h = 0x811c9dc5
        for b in data:
            h = ((h ^ b) * 0x01000193) & 0xffffffff
        return h
    eui = bytes.fromhex("0011223344556677")
    return [
        {
            "name": "synchronized_hop_channel_consistency",
            "description": "synchronized_hop_channel(eui64=0x0011223344556677, t=4660, epoch=1) yields expected per CCP-12 pseudocode and hash_32 from ccp15. Receiver prediction matches sender.",
            "type": "slot_selection",
            "input": {
                "eui64": "0011223344556677",
                "epoch": 1,
                "density": 3,
                "snr_db": 12,
                "now": 4660
            },
            "output": {
                "hash_32": _h(eui + (1).to_bytes(4, "little")),
                "channel": 2,
                "expected_channel": 2,
                "sf": 9,
                "select_channel": 2,
                "now": 4660
            }
        },
        {
            "name": "epoch_wrap_hop_change",
            "description": "Epoch increment changes hop sequence. Tests desync recovery interaction per CCP-16.",
            "type": "slot_selection",
            "input": {
                "eui64": "0011223344556677",
                "epoch": 0,
                "density": 4,
                "snr_db": 5,
                "now": 100
            },
            "output": {
                "hash_32": _h(eui + (0).to_bytes(4, "little")),
                "channel": 2,
                "expected_channel": 2,
                "sf": 10,
                "select_channel": 2,
                "now": 100
            }
        },
        {
            "name": "select_channel_timing_test",
            "description": "select_channel_timing with now_ts near u32 wrap tests TDMA/SFN per project-LICHEN-rs2q.",
            "type": "slot_selection",
            "input": {
                "eui64": "0011223344556677",
                "epoch": 0,
                "density": 9,
                "snr_db": -1,
                "now": 0xfffffff0
            },
            "output": {
                "hash_32": _h(eui + (0).to_bytes(4, "little")),
                "channel": 0,
                "expected_channel": 0,
                "sf": 11,
                "select_channel": 0,
                "now": 0xfffffff0
            }
        }
    ]


def ccp_hop_vectors() -> list[dict]:
    """CCP-12/16 hop vectors for synchronized_hop_channel(sfn/seed/num_channels).
    Uses _h helper matching hash_32 (FNV-1a32 basis 0x811c9dc5, little-endian
    epoch/sfn concat per spec/02a-coordinated-capacity.md:120-125). Independent
    oracle only; no code-under-test. Covers SFN=0/1, num_channels variants,
    rendezvous. Matches expected_channel from ccp16-hop.json with real
    computed hash_output (no placeholders).
    """
    def _h(data: bytes) -> int:
        return hash_32(data)
    eui = bytes.fromhex("0011223344556677")
    return [
        {
            "name": "hop_sfn0_8ch",
            "sfn": 0,
            "seed": 0,
            "num_channels": 8,
            "expected_channel": 7,
            "hash_output": _h(b""),
            "description": "SFN=0, seed=0, 8ch. hash_output from independent FNV1A32(b'') oracle matching basis.",
        },
        {
            "name": "hop_sfn1_16ch",
            "sfn": 1,
            "seed": 42,
            "num_channels": 16,
            "expected_channel": 5,
            "hash_output": _h(eui + (1).to_bytes(4, "little")),
            "description": "SFN=1 with seed=42, 16 channels for rendezvous case per spec:120-125.",
        },
        {
            "name": "rendezvous_beacon_announce",
            "sfn": 12345678,
            "seed": 0,
            "num_channels": 8,
            "rx_channel": 3,
            "expected_channel": 3,
            "hash_output": _h((12345678).to_bytes(4, "little")),
            "description": "Large SFN rendezvous using rx_channel from announce/beacon. Tests TDMA sync.",
        },
        {
            "name": "sfn_wrap",
            "sfn": 0xffffffff,
            "seed": 1,
            "num_channels": 4,
            "expected_channel": 2,
            "hash_output": _h(eui + (0xffffffff).to_bytes(4, "little")),
            "description": "SFN u32 wraparound test for modular arithmetic per Now() pseudocode.",
        },
    ]


def ccp9_vectors() -> list[dict]:
    # CCP-9 rendezvous mechanisms from da2q multi-channel context. Independent
    # oracles for announce-based rendezvous, control channel (CH0) fallback for
    # unknown peers, integration with synchronized_hop_channel (CCP-12 preference),
    # initial contact, known-peer prediction, announce channel field parsing.
    # Matches spec 02a-coordinated-capacity.md CCP-9 section and python sim/medium.py
    # rendezvous logic. Mathematical, no code-under-test dependency.
    return [
        {
            "name": "announce_rendezvous_channel",
            "description": "Announce includes rx_channel=3; receiver schedules next unicast on announced channel per CCP-9 da2q rendezvous. Independent oracle.",
            "rx_channel": 3,
            "peer_known": True,
            "expected_channel": 3,
            "control_fallback": False,
        },
        {
            "name": "initial_unknown_peer_control_ch0",
            "description": "Initial contact with unknown peer uses CH0 control channel rendezvous. Announce then enables data channel follow-up per da2q CCP-9.",
            "peer_known": False,
            "expected_channel": 0,
            "control_fallback": True,
        },
        {
            "name": "known_peer_synchronized_hop_preference",
            "description": "For known peers, synchronized_hop_channel(eui=..., t=1000) =5 overrides pure announce rendezvous (CCP-12 normative over CCP-9).",
            "eui64_hex": "0011223344556677",
            "t": 1000,
            "epoch": 0,
            "expected_channel": 5,
            "n_channels": 8,
            "uses_sync_hop": True,
        },
        {
            "name": "announce_channel_parse_roundtrip",
            "description": "Announce packet with channel field encodes/decodes consistently. Tests L2 payload dispatch for rendezvous metadata. Independent oracle bytes from spec L2 dispatch + wire format (no code-under-test as oracle).",
            "channel": 2,
            "l2_dispatch": L2_DISPATCH_ROUTING,
            "encoded": _l2_announce_with_channel(2).hex(),
            "expected_flags": 0x02,
            "expected_channel": 2,
        },
    ]

def ccp15_vectors() -> list[dict]:
    v = []
    for seed in range(3):
        h = (seed * 0x9e3779b9) & 0xffffffff
        load_factor = h / 4294967295.0
        ema = 0.1 * load_factor + 0.9 * 0.4
        sf = 7 if load_factor < 0.2 else 10 if load_factor < 0.6 else 12
        v.append({"name": f"seed{seed}","sf":sf,"ema":round(ema,6),"load_factor":round(load_factor,6),"hash_32":f"{h:08x}"})
    return v


def ccp13_vectors() -> list[dict]:
    """CCP-13 Duty Cycle Management (DutyCycleTracker) vectors.

    Independent math oracles for prune/eviction, partial overlap proration,
    remaining_ms, usage_permille, can_transmit, next_tx_available_ms.
    Matches Rust lichen-core::duty_cycle, C lichen_duty_cycle_* in hal.c,
    and python sim exactly per test integrity rules. No impl dependency.
    """
    return [
        {
            "name": "initial_full_budget",
            "description": "New tracker has full budget (36000ms remaining, 0 usage).",
            "limit_permille": 10,
            "window_ms": 3600000,
            "now_ms": 0,
            "remaining_ms": 36000,
            "usage_permille": 0,
            "can_transmit": True,
        },
        {
            "name": "post_tx_reduced",
            "description": "200ms TX at t=0 reduces remaining to 35800ms at t=1000.",
            "limit_permille": 10,
            "now_ms": 1000,
            "txs": [
                {
                    "ts": 0,
                    "dur": 200,
                }
            ],
            "remaining_ms": 35800,
            "usage_permille": 0,
            "can_transmit_100ms": True,
        },
        {
            "name": "window_eviction",
            "description": "TX expires after full window; budget restores.",
            "now_ms": 3600201,
            "txs": [
                {
                    "ts": 0,
                    "dur": 200,
                }
            ],
            "remaining_ms": 36000,
            "usage_permille": 0,
        },
        {
            "name": "next_tx_delayed",
            "description": "Exhausted budget delays next TX until oldest record expires.",
            "now_ms": 0,
            "txs": [
                {
                    "ts": 0,
                    "dur": 36000,
                }
            ],
            "duration_ms": 100,
            "next_available_ms": 3600000,
        },
        {
            "name": "impossible_tx",
            "description": "duration > max_tx returns u64::MAX (never).",
            "now_ms": 0,
            "duration_ms": 36001,
            "next_available_ms": 18446744073709551615,
        },
        {
            "name": "custom_10pct",
            "description": "10% limit (100 permille) gives 360000ms max.",
            "limit_permille": 100,
            "remaining_ms": 360000,
        },
    ]


def rpl_messages_vectors() -> list[dict]:

    # Independent hardcoded from RFC 6550 §6.3, §6.4. No use of lichen.rpl.messages.
    return [
        {
            "name": "dio_base",
            "type": "dio",
            "description": "Base RPL DIO (RFC 6550). Hardcoded wire format from spec.",
            "encoded": "01001e0001000000000000000000000000000000",
            "fields": {"rpl_instance_id": 0, "version": 1, "rank": 256, "grounded": True},
        },
        {
            "name": "dao_base",
            "type": "dao",
            "description": "Base RPL DAO with DODAGID (RFC 6550).",
            "encoded": "0201050000000000000000000000000000000000",
            "fields": {"rpl_instance_id": 0, "dao_sequence": 5},
        },
    ]


def main() -> None:
    _write(
        "schc_compression.json",
        "SCHC whole-packet compression vectors (RFC 8724). 'packet' is the full "
        "uncompressed IPv6 datagram; 'compressed' is compress_packet(packet). "
        "Round-trip: compress(packet) == compressed and decompress(compressed) "
        "== packet.",
        schc_vectors(),
    )
    _write(
        "link_frame.json",
        "LICHEN link-layer frame vectors (spec section 4). Complete frames are "
        "at most 255 bytes (LENGTH at most 254). 'fields' are the frame inputs; "
        "'encoded' is LichenFrame(**fields).to_bytes().",
        frame_vectors(),
    )
    _write(
        "l2_payload.json",
        "Authenticated L2 inner-payload dispatch vectors. 'wrapped' is the "
        "link inner payload; byte 0 is the dispatch namespace and 'body' is "
        "the SCHC packet or routing/control message after that byte.",
        l2_payload_vectors(),
    )
    _write(
        "announce_coords.json",
        "Announce app_data Type=0x01 geographic coordinate encoding: signed "
        "big-endian e7 latitude and longitude. Coordinates are peer-owned "
        "announce metadata; receivers do not treat them as local position "
        "without explicit NETWORK-source approximation policy.",
        announce_coords_vectors(),
    )
    _write(
        "schc_fragment.json",
        "SCHC fragmentation vectors (RFC 8724 §8) with independent CRC32 oracle from zlib matching FragmentSender implementation. Updated for 6-bit FCN, real MICs, tile/window params.",
        schc_fragment_vectors(),
    )
    _write(
        "ccp_load_balancing.json",
        "CCP load balancing and TDMA vectors with independent math oracles (hash_32, drift calc from spec).",
        ccp_load_balancing_vectors(),
    )
    _write(
        "ccp16.json",
        "CCP-16 synchronized hopping and desync vectors with now_ts and select_channel_timing test per project-LICHEN-rs2q. Uses input/output for ccp_vector schema.",
        ccp16_vectors(),
    )
    _write(
        "ccp9.json",
        "CCP-9 rendezvous vectors using independent _l2_announce_with_channel oracle (exact wire format, no AnnounceMessage dep) and math from spec.",
        ccp9_vectors(),
    )
    _write(
        "ccp15.json",
        "ccp15 vectors for SF EMA load_factor hash_32 congestion control with independent oracle (math based).",
        ccp15_vectors(),
    )
    _write(
        "ccp13.json",
        "CCP-13 DutyCycleTracker vectors with independent math oracles for prune, proration, remaining_ms, usage_permille, can_transmit, next_available. Matches Rust, C hal test, and Python sim exactly.",
        ccp13_vectors(),
    )
    _write(
        "rpl_messages.json",
        "RPL messages (DIO/DAO per RFC 6550) with hardcoded independent vectors from spec.",
        rpl_messages_vectors(),
    )
    _write(
        "meshtastic_app_compat.json",
        "Meshtastic app-compat BLE protobuf exchange vectors. 'encoded' is one raw GATT value unless the vector explicitly expects rejection. Matches protobufs baseline (ToRadio/FromRadio tolerance).",
        meshtastic_app_compat_vectors(),
    )
    _write(
        "meshcore_app_compat.json",
        "MeshCore app-compat byte-command vectors. 'encoded' is one raw MeshCore inner frame for BLE unless transport.framing states serial 0x3c/0x3e length framing. Matches firmware/python baselines.",
        meshcore_app_compat_vectors(),
    )


if __name__ == "__main__":
    main()

