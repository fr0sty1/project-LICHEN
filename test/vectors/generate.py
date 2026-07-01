#!/usr/bin/env python3
"""Generate cross-language test vectors from the Python reference implementation.

Run:  PYTHONPATH=python/src python3 test/vectors/generate.py

Writes JSON vector files under this directory. The Python prototype is the
source of truth; the Rust and C implementations validate against the same files
(see README.md). Inputs are fixed, so output is deterministic. ``python -m
pytest python/tests/test_vectors.py`` re-derives every vector and fails if the
implementation drifts from the committed files.
"""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

from lichen.ipv6.icmpv6 import EchoRequest
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.link.frame import AddrMode, LichenFrame, MicLength
from lichen.rpl.messages import DAO, DIO, to_icmpv6
from lichen.schc.headers import compress_packet

VECTORS_DIR = Path(__file__).resolve().parent
FORMAT_VERSION = 1

LL_SRC = IPv6Address("fe80::1")
LL_DST = IPv6Address("fe80::2")
G_SRC = IPv6Address("2001:db8::1")
G_DST = IPv6Address("2001:db8::2")
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
    telemetry = (
        _varint_field(1, 0)
        + _varint_field(2, 0)
        + _bool_field(14, False)
    )
    return _bytes_field(6, telemetry)


def _region_presets_default_us_long_fast() -> bytes:
    preset_group = _varint_field(1, 0) + _varint_field(2, 0)
    region_group = _varint_field(1, 1) + _varint_field(2, 0)
    return _bytes_field(1, preset_group) + _bytes_field(2, region_group)


def _data(portnum: int, payload: bytes = b"", request_id: int | None = None) -> bytes:
    out = bytearray()
    out += _varint_field(1, portnum)
    if payload:
        out += _bytes_field(2, payload)
    if request_id is not None:
        out += _fixed32_field(6, request_id)
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


def schc_vectors() -> list[dict]:
    dio = DIO(rpl_instance_id=0, version=1, rank=256, dtsn=0, dodag_id=LL_SRC,
              grounded=True)
    dao = DAO(rpl_instance_id=0, dao_sequence=5, dodag_id=LL_SRC)
    cases = [
        ("coap_linklocal", 0, "Link-local IPv6+UDP+CoAP GET",
         _udp_ipv6(LL_SRC, LL_DST, _coap())),
        ("coap_global", 1, "Global IPv6+UDP+CoAP GET",
         _udp_ipv6(G_SRC, G_DST, _coap())),
        ("icmpv6_echo", 2, "Link-local ICMPv6 Echo Request",
         _icmpv6_ipv6(LL_SRC, LL_DST,
                      EchoRequest(identifier=0xABCD, sequence=7, data=b"ping")
                      .to_message())),
        ("rpl_dio", 3, "Link-local RPL DIO",
         _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dio))),
        ("rpl_dao", 4, "Link-local RPL DAO with DODAGID",
         _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dao))),
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


def frame_vectors() -> list[dict]:
    cases = [
        ("broadcast_min", "Broadcast, no address, 32-bit MIC",
         LichenFrame(epoch=1, seqnum=2, dst_addr=b"", payload=b"abc",
                     mic=bytes([0x01, 0x02, 0x03, 0x04]), addr_mode=AddrMode.NONE,
                     mic_length=MicLength.BITS32)),
        ("short_addr", "16-bit short destination address",
         LichenFrame(epoch=0x10, seqnum=0x2030, dst_addr=bytes([0xAB, 0xCD]),
                     payload=b"hi", mic=bytes(4), addr_mode=AddrMode.SHORT,
                     mic_length=MicLength.BITS32)),
        ("extended_addr_mic64", "64-bit address, 64-bit MIC",
         LichenFrame(epoch=0xFF, seqnum=0xFFFF, dst_addr=bytes(range(8)),
                     payload=b"data", mic=bytes(range(8)),
                     addr_mode=AddrMode.EXTENDED, mic_length=MicLength.BITS64)),
        ("signed_encrypted", "Signature + encrypted flags set",
         LichenFrame(epoch=3, seqnum=4, dst_addr=b"", payload=b"x",
                     mic=bytes(4), addr_mode=AddrMode.NONE,
                     mic_length=MicLength.BITS32, signature_present=True,
                     encrypted=True)),
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
                "encoded": frame.to_bytes().hex(),
            }
        )
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
    inbound_text = _from_radio_packet(
        1,
        _mesh_packet(
            from_num=peer_num,
            to_num=local_num,
            packet_id=0x55667788,
            decoded=_data(1, b"hi"),
        )
    )
    routing_ack = _from_radio_packet(
        2,
        _mesh_packet(
            from_num=peer_num,
            to_num=local_num,
            packet_id=0x55667789,
            decoded=_data(5, request_id=packet_id),
        )
    )
    routing_nak = _from_radio_packet(
        3,
        _mesh_packet(
            from_num=peer_num,
            to_num=local_num,
            packet_id=0x5566778A,
            decoded=_data(5, _routing_error(1), request_id=packet_id),
        )
    )
    heartbeat_queue_status = _from_radio_queue_status(
        _queue_status(res=0, free=4, maxlen=8, mesh_packet_id=packet_id),
    )

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
                    "moduleConfig",
                    "config_complete_id",
                ],
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
        {
            "name": "legacy_full_sync_unknown_nonce",
            "description": "Python/older clients may use a non-staged nonce and still need full sync data.",
            "source_baseline": baseline,
            "transport": transport,
            "direction": "exchange",
            "protobuf": "ToRadio",
            "message": "want_config_id",
            "encoded": _to_radio_want_config(0xA5A5A5A5).hex(),
            "decoded": {"want_config_id": 0xA5A5A5A5},
            "expect": {
                "from_radio_sequence": [
                    "my_info",
                    "metadata",
                    "region_presets",
                    "channel",
                    "config",
                    "moduleConfig",
                    "node_info",
                    "config_complete_id",
                ],
                "terminal_from_radio": _from_radio_config_complete(0xA5A5A5A5).hex(),
            },
        },
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
            "encoded": ("94c3" + len(outbound_text).to_bytes(2, "big").hex()
                        + outbound_text.hex()),
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
        "transport": transport or {
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
            expect={"responses": [_meshcore_channel_info().hex()], "adapter_test": True},
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
            description="Default flood scope is null/empty until compatibility policy is expanded.",
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
            decoded={"command": "SEND_CHANNEL_TXT_MSG", "channel": 0, "txt_type": 0, "payload_utf8": "hi"},
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
            name="set_advert_name_unsupported",
            description="Compatibility display-name writes are rejected until settings-backed local compatibility state exists.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("084c494348454e"),
            decoded={"command": "SET_ADVERT_NAME", "name": "LICHEN"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="set_channel_unsupported",
            description="Channel writes are rejected; LICHEN does not accept MeshCore channel secrets as native group or OSCORE material.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("2000"),
            decoded={"command": "SET_CHANNEL", "index": 0},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="set_device_pin_unsupported",
            description="BLE PIN writes are rejected until a settings-backed MeshCore compatibility PIN store is implemented.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("25313233343536"),
            decoded={"command": "SET_DEVICE_PIN", "pin": "123456"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
        ),
        _meshcore_vector(
            name="set_autoadd_config_unsupported",
            description="Auto-add configuration writes are rejected until compatibility-local persistence exists.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("3a0000"),
            decoded={"command": "SET_AUTOADD_CONFIG", "enabled": False},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
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
            name="newer_set_default_flood_scope_unsupported",
            description="Newer firmware command 0x3f is recognized but unsupported by the MVP shim.",
            direction="exchange",
            frame="command",
            encoded=bytes.fromhex("3f"),
            decoded={"command": "SET_DEFAULT_FLOOD_SCOPE"},
            expect={"responses": [err_unsupported.hex()], "adapter_test": True},
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
            transport={"name": "serial", "framing": "0x3c + uint16_le length + MeshCore inner frame"},
        ),
        _meshcore_vector(
            name="serial_device_to_app_no_more_messages",
            description="Serial/TCP device-to-app framing wraps the raw NO_MORE_MESSAGES response with '>' and uint16_le payload length.",
            direction="node_to_app",
            frame="serial",
            encoded=bytes.fromhex("3e01000a"),
            decoded={"serial_marker": "device_to_app", "payload": "0a"},
            expect={"inner_frame": "0a"},
            transport={"name": "serial", "framing": "0x3e + uint16_le length + MeshCore inner frame"},
        ),
    ]


def _write(filename: str, description: str, vectors: list[dict]) -> None:
    path = VECTORS_DIR / filename
    doc = {
        "format_version": FORMAT_VERSION,
        "description": description,
        "vectors": vectors,
    }
    path.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors to {path.name}")


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
        "LICHEN link-layer frame vectors (spec section 4). 'fields' are the "
        "frame inputs; 'encoded' is LichenFrame(**fields).to_bytes().",
        frame_vectors(),
    )
    _write(
        "meshtastic_app_compat.json",
        "Meshtastic app-compat BLE protobuf exchange vectors. 'encoded' is one "
        "raw GATT value unless the vector explicitly expects rejection.",
        meshtastic_app_compat_vectors(),
    )
    _write(
        "meshcore_app_compat.json",
        "MeshCore app-compat byte-command vectors. 'encoded' is one raw "
        "MeshCore inner frame for BLE unless transport.framing states serial "
        "0x3c/0x3e length framing.",
        meshcore_app_compat_vectors(),
    )


if __name__ == "__main__":
    main()
