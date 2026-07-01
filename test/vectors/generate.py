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
                    "config",
                    "moduleConfig",
                    "channel",
                    "region_presets",
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
                    "config",
                    "moduleConfig",
                    "channel",
                    "region_presets",
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


if __name__ == "__main__":
    main()
