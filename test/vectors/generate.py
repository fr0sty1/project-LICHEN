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


if __name__ == "__main__":
    main()
