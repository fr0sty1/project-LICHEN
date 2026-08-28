#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate independent OSCORE -> SCHC Rule 5 round-trip vectors.

The cryptographic outputs come from ``oscore_cross_exchange.json``, where the
Python and Rust implementations independently agree.  This generator does not
import either SCHC implementation: it builds IPv6/UDP/CoAP and the Rule 5
residue directly from the wire specification, providing an independent oracle
for the cross-layer consumers.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "test" / "vectors" / "oscore_cross_exchange.json"
OUTPUT = ROOT / "test" / "vectors" / "oscore_schc_roundtrip.json"

SOURCE_ADDRESS = bytes.fromhex("fe800000000000000000000000000001")
DESTINATION_ADDRESS = bytes.fromhex("fe800000000000000000000000000002")
COAP_PORT = 5683


def _sum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(int.from_bytes(data[offset : offset + 2], "big") for offset in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _udp_checksum(source: bytes, destination: bytes, udp: bytes) -> int:
    pseudo = source + destination + len(udp).to_bytes(4, "big") + bytes((0, 0, 0, 17))
    checksum = (~_sum16(pseudo + udp)) & 0xFFFF
    return checksum or 0xFFFF


def _coap_option(number: int, value: bytes) -> bytes:
    if not 0 <= number <= 12 or not 0 <= len(value) <= 12:
        raise ValueError("fixture uses only directly encoded CoAP option nibbles")
    return bytes(((number << 4) | len(value),)) + value


def _pack_bits(fields: list[tuple[int, int]]) -> bytes:
    value = 0
    width = 0
    for field, bits in fields:
        if field < 0 or field >= 1 << bits:
            raise ValueError(f"field {field} does not fit {bits} bits")
        value = (value << bits) | field
        width += bits
    padding = (-width) % 8
    return (value << padding).to_bytes((width + padding) // 8, "big")


def _build_packet(option: bytes, ciphertext: bytes, message_id: int) -> tuple[bytes, bytes]:
    coap = (
        bytes((0x40, 0x02))
        + message_id.to_bytes(2, "big")
        + _coap_option(9, option)
        + b"\xff"
        + ciphertext
    )
    udp_length = 8 + len(coap)
    udp_zero = (
        COAP_PORT.to_bytes(2, "big")
        + COAP_PORT.to_bytes(2, "big")
        + udp_length.to_bytes(2, "big")
        + b"\x00\x00"
        + coap
    )
    checksum = _udp_checksum(SOURCE_ADDRESS, DESTINATION_ADDRESS, udp_zero)
    udp = udp_zero[:6] + checksum.to_bytes(2, "big") + udp_zero[8:]
    ipv6 = (
        b"\x60\x00\x00\x00"
        + udp_length.to_bytes(2, "big")
        + bytes((17, 64))
        + SOURCE_ADDRESS
        + DESTINATION_ADDRESS
    )
    packet = ipv6 + udp

    residue = _pack_bits(
        [
            (64, 8),
            (int.from_bytes(SOURCE_ADDRESS[8:], "big"), 64),
            (int.from_bytes(DESTINATION_ADDRESS[8:], "big"), 64),
            (COAP_PORT & 0x0F, 4),
            (COAP_PORT & 0x0F, 4),
            (0, 2),
            (0, 4),
            (2, 8),
            (message_id, 16),
        ]
    )
    if len(residue) != 22:
        raise AssertionError("Rule 5 fixed residue must be 22 octets")
    compressed = bytes((5,)) + residue + coap[4:]
    return packet, compressed


def main() -> int:
    source = json.loads(SOURCE.read_text())
    vectors = []
    for index, exchange in enumerate(source["requests"]):
        python = exchange["python_protected"]
        rust = exchange["rust_protected"]
        if python != rust:
            raise ValueError(f"OSCORE implementations disagree for {exchange['name']}")
        option = bytes.fromhex(python["oscore_option"])
        ciphertext = bytes.fromhex(python["ciphertext"])
        message_id = 0x1234 + index
        packet, compressed = _build_packet(option, ciphertext, message_id)
        vectors.append(
            {
                "name": exchange["name"],
                "source_exchange": exchange["name"],
                "master_secret": exchange["master_secret"],
                "master_salt": exchange["master_salt"],
                "sender_id": exchange["sender_id"],
                "recipient_id": exchange["recipient_id"],
                "id_context": exchange["id_context"],
                "sender_seq": exchange["sender_seq"],
                "plaintext": exchange["plaintext"],
                "outer_code": 2,
                "message_id": message_id,
                "oscore_option": option.hex(),
                "ciphertext": ciphertext.hex(),
                "ipv6_packet": packet.hex(),
                "schc_rule5": compressed.hex(),
            }
        )

    document = {
        "name": "oscore_schc_roundtrip",
        "format_version": 2,
        "description": (
            "Independent protect -> Rule 5 compress -> decompress -> unprotect vectors. "
            "OSCORE bytes are pinned by independent Python/Rust outputs; IPv6/UDP/CoAP "
            "and Rule 5 bytes are encoded directly by this generator."
        ),
        "source_vectors": [
            "test/vectors/oscore.json",
            "test/vectors/oscore_cross_exchange.json",
        ],
        "generator": "test/vectors/generate_oscore_schc_roundtrip.py",
        "vectors": vectors,
    }
    OUTPUT.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {OUTPUT.relative_to(ROOT)} ({len(vectors)} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
