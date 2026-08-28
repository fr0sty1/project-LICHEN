#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate ICMPv6 echo and error vectors without importing LICHEN.

Oracle: RFC 8200 IPv6 header, RFC 4443 ICMPv6, RFC 768/2460 UDP checksum,
Python stdlib ipaddress only.
"""

from __future__ import annotations

import argparse
import sys
from ipaddress import IPv6Address
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)

OUTPUT = VECTORS_DIR / "ipv6-icmpv6.json"
ICMPV6 = 58
UDP = 17
HOP_LIMIT = 64
COAP_PORT = 5683
YGG_SRC = IPv6Address("200:389e:777a:ce07:c7d6:ca08:166e:cd20")
YGG_DST = IPv6Address("200:514a:cffc:fa9d:ea90:5568:258:6d37")


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _pseudo_header(src: bytes, dst: bytes, payload: bytes, next_header: int) -> bytes:
    return src + dst + len(payload).to_bytes(4, "big") + bytes(3) + bytes([next_header])


def _ipv6_header(src: bytes, dst: bytes, payload_len: int, next_header: int) -> bytes:
    first_word = 6 << 28
    return (
        first_word.to_bytes(4, "big")
        + payload_len.to_bytes(2, "big")
        + bytes([next_header, HOP_LIMIT])
        + src
        + dst
    )


def _icmpv6_message(src: bytes, dst: bytes, icmp_type: int, code: int, body: bytes) -> bytes:
    with_zero = bytes([icmp_type, code, 0, 0]) + body
    checksum = _internet_checksum(_pseudo_header(src, dst, with_zero, ICMPV6) + with_zero)
    return bytes([icmp_type, code]) + checksum.to_bytes(2, "big") + body


def _icmpv6_wire(src: IPv6Address, dst: IPv6Address, icmp_type: int, code: int, body: bytes) -> bytes:
    message = _icmpv6_message(src.packed, dst.packed, icmp_type, code, body)
    return _ipv6_header(src.packed, dst.packed, len(message), ICMPV6) + message


def _udp_ipv6(src: IPv6Address, dst: IPv6Address, payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    header_zero = (
        COAP_PORT.to_bytes(2, "big")
        + COAP_PORT.to_bytes(2, "big")
        + udp_len.to_bytes(2, "big")
        + b"\x00\x00"
    )
    datagram_zero = header_zero + payload
    checksum = _internet_checksum(
        _pseudo_header(src.packed, dst.packed, datagram_zero, UDP) + datagram_zero
    )
    if checksum == 0:
        checksum = 0xFFFF
    datagram = (
        COAP_PORT.to_bytes(2, "big")
        + COAP_PORT.to_bytes(2, "big")
        + udp_len.to_bytes(2, "big")
        + checksum.to_bytes(2, "big")
        + payload
    )
    return _ipv6_header(src.packed, dst.packed, len(datagram), UDP) + datagram


def _echo_vector(
    name: str,
    description: str,
    src: IPv6Address,
    dst: IPv6Address,
    icmp_type: int,
    identifier: int,
    sequence: int,
    data: bytes,
    *,
    include_code: bool,
    include_packed: bool,
) -> dict[str, object]:
    body = identifier.to_bytes(2, "big") + sequence.to_bytes(2, "big") + data
    vector: dict[str, object] = {
        "name": name,
        "description": description,
        "src": str(src),
        "dst": str(dst),
    }
    if include_packed:
        vector["src_packed"] = src.packed.hex()
        vector["dst_packed"] = dst.packed.hex()
    vector["icmp_type"] = icmp_type
    if include_code:
        vector["icmp_code"] = 0
    vector["identifier"] = identifier
    vector["sequence"] = sequence
    vector["data"] = data.hex()
    vector["wire"] = _icmpv6_wire(src, dst, icmp_type, 0, body).hex()
    return vector


def _error_vector(
    name: str,
    icmp_type: int,
    icmp_code: int,
    invoking: bytes,
    mtu: int,
) -> dict[str, object]:
    src = YGG_DST
    dst = YGG_SRC
    rest = mtu.to_bytes(4, "big")
    body = rest + invoking
    return {
        "name": name,
        "description": f"ICMPv6 error {name}",
        "src": str(src),
        "dst": str(dst),
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "invoking_packet": invoking.hex(),
        "wire": _icmpv6_wire(src, dst, icmp_type, icmp_code, body).hex(),
    }


def document() -> dict[str, object]:
    """Return the independently derived ICMPv6 vector document."""
    invoking = _udp_ipv6(YGG_SRC, YGG_DST, b"payload for error")
    ll_src = IPv6Address("fe80::1")
    ll_dst = IPv6Address("fe80::2")
    return {
        "$schema": "./schema.json",
        "format_version": 2,
        "description": (
            "ICMPv6 Echo Request/Reply and error vectors (RFC 4443, spec 6.4) "
            "with IPv6 pseudo-header checksum. Includes link-local and 0200::/8 "
            "primary addresses."
        ),
        "vectors": [
            _echo_vector(
                "echo_request_basic",
                "Echo Request id=0x1234 seq=1 data=test, link-local",
                ll_src,
                ll_dst,
                128,
                0x1234,
                1,
                b"test",
                include_code=True,
                include_packed=False,
            ),
            _echo_vector(
                "echo_reply_basic",
                "Echo Reply mirroring request (swapped addrs)",
                ll_dst,
                ll_src,
                129,
                0x1234,
                1,
                b"test",
                include_code=True,
                include_packed=False,
            ),
            _echo_vector(
                "echo_request_yggdrasil",
                "Echo Request over primary 0200::/8 addresses",
                YGG_SRC,
                YGG_DST,
                128,
                0xABCD,
                42,
                b"hello ygg",
                include_code=False,
                include_packed=True,
            ),
            _error_vector("dest_unreachable_no_route", 1, 0, invoking, 0),
            _error_vector("dest_unreachable_port", 1, 4, invoking, 0),
            _error_vector("packet_too_big_1280", 2, 0, invoking, 1280),
            _error_vector("time_exceeded_hop", 3, 0, invoking, 0),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    vectors = generated["vectors"]
    assert isinstance(vectors, list)
    print(f"Wrote {len(vectors)} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
