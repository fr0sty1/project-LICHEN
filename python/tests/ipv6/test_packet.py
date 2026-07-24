# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for IPv6 packet construction and parsing (RFC 8200, spec 6).

Header byte oracles are hand-computed from the RFC 8200 layout.
"""

from __future__ import annotations

import pytest

from lichen.ipv6.packet import (
    HEADER_LENGTH,
    ExtensionHeader,
    IPv6Header,
    IPv6Packet,
    NextHeader,
    PacketError,
)


def test_header_to_bytes_known_vector() -> None:
    hdr = IPv6Header(
        src_addr="::1",
        dst_addr="::2",
        next_header=NextHeader.ICMPV6,
        hop_limit=64,
    )
    expected = (
        bytes([0x60, 0x00, 0x00, 0x00])  # version 6, tc 0, flow 0
        + bytes([0x00, 0x00])  # payload length 0
        + bytes([0x3A, 0x40])  # next header 58 (ICMPv6), hop limit 64
        + bytes(15) + bytes([0x01])  # ::1
        + bytes(15) + bytes([0x02])  # ::2
    )
    assert hdr.to_bytes() == expected
    assert len(hdr.to_bytes()) == HEADER_LENGTH


def test_header_first_word_bit_packing() -> None:
    # (6 << 28) | (0xFF << 20) | 0xABCDE = 0x6FFABCDE
    hdr = IPv6Header(
        src_addr="::",
        dst_addr="::",
        next_header=NextHeader.UDP,
        traffic_class=0xFF,
        flow_label=0xABCDE,
    )
    assert hdr.to_bytes()[0:4] == bytes([0x6F, 0xFA, 0xBC, 0xDE])


def test_header_round_trip() -> None:
    hdr = IPv6Header(
        src_addr="fe80::1",
        dst_addr="fd00::abcd",
        next_header=NextHeader.UDP,
        payload_length=12,
        hop_limit=32,
        traffic_class=0x11,
        flow_label=0x12345,
    )
    parsed = IPv6Header.from_bytes(hdr.to_bytes())
    assert parsed == hdr


def test_header_from_bytes_rejects_truncated() -> None:
    with pytest.raises(PacketError):
        IPv6Header.from_bytes(bytes(39))


def test_header_from_bytes_rejects_bad_version() -> None:
    data = bytearray(IPv6Header("::1", "::2", NextHeader.UDP).to_bytes())
    data[0] = 0x40  # version 4
    with pytest.raises(PacketError):
        IPv6Header.from_bytes(bytes(data))


def test_header_validates_ranges() -> None:
    with pytest.raises(PacketError):
        IPv6Header("::1", "::2", next_header=NextHeader.UDP, hop_limit=256).to_bytes()


def test_packet_no_extension_headers_round_trip() -> None:
    pkt = IPv6Packet(
        header=IPv6Header("fe80::1", "fe80::2", NextHeader.UDP),
        payload=b"hello",
    )
    raw = pkt.to_bytes()
    # payload_length is computed even though the input header left it at 0.
    assert raw[4:6] == len(b"hello").to_bytes(2, "big")
    parsed = IPv6Packet.from_bytes(raw)
    assert parsed.payload == b"hello"
    assert parsed.header.next_header == NextHeader.UDP
    assert parsed.extension_headers == []


def test_packet_with_hop_by_hop_chain() -> None:
    ext = ExtensionHeader(header_type=NextHeader.HOP_BY_HOP, data=b"\x00" * 6)
    pkt = IPv6Packet(
        header=IPv6Header("fe80::1", "fe80::2", NextHeader.UDP),
        payload=b"data",
        extension_headers=[ext],
    )
    raw = pkt.to_bytes()

    # Base header Next Header points at the HBH option header (0).
    assert raw[6] == NextHeader.HOP_BY_HOP
    # The HBH header's own Next Header points at the upper-layer protocol (UDP).
    assert raw[HEADER_LENGTH] == NextHeader.UDP
    assert raw[HEADER_LENGTH + 1] == 0  # hdr_ext_len for an 8-byte header

    parsed = IPv6Packet.from_bytes(raw)
    assert len(parsed.extension_headers) == 1
    assert parsed.extension_headers[0].header_type == NextHeader.HOP_BY_HOP
    assert parsed.extension_headers[0].data == b"\x00" * 6
    assert parsed.header.next_header == NextHeader.UDP
    assert parsed.payload == b"data"


def test_packet_with_two_extension_headers_chain() -> None:
    hbh = ExtensionHeader(header_type=NextHeader.HOP_BY_HOP, data=b"\x01" * 6)
    dst = ExtensionHeader(header_type=NextHeader.DEST_OPTIONS, data=b"\x02" * 14)
    pkt = IPv6Packet(
        header=IPv6Header("fe80::1", "fe80::2", NextHeader.ICMPV6),
        payload=b"x",
        extension_headers=[hbh, dst],
    )
    parsed = IPv6Packet.from_bytes(pkt.to_bytes())
    assert [e.header_type for e in parsed.extension_headers] == [
        NextHeader.HOP_BY_HOP,
        NextHeader.DEST_OPTIONS,
    ]
    assert parsed.extension_headers[1].data == b"\x02" * 14
    assert parsed.header.next_header == NextHeader.ICMPV6
    assert parsed.payload == b"x"


def test_extension_header_rejects_unsupported_type() -> None:
    with pytest.raises(PacketError):
        ExtensionHeader(header_type=NextHeader.UDP, data=b"\x00" * 6)


def test_extension_header_rejects_misaligned_length() -> None:
    with pytest.raises(PacketError):
        ExtensionHeader(header_type=NextHeader.HOP_BY_HOP, data=b"\x00" * 5)


def test_packet_rejects_fragment_header() -> None:
    # Hand-build a base header whose Next Header is Fragment (44).
    base = IPv6Header("::1", "::2", next_header=NextHeader.FRAGMENT, payload_length=8)
    raw = base.to_bytes() + bytes(8)
    with pytest.raises(PacketError):
        IPv6Packet.from_bytes(raw)


def test_packet_rejects_truncated_payload() -> None:
    hdr = IPv6Header("::1", "::2", NextHeader.UDP, payload_length=10)
    with pytest.raises(PacketError):
        IPv6Packet.from_bytes(hdr.to_bytes() + b"short")


def test_packet_from_bytes_ignores_trailing_data_by_default() -> None:
    pkt = IPv6Packet(
        header=IPv6Header("fe80::1", "fe80::2", NextHeader.UDP),
        payload=b"hello",
    )
    raw = pkt.to_bytes()
    padded = raw + b"trailing"
    parsed = IPv6Packet.from_bytes(padded)
    assert parsed.payload == b"hello"
    assert parsed.header.next_header == NextHeader.UDP


def test_packet_from_bytes_strict_rejects_trailing_data() -> None:
    pkt = IPv6Packet(
        header=IPv6Header("fe80::1", "fe80::2", NextHeader.UDP),
        payload=b"hello",
    )
    raw = pkt.to_bytes()
    padded = raw + b"trailing"
    with pytest.raises(PacketError, match="trailing"):
        IPv6Packet.from_bytes(padded, strict=True)


def test_packet_from_bytes_strict_accepts_exact_data() -> None:
    pkt = IPv6Packet(
        header=IPv6Header("fe80::1", "fe80::2", NextHeader.UDP),
        payload=b"hello",
    )
    raw = pkt.to_bytes()
    parsed = IPv6Packet.from_bytes(raw, strict=True)
    assert parsed.payload == b"hello"


def test_packet_rejects_oversized_payload() -> None:
    pkt = IPv6Packet(
        header=IPv6Header("::1", "::2", NextHeader.UDP),
        payload=b"x" * 70000,
    )
    with pytest.raises(PacketError):
        pkt.to_bytes()
    ext = ExtensionHeader(
        header_type=NextHeader.HOP_BY_HOP, data=b"\x00" * 6
    )
    pkt = IPv6Packet(
        header=IPv6Header("::1", "::2", NextHeader.UDP),
        payload=b"x" * 65530,
        extension_headers=[ext],
    )
    with pytest.raises(PacketError):
        pkt.to_bytes()
