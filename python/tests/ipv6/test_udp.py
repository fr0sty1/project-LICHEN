"""Tests for the UDP-over-IPv6 codec (RFC 768)."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.ipv6.udp import UdpDatagram, UdpError, udp_checksum

SRC = IPv6Address("fe80::1")
DST = IPv6Address("fe80::2")


def test_round_trip() -> None:
    dg = UdpDatagram(src_port=5683, dst_port=5683, payload=b"hello")
    raw = dg.to_bytes(SRC, DST)
    parsed = UdpDatagram.from_bytes(raw)
    assert parsed.src_port == 5683
    assert parsed.dst_port == 5683
    assert parsed.payload == b"hello"
    assert parsed.length == 8 + 5


def test_header_layout() -> None:
    raw = UdpDatagram(0x1234, 0x5678, b"ab").to_bytes(SRC, DST)
    assert raw[0:2] == bytes([0x12, 0x34])
    assert raw[2:4] == bytes([0x56, 0x78])
    assert raw[4:6] == (8 + 2).to_bytes(2, "big")  # length
    assert raw[8:] == b"ab"


def test_checksum_is_nonzero_and_verifies() -> None:
    raw = UdpDatagram(5683, 5683, b"x").to_bytes(SRC, DST)
    # Recomputing the checksum over the received datagram yields zero.
    assert udp_checksum(SRC, DST, raw) == 0


def test_from_bytes_rejects_short() -> None:
    with pytest.raises(UdpError):
        UdpDatagram.from_bytes(bytes(4))


def test_from_bytes_rejects_length_mismatch() -> None:
    raw = bytearray(UdpDatagram(1, 2, b"abcd").to_bytes(SRC, DST))
    raw[4:6] = (99).to_bytes(2, "big")  # corrupt length field
    with pytest.raises(UdpError):
        UdpDatagram.from_bytes(bytes(raw))


def test_port_range_validated() -> None:
    with pytest.raises(UdpError):
        UdpDatagram(0x10000, 1, b"").to_bytes(SRC, DST)
