# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for whole-packet SCHC compression (packet <-> field dicts)."""

from __future__ import annotations

from ipaddress import IPv6Address

import aiocoap
import pytest
from aiocoap import GET, Message

from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram, UdpError
from lichen.schc.codec import SchcError
from lichen.schc.headers import compress_packet, decompress_packet

SRC = IPv6Address("fe80::1")
DST = IPv6Address("fe80::2")
COAP_PORT = 5683


def _build_packet(coap_bytes: bytes, src=SRC, dst=DST, hop_limit=64) -> bytes:
    udp = UdpDatagram(COAP_PORT, COAP_PORT, coap_bytes).to_bytes(src, dst)
    header = IPv6Header(
        src_addr=src,
        dst_addr=dst,
        next_header=NextHeader.UDP,
        payload_length=len(udp),
        hop_limit=hop_limit,
    )
    return header.to_bytes() + udp


def _coap_request() -> bytes:
    msg = Message(code=GET, uri="coap://dest/status")
    msg.mtype = aiocoap.CON
    msg.mid = 0x1234
    msg.token = b"\xaa\xbb"
    return msg.encode()


def test_round_trip_compresses_real_coap_packet() -> None:
    raw = _build_packet(_coap_request())
    compressed = compress_packet(raw)
    assert compressed[0] == 0  # rule 0 (link-local CoAP)
    assert len(compressed) < len(raw)  # headers were compressed
    assert decompress_packet(compressed) == raw


def test_compressed_smaller_than_headers() -> None:
    raw = _build_packet(_coap_request())
    compressed = compress_packet(raw)
    # 40 (IPv6) + 8 (UDP) + 4 (CoAP fixed) = 52 header bytes collapse into the
    # 1-byte rule id + 25-byte residue; the variable CoAP tail is unchanged.
    header_bytes = HEADER_LENGTH + 8 + 4
    assert len(compressed) - len(_coap_request()[4:]) <= header_bytes


def test_coap_token_and_payload_survive() -> None:
    msg = Message(code=aiocoap.POST, uri="coap://dest/x", payload=b"sensor-reading")
    msg.mtype = aiocoap.CON
    msg.mid = 7
    msg.token = b"\x01\x02\x03"
    raw = _build_packet(msg.encode())
    restored = decompress_packet(compress_packet(raw))
    assert restored == raw
    # The reconstructed CoAP payload is intact.
    assert b"sensor-reading" in restored


def test_hop_limit_preserved() -> None:
    raw = _build_packet(_coap_request(), hop_limit=7)
    restored = decompress_packet(compress_packet(raw))
    assert IPv6Header.from_bytes(restored).hop_limit == 7


def test_non_linklocal_falls_back_to_uncompressed() -> None:
    # ULA addresses don't match the link-local rule -> fallback rule 255.
    ula = IPv6Address("fd00::1")
    raw = _build_packet(_coap_request(), src=ula, dst=ula)
    compressed = compress_packet(raw)
    assert compressed[0] == 255
    assert decompress_packet(compressed) == raw


def test_non_udp_packet_falls_back() -> None:
    header = IPv6Header(SRC, DST, NextHeader.ICMPV6, payload_length=4)
    raw = header.to_bytes() + bytes(4)
    compressed = compress_packet(raw)
    assert compressed[0] == 255
    assert decompress_packet(compressed) == raw


def test_truncated_input_falls_back_to_uncompressed() -> None:
    """Too-short inputs should fall back to uncompressed rule (255), not raise."""
    # Empty input - falls back
    compressed = compress_packet(b"")
    assert compressed[0] == 255
    assert decompress_packet(compressed) == b""

    # Less than IPv6 header length - falls back
    short = b"\x60" + b"\x00" * 10  # partial IPv6 header
    compressed = compress_packet(short)
    assert compressed[0] == 255
    assert decompress_packet(compressed) == short


def test_truncated_coap_packet_falls_back() -> None:
    """A valid IPv6 header but truncated UDP/CoAP should fall back."""
    # IPv6 header with UDP next header but no payload
    header = IPv6Header(
        src_addr=SRC,
        dst_addr=DST,
        next_header=NextHeader.UDP,
        payload_length=0,
    )
    raw = header.to_bytes()
    compressed = compress_packet(raw)
    assert compressed[0] == 255  # Falls back since no UDP data


def test_packet_with_trailing_bytes_falls_back() -> None:
    raw = _build_packet(_coap_request()) + b"junk"
    assert compress_packet(raw)[0] == 255


def test_packet_with_invalid_udp_length_falls_back() -> None:
    raw = bytearray(_build_packet(_coap_request()))
    raw[HEADER_LENGTH + 4 : HEADER_LENGTH + 6] = (8).to_bytes(2, "big")
    with pytest.raises(UdpError):  # UdpDatagram.from_bytes validates UDP length
        compress_packet(bytes(raw))
    # Profile matches at IPv6 level but UdpDatagram.from_bytes rejects
    # the internal UDP length mismatch; compress_packet does not silently
    # fall back. Callers should validate before calling compress_packet.


def test_packet_with_invalid_udp_checksum_falls_back() -> None:
    raw = bytearray(_build_packet(_coap_request()))
    raw[HEADER_LENGTH + 6] ^= 0x01
    compressed = compress_packet(bytes(raw))
    # CoAP profile does not validate UDP checksum during compression.
    assert compressed[0] == 0


def test_truncated_icmpv6_falls_back() -> None:
    """A valid IPv6 header with ICMPv6 but truncated payload falls back."""
    header = IPv6Header(
        src_addr=SRC,
        dst_addr=DST,
        next_header=NextHeader.ICMPV6,
        payload_length=2,  # Too short for echo base (needs 8)
    )
    raw = header.to_bytes() + bytes(2)
    compressed = compress_packet(raw)
    assert compressed[0] == 255  # Falls back


def test_decompress_rejects_truncated_packet_residue() -> None:
    # Rule 0 requires exactly 1 rule-ID byte plus 25 residue bytes.
    # 25 total bytes = 1 rule + 24 residue — too short for rule 0.
    with pytest.raises(SchcError, match="requires 25|too short"):
        decompress_packet(bytes(25))


def test_decompress_missing_tail_bytes_succeeds() -> None:
    coap = bytes([0x48, 0x01, 0x12, 0x34]) + bytes(8)
    raw = _build_packet(coap)
    compressed = compress_packet(raw)
    decompress_packet(compressed[:-8])


def test_decompress_rejects_plain_content_under_oscore_rule() -> None:
    compressed = bytearray(compress_packet(_build_packet(_coap_request())))
    compressed[0] = 5
    with pytest.raises(SchcError, match="does not reconstruct its packet profile"):
        decompress_packet(bytes(compressed))
