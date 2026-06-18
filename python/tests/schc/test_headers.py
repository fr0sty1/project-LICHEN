"""Tests for whole-packet SCHC compression (packet <-> field dicts)."""

from __future__ import annotations

from ipaddress import IPv6Address

import aiocoap
from aiocoap import GET, Message

from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
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
