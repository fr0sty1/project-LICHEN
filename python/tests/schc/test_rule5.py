# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Focused decompression coverage for SCHC Rule 5 (link-local OSCORE)."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.schc.codec import SchcError, residue_bit_length, residue_byte_length
from lichen.schc.fragment import MAX_PACKET_SIZE
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.rules import LINK_LOCAL_OSCORE_RULE

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SRC = IPv6Address("fe80::1")
_DST = IPv6Address("fe80::2")

_CANONICAL_PACKET = bytes.fromhex(
    "6000000000161140"
    "fe800000000000000000000000000001"
    "fe800000000000000000000000000002"
    "163316330016517b"
    "420112340001920900ffdeadbeef"
)
_CANONICAL_COMPRESSED = bytes.fromhex(
    "05"
    "40"
    "0000000000000001"
    "0000000000000002"
    "33"
    "080448d0"
    "0001920900ffdeadbeef"
)


def _packet(options_and_payload: bytes, *, token: bytes = b"", hop_limit: int = 64) -> bytes:
    coap = bytes((0x40 | len(token), 1, 0x12, 0x34)) + token + options_and_payload
    udp = UdpDatagram(5683, 5683, coap).to_bytes(_SRC, _DST)
    return (
        IPv6Header(
            _SRC,
            _DST,
            NextHeader.UDP,
            payload_length=len(udp),
            hop_limit=hop_limit,
        ).to_bytes()
        + udp
    )


def test_rule5_canonical_shared_vector_decompresses_exactly() -> None:
    document = json.loads(
        (_REPO_ROOT / "test/vectors/schc_compression.json").read_text(encoding="utf-8")
    )
    vector = next(item for item in document["vectors"] if item["name"] == "oscore_linklocal")

    assert LINK_LOCAL_OSCORE_RULE.rule_id == 5
    assert residue_bit_length(LINK_LOCAL_OSCORE_RULE) == 174
    assert residue_byte_length(LINK_LOCAL_OSCORE_RULE) == 22
    assert bytes.fromhex(vector["packet"]) == _CANONICAL_PACKET
    assert bytes.fromhex(vector["compressed"]) == _CANONICAL_COMPRESSED
    assert decompress_packet(_CANONICAL_COMPRESSED) == _CANONICAL_PACKET
    assert compress_packet(_CANONICAL_PACKET) == _CANONICAL_COMPRESSED


def test_rule5_preserves_oscore_option_without_a_payload() -> None:
    # RFC 8613 permits an empty Object-Security option; RFC 7252 permits a
    # message to end after its options without a payload marker.
    packet = _packet(b"\x90")
    compressed = compress_packet(packet)

    assert compressed[0] == 5
    assert decompress_packet(compressed) == packet


def test_rule5_decompresses_independently_encoded_fields_and_tail() -> None:
    # Hand-packed Rule 5 residue: hop limit, two IIDs, two port low nibbles,
    # CoAP type/TKL/code/MID, two zero padding bits, then unchanged CoAP tail.
    token_and_oscore_tail = bytes.fromhex("aa55 920901 ff010203")
    compressed = bytes.fromhex(
        "05"
        "01"
        "ffffffffffffffff"
        "0102030405060708"
        "0f"
        "c916fbbc"
    ) + token_and_oscore_tail

    src = IPv6Address("fe80::ffff:ffff:ffff:ffff")
    dst = IPv6Address("fe80::102:304:506:708")
    coap = bytes.fromhex("7245beef") + token_and_oscore_tail
    udp = UdpDatagram(5680, 5695, coap).to_bytes(src, dst)
    expected = (
        IPv6Header(src, dst, NextHeader.UDP, payload_length=len(udp), hop_limit=1).to_bytes()
        + udp
    )

    assert decompress_packet(compressed) == expected


def test_rule5_accepts_exact_profile_maximum_and_rejects_one_over() -> None:
    exact_tail = b"\x90\xff" + bytes(MAX_PACKET_SIZE - 25)
    exact_packet = _packet(exact_tail)
    exact_compressed = compress_packet(exact_packet)

    assert len(exact_compressed) == MAX_PACKET_SIZE
    assert exact_compressed[0] == 5
    assert decompress_packet(exact_compressed) == exact_packet

    with pytest.raises(SchcError, match="profile limit"):
        decompress_packet(exact_compressed + b"\x00")


def test_rule5_rejects_every_truncated_residue() -> None:
    for truncated_length in range(1, 23):
        with pytest.raises(
            SchcError,
            match=rf"packet too short: need 23 bytes .* got {truncated_length}",
        ):
            decompress_packet(_CANONICAL_COMPRESSED[:truncated_length])


@pytest.mark.parametrize("padding_bit", (0x01, 0x02))
def test_rule5_rejects_every_nonzero_residue_padding_bit(padding_bit: int) -> None:
    malformed = bytearray(_CANONICAL_COMPRESSED)
    malformed[22] |= padding_bit
    with pytest.raises(SchcError, match="nonzero padding"):
        decompress_packet(bytes(malformed))


@pytest.mark.parametrize(
    "tail",
    (
        b"",  # TKL=2 but no token bytes.
        b"\x00\x01",  # Token present, but required OSCORE option absent.
        b"\x00\x01\x9f",  # Reserved option length nibble.
        b"\x00\x01\x9d",  # Truncated extended option length.
        b"\x00\x01\x91\x01",  # PIV length 1 but missing the PIV byte.
        b"\x00\x01\x90\x00\x90",  # Duplicate OSCORE options.
        b"\x00\x01\x90\xff",  # Payload marker without a payload byte.
    ),
    ids=(
        "token-truncated",
        "oscore-absent",
        "reserved-option-length",
        "extended-length-truncated",
        "invalid-oscore-value",
        "duplicate-oscore-option",
        "empty-payload-marker",
    ),
)
def test_rule5_rejects_malformed_or_non_oscore_tail(tail: bytes) -> None:
    malformed = _CANONICAL_COMPRESSED[:23] + tail
    with pytest.raises(SchcError, match="does not reconstruct its packet profile"):
        decompress_packet(malformed)
