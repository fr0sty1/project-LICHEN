# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Strict inverse coverage for current-spec SCHC Rule 6 (global OSCORE)."""

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
from lichen.schc.rules import GLOBAL_OSCORE_RULE

_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXED_LENGTH = 37
_CANONICAL_PACKET = bytes.fromhex(
    "6000000000161140"
    "027dd5cfc679ab637dd5cfc679ab6342"
    "02f77a7baa1226b5f57a7baa1226b50c"
    "1633163300165339"
    "420112340001920900ffdeadbeef"
)
_CANONICAL_COMPRESSED = bytes.fromhex(
    "06"
    "40"
    "7dd5cfc679ab637dd5cfc679ab6342"
    "f77a7baa1226b5f57a7baa1226b50c"
    "33"
    "080448d0"
    "0001920900ffdeadbeef"
)


def test_rule6_canonical_shared_vector_decompresses_exactly() -> None:
    document = json.loads(
        (_REPO_ROOT / "test/vectors/schc_compression.json").read_text(encoding="utf-8")
    )
    vector = next(item for item in document["vectors"] if item["name"] == "oscore_global")

    assert GLOBAL_OSCORE_RULE.rule_id == 6
    assert residue_bit_length(GLOBAL_OSCORE_RULE) == 286
    assert residue_byte_length(GLOBAL_OSCORE_RULE) == 36
    assert bytes.fromhex(vector["packet"]) == _CANONICAL_PACKET
    assert bytes.fromhex(vector["compressed"]) == _CANONICAL_COMPRESSED
    assert decompress_packet(_CANONICAL_COMPRESSED) == _CANONICAL_PACKET


def test_rule6_decompresses_independently_encoded_fields_and_tail() -> None:
    source = IPv6Address("02ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    destination = IPv6Address("0200::1")
    token_and_tail = bytes.fromhex("aa55920901ff010203")
    compressed = (
        bytes.fromhex("0601")
        + bytes.fromhex("ff" * 15)
        + bytes.fromhex("00" * 14 + "01")
        + bytes.fromhex("0fc916fbbc")
        + token_and_tail
    )

    coap = bytes.fromhex("7245beef") + token_and_tail
    udp = UdpDatagram(5680, 5695, coap).to_bytes(source, destination)
    expected = (
        IPv6Header(
            source,
            destination,
            NextHeader.UDP,
            payload_length=len(udp),
            hop_limit=1,
        ).to_bytes()
        + udp
    )

    assert decompress_packet(compressed) == expected
    assert compress_packet(expected) == compressed


def test_rule6_rejects_every_truncated_residue_without_mutating_input() -> None:
    for length in range(1, _FIXED_LENGTH):
        encoded = bytearray(_CANONICAL_COMPRESSED[:length])
        original = encoded[:]
        with pytest.raises(
            SchcError,
            match=rf"packet too short: need {_FIXED_LENGTH} bytes .* got {length}",
        ):
            decompress_packet(bytes(encoded))
        assert encoded == original


@pytest.mark.parametrize("padding_bit", (0x01, 0x02))
def test_rule6_rejects_both_nonzero_residue_padding_bits(padding_bit: int) -> None:
    malformed = bytearray(_CANONICAL_COMPRESSED)
    malformed[_FIXED_LENGTH - 1] |= padding_bit
    original = malformed[:]
    with pytest.raises(SchcError, match="nonzero padding"):
        decompress_packet(bytes(malformed))
    assert malformed == original


@pytest.mark.parametrize(
    "tail",
    (
        b"",
        b"\x00\x01",
        b"\x00\x01\x9f",
        b"\x00\x01\x9d",
        b"\x00\x01\x91\x01",
        b"\x00\x01\x90\x00",
        b"\x00\x01\x90\xff",
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
def test_rule6_rejects_plaintext_or_malformed_oscore_tail(tail: bytes) -> None:
    malformed = _CANONICAL_COMPRESSED[:_FIXED_LENGTH] + tail
    with pytest.raises(SchcError, match="does not reconstruct its packet profile"):
        decompress_packet(malformed)


def test_rule6_rejects_reserved_token_length() -> None:
    malformed = bytearray(_CANONICAL_COMPRESSED[:_FIXED_LENGTH])
    malformed[33] = (malformed[33] & 0xC3) | (9 << 2)
    malformed.extend(bytes(9))
    with pytest.raises(SchcError, match="does not reconstruct its packet profile"):
        decompress_packet(bytes(malformed))


def test_rule6_accepts_exact_profile_maximum_and_rejects_one_over() -> None:
    exact = bytearray(_CANONICAL_COMPRESSED[:_FIXED_LENGTH])
    exact.extend(b"\x00\x01\x90\xff")
    exact.extend(bytes(MAX_PACKET_SIZE - len(exact)))
    exact_bytes = bytes(exact)

    restored = decompress_packet(exact_bytes)
    assert len(exact_bytes) == MAX_PACKET_SIZE
    assert compress_packet(restored) == exact_bytes

    overlong = exact_bytes + b"\x00"
    with pytest.raises(SchcError, match="profile limit"):
        decompress_packet(overlong)


def test_rule6_decompression_requires_immutable_bytes_input() -> None:
    with pytest.raises(TypeError, match="bytes"):
        decompress_packet(bytearray(_CANONICAL_COMPRESSED))  # type: ignore[arg-type]
