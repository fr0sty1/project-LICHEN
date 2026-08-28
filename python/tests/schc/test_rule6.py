# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Current-spec compression coverage for SCHC Rule 6 (global OSCORE)."""

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
_SRC = IPv6Address("027d:d5cf:c679:ab63:7dd5:cfc6:79ab:6342")
_DST = IPv6Address("02f7:7a7b:aa12:26b5:f57a:7baa:1226:b50c")

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


def _packet(
    options_and_payload: bytes,
    *,
    src: IPv6Address = _SRC,
    dst: IPv6Address = _DST,
    src_port: int = 5683,
    dst_port: int = 5683,
    hop_limit: int = 64,
    coap_type: int = 0,
    token: bytes = b"",
    code: int = 1,
    mid: int = 0x1234,
) -> bytes:
    coap = (
        bytes(((1 << 6) | (coap_type << 4) | len(token), code, mid >> 8, mid & 0xFF))
        + token
        + options_and_payload
    )
    udp = UdpDatagram(src_port, dst_port, coap).to_bytes(src, dst)
    return (
        IPv6Header(
            src,
            dst,
            NextHeader.UDP,
            payload_length=len(udp),
            hop_limit=hop_limit,
        ).to_bytes()
        + udp
    )


def test_rule6_is_current_global_oscore_contract_and_matches_shared_vector() -> None:
    document = json.loads(
        (_REPO_ROOT / "test/vectors/schc_compression.json").read_text(encoding="utf-8")
    )
    vector = next(item for item in document["vectors"] if item["name"] == "oscore_global")

    assert GLOBAL_OSCORE_RULE.rule_id == 6
    assert residue_bit_length(GLOBAL_OSCORE_RULE) == 286
    assert residue_byte_length(GLOBAL_OSCORE_RULE) == 36
    assert bytes.fromhex(vector["packet"]) == _CANONICAL_PACKET
    assert bytes.fromhex(vector["compressed"]) == _CANONICAL_COMPRESSED
    assert compress_packet(_CANONICAL_PACKET) == _CANONICAL_COMPRESSED
    assert decompress_packet(_CANONICAL_COMPRESSED) == _CANONICAL_PACKET


def test_rule6_independent_field_extremes_have_exact_canonical_packing() -> None:
    source = IPv6Address("02ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    destination = IPv6Address("0200::1")
    tail = bytes.fromhex("920901ff010203")
    packet = _packet(
        tail,
        src=source,
        dst=destination,
        src_port=5680,
        dst_port=5695,
        hop_limit=1,
        coap_type=3,
        token=bytes.fromhex("aa55"),
        code=0x45,
        mid=0xBEEF,
    )
    expected = (
        bytes.fromhex("0601")
        + bytes.fromhex("ff" * 15)
        + bytes.fromhex("00" * 14 + "01")
        + bytes.fromhex("0fc916fbbcaa55")
        + tail
    )

    assert compress_packet(packet) == expected
    assert decompress_packet(expected) == packet


@pytest.mark.parametrize(
    "tail",
    (
        b"",
        b"\x9f",
        b"\x9d",
        b"\x91\x01",
        b"\x90\x00",
        b"\x90\xff",
    ),
    ids=(
        "oscore-absent",
        "reserved-option-length",
        "extended-length-truncated",
        "invalid-oscore-value",
        "duplicate-oscore-option",
        "empty-payload-marker",
    ),
)
def test_rule6_never_claims_plaintext_or_malformed_oscore(tail: bytes) -> None:
    # These are structurally valid IPv6/UDP/CoAP packets, but not valid OSCORE.
    # Current-spec Rule 1 preserves them; stale EDHOC wording must not select 6.
    compressed = compress_packet(_packet(tail))
    assert compressed[0] == 1
    assert decompress_packet(compressed) == _packet(tail)


@pytest.mark.parametrize(
    "tail",
    (
        b"\x90",
        b"\x92\x09\x01",
        b"\x92\x01\x01",
        b"\x95\x19\x01\x01\xaa\xbb",
    ),
)
def test_rule6_accepts_valid_oscore_option_forms(tail: bytes) -> None:
    packet = _packet(tail)
    compressed = compress_packet(packet)
    assert compressed[0] == 6
    assert decompress_packet(compressed) == packet


@pytest.mark.parametrize(
    ("src", "dst"),
    (
        (IPv6Address("2001:db8::1"), _DST),
        (_SRC, IPv6Address("2001:db8::2")),
        (IPv6Address("fe80::1"), IPv6Address("fe80::2")),
    ),
)
def test_rule6_requires_both_canonical_yggdrasil_addresses(
    src: IPv6Address, dst: IPv6Address
) -> None:
    compressed = compress_packet(_packet(b"\x90", src=src, dst=dst))
    assert compressed[0] != 6


def test_rule6_accepts_exact_profile_maximum_and_rejects_one_over() -> None:
    exact_tail = b"\x90\xff" + bytes(MAX_PACKET_SIZE - 39)
    packet = _packet(exact_tail)
    compressed = compress_packet(packet)

    assert len(compressed) == MAX_PACKET_SIZE
    assert compressed[0] == 6
    assert decompress_packet(compressed) == packet

    with pytest.raises(SchcError, match="profile limit"):
        compress_packet(_packet(exact_tail + b"\x00"))


def test_rule6_rejects_invalid_udp_checksum_without_output() -> None:
    malformed = bytearray(_CANONICAL_PACKET)
    malformed[47] ^= 1
    with pytest.raises(SchcError, match="checksum"):
        compress_packet(bytes(malformed))


def test_rule6_requires_immutable_bytes_input() -> None:
    with pytest.raises(SchcError, match="bytes"):
        compress_packet(bytearray(_CANONICAL_PACKET))  # type: ignore[arg-type]
