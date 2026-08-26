# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent conformance tests for Version 3 SCHC Rule 2."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.schc.codec import SchcError, residue_bit_length, residue_byte_length
from lichen.schc.fragment import MAX_PACKET_SIZE
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.rules import CDA, LINK_LOCAL_ICMPV6_ECHO_RULE, MO

CANONICAL_REQUEST = bytes.fromhex(
    "60000000000c3a40"
    "fe800000000000000000000000000001"
    "fe800000000000000000000000000002"
    "8000f80eabcd000770696e67"
)
CANONICAL_REQUEST_COMPRESSED = bytes.fromhex(
    "02400000000000000001000000000000000280abcd000770696e67"
)
CANONICAL_REPLY = bytes.fromhex(
    "60000000000c3a40"
    "fe800000000000000000000000000001"
    "fe800000000000000000000000000002"
    "8100907f1234002a706f6e67"
)
CANONICAL_REPLY_COMPRESSED = bytes.fromhex("024000000000000000010000000000000002811234002a706f6e67")
LINK_LOCAL_SOURCE = IPv6Address("fe80::1")
LINK_LOCAL_DESTINATION = IPv6Address("fe80::2")


def _internet_checksum(data: bytes) -> int:
    """Small independent RFC 1071 oracle used only to make test packets."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[offset : offset + 2], "big") for offset in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _echo_packet(
    payload: bytes,
    *,
    source: IPv6Address = LINK_LOCAL_SOURCE,
    destination: IPv6Address = LINK_LOCAL_DESTINATION,
    echo_type: int = 128,
    code: int = 0,
    identifier: int = 0xABCD,
    sequence: int = 7,
    traffic_class: int = 0,
    flow_label: int = 0,
    hop_limit: int = 64,
) -> bytes:
    """Serialize IPv6 and ICMPv6 directly, independently of LICHEN codecs."""
    body = identifier.to_bytes(2, "big") + sequence.to_bytes(2, "big") + payload
    without_checksum = bytes((echo_type, code, 0, 0)) + body
    pseudo_header = (
        source.packed
        + destination.packed
        + len(without_checksum).to_bytes(4, "big")
        + b"\x00\x00\x00\x3a"
    )
    checksum = _internet_checksum(pseudo_header + without_checksum)
    icmpv6 = bytes((echo_type, code)) + checksum.to_bytes(2, "big") + body
    version_tc_fl = (6 << 28) | (traffic_class << 20) | flow_label
    ipv6 = (
        version_tc_fl.to_bytes(4, "big")
        + len(icmpv6).to_bytes(2, "big")
        + bytes((58, hop_limit))
        + source.packed
        + destination.packed
    )
    return ipv6 + icmpv6


def test_rule2_v3_descriptors_have_exact_mo_cda_contract() -> None:
    rule = LINK_LOCAL_ICMPV6_ECHO_RULE
    assert rule.rule_id == 2
    assert residue_bit_length(rule) == 176
    assert residue_byte_length(rule) == 22
    assert [
        (
            field.field_id,
            field.length_bits,
            field.mo,
            field.cda,
            field.target_value,
            field.mo_arg,
        )
        for field in rule.fields
    ] == [
        ("IPv6.version", 4, MO.EQUAL, CDA.NOT_SENT, 6, None),
        ("IPv6.traffic_class", 8, MO.EQUAL, CDA.NOT_SENT, 0, None),
        ("IPv6.flow_label", 20, MO.EQUAL, CDA.NOT_SENT, 0, None),
        ("IPv6.payload_length", 16, MO.IGNORE, CDA.COMPUTE, 0, None),
        ("IPv6.next_header", 8, MO.EQUAL, CDA.NOT_SENT, 58, None),
        ("IPv6.hop_limit", 8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        (
            "IPv6.src",
            128,
            MO.MSB,
            CDA.LSB,
            int(IPv6Address("fe80::")),
            64,
        ),
        (
            "IPv6.dst",
            128,
            MO.MSB,
            CDA.LSB,
            int(IPv6Address("fe80::")),
            64,
        ),
        ("ICMPv6.type", 8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        ("ICMPv6.code", 8, MO.EQUAL, CDA.NOT_SENT, 0, None),
        ("ICMPv6.checksum", 16, MO.IGNORE, CDA.COMPUTE, 0, None),
        ("ICMPv6.identifier", 16, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        ("ICMPv6.sequence", 16, MO.IGNORE, CDA.VALUE_SENT, 0, None),
    ]


@pytest.mark.parametrize(
    ("packet", "compressed"),
    [
        (CANONICAL_REQUEST, CANONICAL_REQUEST_COMPRESSED),
        (CANONICAL_REPLY, CANONICAL_REPLY_COMPRESSED),
    ],
)
def test_rule2_matches_independently_derived_canonical_bytes(
    packet: bytes, compressed: bytes
) -> None:
    assert compress_packet(packet) == compressed
    assert decompress_packet(compressed) == packet


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00",
        bytes.fromhex("00ff807f") * 17,
        bytes(range(256)),
        b"opaque-echo-data" * 73,
    ],
)
def test_rule2_preserves_variable_echo_payload(payload: bytes) -> None:
    packet = _echo_packet(payload, identifier=0, sequence=0xFFFF, hop_limit=1)
    compressed = compress_packet(packet)
    assert compressed[0] == 2
    assert compressed[23:] == payload
    assert decompress_packet(compressed) == packet


@pytest.mark.parametrize("echo_type", [128, 129])
@pytest.mark.parametrize("hop_limit", [0, 255])
@pytest.mark.parametrize("identifier", [0, 0xFFFF])
@pytest.mark.parametrize("sequence", [0, 0xFFFF])
def test_rule2_decompresses_independently_encoded_field_extremes(
    echo_type: int, hop_limit: int, identifier: int, sequence: int
) -> None:
    """Exercise the decompressor without using the production compressor."""
    source_iid = 0x0000_0000_0000_0000
    destination_iid = 0xFFFF_FFFF_FFFF_FFFF
    payload = b"\x00\xffopaque"
    compressed = (
        bytes((2, hop_limit))
        + source_iid.to_bytes(8, "big")
        + destination_iid.to_bytes(8, "big")
        + bytes((echo_type,))
        + identifier.to_bytes(2, "big")
        + sequence.to_bytes(2, "big")
        + payload
    )
    expected = _echo_packet(
        payload,
        source=IPv6Address("fe80::"),
        destination=IPv6Address("fe80::ffff:ffff:ffff:ffff"),
        echo_type=echo_type,
        identifier=identifier,
        sequence=sequence,
        hop_limit=hop_limit,
    )

    assert decompress_packet(compressed) == expected


@pytest.mark.parametrize("first_payload_octet", range(256))
def test_rule2_byte_aligned_residue_preserves_every_first_payload_octet(
    first_payload_octet: int,
) -> None:
    """Rule 2 has no padding bits: all bits after byte 22 are opaque payload."""
    payload = bytes((first_payload_octet,)) + b"tail"
    compressed = CANONICAL_REQUEST_COMPRESSED[:23] + payload

    assert decompress_packet(compressed) == _echo_packet(payload)


@pytest.mark.parametrize(
    "packet",
    [
        _echo_packet(b"tc", traffic_class=1),
        _echo_packet(b"flow", flow_label=1),
        _echo_packet(b"prefix", source=IPv6Address("fe80:0:0:1::1")),
        _echo_packet(b"global", destination=IPv6Address("2001:db8::2")),
        _echo_packet(b"other-type", echo_type=1),
        _echo_packet(b"nonzero-code", code=1),
    ],
)
def test_rule2_well_formed_nonmatches_use_rule255(packet: bytes) -> None:
    compressed = compress_packet(packet)
    assert compressed == b"\xff" + packet
    assert decompress_packet(compressed) == packet


def test_rule2_checksum_nonmatch_is_not_normalized() -> None:
    packet = bytearray(_echo_packet(b"checksum"))
    packet[42] ^= 1
    compressed = compress_packet(bytes(packet))
    assert compressed == b"\xff" + packet
    assert decompress_packet(compressed) == packet


def test_rule2_accepts_exact_profile_ceiling() -> None:
    payload = bytes(MAX_PACKET_SIZE - 23)
    packet = _echo_packet(payload)
    compressed = compress_packet(packet)
    assert len(compressed) == MAX_PACKET_SIZE
    assert compressed[:23] == CANONICAL_REQUEST_COMPRESSED[:23]
    assert decompress_packet(compressed) == packet


def test_rule2_rejects_packet_beyond_profile_ceiling() -> None:
    with pytest.raises(SchcError, match="profile limit"):
        compress_packet(_echo_packet(bytes(MAX_PACKET_SIZE - 22)))


@pytest.mark.parametrize("wire_length", range(1, 23))
def test_rule2_rejects_every_truncated_fixed_residue(wire_length: int) -> None:
    with pytest.raises(SchcError, match="packet too short"):
        decompress_packet(CANONICAL_REQUEST_COMPRESSED[:wire_length])


@pytest.mark.parametrize("echo_type", [value for value in range(256) if value not in (128, 129)])
def test_rule2_decoder_rejects_non_echo_type_residue(echo_type: int) -> None:
    malformed = bytearray(CANONICAL_REQUEST_COMPRESSED)
    malformed[18] = echo_type
    with pytest.raises(SchcError, match="does not reconstruct its packet profile"):
        decompress_packet(bytes(malformed))


def test_rule2_rejects_oversized_encoded_packet() -> None:
    with pytest.raises(SchcError, match="profile limit"):
        decompress_packet(CANONICAL_REQUEST_COMPRESSED + bytes(MAX_PACKET_SIZE))
