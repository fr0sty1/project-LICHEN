# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Bit-exact coverage for Rule Set Version 3 Rule 1."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.schc.codec import SchcError, residue_bit_length, residue_byte_length
from lichen.schc.fragment import MAX_PACKET_SIZE
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.rules import CDA, GLOBAL_COAP_RULE, MO

_SRC = IPv6Address("027d:d5cf:c679:ab63:7dd5:cfc6:79ab:6342")
_DST = IPv6Address("02f7:7a7b:aa12:26b5:f57a:7baa:1226:b50c")

# Hand-copied wire oracle from the normative field order, not generated through
# the implementation under test.  It exercises the complete 120-bit address
# residues and the two zero padding bits at the end of the 286-bit residue.
_CANONICAL_PACKET = bytes.fromhex(
    "6000000000131140"
    "027dd5cfc679ab637dd5cfc679ab6342"
    "02f77a7baa1226b5f57a7baa1226b50c"
    "1633163300132a9b"
    "40011234ff737461747573"
)
_CANONICAL_COMPRESSED = bytes.fromhex(
    "01407dd5cfc679ab637dd5cfc679ab6342f77a7baa1226b5f57a7baa1226b50c33000448d0ff737461747573"
)


def _coap_packet(
    *,
    src: IPv6Address = _SRC,
    dst: IPv6Address = _DST,
    src_port: int = 5683,
    dst_port: int = 5683,
    traffic_class: int = 0,
    flow_label: int = 0,
    hop_limit: int = 64,
    coap_version: int = 1,
    coap_type: int = 0,
    token: bytes = b"",
    code: int = 1,
    mid: int = 0x1234,
    tail: bytes = b"",
) -> bytes:
    coap = (
        bytes(
            [
                (coap_version << 6) | (coap_type << 4) | len(token),
                code,
                mid >> 8,
                mid & 0xFF,
            ]
        )
        + token
        + tail
    )
    udp = UdpDatagram(src_port, dst_port, coap).to_bytes(src, dst)
    header = IPv6Header(
        src,
        dst,
        NextHeader.UDP,
        payload_length=len(udp),
        hop_limit=hop_limit,
        traffic_class=traffic_class,
        flow_label=flow_label,
    )
    return header.to_bytes() + udp


def test_rule1_descriptor_is_exact_rule_set_v3_contract() -> None:
    global_prefix = 0x02 << 120
    expected = (
        ("IPv6.version", 4, MO.EQUAL, CDA.NOT_SENT, 6, None),
        ("IPv6.traffic_class", 8, MO.EQUAL, CDA.NOT_SENT, 0, None),
        ("IPv6.flow_label", 20, MO.EQUAL, CDA.NOT_SENT, 0, None),
        ("IPv6.payload_length", 16, MO.IGNORE, CDA.COMPUTE, 0, None),
        ("IPv6.next_header", 8, MO.EQUAL, CDA.NOT_SENT, 17, None),
        ("IPv6.hop_limit", 8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        ("IPv6.src", 128, MO.MSB, CDA.LSB, global_prefix, 8),
        ("IPv6.dst", 128, MO.MSB, CDA.LSB, global_prefix, 8),
        ("UDP.src_port", 16, MO.MSB, CDA.LSB, 5683, 12),
        ("UDP.dst_port", 16, MO.MSB, CDA.LSB, 5683, 12),
        ("UDP.length", 16, MO.IGNORE, CDA.COMPUTE, 0, None),
        ("UDP.checksum", 16, MO.IGNORE, CDA.COMPUTE, 0, None),
        ("CoAP.version", 2, MO.EQUAL, CDA.NOT_SENT, 1, None),
        ("CoAP.type", 2, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        ("CoAP.tkl", 4, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        ("CoAP.code", 8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        ("CoAP.mid", 16, MO.IGNORE, CDA.VALUE_SENT, 0, None),
    )
    actual = tuple(
        (
            field.field_id,
            field.length_bits,
            field.mo,
            field.cda,
            field.target_value,
            field.mo_arg,
        )
        for field in GLOBAL_COAP_RULE.fields
    )
    assert GLOBAL_COAP_RULE.rule_id == 1
    assert actual == expected
    assert residue_bit_length(GLOBAL_COAP_RULE) == 286
    assert residue_byte_length(GLOBAL_COAP_RULE) == 36


def test_rule1_matches_independent_canonical_wire_oracle() -> None:
    assert compress_packet(_CANONICAL_PACKET) == _CANONICAL_COMPRESSED
    assert decompress_packet(_CANONICAL_COMPRESSED) == _CANONICAL_PACKET


@pytest.mark.parametrize(
    "packet",
    [
        _coap_packet(src=IPv6Address("2001:db8::1")),
        _coap_packet(dst=IPv6Address("2001:db8::2")),
        _coap_packet(src_port=5696),
        _coap_packet(dst_port=5696),
        _coap_packet(traffic_class=1),
        _coap_packet(flow_label=1),
        _coap_packet(coap_version=2),
    ],
    ids=(
        "source-prefix",
        "destination-prefix",
        "source-port-msb",
        "destination-port-msb",
        "traffic-class",
        "flow-label",
        "coap-version",
    ),
)
def test_rule1_nonmatches_use_validated_rule255(packet: bytes) -> None:
    compressed = compress_packet(packet)
    assert compressed == b"\xff" + packet
    assert decompress_packet(compressed) == packet


def test_rule1_preserves_variable_token_options_and_payload_tail() -> None:
    token = b"\xaa\x55"
    options_and_payload = b"\xb1x\x11y\xffvariable payload"
    packet = _coap_packet(
        src_port=5680,
        dst_port=5695,
        hop_limit=255,
        coap_type=3,
        token=token,
        code=0x45,
        mid=0xBEEF,
        tail=options_and_payload,
    )
    compressed = compress_packet(packet)
    unchanged_tail = token + options_and_payload
    assert compressed[0] == 1
    assert len(compressed) == 37 + len(unchanged_tail)
    assert compressed[37:] == unchanged_tail
    assert decompress_packet(compressed) == packet


def test_rule1_decompresses_independently_encoded_field_extremes_and_tail() -> None:
    source = IPv6Address("02ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    destination = IPv6Address("0200::1")
    token = bytes.fromhex("aa55")
    options_and_payload = bytes.fromhex("b1781179ff") + b"opaque payload"
    # Hand-packed from the Rule 1 descriptor: hop limit, two 120-bit address
    # suffixes, two 4-bit port suffixes, CoAP type/TKL/code/MID, then two zero
    # padding bits.  It deliberately does not pass through compress_packet().
    compressed = bytes.fromhex(
        "01"
        "01"
        "ffffffffffffffffffffffffffffff"
        "000000000000000000000000000001"
        "0fc916fbbc"
    ) + token + options_and_payload

    assert decompress_packet(compressed) == _coap_packet(
        src=source,
        dst=destination,
        src_port=5680,
        dst_port=5695,
        hop_limit=1,
        coap_type=3,
        token=token,
        code=0x45,
        mid=0xBEEF,
        tail=options_and_payload,
    )


def test_rule1_accepts_exact_profile_maximum_and_rejects_one_over() -> None:
    exact_tail = bytes(MAX_PACKET_SIZE - 37)
    exact_packet = _coap_packet(tail=exact_tail)
    exact_compressed = compress_packet(exact_packet)
    assert len(exact_compressed) == MAX_PACKET_SIZE
    assert exact_compressed[0] == 1
    assert decompress_packet(exact_compressed) == exact_packet

    one_over = _coap_packet(tail=exact_tail + b"\x00")
    with pytest.raises(SchcError, match="profile limit"):
        compress_packet(one_over)

    overlong_compressed = _CANONICAL_COMPRESSED + bytes(
        MAX_PACKET_SIZE - len(_CANONICAL_COMPRESSED) + 1
    )
    with pytest.raises(SchcError, match="profile limit"):
        decompress_packet(overlong_compressed)


def test_rule1_rejects_truncated_residue() -> None:
    for truncated_length in range(1, 37):
        with pytest.raises(
            SchcError,
            match=rf"packet too short: need 37 bytes .* got {truncated_length}",
        ):
            decompress_packet(_CANONICAL_COMPRESSED[:truncated_length])


@pytest.mark.parametrize("padding_bit", (0x01, 0x02))
def test_rule1_rejects_every_nonzero_residue_padding_bit(padding_bit: int) -> None:
    malformed = bytearray(_CANONICAL_COMPRESSED)
    malformed[36] |= padding_bit
    with pytest.raises(SchcError, match="nonzero padding"):
        decompress_packet(bytes(malformed))


@pytest.mark.parametrize(
    "malformed",
    (
        # TKL=1 with no token byte following the fixed residue.
        bytes.fromhex(
            "01407dd5cfc679ab637dd5cfc679ab6342"
            "f77a7baa1226b5f57a7baa1226b50c33040448d0"
        ),
        # TKL=9 is reserved by RFC 7252 even if tail bytes are available.
        bytes.fromhex(
            "01407dd5cfc679ab637dd5cfc679ab6342"
            "f77a7baa1226b5f57a7baa1226b50c33240448d0"
        )
        + bytes(9),
    ),
    ids=("token-shorter-than-tkl", "reserved-tkl"),
)
def test_rule1_rejects_residue_that_reconstructs_malformed_coap(malformed: bytes) -> None:
    with pytest.raises(SchcError, match="does not reconstruct its packet profile"):
        decompress_packet(malformed)


def test_rule1_rejects_invalid_udp_checksum_before_compression() -> None:
    malformed = bytearray(_CANONICAL_PACKET)
    malformed[46] ^= 0x01
    with pytest.raises(SchcError, match="checksum"):
        compress_packet(bytes(malformed))


@pytest.mark.parametrize(
    ("payload_length", "message"),
    ((18, "trailing byte"), (20, "payload_length says 20 but 19 bytes present")),
    ids=("understated", "overstated"),
)
def test_rule1_rejects_inconsistent_ipv6_payload_length(
    payload_length: int, message: str
) -> None:
    malformed = bytearray(_CANONICAL_PACKET)
    malformed[4:6] = payload_length.to_bytes(2, "big")
    with pytest.raises(SchcError, match=message):
        compress_packet(bytes(malformed))


@pytest.mark.parametrize(
    ("udp_length", "message"),
    ((7, "UDP length 7 too small"), (18, "UDP length 18 != 19 bytes present")),
    ids=("below-minimum", "inconsistent-with-ipv6"),
)
def test_rule1_rejects_malformed_udp_length(udp_length: int, message: str) -> None:
    malformed = bytearray(_CANONICAL_PACKET)
    malformed[44:46] = udp_length.to_bytes(2, "big")
    with pytest.raises(SchcError, match=message):
        compress_packet(bytes(malformed))


def test_rule1_rejects_zero_ipv6_udp_checksum() -> None:
    malformed = bytearray(_CANONICAL_PACKET)
    malformed[46:48] = bytes(2)
    with pytest.raises(SchcError, match="checksum is zero"):
        compress_packet(bytes(malformed))
