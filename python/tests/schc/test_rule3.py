# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent wire and rejection oracles for SCHC Rule 3 (RPL DIO)."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.ipv6.icmpv6 import icmpv6_checksum
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.schc import CDA, MO, SchcError
from lichen.schc.codec import decompress, residue_bit_length, residue_byte_length
from lichen.schc.fragment import MAX_PACKET_SIZE
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.rules import RPL_DIO_RULE

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SRC = IPv6Address("fe80::1")
_DST = IPv6Address("fe80::2")
_DODAG_ID = IPv6Address("fe80::1")

# Derived directly from the Rule Set Version 3 field layout in Appendix A.5:
# RuleID, HopLimit, two 64-bit IIDs, Instance, Version, Rank, GMOP, DTSN,
# and DODAGID. ICMPv6 type/code/checksum and the zero flags/reserved octets are
# elided; this constant does not call the codec under test.
_CANONICAL_PACKET = bytes.fromhex(
    "60000000001c3a40"
    "fe800000000000000000000000000001"
    "fe800000000000000000000000000002"
    "9b01e01f"
    "0001010088000000"
    "fe800000000000000000000000000001"
)
_CANONICAL_COMPRESSED = bytes.fromhex(
    "034000000000000000010000000000000002000101008800fe800000000000000000000000000001"
)


def _dio_packet(
    *,
    source: IPv6Address = _SRC,
    destination: IPv6Address = _DST,
    hop_limit: int = 64,
    instance: int = 0,
    version: int = 1,
    rank: int = 256,
    gmop: int = 0x88,
    dtsn: int = 0,
    flags: int = 0,
    reserved: int = 0,
    dodag_id: IPv6Address = _DODAG_ID,
    tail: bytes = b"",
    traffic_class: int = 0,
    flow_label: int = 0,
    rpl_type: int = 155,
    code: int = 1,
) -> bytes:
    """Build a DIO packet directly from RFC 6550 base-object fields."""
    dio = (
        bytes((instance, version))
        + rank.to_bytes(2, "big")
        + bytes((gmop, dtsn, flags, reserved))
        + dodag_id.packed
        + tail
    )
    without_checksum = bytes((rpl_type, code, 0, 0)) + dio
    checksum = icmpv6_checksum(source, destination, without_checksum)
    icmpv6 = bytes((rpl_type, code)) + checksum.to_bytes(2, "big") + dio
    ipv6 = IPv6Header(
        source,
        destination,
        NextHeader.ICMPV6,
        payload_length=len(icmpv6),
        hop_limit=hop_limit,
        traffic_class=traffic_class,
        flow_label=flow_label,
    )
    return ipv6.to_bytes() + icmpv6


def test_rule3_descriptor_contract_and_residue_width() -> None:
    expected = {
        "IPv6.version": (4, MO.EQUAL, CDA.NOT_SENT, 6, None),
        "IPv6.traffic_class": (8, MO.EQUAL, CDA.NOT_SENT, 0, None),
        "IPv6.flow_label": (20, MO.EQUAL, CDA.NOT_SENT, 0, None),
        "IPv6.payload_length": (16, MO.IGNORE, CDA.COMPUTE, 0, None),
        "IPv6.next_header": (8, MO.EQUAL, CDA.NOT_SENT, 58, None),
        "IPv6.hop_limit": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "IPv6.src": (128, MO.MSB, CDA.LSB, int(IPv6Address("fe80::")), 64),
        "IPv6.dst": (128, MO.MSB, CDA.LSB, int(IPv6Address("fe80::")), 64),
        "ICMPv6.type": (8, MO.EQUAL, CDA.NOT_SENT, 155, None),
        "ICMPv6.code": (8, MO.EQUAL, CDA.NOT_SENT, 1, None),
        "ICMPv6.checksum": (16, MO.IGNORE, CDA.COMPUTE, 0, None),
        "RPL.instance": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "RPL.version": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "RPL.rank": (16, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "RPL.gmop": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "RPL.dtsn": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "RPL.flags": (8, MO.EQUAL, CDA.NOT_SENT, 0, None),
        "RPL.reserved": (8, MO.EQUAL, CDA.NOT_SENT, 0, None),
        "RPL.dodagid": (128, MO.IGNORE, CDA.VALUE_SENT, 0, None),
    }
    actual = {
        field.field_id: (
            field.length_bits,
            field.mo,
            field.cda,
            field.target_value,
            field.mo_arg,
        )
        for field in RPL_DIO_RULE.fields
    }

    assert RPL_DIO_RULE.rule_id == 3
    assert actual == expected
    assert all(field.mo is not MO.MATCH_MAPPING for field in RPL_DIO_RULE.fields)
    assert residue_bit_length(RPL_DIO_RULE) == 312
    assert residue_byte_length(RPL_DIO_RULE) == 39


def test_rule3_independent_wire_oracle_matches_canonical_vector() -> None:
    assert _dio_packet() == _CANONICAL_PACKET
    assert compress_packet(_CANONICAL_PACKET) == _CANONICAL_COMPRESSED
    assert decompress_packet(_CANONICAL_COMPRESSED) == _CANONICAL_PACKET

    document = json.loads(
        (_REPO_ROOT / "test/vectors/schc_compression.json").read_text(encoding="utf-8")
    )
    canonical = next(vector for vector in document["vectors"] if vector["name"] == "rpl_dio")
    assert bytes.fromhex(canonical["packet"]) == _CANONICAL_PACKET
    assert bytes.fromhex(canonical["compressed"]) == _CANONICAL_COMPRESSED
    assert canonical["rule_id"] == 3


def test_rule3_preserves_variable_fields_and_opaque_option_tail() -> None:
    # A complete Prefix Information Option (type 8, length 30) is opaque in
    # Version 3 and follows the fixed residue without mapping compression.
    tail = bytes.fromhex("081e40c0000151800000a8c000000000fd000000000000000000000000000000")
    packet = _dio_packet(
        source=IPv6Address("fe80::ffff:ffff:ffff:ffff"),
        destination=IPv6Address("fe80::102:304:506:708"),
        hop_limit=1,
        instance=255,
        version=255,
        rank=0xFFFF,
        gmop=255,
        dtsn=255,
        dodag_id=IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"),
        tail=tail,
    )
    compressed = compress_packet(packet)

    assert compressed[0] == 3
    assert compressed[1] == 1
    assert compressed[18:24] == bytes.fromhex("ffffffffffff")
    assert compressed[40:] == tail
    assert decompress_packet(compressed) == packet


def test_rule3_decompresses_independently_encoded_opaque_tail() -> None:
    source = IPv6Address("fe80::ffff:ffff:ffff:ffff")
    destination = IPv6Address("fe80::102:304:506:708")
    dodag_id = IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    # Deliberately not a well-formed option sequence: the Version 3 codec must
    # carry tail bytes verbatim and leave option parsing to the RPL layer.
    tail = bytes.fromhex("00ff")
    compressed = (
        bytes((3, 255))
        + source.packed[8:]
        + destination.packed[8:]
        + bytes((255, 255))
        + bytes.fromhex("ffff")
        + bytes((255, 255))
        + dodag_id.packed
        + tail
    )

    assert decompress_packet(compressed) == _dio_packet(
        source=source,
        destination=destination,
        hop_limit=255,
        instance=255,
        version=255,
        rank=0xFFFF,
        gmop=255,
        dtsn=255,
        dodag_id=dodag_id,
        tail=tail,
    )


@pytest.mark.parametrize(
    "packet",
    [
        _dio_packet(flags=1),
        _dio_packet(reserved=1),
        _dio_packet(traffic_class=1),
        _dio_packet(flow_label=1),
        _dio_packet(source=IPv6Address("fe80:0:0:1::1")),
        _dio_packet(destination=IPv6Address("fe80:0:0:1::2")),
        _dio_packet(destination=IPv6Address("ff02::1a")),
        _dio_packet(rpl_type=154),
        _dio_packet(code=0),
    ],
    ids=(
        "flags-nonzero",
        "reserved-nonzero",
        "traffic-class-nonzero",
        "flow-label-nonzero",
        "source-outside-canonical-prefix",
        "destination-outside-canonical-prefix",
        "canonical-multicast-destination",
        "wrong-icmpv6-type",
        "wrong-rpl-code",
    ),
)
def test_rule3_well_formed_nonmatches_use_rule255(packet: bytes) -> None:
    compressed = compress_packet(packet)
    assert compressed == b"\xff" + packet
    assert decompress_packet(compressed) == packet


def test_rule3_rejects_truncated_residue_and_malformed_packets() -> None:
    for truncated_length in range(1, len(_CANONICAL_COMPRESSED)):
        with pytest.raises(
            SchcError,
            match=rf"packet too short: need 40 bytes .* got {truncated_length}",
        ):
            decompress_packet(_CANONICAL_COMPRESSED[:truncated_length])

    with pytest.raises(ValueError, match="empty SCHC packet"):
        decompress_packet(b"")
    with pytest.raises(SchcError, match="IPv6 packet length"):
        compress_packet(b"\x60" * 39)

    understated_payload = bytearray(_CANONICAL_PACKET)
    understated_payload[4:6] = (27).to_bytes(2, "big")
    with pytest.raises(SchcError, match="trailing byte"):
        compress_packet(bytes(understated_payload))

    overstated_payload = bytearray(_CANONICAL_PACKET)
    overstated_payload[4:6] = (29).to_bytes(2, "big")
    with pytest.raises(SchcError, match="payload_length says 29 but 28 bytes present"):
        compress_packet(bytes(overstated_payload))


def test_rule3_low_level_decoder_rejects_rule_id_mismatch() -> None:
    wrong_rule_id = bytes((4,)) + _CANONICAL_COMPRESSED[1:]

    with pytest.raises(SchcError, match="rule ID mismatch: packet has 4, rule is 3"):
        decompress(wrong_rule_id, RPL_DIO_RULE)


def test_rule3_enforces_encoded_profile_size_boundary() -> None:
    exact_tail = bytes(MAX_PACKET_SIZE - len(_CANONICAL_COMPRESSED))
    exact_packet = _dio_packet(tail=exact_tail)
    exact_compressed = compress_packet(exact_packet)

    assert len(exact_compressed) == MAX_PACKET_SIZE
    assert exact_compressed[: len(_CANONICAL_COMPRESSED)] == _CANONICAL_COMPRESSED
    assert decompress_packet(exact_compressed) == exact_packet

    with pytest.raises(SchcError, match="profile limit"):
        compress_packet(_dio_packet(tail=exact_tail + b"\x00"))

    overlong_compressed = _CANONICAL_COMPRESSED + bytes(
        MAX_PACKET_SIZE - len(_CANONICAL_COMPRESSED) + 1
    )
    with pytest.raises(SchcError, match="profile limit"):
        decompress_packet(overlong_compressed)
