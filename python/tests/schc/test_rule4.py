# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent wire and rejection oracles for SCHC Rule 4 (RPL DAO)."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.ipv6.icmpv6 import icmpv6_checksum
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.schc import CDA, MO, SchcError
from lichen.schc.codec import residue_bit_length, residue_byte_length
from lichen.schc.fragment import MAX_PACKET_SIZE
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.schc.rules import RPL_DAO_RULE

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SRC = IPv6Address("fe80::1")
_DST = IPv6Address("fe80::2")
_DODAG_ID = IPv6Address("fe80::1")

# Derived by laying out Appendix A.5 fields directly, not by calling the codec:
# RuleID, HopLimit, two 64-bit IIDs, Instance, KD flags, Sequence, DODAGID.
_CANONICAL_PACKET = bytes.fromhex(
    "6000000000183a40"
    "fe800000000000000000000000000001"
    "fe800000000000000000000000000002"
    "9b0268df"
    "00400005"
    "fe800000000000000000000000000001"
)
_CANONICAL_COMPRESSED = bytes.fromhex(
    "04"
    "40"
    "0000000000000001"
    "0000000000000002"
    "00"
    "40"
    "05"
    "fe800000000000000000000000000001"
)


def _dao_packet(
    *,
    source: IPv6Address = _SRC,
    destination: IPv6Address = _DST,
    hop_limit: int = 64,
    instance: int = 0,
    kd_flags: int = 0x40,
    reserved: int = 0,
    sequence: int = 5,
    dodag_id: IPv6Address = _DODAG_ID,
    tail: bytes = b"",
    traffic_class: int = 0,
    flow_label: int = 0,
    code: int = 2,
) -> bytes:
    """Build a DAO packet directly from RFC 6550 fields."""
    dao = bytes((instance, kd_flags, reserved, sequence)) + dodag_id.packed + tail
    without_checksum = bytes((155, code, 0, 0)) + dao
    checksum = icmpv6_checksum(source, destination, without_checksum)
    icmpv6 = bytes((155, code)) + checksum.to_bytes(2, "big") + dao
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


def test_rule4_descriptor_contract_and_residue_width() -> None:
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
        "ICMPv6.code": (8, MO.EQUAL, CDA.NOT_SENT, 2, None),
        "ICMPv6.checksum": (16, MO.IGNORE, CDA.COMPUTE, 0, None),
        "RPL.instance": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "RPL.kd_flags": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
        "RPL.reserved": (8, MO.EQUAL, CDA.NOT_SENT, 0, None),
        "RPL.seq": (8, MO.IGNORE, CDA.VALUE_SENT, 0, None),
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
        for field in RPL_DAO_RULE.fields
    }

    assert RPL_DAO_RULE.rule_id == 4
    assert actual == expected
    assert residue_bit_length(RPL_DAO_RULE) == 288
    assert residue_byte_length(RPL_DAO_RULE) == 36


def test_rule4_independent_wire_oracle_matches_canonical_vector() -> None:
    assert _dao_packet() == _CANONICAL_PACKET
    assert compress_packet(_CANONICAL_PACKET) == _CANONICAL_COMPRESSED
    assert decompress_packet(_CANONICAL_COMPRESSED) == _CANONICAL_PACKET

    document = json.loads(
        (_REPO_ROOT / "test/vectors/schc_compression.json").read_text(encoding="utf-8")
    )
    canonical = next(vector for vector in document["vectors"] if vector["name"] == "rpl_dao")
    assert bytes.fromhex(canonical["packet"]) == _CANONICAL_PACKET
    assert bytes.fromhex(canonical["compressed"]) == _CANONICAL_COMPRESSED
    assert canonical["rule_id"] == 4


def test_rule4_preserves_variable_fields_and_opaque_option_tail() -> None:
    # RFC 6550 Target (type 5) and Transit Information (type 6) option-shaped
    # bytes remain an opaque Rule Set Version 3 tail.
    tail = bytes.fromhex("0512000000000000000000000000000000000001060400010203")
    packet = _dao_packet(
        hop_limit=1,
        instance=255,
        kd_flags=0xC0,
        sequence=255,
        dodag_id=IPv6Address("fe80::ffff:ffff:ffff:ffff"),
        tail=tail,
    )
    compressed = compress_packet(packet)

    assert compressed[0] == 4
    assert compressed[1] == 1
    assert compressed[18:21] == bytes.fromhex("ffc0ff")
    assert compressed[37:] == tail
    assert decompress_packet(compressed) == packet


def test_rule4_decompresses_independently_encoded_field_extremes_and_opaque_tail() -> None:
    source = IPv6Address("fe80::ffff:ffff:ffff:ffff")
    destination = IPv6Address("fe80::102:304:506:708")
    dodag_id = IPv6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    # Rule Set Version 3 does not parse the option tail. These deliberately
    # non-option-shaped octets must therefore survive decompression verbatim.
    tail = bytes.fromhex("00ff")
    compressed = (
        bytes((4, 255))
        + source.packed[8:]
        + destination.packed[8:]
        + bytes((255, 255, 255))
        + dodag_id.packed
        + tail
    )

    assert decompress_packet(compressed) == _dao_packet(
        source=source,
        destination=destination,
        hop_limit=255,
        instance=255,
        kd_flags=255,
        sequence=255,
        dodag_id=dodag_id,
        tail=tail,
    )


@pytest.mark.parametrize(
    "packet",
    [
        _dao_packet(kd_flags=0),
        _dao_packet(reserved=1),
        _dao_packet(traffic_class=1),
        _dao_packet(flow_label=1),
        _dao_packet(source=IPv6Address("fe80:0:0:1::1")),
        _dao_packet(destination=IPv6Address("fe80:0:0:1::2")),
        _dao_packet(code=1),
    ],
    ids=(
        "dodagid-flag-clear",
        "reserved-nonzero",
        "traffic-class-nonzero",
        "flow-label-nonzero",
        "source-outside-canonical-prefix",
        "destination-outside-canonical-prefix",
        "wrong-rpl-code",
    ),
)
def test_rule4_well_formed_nonmatches_use_rule255(packet: bytes) -> None:
    compressed = compress_packet(packet)
    assert compressed == b"\xff" + packet
    assert decompress_packet(compressed) == packet


def test_rule4_rejects_truncated_or_semantically_invalid_residue() -> None:
    for truncated_length in range(1, len(_CANONICAL_COMPRESSED)):
        with pytest.raises(
            SchcError,
            match=rf"packet too short: need 37 bytes .* got {truncated_length}",
        ):
            decompress_packet(_CANONICAL_COMPRESSED[:truncated_length])

    d_flag_clear = bytearray(_CANONICAL_COMPRESSED)
    d_flag_clear[19] &= ~0x40
    with pytest.raises(SchcError, match="D flag clear"):
        decompress_packet(bytes(d_flag_clear))


def test_rule4_enforces_encoded_profile_size_boundary() -> None:
    exact_tail = bytes(MAX_PACKET_SIZE - len(_CANONICAL_COMPRESSED))
    exact_packet = _dao_packet(tail=exact_tail)
    exact_compressed = compress_packet(exact_packet)

    assert len(exact_compressed) == MAX_PACKET_SIZE
    assert exact_compressed[: len(_CANONICAL_COMPRESSED)] == _CANONICAL_COMPRESSED
    assert decompress_packet(exact_compressed) == exact_packet

    with pytest.raises(SchcError, match="profile limit"):
        compress_packet(_dao_packet(tail=exact_tail + b"\x00"))

    overlong_compressed = _CANONICAL_COMPRESSED + bytes(
        MAX_PACKET_SIZE - len(_CANONICAL_COMPRESSED) + 1
    )
    with pytest.raises(SchcError, match="profile limit"):
        decompress_packet(overlong_compressed)
