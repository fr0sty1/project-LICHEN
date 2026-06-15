"""Tests for the SCHC match-mapping / mapping-sent action (RFC 8724)."""

from __future__ import annotations

import pytest

from lichen.schc.codec import SchcError, compress, decompress
from lichen.schc.rules import CDA, MO, FieldDescriptor, Rule

MAPPING = (10, 20, 30, 40)
MAP_RULE = Rule(
    rule_id=70,
    fields=(
        FieldDescriptor(
            "M", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT, mapping=MAPPING
        ),
    ),
)


def test_mapping_bits_is_ceil_log2() -> None:
    def bits(n: int) -> int:
        fd = FieldDescriptor("x", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT,
                             mapping=tuple(range(n)))
        return fd.mapping_bits()

    assert [bits(n) for n in (1, 2, 3, 4, 5)] == [0, 1, 2, 2, 3]


def test_mapping_known_vector() -> None:
    # index of 30 is 2; 2 bits = 0b10, padded to a byte = 0x80.
    packet = compress(MAP_RULE, {"M": 30})
    assert packet == bytes([70, 0x80])


def test_mapping_round_trip() -> None:
    for value in MAPPING:
        rule_id, out = decompress(compress(MAP_RULE, {"M": value}), MAP_RULE)
        assert rule_id == 70
        assert out["M"] == value


def test_mapping_value_not_in_mapping_rejected() -> None:
    with pytest.raises(SchcError):
        compress(MAP_RULE, {"M": 99})


def test_single_entry_mapping_sends_no_bits() -> None:
    rule = Rule(
        rule_id=71,
        fields=(
            FieldDescriptor("M", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT, mapping=(10,)),
        ),
    )
    packet = compress(rule, {"M": 10})
    assert packet == bytes([71])  # zero residue bits
    _, out = decompress(packet, rule)
    assert out["M"] == 10


def test_decompress_rejects_out_of_range_index() -> None:
    # 3-entry mapping uses 2 bits; index 3 is invalid.
    rule = Rule(
        rule_id=72,
        fields=(
            FieldDescriptor(
                "M", 8, MO.MATCH_MAPPING, CDA.MAPPING_SENT, mapping=(10, 20, 30)
            ),
        ),
    )
    # Residue byte 0xC0 = 0b11_000000 -> index 3.
    with pytest.raises(SchcError):
        decompress(bytes([72, 0xC0]), rule)
