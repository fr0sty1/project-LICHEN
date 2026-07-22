# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the SCHC compression engine.

Oracles are hand-computed from RFC 8724 semantics and the LICHEN rule
definitions, independent of the code under test.
"""

from __future__ import annotations

import pytest

from lichen.schc import (
    COAP_RULE,
    RULES,
    UDP_PORT_RULE,
    SchcError,
    compress,
    decompress,
)
from lichen.schc.codec import BitReader, BitWriter, _check_msb
from lichen.schc.rules import CDA, MO, FieldDescriptor


class TestBitWriter:
    def test_pack_and_pad(self) -> None:
        # write 0b101 then 0b11 -> 10111, padded with 3 zero bits -> 10111000 = 0xB8
        w = BitWriter()
        w.write(0b101, 3)
        w.write(0b11, 2)
        assert w.bit_length == 5
        assert w.to_bytes() == b"\xb8"

    def test_empty(self) -> None:
        assert BitWriter().to_bytes() == b""

    def test_exact_byte(self) -> None:
        w = BitWriter()
        w.write(0xAB, 8)
        assert w.to_bytes() == b"\xab"

    def test_value_too_large_raises(self) -> None:
        w = BitWriter()
        with pytest.raises(ValueError, match="does not fit"):
            w.write(8, 3)  # 8 needs 4 bits

    def test_negative_raises(self) -> None:
        w = BitWriter()
        with pytest.raises(ValueError):
            w.write(-1, 3)

    def test_excessive_bits_raises(self) -> None:
        """BitWriter rejects bit counts that would exhaust memory."""
        w = BitWriter()
        w.write(0, 70000)  # exceeds 65536 limit
        with pytest.raises(OverflowError, match="excessive bit count"):
            w.to_bytes()


class TestBitReader:
    def test_read_msb_first(self) -> None:
        r = BitReader(b"\xb8")  # 10111000
        assert r.read(3) == 0b101
        assert r.read(2) == 0b11

    def test_underrun_raises(self) -> None:
        r = BitReader(b"\x00")
        with pytest.raises(SchcError, match="underrun"):
            r.read(9)

    def test_roundtrip_varied_widths(self) -> None:
        w = BitWriter()
        values = [(5, 3), (0, 1), (1023, 10), (2, 2), (255, 8)]
        for v, n in values:
            w.write(v, n)
        r = BitReader(w.to_bytes())
        assert [r.read(n) for _, n in values] == [v for v, _ in values]


class TestCoapRule:
    def test_compress_spec_vector(self) -> None:
        """Hand-computed residue for a known CoAP header.

        Version=1 (equal, not-sent -> 0 bits), Type=0 (2b), TKL=0 (4b),
        Code=1 (8b), MID=0x1234 (16b). Residue bits (30) padded to 4 bytes:
        00 0000 00000001 0001001000110100 00 -> 0x00 0x04 0x48 0xD0.
        Rule ID is 64.
        """
        out = compress(
            COAP_RULE,
            {"CoAP.version": 1, "CoAP.type": 0, "CoAP.tkl": 0,
             "CoAP.code": 1, "CoAP.mid": 0x1234},
        )
        assert out == bytes([64, 0x00, 0x04, 0x48, 0xD0])

    def test_decompress_recovers_fields(self) -> None:
        rule_id, fields = decompress(bytes([64, 0x00, 0x04, 0x48, 0xD0]))
        assert rule_id == 64
        assert fields["CoAP.version"] == 1
        assert fields["CoAP.type"] == 0
        assert fields["CoAP.tkl"] == 0
        assert fields["CoAP.code"] == 1
        assert fields["CoAP.mid"] == 0x1234

    def test_roundtrip_nonzero(self) -> None:
        original = {
            "CoAP.Version": 1,
            "CoAP.Type": 2,
            "CoAP.TKL": 5,
            "CoAP.Code": 0x45,
            "CoAP.MID": 0xBEEF,
        }
        rule_id, recovered = decompress(compress(COAP_RULE, original))
        assert rule_id == 64
        assert recovered == original

    def test_equal_mismatch_raises(self) -> None:
        with pytest.raises(SchcError, match="EQUAL mismatch"):
            compress(COAP_RULE, {"CoAP.Version": 2, "CoAP.Type": 0,
                                 "CoAP.TKL": 0, "CoAP.Code": 0, "CoAP.MID": 0})

    def test_missing_field_raises(self) -> None:
        with pytest.raises(SchcError, match="missing required field"):
            compress(COAP_RULE, {"CoAP.Version": 1, "CoAP.Type": 0})

    def test_value_out_of_range_raises(self) -> None:
        with pytest.raises(SchcError, match="does not fit"):
            compress(COAP_RULE, {"CoAP.Version": 1, "CoAP.Type": 4,  # 2-bit field
                                 "CoAP.TKL": 0, "CoAP.Code": 0, "CoAP.MID": 0})


class TestUdpPortRule:
    def test_compress_msb_lsb_vector(self) -> None:
        """SrcPort 5683 -> LSB nibble 3; DstPort 5684 -> LSB nibble 4.

        Residue = 0011 0100 = 0x34; Rule ID 65.
        """
        out = compress(UDP_PORT_RULE, {"UDP.SrcPort": 5683, "UDP.DstPort": 5684})
        assert out == bytes([65, 0x34])

    def test_roundtrip(self) -> None:
        rule_id, fields = decompress(compress(
            UDP_PORT_RULE, {"UDP.SrcPort": 5683, "UDP.DstPort": 5690}
        ))
        assert rule_id == 65
        assert fields["UDP.SrcPort"] == 5683
        assert fields["UDP.DstPort"] == 5690

    def test_msb_mismatch_raises(self) -> None:
        # Port 1234 has different top 12 bits than 5683 -> rule does not apply.
        with pytest.raises(SchcError, match="MSB"):
            compress(UDP_PORT_RULE, {"UDP.SrcPort": 1234, "UDP.DstPort": 5683})


class TestDecompressRegistry:
    def test_unknown_rule_raises(self) -> None:
        with pytest.raises(SchcError, match="unknown rule"):
            decompress(bytes([200, 0x00]))

    def test_empty_raises(self) -> None:
        with pytest.raises(SchcError, match="empty"):
            decompress(b"")

    def test_rule_id_mismatch_raises(self) -> None:
        with pytest.raises(SchcError, match="rule ID mismatch"):
            decompress(bytes([65, 0x00]), rule=COAP_RULE)

    def test_registry_contains_rules(self) -> None:
        assert RULES[64] is COAP_RULE
        assert RULES[65] is UDP_PORT_RULE


class TestCheckMsb:
    def test_mo_arg_exceeds_length_bits_raises(self) -> None:
        """mo_arg > length_bits is invalid and should raise a clear error."""
        # 16-bit field with mo_arg=20 is invalid (would require negative shift)
        fd = FieldDescriptor(
            field_id="Test.Field",
            length_bits=16,
            mo=MO.MSB,
            cda=CDA.LSB,
            target_value=0x5000,
            mo_arg=20,
        )
        with pytest.raises(SchcError, match="mo_arg.*exceeds.*length_bits"):
            _check_msb(fd, 0x5678)
