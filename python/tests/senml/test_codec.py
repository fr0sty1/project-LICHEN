# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the SenML CBOR codec (RFC 8428)."""

from __future__ import annotations

import cbor2
import pytest

from lichen.senml.codec import SenmlRecord, make_base_name, pack, unpack


class TestSenmlRecord:
    def test_to_cbor_map_omits_none(self) -> None:
        r = SenmlRecord(n="temperature", u="Cel", v=23.4)
        m = r.to_cbor_map()
        assert m == {0: "temperature", 1: "Cel", 2: 23.4}

    def test_to_cbor_map_base_fields(self) -> None:
        r = SenmlRecord(bn="urn:dev:mac:aabbccddeeff0011:", bt=1_700_000_000.0)
        m = r.to_cbor_map()
        assert m[-2] == "urn:dev:mac:aabbccddeeff0011:"
        assert m[-3] == 1_700_000_000.0
        assert 0 not in m  # n not set

    def test_to_cbor_map_boolean_value(self) -> None:
        r = SenmlRecord(n="door-open", vb=True)
        m = r.to_cbor_map()
        assert m == {0: "door-open", 4: True}

    def test_to_cbor_map_string_value(self) -> None:
        r = SenmlRecord(n="status", vs="active")
        m = r.to_cbor_map()
        assert m == {0: "status", 3: "active"}

    def test_to_cbor_map_data_value(self) -> None:
        r = SenmlRecord(n="raw", vd=b"\x01\x02")
        m = r.to_cbor_map()
        assert m[8] == b"\x01\x02"

    def test_from_cbor_map_round_trip(self) -> None:
        original = SenmlRecord(n="humidity", u="%RH", v=61.5, t=-1.0)
        decoded = SenmlRecord.from_cbor_map(original.to_cbor_map())
        assert decoded.n == "humidity"
        assert decoded.u == "%RH"
        assert decoded.v == 61.5
        assert decoded.t == -1.0

    def test_from_cbor_map_ignores_unknown_labels(self) -> None:
        # Unknown numeric label should not raise
        r = SenmlRecord.from_cbor_map({0: "x", 999: "ignored"})
        assert r.n == "x"


class TestPack:
    def test_empty_pack(self) -> None:
        data = pack([])
        raw = cbor2.loads(data)
        assert raw == []

    def test_single_record(self) -> None:
        data = pack([SenmlRecord(n="temperature", u="Cel", v=23.4)])
        raw = cbor2.loads(data)
        assert len(raw) == 1
        assert raw[0][0] == "temperature"  # label 0 = n
        assert raw[0][1] == "Cel"          # label 1 = u
        assert raw[0][2] == pytest.approx(23.4)  # label 2 = v

    def test_multi_record_with_base(self) -> None:
        records = [
            SenmlRecord(bn="urn:dev:mac:0102030405060708:", bt=1_700_000_000.0),
            SenmlRecord(n="temperature", u="Cel", v=22.1),
            SenmlRecord(n="rel-humidity", u="%RH", v=55.3),
        ]
        data = pack(records)
        raw = cbor2.loads(data)
        assert len(raw) == 3
        assert raw[0][-2] == "urn:dev:mac:0102030405060708:"
        assert raw[0][-3] == 1_700_000_000.0
        assert raw[1][0] == "temperature"
        assert raw[2][0] == "rel-humidity"

    def test_produces_bytes(self) -> None:
        assert isinstance(pack([SenmlRecord(n="x", v=1.0)]), bytes)


class TestUnpack:
    def test_round_trip(self) -> None:
        original = [
            SenmlRecord(bn="urn:dev:mac:0102030405060708:", bt=1_700_000_000.0),
            SenmlRecord(n="temperature", u="Cel", v=22.1),
            SenmlRecord(n="rel-humidity", u="%RH", v=55.3, t=-1.0),
        ]
        decoded = unpack(pack(original))
        assert len(decoded) == 3
        assert decoded[0].bn == "urn:dev:mac:0102030405060708:"
        assert decoded[1].v == pytest.approx(22.1)
        assert decoded[2].t == pytest.approx(-1.0)

    def test_not_array_raises(self) -> None:
        with pytest.raises(ValueError, match="array"):
            unpack(cbor2.dumps({"key": "value"}))

    def test_record_not_map_raises(self) -> None:
        with pytest.raises(ValueError, match="map"):
            unpack(cbor2.dumps([42]))

    def test_invalid_cbor_raises(self) -> None:
        # Truncated CBOR (a map header with no body) — cbor2 raises on decode
        with pytest.raises(ValueError):
            unpack(b"\xa5\x01")

    def test_boolean_value_round_trip(self) -> None:
        records = [SenmlRecord(n="alarm", vb=False)]
        assert unpack(pack(records))[0].vb is False

    def test_bytes_value_round_trip(self) -> None:
        records = [SenmlRecord(n="blob", vd=b"\xde\xad\xbe\xef")]
        assert unpack(pack(records))[0].vd == b"\xde\xad\xbe\xef"


class TestMakeBaseName:
    def test_standard_eui64(self) -> None:
        eui64 = bytes.fromhex("0102030405060708")
        assert make_base_name(eui64) == "urn:dev:mac:0102030405060708:"

    def test_all_zeros(self) -> None:
        assert make_base_name(b"\x00" * 8) == "urn:dev:mac:0000000000000000:"

    def test_wrong_length_raises(self) -> None:
        with pytest.raises(ValueError, match="8 bytes"):
            make_base_name(b"\x01\x02\x03")
