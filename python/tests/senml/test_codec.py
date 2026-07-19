# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the SenML CBOR codec (RFC 8428)."""

from __future__ import annotations

from decimal import Decimal

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

    @pytest.mark.parametrize("label", [True, 1.0])
    def test_from_cbor_map_rejects_invalid_label_types(self, label: object) -> None:
        with pytest.raises(ValueError, match="label must be an integer or string"):
            SenmlRecord.from_cbor_map({label: "not-a-unit"})

    def test_from_cbor_map_rejects_unknown_mandatory_label(self) -> None:
        with pytest.raises(ValueError, match="unknown mandatory SenML label 'vendor_'"):
            SenmlRecord.from_cbor_map({"vendor_": 1})

    def test_from_cbor_map_ignores_unknown_optional_string_label(self) -> None:
        assert SenmlRecord.from_cbor_map({"vendor": 1}) == SenmlRecord()

    @pytest.mark.parametrize("value", [True, "42"])
    @pytest.mark.parametrize("label", [-3, -5, -6, 2, 5, 6, 7])
    def test_from_cbor_map_rejects_non_numeric_fields(self, label: int, value: object) -> None:
        with pytest.raises(ValueError, match="must be a number"):
            SenmlRecord.from_cbor_map({label: value})

    @pytest.mark.parametrize(
        ("label", "field"),
        [(-3, "bt"), (-5, "bv"), (-6, "bs"), (2, "v"), (5, "s"), (6, "t"), (7, "ut")],
    )
    def test_from_cbor_map_accepts_int_for_numeric_fields(self, label: int, field: str) -> None:
        record = SenmlRecord.from_cbor_map({label: 42})
        assert getattr(record, field) == 42

    @pytest.mark.parametrize("value", [True, 10.0])
    def test_from_cbor_map_requires_exact_int_for_bver(self, value: object) -> None:
        with pytest.raises(ValueError, match="'bver' must be an integer"):
            SenmlRecord.from_cbor_map({-1: value})

    def test_from_cbor_map_accepts_int_for_bver(self) -> None:
        assert SenmlRecord.from_cbor_map({-1: 10}).bver == 10

    @pytest.mark.parametrize("value", [0, 1])
    def test_from_cbor_map_requires_exact_bool_for_vb(self, value: object) -> None:
        with pytest.raises(ValueError, match="'vb' must be a boolean"):
            SenmlRecord.from_cbor_map({4: value})

    def test_from_cbor_map_requires_exact_bytes_for_vd(self) -> None:
        with pytest.raises(ValueError, match="'vd' must be bytes"):
            SenmlRecord.from_cbor_map({8: bytearray(b"data")})

    def test_from_cbor_map_accepts_exact_bool_and_bytes(self) -> None:
        record = SenmlRecord.from_cbor_map({4: False, 8: b"data"})
        assert record.vb is False
        assert record.vd == b"data"

    @pytest.mark.parametrize(
        ("label", "field"), [(-2, "bn"), (-4, "bu"), (0, "n"), (1, "u"), (3, "vs")]
    )
    def test_from_cbor_map_rejects_wrong_string_type(self, label: int, field: str) -> None:
        with pytest.raises(ValueError, match=rf"'{field}' must be a string"):
            SenmlRecord.from_cbor_map({label: 1})


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
        assert raw[0][1] == "Cel"  # label 1 = u
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
    @pytest.mark.parametrize(
        "data",
        [
            bytes.fromhex("81a2016343656cf5646576696c"),
            bytes.fromhex("81a2016343656cfb3ff0000000000000646576696c"),
        ],
    )
    def test_rejects_labels_that_alias_integer_keys(self, data: bytes) -> None:
        with pytest.raises(ValueError, match="Duplicate map key"):
            unpack(data)

    def test_rejects_bool_for_numeric_field_from_literal_cbor(self) -> None:
        with pytest.raises(ValueError, match="'v' must be a number"):
            unpack(bytes.fromhex("81a102f5"))

    def test_accepts_integer_numeric_value_from_literal_cbor(self) -> None:
        assert unpack(bytes.fromhex("81a102182a"))[0].v == 42

    def test_accepts_decimal_fraction_from_literal_cbor(self) -> None:
        value = unpack(bytes.fromhex("81a102c482211864"))[0].v
        assert type(value) is Decimal
        assert value == Decimal("1.00")

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
