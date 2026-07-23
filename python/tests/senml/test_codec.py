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

    def test_from_cbor_map_rejects_wrong_type_for_v(self) -> None:
        # v (label 2) must be a number, not a string
        with pytest.raises(ValueError, match="'v' must be a number"):
            SenmlRecord.from_cbor_map({2: "not_a_number"})

    def test_from_cbor_map_rejects_wrong_type_for_n(self) -> None:
        # n (label 0) must be a string, not an int
        with pytest.raises(ValueError, match="'n' must be a string"):
            SenmlRecord.from_cbor_map({0: 123})

    def test_from_cbor_map_rejects_wrong_type_for_vb(self) -> None:
        # vb (label 4) must be a boolean, not a string
        with pytest.raises(ValueError, match="'vb' must be a boolean"):
            SenmlRecord.from_cbor_map({4: "true"})

    def test_from_cbor_map_rejects_wrong_type_for_vd(self) -> None:
        # vd (label 8) must be bytes, not a string
        with pytest.raises(ValueError, match="'vd' must be bytes"):
            SenmlRecord.from_cbor_map({8: "not_bytes"})

    def test_from_cbor_map_rejects_wrong_type_for_bver(self) -> None:
        # bver (label -1) must be an integer, not a float
        with pytest.raises(ValueError, match="'bver' must be an integer"):
            SenmlRecord.from_cbor_map({-1: 10.5})

    def test_from_cbor_map_rejects_bool_for_numeric_field(self) -> None:
        # v (label 2) must be a number, not a boolean (bool is subclass of int)
        with pytest.raises(ValueError, match="'v' must be a number"):
            SenmlRecord.from_cbor_map({2: True})

    def test_from_cbor_map_rejects_non_finite_for_numeric_field(self) -> None:
        """Independent literal CBOR vectors (do not derive from codec/pack()).

        RFC 8428 decoded numeric policy: reject non-finite floats.
        Tag 5 bigfloats rejected (decode to Decimal); Tag 4 also rejected
        for simplicity (embedded float32 constraint).
        """
        # v = NaN, +inf, -inf using float16 special values (label 2=v)
        nan_cbor = b"\x81\xa1\x02\xf9\x7e\x00"
        inf_cbor = b"\x81\xa1\x02\xf9\x7c\x00"
        ninf_cbor = b"\x81\xa1\x02\xf9\xfc\x00"
        for cbor_bytes in (nan_cbor, inf_cbor, ninf_cbor):
            with pytest.raises(ValueError, match="must be finite"):
                unpack(cbor_bytes)

    def test_from_cbor_map_accepts_int_for_numeric_field(self) -> None:
        # v (label 2) should accept int (which gets stored as float conceptually)
        r = SenmlRecord.from_cbor_map({2: 42})
        assert r.v == 42


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
