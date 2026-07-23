# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for standard SenML sensor profiles."""

from __future__ import annotations

import pytest

from lichen.senml.profiles import (
    accelerometer,
    battery,
    co2_ppm,
    gyroscope,
    humidity,
    location,
    metrics,
    pressure,
    temperature,
    voc_index,
)


class TestLocation:
    def test_lat_lon_only(self) -> None:
        records = location(48.2049, 16.3710)
        assert len(records) == 2
        assert records[0].n == "lat"
        assert records[0].u == "lat"
        assert records[0].v == pytest.approx(48.2049)
        assert records[1].n == "lon"
        assert records[1].u == "lon"
        assert records[1].v == pytest.approx(16.3710)

    def test_with_altitude(self) -> None:
        records = location(48.2049, 16.3710, alt=158.3)
        assert len(records) == 3
        assert records[2].n == "alt"
        assert records[2].u == "m"
        assert records[2].v == pytest.approx(158.3)

    def test_with_speed(self) -> None:
        records = location(48.2049, 16.3710, speed=5.5)
        assert len(records) == 3
        assert records[2].n == "speed"
        assert records[2].u == "m/s"
        assert records[2].v == pytest.approx(5.5)

    def test_without_altitude(self) -> None:
        assert len(location(0.0, 0.0)) == 2

    def test_negative_coordinates(self) -> None:
        records = location(-33.8688, -70.6693)
        assert records[0].v == pytest.approx(-33.8688)
        assert records[1].v == pytest.approx(-70.6693)

    def test_invalid_lat(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            location(91.0, 0.0)
        with pytest.raises(ValueError, match="out of range"):
            location(-91.0, 0.0)

    def test_invalid_lon(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            location(0.0, 181.0)
        with pytest.raises(ValueError, match="out of range"):
            location(0.0, -181.0)

    def test_nan_inf(self) -> None:
        with pytest.raises(ValueError, match="NaN or Inf"):
            location(float("nan"), 0.0)
        with pytest.raises(ValueError, match="NaN or Inf"):
            location(0.0, float("inf"))
        with pytest.raises(ValueError, match="NaN or Inf"):
            location(float("-inf"), 0.0)


class TestBattery:
    def test_voltage_only(self) -> None:
        records = battery(voltage_v=3.85)
        assert len(records) == 1
        assert records[0].n == "voltage"
        assert records[0].u == "V"
        assert records[0].v == pytest.approx(3.85)

    def test_percent_only(self) -> None:
        records = battery(percent=72.0)
        assert len(records) == 1
        assert records[0].n == "battery"
        assert records[0].u == "%"
        assert records[0].v == pytest.approx(72.0)

    def test_both(self) -> None:
        records = battery(voltage_v=3.7, percent=55.0)
        assert len(records) == 2

    def test_neither(self) -> None:
        assert battery() == []


class TestTemperature:
    def test_value_and_unit(self) -> None:
        r = temperature(23.4)
        assert r.n == "temperature"
        assert r.u == "Cel"
        assert r.v == pytest.approx(23.4)

    def test_negative(self) -> None:
        r = temperature(-5.0)
        assert r.v == pytest.approx(-5.0)


class TestHumidity:
    def test_value_and_unit(self) -> None:
        r = humidity(61.5)
        assert r.n == "rel-humidity"
        assert r.u == "%RH"
        assert r.v == pytest.approx(61.5)


class TestPressure:
    def test_value_and_unit(self) -> None:
        r = pressure(101325.0)
        assert r.n == "pressure"
        assert r.u == "Pa"
        assert r.v == pytest.approx(101325.0)


class TestAccelerometer:
    def test_three_axes(self) -> None:
        records = accelerometer(0.1, -0.2, 9.81)
        assert len(records) == 3
        assert [r.n for r in records] == ["accel-x", "accel-y", "accel-z"]
        assert all(r.u == "m/s2" for r in records)
        assert records[2].v == pytest.approx(9.81)


class TestGyroscope:
    def test_three_axes(self) -> None:
        records = gyroscope(0.01, -0.02, 0.005)
        assert len(records) == 3
        assert [r.n for r in records] == ["gyro-x", "gyro-y", "gyro-z"]
        assert all(r.u == "rad/s" for r in records)


class TestCO2:
    def test_value_and_unit(self) -> None:
        r = co2_ppm(450.0)
        assert r.n == "CO2"
        assert r.u == "ppm"
        assert r.v == pytest.approx(450.0)


class TestVocIndex:
    def test_dimensionless(self) -> None:
        r = voc_index(123.0)
        assert r.n == "voc-index"
        assert r.u is None
        assert r.v == pytest.approx(123.0)


class TestMetrics:
    """Tests for telemetry+battery metrics profile. Uses independent oracle
    via direct cbor2 map construction for one test vector to avoid oracle
    coupling with pack() under test.
    """

    def test_rssi_only(self) -> None:
        records = metrics(rssi=-85)
        assert len(records) == 1
        r = records[0]
        assert r.n == "rssi"
        assert r.u == "dBm"
        assert r.v == pytest.approx(-85.0)

    def test_full_profile(self) -> None:
        records = metrics(
            rssi=-72,
            nodecount=8,
            packets_per_sec=1.25,
            battery=42.0,
            collision_rate=0.3,
        )
        assert len(records) == 5
        by_n = {r.n: r for r in records}
        assert by_n["rssi"].v == pytest.approx(-72)
        assert by_n["nodecount"].v == 8
        assert by_n["pps"].v == pytest.approx(1.25)
        assert by_n["battery"].v == pytest.approx(42.0)
        assert by_n["collision-rate"].v == pytest.approx(0.3)

    def test_omitted_fields(self) -> None:
        assert metrics() == []
        assert len(metrics(rssi=-90)) == 1
        assert len(metrics(battery=100.0)) == 1

    def test_independent_test_vector(self) -> None:
        """Independent oracle: hardcoded CBOR bytes generated via external
        cbor2 construction (cross-validated against RFC 8428 example structure).
        Avoids using pack() as self-oracle.
        """
        from lichen.senml.codec import SenmlRecord, make_base_name, pack
        bn = make_base_name(bytes.fromhex("0011223344556677"))
        records = [SenmlRecord(bn=bn)] + metrics(rssi=-85, battery=75.0)
        payload = pack(records)
        # Independent reference (computed once with separate cbor2 script)
        expected = bytes.fromhex(
            "83a121781d75726e3a6465763a6d61633a303031313232333334343535363637373a"
            "a3006472737369016364426d023854a300676261747465727901612502fb4052c00000000000"
        )
        assert payload == expected
