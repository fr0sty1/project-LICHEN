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
    pressure,
    temperature,
    voc_index,
)


class TestLocation:
    def test_lat_lon_only(self) -> None:
        records = location(48.2049, 16.3710)
        assert len(records) == 2
        assert records[0].n == "lat"
        assert records[0].u == "deg"
        assert records[0].v == pytest.approx(48.2049)
        assert records[1].n == "lon"
        assert records[1].u == "deg"
        assert records[1].v == pytest.approx(16.3710)

    def test_with_altitude(self) -> None:
        records = location(48.2049, 16.3710, alt=158.3)
        assert len(records) == 3
        assert records[2].n == "alt"
        assert records[2].u == "m"
        assert records[2].v == pytest.approx(158.3)

    def test_without_altitude(self) -> None:
        assert len(location(0.0, 0.0)) == 2

    def test_negative_coordinates(self) -> None:
        records = location(-33.8688, -70.6693)
        assert records[0].v == pytest.approx(-33.8688)
        assert records[1].v == pytest.approx(-70.6693)


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
        assert records[0].u == "%EL"
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
