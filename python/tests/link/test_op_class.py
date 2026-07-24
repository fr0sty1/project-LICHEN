# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Tests for operating class parameter definitions and lookup tables (CCP-3/CCP-4)."""

from lichen.link.op_class import (
    OPERATING_CLASS_TABLE,
    OperatingClass,
    OperatingClassParams,
    lookup_operating_class,
)


def test_from_int():
    assert OperatingClass(0) == OperatingClass.US_CA
    assert OperatingClass(1) == OperatingClass.EU
    assert OperatingClass(2) == OperatingClass.AU_NZ


def test_to_int():
    assert int(OperatingClass.US_CA) == 0
    assert int(OperatingClass.EU) == 1
    assert int(OperatingClass.AU_NZ) == 2


def test_lookup_known_class_returns_params():
    for class_id in (0, 1, 2):
        params = lookup_operating_class(class_id)
        assert params is not None, f"class_id={class_id} should exist"
        assert params.class_id == class_id
        assert params.frequency_hz > 0
        assert 7 <= params.spreading_factor <= 12
        assert params.bandwidth_hz > 0
        assert 4 <= params.coding_rate <= 8
        assert params.duty_permille > 0


def test_lookup_unknown_class_returns_none():
    assert lookup_operating_class(3) is None
    assert lookup_operating_class(255) is None


def test_table_has_all_enum_values():
    for oc in OperatingClass:
        assert oc.value in OPERATING_CLASS_TABLE


def test_us_ca_params():
    params = lookup_operating_class(0)
    assert params is not None
    assert params.label == "US/CA"
    assert params.frequency_hz == 903_900_000
    assert params.spreading_factor == 10
    assert params.bandwidth_hz == 125_000
    assert params.coding_rate == 5
    assert params.tx_power_dbm == 20
    assert params.duty_permille == 1000


def test_eu_params():
    params = lookup_operating_class(1)
    assert params is not None
    assert params.label == "EU"
    assert params.frequency_hz == 868_100_000
    assert params.spreading_factor == 10
    assert params.bandwidth_hz == 125_000
    assert params.coding_rate == 5
    assert params.tx_power_dbm == 14
    assert params.duty_permille == 10


def test_au_nz_params():
    params = lookup_operating_class(2)
    assert params is not None
    assert params.label == "AU/NZ"
    assert params.frequency_hz == 916_800_000
    assert params.spreading_factor == 10
    assert params.bandwidth_hz == 125_000
    assert params.coding_rate == 5
    assert params.tx_power_dbm == 30
    assert params.duty_permille == 50


def test_params_repr():
    params = lookup_operating_class(0)
    assert params is not None
    r = repr(params)
    assert "US/CA" in r
    assert "903900000" in r
