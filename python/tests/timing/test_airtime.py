# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.airtime module."""

from __future__ import annotations

import pytest

from lichen.timing.airtime import (
    LORA_BANDWIDTHS_HZ,
    LORA_BW_DEFAULT_HZ,
    LORA_CR_DEFAULT,
    LORA_PREAMBLE_DEFAULT,
    LORA_SF_DEFAULT,
    SPEC_SF9_125KHZ_60B_AIRTIME_MS,
    _airtime_us_fallback,
    airtime_ms,
    airtime_us,
    airtime_us_with_params,
)


class TestAirtimeConstants:
    """Test default constants match spec."""

    def test_default_sf(self) -> None:
        assert LORA_SF_DEFAULT == 10

    def test_default_bw(self) -> None:
        assert LORA_BW_DEFAULT_HZ == 125_000

    def test_default_cr(self) -> None:
        assert LORA_CR_DEFAULT == 5  # 4/5

    def test_default_preamble(self) -> None:
        assert LORA_PREAMBLE_DEFAULT == 8

    def test_spec_sf9_example(self) -> None:
        assert SPEC_SF9_125KHZ_60B_AIRTIME_MS == 369.664


class TestAirtimeFallback:
    """Test pure-Python airtime calculation."""

    def test_zero_payload(self) -> None:
        # Zero-byte payload should return positive airtime (header overhead)
        result = _airtime_us_fallback(0)
        assert result > 0

    def test_negative_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="0..255"):
            _airtime_us_fallback(-1)

    def test_sf6_requires_implicit_header(self) -> None:
        with pytest.raises(ValueError, match="requires implicit_header"):
            _airtime_us_fallback(10, sf=6)

        assert _airtime_us_fallback(10, sf=6, implicit_header=True) > 0

    @pytest.mark.parametrize("sf", [5, 13])
    def test_invalid_sf_raises(self, sf: int) -> None:
        with pytest.raises(ValueError, match="sf must be 6..12"):
            _airtime_us_fallback(10, sf=sf)

    def test_sf_range_valid(self) -> None:
        # All explicit-header SF values should work.
        for sf in range(7, 13):
            result = _airtime_us_fallback(60, sf=sf)
            assert result > 0

    def test_sf9_60b_positive(self) -> None:
        # SF9/125kHz, 60-byte produces valid airtime
        result_us = _airtime_us_fallback(60, sf=9)
        assert result_us == 369_664

    def test_higher_sf_longer_airtime(self) -> None:
        # Higher SF = longer airtime (more symbols)
        at_sf7 = _airtime_us_fallback(60, sf=7)
        at_sf10 = _airtime_us_fallback(60, sf=10)
        at_sf12 = _airtime_us_fallback(60, sf=12)
        assert at_sf7 < at_sf10 < at_sf12

    def test_larger_payload_longer_airtime(self) -> None:
        at_10b = _airtime_us_fallback(10)
        at_60b = _airtime_us_fallback(60)
        at_200b = _airtime_us_fallback(200)
        assert at_10b < at_60b < at_200b

    def test_lower_bw_longer_airtime(self) -> None:
        # Lower bandwidth = longer symbol time
        at_250k = _airtime_us_fallback(60, bw_hz=250_000)
        at_125k = _airtime_us_fallback(60, bw_hz=125_000)
        at_62k = _airtime_us_fallback(60, bw_hz=62_500)
        assert at_250k < at_125k < at_62k

    def test_higher_cr_longer_airtime(self) -> None:
        # Higher CR = more redundancy = more symbols
        at_cr5 = _airtime_us_fallback(60, cr=5)  # 4/5
        at_cr8 = _airtime_us_fallback(60, cr=8)  # 4/8
        assert at_cr5 < at_cr8


class TestAirtimePublicApi:
    """Test public API functions."""

    def test_airtime_us_returns_int(self) -> None:
        result = airtime_us(60)
        assert isinstance(result, int)
        assert result > 0

    def test_airtime_ms_returns_float(self) -> None:
        result = airtime_ms(60)
        assert isinstance(result, float)
        assert result > 0

    def test_airtime_ms_equals_us_divided(self) -> None:
        payload = 100
        us = airtime_us(payload)
        ms = airtime_ms(payload)
        assert abs(ms - us / 1000) < 0.001

    def test_airtime_us_with_params_explicit(self) -> None:
        # Should accept explicit params
        result = airtime_us_with_params(
            60,
            sf=9,
            bw_hz=125_000,
            cr=5,
            preamble_symbols=8,
        )
        assert isinstance(result, int)
        assert result > 0


class TestAirtimeEdgeCases:
    """Edge case tests."""

    def test_max_payload_255(self) -> None:
        # Maximum typical LoRa payload
        result = _airtime_us_fallback(255)
        assert result > 0

    def test_payload_above_radio_maximum_rejected(self) -> None:
        with pytest.raises(ValueError, match="0..255"):
            _airtime_us_fallback(256)

    @pytest.mark.parametrize("payload_len", [True, 1.0, "1", None])
    def test_payload_length_requires_exact_integer(self, payload_len: object) -> None:
        with pytest.raises(TypeError, match="payload_len must be an integer"):
            _airtime_us_fallback(payload_len)  # type: ignore[arg-type]

    def test_huge_payload_rejected_before_formula_conversion(self) -> None:
        with pytest.raises(ValueError, match="0..255"):
            _airtime_us_fallback(1 << 4096)

    def test_preamble_variation(self) -> None:
        # Longer preamble = longer airtime
        at_p8 = _airtime_us_fallback(60, preamble_symbols=8)
        at_p16 = _airtime_us_fallback(60, preamble_symbols=16)
        assert at_p8 < at_p16

    def test_sf7_minimum_airtime(self) -> None:
        # SF7 with small payload should be fast
        result_us = _airtime_us_fallback(10, sf=7)
        result_ms = result_us / 1000
        # SF7 should be under 50ms for small payload
        assert result_ms < 50

    def test_sf12_maximum_airtime(self) -> None:
        # SF12 with large payload should be slow
        result_us = _airtime_us_fallback(200, sf=12)
        result_ms = result_us / 1000
        # SF12 should be multiple seconds
        assert result_ms > 2000


class TestAirtimeSfBwCombinations:
    """Test the complete SX127x SF/BW/CR parameter space."""

    @pytest.mark.parametrize(
        "sf",
        range(7, 13),
    )
    @pytest.mark.parametrize("bw_hz", LORA_BANDWIDTHS_HZ)
    @pytest.mark.parametrize("cr", range(5, 9))
    def test_valid_sf_bw_cr_combination(self, sf: int, bw_hz: int, cr: int) -> None:
        assert _airtime_us_fallback(60, sf=sf, bw_hz=bw_hz, cr=cr) > 0

    @pytest.mark.parametrize("bw_hz", LORA_BANDWIDTHS_HZ)
    @pytest.mark.parametrize("cr", range(5, 9))
    def test_sf6_bw_cr_combination(self, bw_hz: int, cr: int) -> None:
        assert _airtime_us_fallback(60, sf=6, bw_hz=bw_hz, cr=cr, implicit_header=True) > 0

    def test_low_data_rate_optimization_is_automatic(self) -> None:
        automatic = _airtime_us_fallback(60, sf=11, bw_hz=125_000)
        enabled = _airtime_us_fallback(60, sf=11, bw_hz=125_000, low_data_rate_optimization=True)
        disabled = _airtime_us_fallback(60, sf=11, bw_hz=125_000, low_data_rate_optimization=False)
        assert automatic == enabled == 1_478_656
        assert automatic > disabled

    @pytest.mark.parametrize("cr", [4, 9])
    def test_invalid_coding_rate_rejected(self, cr: int) -> None:
        with pytest.raises(ValueError, match="cr must be 5..8"):
            _airtime_us_fallback(60, cr=cr)

    @pytest.mark.parametrize("bw_hz", [0, 125_001])
    def test_invalid_bandwidth_rejected(self, bw_hz: int) -> None:
        with pytest.raises(ValueError, match="bw_hz must be one of"):
            _airtime_us_fallback(60, bw_hz=bw_hz)

    @pytest.mark.parametrize("preamble", [5, 65_536])
    def test_invalid_preamble_rejected(self, preamble: int) -> None:
        with pytest.raises(ValueError, match="preamble_symbols must be 6..65535"):
            _airtime_us_fallback(60, preamble_symbols=preamble)

    @pytest.mark.parametrize("preamble", [6, 65_535])
    def test_preamble_boundaries_are_valid(self, preamble: int) -> None:
        assert _airtime_us_fallback(60, preamble_symbols=preamble) > 0

    def test_modem_parameters_require_exact_integers(self) -> None:
        with pytest.raises(TypeError, match="sf must be an integer"):
            _airtime_us_fallback(60, sf=10.0)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="bw_hz must be an integer"):
            _airtime_us_fallback(60, bw_hz=125_000.0)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="cr must be an integer"):
            _airtime_us_fallback(60, cr=5.0)  # type: ignore[arg-type]

    def test_header_and_crc_flags_match_datasheet_terms(self) -> None:
        explicit_crc = _airtime_us_fallback(0, sf=7)
        implicit_crc = _airtime_us_fallback(0, sf=7, implicit_header=True)
        explicit_no_crc = _airtime_us_fallback(0, sf=7, crc_enabled=False)
        assert explicit_crc > implicit_crc
        assert explicit_crc > explicit_no_crc

    def test_sf10_125k_60b_typical(self) -> None:
        # SF10/125kHz is the LICHEN default
        result_us = _airtime_us_fallback(60, sf=10)
        result_ms = result_us / 1000
        assert result_ms == 698.368
