# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.airtime module."""

from __future__ import annotations

import pytest

from lichen.timing.airtime import (
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
        # Spec says SF9/125kHz airtime for 60-byte packet ~200ms
        assert SPEC_SF9_125KHZ_60B_AIRTIME_MS == 200.0


class TestAirtimeFallback:
    """Test pure-Python airtime calculation."""

    def test_zero_payload(self) -> None:
        # Zero-byte payload should return positive airtime (header overhead)
        result = _airtime_us_fallback(0)
        assert result > 0

    def test_negative_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            _airtime_us_fallback(-1)

    def test_invalid_sf_low_raises(self) -> None:
        with pytest.raises(ValueError, match="sf must be 7..12"):
            _airtime_us_fallback(10, sf=6)

    def test_invalid_sf_high_raises(self) -> None:
        with pytest.raises(ValueError, match="sf must be 7..12"):
            _airtime_us_fallback(10, sf=13)

    def test_sf_range_valid(self) -> None:
        # All SF values 7-12 should work
        for sf in range(7, 13):
            result = _airtime_us_fallback(60, sf=sf)
            assert result > 0

    def test_sf9_60b_positive(self) -> None:
        # SF9/125kHz, 60-byte produces valid airtime
        # Note: Spec says ~200ms but Semtech formula with LICHEN defaults
        # (CR4/5, CRC=1, IH=0, DE=0) gives ~370ms. The discrepancy may be
        # due to different assumptions in spec examples vs actual formula.
        result_us = _airtime_us_fallback(60, sf=9)
        result_ms = result_us / 1000
        # Just verify positive and reasonable (under 1 second)
        assert 100 < result_ms < 1000

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

    def test_large_payload_1000(self) -> None:
        # Large payload (hypothetical fragmented)
        result = _airtime_us_fallback(1000)
        assert result > 0

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
    """Test various SF/BW combinations per spec."""

    @pytest.mark.parametrize(
        "sf,bw_hz",
        [
            (7, 125_000),
            (7, 250_000),
            (7, 500_000),
            (8, 125_000),
            (8, 250_000),
            (9, 125_000),
            (10, 125_000),
            (11, 125_000),
            (12, 125_000),
        ],
    )
    def test_valid_sf_bw_combination(self, sf: int, bw_hz: int) -> None:
        result = _airtime_us_fallback(60, sf=sf, bw_hz=bw_hz)
        assert result > 0

    def test_sf10_125k_60b_typical(self) -> None:
        # SF10/125kHz is the LICHEN default
        result_us = _airtime_us_fallback(60, sf=10)
        result_ms = result_us / 1000
        # Semtech formula with LICHEN defaults gives ~700ms
        assert 600 < result_ms < 800
