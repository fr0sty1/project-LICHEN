# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.duty_cycle module."""

from __future__ import annotations

import pytest

from lichen.timing.duty_cycle import (
    EU868_COMFORTABLE_PACKETS_PER_HOUR,
    EU868_DUTY_CYCLE_PERCENT,
    EU868_MAX_PACKETS_PER_HOUR,
    EU868_SF9_AIRTIME_60B_MS,
    REGIONAL_CONFIGS,
    REGIONAL_LIMITS,
    SIM_DUTY_CYCLE_LIMIT_PERCENT,
    SIM_WINDOW_S,
    US915_FCC_DWELL_TIME_MS,
    RegionalDutyCycleEnforcer,
    RegionalDutyCycleLimit,
    duty_cycle_usage_percent,
    get_regional_limit,
    max_packets_per_hour,
)


class TestDutyCycleConstants:
    """Test duty cycle constants match spec."""

    def test_eu868_duty_cycle_percent(self) -> None:
        assert EU868_DUTY_CYCLE_PERCENT == 10.0

    def test_eu868_sf9_airtime(self) -> None:
        assert EU868_SF9_AIRTIME_60B_MS == 200.0

    def test_eu868_max_packets(self) -> None:
        # Spec: 3600 * 0.1 / 0.2 = 1800
        assert EU868_MAX_PACKETS_PER_HOUR == 1800

    def test_eu868_comfortable_range(self) -> None:
        assert EU868_COMFORTABLE_PACKETS_PER_HOUR == (100, 300)

    def test_sim_duty_cycle_limit(self) -> None:
        assert SIM_DUTY_CYCLE_LIMIT_PERCENT == 1.0

    def test_sim_window_s(self) -> None:
        assert SIM_WINDOW_S == 3600


class TestRegionalLimits:
    """Test regional duty cycle limits."""

    def test_eu868_1_percent(self) -> None:
        assert REGIONAL_LIMITS["EU868"] == 1.0

    def test_eu868_10pct_example(self) -> None:
        assert REGIONAL_LIMITS["EU868_10pct_example"] == 10.0

    def test_us915_100_percent(self) -> None:
        assert REGIONAL_LIMITS["US915"] == 100.0

    def test_eu868_configuration(self) -> None:
        limit = get_regional_limit("EU868")
        assert limit == RegionalDutyCycleLimit("EU868", duty_cycle_percent=1.0)
        assert limit.max_dwell_time_ms is None

    def test_us915_fcc_configuration(self) -> None:
        limit = get_regional_limit("US915")
        assert limit.duty_cycle_percent == 100.0
        assert limit.max_dwell_time_ms == US915_FCC_DWELL_TIME_MS

    def test_configurations_are_read_only(self) -> None:
        with pytest.raises(TypeError):
            REGIONAL_CONFIGS["EU868"] = RegionalDutyCycleLimit(  # type: ignore[index]
                "EU868", duty_cycle_percent=2.0
            )

    def test_unknown_region_fails_closed(self) -> None:
        with pytest.raises(ValueError, match="unknown duty-cycle region"):
            get_regional_limit("UNKNOWN")


class TestRegionalDutyCycleEnforcer:
    """Regional configuration is applied to actual transmit decisions."""

    def test_eu868_enforces_one_percent_rolling_budget(self) -> None:
        enforcer = RegionalDutyCycleEnforcer("EU868")
        assert enforcer.try_transmit(airtime_us=36_000_000, time_us=0)
        assert not enforcer.try_transmit(airtime_us=1, time_us=0)
        assert enforcer.usage(0) == pytest.approx(1.0)

    def test_us915_enforces_fcc_dwell_limit(self) -> None:
        enforcer = RegionalDutyCycleEnforcer("US915")
        assert enforcer.try_transmit(airtime_us=400_000, time_us=0)
        assert not enforcer.try_transmit(airtime_us=400_001, time_us=1_000_000)
        assert enforcer.usage(1_000_000) == pytest.approx(400_000 / 3_600_000_000)

    def test_regional_limit_is_configurable(self) -> None:
        enforcer = RegionalDutyCycleEnforcer(
            "EU868", duty_cycle_percent=2.0, window_s=100
        )
        assert enforcer.limit.duty_cycle_percent == 2.0
        assert enforcer.limit.window_s == 100
        assert enforcer.try_transmit(airtime_us=2_000_000, time_us=0)
        assert not enforcer.can_transmit(airtime_us=1, time_us=0)

    @pytest.mark.parametrize("airtime_us", [0, -1])
    def test_nonpositive_airtime_rejected(self, airtime_us: int) -> None:
        with pytest.raises(ValueError, match="airtime_us must be positive"):
            RegionalDutyCycleEnforcer("EU868").can_transmit(airtime_us, 0)


class TestMaxPacketsPerHour:
    """Test max_packets_per_hour calculation."""

    def test_spec_example_eu868(self) -> None:
        # Spec: 200ms airtime, 10% duty cycle = 1800 packets/hour
        result = max_packets_per_hour(200.0, 10.0)
        assert result == 1800

    def test_1_percent_duty_cycle(self) -> None:
        # 200ms airtime, 1% duty cycle = 180 packets/hour
        result = max_packets_per_hour(200.0, 1.0)
        assert result == 180

    def test_smaller_airtime_more_packets(self) -> None:
        at_100ms = max_packets_per_hour(100.0, 10.0)
        at_200ms = max_packets_per_hour(200.0, 10.0)
        assert at_100ms > at_200ms

    def test_larger_duty_cycle_more_packets(self) -> None:
        at_1pct = max_packets_per_hour(200.0, 1.0)
        at_10pct = max_packets_per_hour(200.0, 10.0)
        assert at_10pct > at_1pct

    def test_custom_window(self) -> None:
        # Half hour window
        result = max_packets_per_hour(200.0, 10.0, window_s=1800)
        assert result == 900  # Half of hourly

    def test_negative_airtime_raises(self) -> None:
        with pytest.raises(ValueError, match="airtime_ms must be positive"):
            max_packets_per_hour(-100.0, 10.0)

    def test_zero_airtime_raises(self) -> None:
        with pytest.raises(ValueError, match="airtime_ms must be positive"):
            max_packets_per_hour(0.0, 10.0)

    def test_zero_duty_cycle_raises(self) -> None:
        with pytest.raises(ValueError, match="duty_cycle_percent must be"):
            max_packets_per_hour(200.0, 0.0)

    def test_negative_duty_cycle_raises(self) -> None:
        with pytest.raises(ValueError, match="duty_cycle_percent must be"):
            max_packets_per_hour(200.0, -1.0)

    def test_over_100_duty_cycle_raises(self) -> None:
        with pytest.raises(ValueError, match="duty_cycle_percent must be"):
            max_packets_per_hour(200.0, 101.0)


class TestDutyCycleUsagePercent:
    """Test duty_cycle_usage_percent calculation."""

    def test_zero_usage(self) -> None:
        result = duty_cycle_usage_percent(0.0)
        assert result == 0.0

    def test_1_percent_usage(self) -> None:
        # 1% of 3600s = 36s = 36000ms
        result = duty_cycle_usage_percent(36_000.0)
        assert abs(result - 1.0) < 0.001

    def test_10_percent_usage(self) -> None:
        # 10% of 3600s = 360s = 360000ms
        result = duty_cycle_usage_percent(360_000.0)
        assert abs(result - 10.0) < 0.001

    def test_100_percent_usage(self) -> None:
        # 100% = 3600s = 3600000ms
        result = duty_cycle_usage_percent(3_600_000.0)
        assert abs(result - 100.0) < 0.001

    def test_over_100_percent(self) -> None:
        # Can exceed 100% (regulatory violation)
        result = duty_cycle_usage_percent(7_200_000.0)  # 200%
        assert abs(result - 200.0) < 0.001

    def test_custom_window(self) -> None:
        # 10% of 1800s = 180s = 180000ms
        result = duty_cycle_usage_percent(180_000.0, window_s=1800)
        assert abs(result - 10.0) < 0.001

    def test_negative_window_raises(self) -> None:
        with pytest.raises(ValueError, match="window_s must be positive"):
            duty_cycle_usage_percent(1000.0, window_s=-1)

    def test_zero_window_raises(self) -> None:
        with pytest.raises(ValueError, match="window_s must be positive"):
            duty_cycle_usage_percent(1000.0, window_s=0)


class TestDutyCycleScenarios:
    """Integration tests for duty cycle scenarios."""

    def test_single_packet_usage(self) -> None:
        # One 200ms packet in an hour
        usage = duty_cycle_usage_percent(200.0)
        # 200ms / 3600000ms = 0.00556%
        assert usage < 0.01

    def test_1800_packets_usage(self) -> None:
        # 1800 packets * 200ms = 360000ms = 10%
        usage = duty_cycle_usage_percent(1800 * 200.0)
        assert abs(usage - 10.0) < 0.001

    def test_comfortable_packet_rate(self) -> None:
        # 100-300 packets at 200ms airtime
        low, high = EU868_COMFORTABLE_PACKETS_PER_HOUR
        usage_low = duty_cycle_usage_percent(low * 200.0)
        usage_high = duty_cycle_usage_percent(high * 200.0)
        # Should be well under 10%
        assert usage_low < 10.0
        assert usage_high < 10.0

    def test_us915_no_duty_limit(self) -> None:
        # US915 has no duty cycle limit
        # 100% duty cycle allows theoretical continuous TX
        packets = max_packets_per_hour(200.0, 100.0)
        # 3600s / 0.2s = 18000 packets
        assert packets == 18000
