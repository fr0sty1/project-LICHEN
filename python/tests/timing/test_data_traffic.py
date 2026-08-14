# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.data_traffic module."""

from __future__ import annotations

from lichen.timing.data_traffic import (
    HEARTBEAT_INTERVAL_S,
    RECOMMENDED_INTERVALS,
    TELEMETRY_INTERVAL_MAX_S,
    TELEMETRY_INTERVAL_MIN_S,
    is_valid_heartbeat_interval,
    is_valid_telemetry_interval,
)


class TestDataTrafficConstants:
    """Test data traffic constants match spec."""

    def test_telemetry_min(self) -> None:
        assert TELEMETRY_INTERVAL_MIN_S == 5 * 60  # 5 minutes

    def test_telemetry_max(self) -> None:
        assert TELEMETRY_INTERVAL_MAX_S == 60 * 60  # 60 minutes

    def test_heartbeat_interval(self) -> None:
        assert HEARTBEAT_INTERVAL_S == 30 * 60  # 30 minutes


class TestRecommendedIntervals:
    """Test recommended intervals documentation."""

    def test_periodic_telemetry(self) -> None:
        assert RECOMMENDED_INTERVALS["periodic_telemetry"] == "5-60 minutes"

    def test_event_driven(self) -> None:
        assert RECOMMENDED_INTERVALS["event_driven"] == "As needed"

    def test_heartbeat_keepalive(self) -> None:
        assert RECOMMENDED_INTERVALS["heartbeat_keepalive"] == "30 minutes"


class TestIsValidTelemetryInterval:
    """Test telemetry interval validation."""

    def test_below_min_invalid(self) -> None:
        assert is_valid_telemetry_interval(299) is False

    def test_at_min_valid(self) -> None:
        assert is_valid_telemetry_interval(300) is True  # 5 minutes

    def test_mid_range_valid(self) -> None:
        assert is_valid_telemetry_interval(1800) is True  # 30 minutes

    def test_at_max_valid(self) -> None:
        assert is_valid_telemetry_interval(3600) is True  # 60 minutes

    def test_above_max_invalid(self) -> None:
        assert is_valid_telemetry_interval(3601) is False

    def test_zero_invalid(self) -> None:
        assert is_valid_telemetry_interval(0) is False

    def test_negative_invalid(self) -> None:
        assert is_valid_telemetry_interval(-60) is False


class TestIsValidHeartbeatInterval:
    """Test heartbeat interval validation."""

    def test_exact_30_minutes_valid(self) -> None:
        assert is_valid_heartbeat_interval(1800) is True

    def test_below_30_minutes_invalid(self) -> None:
        assert is_valid_heartbeat_interval(1799) is False

    def test_above_30_minutes_invalid(self) -> None:
        assert is_valid_heartbeat_interval(1801) is False

    def test_zero_invalid(self) -> None:
        assert is_valid_heartbeat_interval(0) is False

    def test_negative_invalid(self) -> None:
        assert is_valid_heartbeat_interval(-1800) is False


class TestDataTrafficScenarios:
    """Integration tests for data traffic timing scenarios."""

    def test_5_minute_telemetry(self) -> None:
        interval = 5 * 60
        assert is_valid_telemetry_interval(interval) is True

    def test_15_minute_telemetry(self) -> None:
        interval = 15 * 60
        assert is_valid_telemetry_interval(interval) is True

    def test_30_minute_telemetry(self) -> None:
        interval = 30 * 60
        assert is_valid_telemetry_interval(interval) is True

    def test_60_minute_telemetry(self) -> None:
        interval = 60 * 60
        assert is_valid_telemetry_interval(interval) is True

    def test_heartbeat_equals_telemetry_mid(self) -> None:
        # Heartbeat at 30 min is valid telemetry interval too
        assert is_valid_telemetry_interval(HEARTBEAT_INTERVAL_S) is True
        assert is_valid_heartbeat_interval(HEARTBEAT_INTERVAL_S) is True
