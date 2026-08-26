# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for time provider abstraction."""

import pytest

from lichen.time_provider import (
    MonotonicTimeProvider,
    SimulatedTimeProvider,
    TimeProvider,
)


class TestMonotonicTimeProvider:
    """Tests for MonotonicTimeProvider."""

    def test_unix_time_returns_none(self) -> None:
        """Monotonic provider has no absolute time reference."""
        provider = MonotonicTimeProvider()
        assert provider.unix_time_us() is None
        assert provider.wall_clock_valid is False

    def test_has_gnss_fix_returns_false(self) -> None:
        """Monotonic provider is not a GNSS source."""
        provider = MonotonicTimeProvider()
        assert provider.has_gnss_fix() is False

    def test_monotonic_ns_returns_positive_int(self) -> None:
        """Monotonic time should be a positive integer."""
        provider = MonotonicTimeProvider()
        ns = provider.monotonic_ns()
        assert isinstance(ns, int)
        assert ns > 0

    def test_monotonic_ns_is_monotonic(self) -> None:
        """Subsequent calls should return non-decreasing values."""
        provider = MonotonicTimeProvider()
        t1 = provider.monotonic_ns()
        t2 = provider.monotonic_ns()
        assert t2 >= t1

    def test_satisfies_protocol(self) -> None:
        """MonotonicTimeProvider satisfies TimeProvider protocol."""
        provider: TimeProvider = MonotonicTimeProvider()
        assert provider.unix_time_us() is None
        assert provider.wall_clock_valid is False
        assert provider.has_gnss_fix() is False


class TestSimulatedTimeProvider:
    """Tests for SimulatedTimeProvider."""

    def test_default_returns_none(self) -> None:
        """Default provider has no time set."""
        provider = SimulatedTimeProvider()
        assert provider.unix_time_us() is None
        assert provider.wall_clock_valid is False
        assert provider.has_gnss_fix() is False

    def test_initial_unix_time(self) -> None:
        """Provider returns configured Unix time."""
        provider = SimulatedTimeProvider(unix_time_us=1234567890_000000)
        assert provider.unix_time_us() == 1234567890_000000
        assert provider.wall_clock_valid is True

    def test_initial_gnss_fix(self) -> None:
        """Provider returns configured GNSS fix state."""
        provider = SimulatedTimeProvider(has_gnss=True)
        assert provider.has_gnss_fix() is True

    def test_set_unix_time(self) -> None:
        """Unix time can be updated."""
        provider = SimulatedTimeProvider()
        assert provider.unix_time_us() is None

        provider.set_unix_time_us(9876543210_000000)
        assert provider.unix_time_us() == 9876543210_000000
        assert provider.wall_clock_valid is True

        provider.set_unix_time_us(None)
        assert provider.unix_time_us() is None
        assert provider.wall_clock_valid is False

    def test_explicit_invalid_state_retains_time_for_diagnostics(self) -> None:
        """A candidate timestamp need not establish the wall clock."""
        provider = SimulatedTimeProvider(
            unix_time_us=9876543210_000000,
            wall_clock_valid=False,
        )
        assert provider.unix_time_us() == 9876543210_000000
        assert provider.wall_clock_valid is False

        provider.set_wall_clock_valid(True)
        assert provider.wall_clock_valid is True

        provider.set_wall_clock_valid(False)
        assert provider.wall_clock_valid is False

    def test_valid_state_requires_time(self) -> None:
        """Validity cannot be asserted before a wall-clock sample exists."""
        with pytest.raises(ValueError, match="without Unix time"):
            SimulatedTimeProvider(wall_clock_valid=True)

        provider = SimulatedTimeProvider()
        with pytest.raises(ValueError, match="without Unix time"):
            provider.set_wall_clock_valid(True)

    def test_set_gnss_fix(self) -> None:
        """GNSS fix state can be updated."""
        provider = SimulatedTimeProvider()
        assert provider.has_gnss_fix() is False

        provider.set_gnss_fix(True)
        assert provider.has_gnss_fix() is True

        provider.set_gnss_fix(False)
        assert provider.has_gnss_fix() is False

    def test_advance_us(self) -> None:
        """Time can be advanced by microseconds."""
        provider = SimulatedTimeProvider(unix_time_us=1000000)
        provider.advance_us(500000)
        assert provider.unix_time_us() == 1500000

    def test_advance_us_negative(self) -> None:
        """Time can be advanced by negative amount."""
        provider = SimulatedTimeProvider(unix_time_us=1000000)
        provider.advance_us(-300000)
        assert provider.unix_time_us() == 700000

    def test_advance_us_raises_when_none(self) -> None:
        """Advancing time raises error when time is None."""
        provider = SimulatedTimeProvider()
        with pytest.raises(ValueError, match="Cannot advance time"):
            provider.advance_us(100)

    def test_satisfies_protocol(self) -> None:
        """SimulatedTimeProvider satisfies TimeProvider protocol."""
        provider: TimeProvider = SimulatedTimeProvider(
            unix_time_us=1000000,
            has_gnss=True,
        )
        assert provider.unix_time_us() == 1000000
        assert provider.wall_clock_valid is True
        assert provider.has_gnss_fix() is True
