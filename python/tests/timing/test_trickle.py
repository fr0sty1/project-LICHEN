# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.trickle module."""

from __future__ import annotations

import pytest

from lichen.timing.trickle import (
    TRICKLE_IMAX_DOUBLINGS,
    TRICKLE_IMAX_EXACT_MS,
    TRICKLE_IMAX_MS,
    TRICKLE_IMIN_MS,
    TRICKLE_K,
    TRICKLE_RATIONALE,
    TrickleTimer,
    spec_constants_valid,
)


class TestTrickleConstants:
    """Test Trickle constants match spec."""

    def test_imin_ms(self) -> None:
        assert TRICKLE_IMIN_MS == 4000

    def test_imax_ms_is_exact_profile_clamp(self) -> None:
        assert TRICKLE_IMAX_MS == 1_024_000
        assert TRICKLE_IMAX_MS // 1000 == 1024
        assert TRICKLE_IMAX_DOUBLINGS == 8

    def test_imax_exact_ms(self) -> None:
        # Imin * 2^8 = 4000 * 256 = 1024000
        assert TRICKLE_IMAX_EXACT_MS == 1_024_000

    def test_profile_constructor_uses_only_exact_constants(self) -> None:
        timer = TrickleTimer.lichen_profile(rng=lambda: 0.0)
        assert timer.imin == TRICKLE_IMIN_MS
        assert timer.imax_doublings == TRICKLE_IMAX_DOUBLINGS
        assert timer.max_interval == TRICKLE_IMAX_MS
        assert timer.k == TRICKLE_K

    def test_k(self) -> None:
        assert TRICKLE_K == 10

    def test_rationale_keys(self) -> None:
        assert "Imin" in TRICKLE_RATIONALE
        assert "Imax" in TRICKLE_RATIONALE
        assert "k" in TRICKLE_RATIONALE

    def test_spec_constants_valid(self) -> None:
        assert spec_constants_valid() is True


class TestTrickleTimerInit:
    """Test TrickleTimer initialization."""

    def test_valid_init(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        assert timer.imin == 1000
        assert timer.imax_doublings == 4
        assert timer.k == 3

    def test_max_interval_computed(self) -> None:
        # imin * 2^doublings
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        assert timer.max_interval == 16000  # 1000 * 2^4

    def test_zero_doublings(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=0, k=3)
        assert timer.max_interval == 1000  # No doubling

    def test_negative_imin_raises(self) -> None:
        with pytest.raises(ValueError, match="imin_ms must be positive"):
            TrickleTimer(imin_ms=-1, imax_doublings=4, k=3)

    def test_zero_imin_raises(self) -> None:
        with pytest.raises(ValueError, match="imin_ms must be positive"):
            TrickleTimer(imin_ms=0, imax_doublings=4, k=3)

    def test_negative_doublings_raises(self) -> None:
        with pytest.raises(ValueError, match="imax_doublings must be non-negative"):
            TrickleTimer(imin_ms=1000, imax_doublings=-1, k=3)

    def test_custom_rng(self) -> None:
        # Fixed RNG for determinism
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3, rng=lambda: 0.5)
        timer.start(0)
        # transmit_time should be at midpoint of second half
        # half = 500, range = 500, t = 500 + 0.5*500 = 750
        assert timer.transmit_time == 750


class TestTrickleTimerStart:
    """Test TrickleTimer.start()."""

    def test_sets_interval_to_imin(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(100)
        assert timer.interval == 1000

    def test_sets_interval_start(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(100)
        assert timer.interval_start == 100

    def test_resets_counter(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.counter = 5
        timer.start(100)
        assert timer.counter == 0

    def test_transmit_time_in_second_half(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3, rng=lambda: 0.0)
        timer.start(0)
        # t in [half, interval) = [500, 1000)
        # with rng=0.0, t = 500 + 0 = 500
        assert timer.transmit_time >= 500
        assert timer.transmit_time < 1000


class TestTrickleTimerIntervalEnd:
    """Test interval_end property."""

    def test_interval_end(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(100)
        assert timer.interval_end == 1100  # 100 + 1000


class TestTrickleTimerHeardConsistent:
    """Test heard_consistent() counter increment."""

    def test_increments_counter(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        assert timer.counter == 0
        timer.heard_consistent()
        assert timer.counter == 1
        timer.heard_consistent()
        assert timer.counter == 2

    def test_saturating_increment(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.counter = (1 << 32) - 2
        timer.heard_consistent()
        assert timer.counter == (1 << 32) - 1
        # Should not wrap
        timer.heard_consistent()
        assert timer.counter == (1 << 32) - 1


class TestTrickleTimerShouldTransmit:
    """Test should_transmit() based on counter vs k."""

    def test_counter_below_k_should_transmit(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.counter = 0
        assert timer.should_transmit() is True
        timer.counter = 1
        assert timer.should_transmit() is True
        timer.counter = 2
        assert timer.should_transmit() is True

    def test_counter_at_k_should_not_transmit(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.counter = 3
        assert timer.should_transmit() is False

    def test_counter_above_k_should_not_transmit(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.counter = 10
        assert timer.should_transmit() is False


class TestTrickleTimerFireTransmit:
    """Test fire_transmit() marks transmitted."""

    def test_marks_transmitted(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        assert timer._transmitted is False
        timer.fire_transmit()
        assert timer._transmitted is True

    def test_returns_should_transmit(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.counter = 0
        assert timer.fire_transmit() is True
        timer._transmitted = False
        timer.counter = 10
        assert timer.fire_transmit() is False


class TestTrickleTimerExpire:
    """Test expire() interval doubling."""

    def test_doubles_interval(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        assert timer.interval == 1000
        timer.expire(1000)
        assert timer.interval == 2000
        timer.expire(3000)
        assert timer.interval == 4000

    def test_interval_capped_at_max(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=2, k=3)
        # max_interval = 1000 * 2^2 = 4000
        timer.start(0)
        timer.expire(1000)  # 2000
        timer.expire(3000)  # 4000
        timer.expire(7000)  # Still 4000 (capped)
        assert timer.interval == 4000

    def test_resets_counter(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.counter = 5
        timer.expire(1000)
        assert timer.counter == 0

    def test_updates_interval_start(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.expire(1000)
        assert timer.interval_start == 1000


class TestTrickleTimerReset:
    """Test reset() on inconsistency."""

    def test_reset_sets_interval_to_imin(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.expire(1000)  # 2000
        timer.expire(3000)  # 4000
        assert timer.interval == 4000
        timer.reset(7000)
        assert timer.interval == 1000

    def test_reset_at_imin_restarts(self) -> None:
        samples = iter((0.0, 0.5))
        timer = TrickleTimer(
            imin_ms=1000,
            imax_doublings=4,
            k=3,
            rng=lambda: next(samples),
        )
        timer.start(0)
        gen_before = timer._generation
        timer.reset(500)
        assert timer._generation == gen_before + 1
        assert timer.interval_start == 500
        assert timer.transmit_time == 1250

    def test_reset_before_start_starts(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        assert timer._generation == 0
        timer.reset(0)
        assert timer._generation == 1
        assert timer.interval == 1000


class TestTrickleTimerNextEvent:
    """Test next_event() scheduling."""

    def test_before_transmit(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        event_type, event_time = timer.next_event()
        assert event_type == "transmit"
        assert event_time == timer.transmit_time

    def test_after_transmit(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.fire_transmit()
        event_type, event_time = timer.next_event()
        assert event_type == "expire"
        assert event_time == timer.interval_end


class TestTrickleTimerTransmitTime:
    """Test transmit_time falls in [I/2, I)."""

    def test_transmit_time_rng_0(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3, rng=lambda: 0.0)
        timer.start(0)
        # t = half + 0 = 500
        assert timer.transmit_time == 500

    def test_transmit_time_rng_0_5(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3, rng=lambda: 0.5)
        timer.start(0)
        # half = 500, range = 500, t = 500 + 250 = 750
        assert timer.transmit_time == 750

    def test_transmit_time_rng_almost_1(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3, rng=lambda: 0.999)
        timer.start(0)
        # t = 500 + 0.999*500 = 999
        assert timer.transmit_time >= 999

    def test_transmit_time_never_at_interval_end(self) -> None:
        # Even with rng approaching 1, should be < interval
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3, rng=lambda: 0.9999)
        timer.start(0)
        assert timer.transmit_time < timer.interval_end


class TestTrickleTimerGenerations:
    """Test generation tracking for reset detection."""

    def test_generation_increments_on_start(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        assert timer._generation == 0
        timer.start(0)
        assert timer._generation == 1

    def test_generation_increments_on_expire(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        gen = timer._generation
        timer.expire(1000)
        assert timer._generation == gen + 1

    def test_generation_increments_on_reset(self) -> None:
        timer = TrickleTimer(imin_ms=1000, imax_doublings=4, k=3)
        timer.start(0)
        timer.expire(1000)  # Now at 2x Imin
        gen = timer._generation
        timer.reset(2000)
        assert timer._generation == gen + 1


class TestTrickleTimerSpecValues:
    """Test with spec values (Imin=4s, doublings=8, k=10)."""

    def test_spec_imin(self) -> None:
        timer = TrickleTimer(imin_ms=4000, imax_doublings=8, k=10)
        timer.start(0)
        assert timer.interval == 4000

    def test_spec_imax(self) -> None:
        timer = TrickleTimer(imin_ms=4000, imax_doublings=8, k=10)
        # max_interval = 4000 * 2^8 = 1024000ms = ~17 minutes
        assert timer.max_interval == 1_024_000

    def test_spec_k_suppression(self) -> None:
        timer = TrickleTimer(imin_ms=4000, imax_doublings=8, k=10)
        timer.start(0)
        # 9 consistent messages
        for _ in range(9):
            timer.heard_consistent()
        assert timer.should_transmit() is True
        # 10th makes counter == k
        timer.heard_consistent()
        assert timer.should_transmit() is False

    def test_full_doubling_sequence(self) -> None:
        timer = TrickleTimer(imin_ms=4000, imax_doublings=8, k=10)
        timer.start(0)
        expected_intervals = [4000 * (2**i) for i in range(9)]  # 0 to 8 doublings
        expected_intervals[-1] = min(expected_intervals[-1], timer.max_interval)

        now = 0
        for i, expected in enumerate(expected_intervals):
            assert timer.interval == expected, f"Failed at doubling {i}"
            now += timer.interval
            if i < 8:  # Don't expire after last
                timer.expire(now)
