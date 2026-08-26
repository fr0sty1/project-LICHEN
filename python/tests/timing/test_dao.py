# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.dao module."""

from __future__ import annotations

import random

import pytest

from lichen.timing.dao import (
    DAO_INITIAL_DELAY_MAX_MS,
    DAO_INITIAL_DELAY_MIN_MS,
    DAO_REFRESH_S,
    DAO_RETRY_DELAYS_MS,
    DAO_SEQUENCE_MAX,
    DAO_SEQUENCE_START_MIN,
    DAO_SOFT_STATE_LIFETIME_S,
    dao_initial_delay,
    dao_retry_delay,
    dao_retry_exhausted,
    is_valid_dao_sequence,
)


class TestDaoConstants:
    """Test DAO constants match spec."""

    def test_initial_delay_min(self) -> None:
        assert DAO_INITIAL_DELAY_MIN_MS == 0

    def test_initial_delay_max(self) -> None:
        assert DAO_INITIAL_DELAY_MAX_MS == 2000

    def test_retry_delays(self) -> None:
        assert DAO_RETRY_DELAYS_MS == (4000, 8000, 16000)

    def test_refresh_s(self) -> None:
        assert DAO_REFRESH_S == 15 * 60  # 15 minutes

    def test_soft_state_lifetime_s(self) -> None:
        assert DAO_SOFT_STATE_LIFETIME_S == 30 * 60  # 30 minutes

    def test_sequence_max(self) -> None:
        assert DAO_SEQUENCE_MAX == 0xFFFFFFFFFFFFFFFF  # 64-bit max

    def test_sequence_start_min(self) -> None:
        assert DAO_SEQUENCE_START_MIN == 1


class TestDaoInitialDelay:
    """Test the randomized initial DAO delay."""

    def test_samples_inclusive_protocol_range(self) -> None:
        rng = random.Random(0)
        delays = [dao_initial_delay(rng) for _ in range(10_000)]

        assert min(delays) == DAO_INITIAL_DELAY_MIN_MS
        assert max(delays) == DAO_INITIAL_DELAY_MAX_MS
        assert all(
            DAO_INITIAL_DELAY_MIN_MS <= delay <= DAO_INITIAL_DELAY_MAX_MS for delay in delays
        )

    def test_seeded_rng_is_reproducible(self) -> None:
        first = random.Random(42)
        second = random.Random(42)

        assert [dao_initial_delay(first) for _ in range(20)] == [
            dao_initial_delay(second) for _ in range(20)
        ]

    @pytest.mark.parametrize("delay_ms", [DAO_INITIAL_DELAY_MIN_MS, DAO_INITIAL_DELAY_MAX_MS])
    def test_default_rng_uses_inclusive_bounds(
        self, monkeypatch: pytest.MonkeyPatch, delay_ms: int
    ) -> None:
        def fake_randint(lower: int, upper: int) -> int:
            assert lower == DAO_INITIAL_DELAY_MIN_MS
            assert upper == DAO_INITIAL_DELAY_MAX_MS
            return delay_ms

        monkeypatch.setattr("lichen.timing.dao.random.randint", fake_randint)

        assert dao_initial_delay() == delay_ms


class TestDaoRetryDelay:
    """Test dao_retry_delay calculation."""

    def test_attempt_0_returns_4000(self) -> None:
        assert dao_retry_delay(0) == 4000

    def test_attempt_1_returns_8000(self) -> None:
        assert dao_retry_delay(1) == 8000

    def test_attempt_2_returns_16000(self) -> None:
        assert dao_retry_delay(2) == 16000

    def test_attempt_3_returns_none(self) -> None:
        assert dao_retry_delay(3) is None

    def test_attempt_100_returns_none(self) -> None:
        assert dao_retry_delay(100) is None

    def test_negative_attempt_raises(self) -> None:
        with pytest.raises(ValueError, match="attempt must be non-negative"):
            dao_retry_delay(-1)

    @pytest.mark.parametrize("attempt", [True, 1.0, "1"])
    def test_coercive_attempt_rejected(self, attempt: object) -> None:
        with pytest.raises(TypeError, match="exact integer"):
            dao_retry_delay(attempt)  # type: ignore[arg-type]


class TestDaoRetryExhausted:
    """Test dao_retry_exhausted check."""

    def test_0_attempts_not_exhausted(self) -> None:
        assert dao_retry_exhausted(0) is False

    def test_1_attempt_not_exhausted(self) -> None:
        assert dao_retry_exhausted(1) is False

    def test_2_attempts_not_exhausted(self) -> None:
        assert dao_retry_exhausted(2) is False

    def test_3_attempts_exhausted(self) -> None:
        assert dao_retry_exhausted(3) is True

    def test_10_attempts_exhausted(self) -> None:
        assert dao_retry_exhausted(10) is True

    def test_negative_attempts_rejected(self) -> None:
        with pytest.raises(ValueError, match="attempts must be non-negative"):
            dao_retry_exhausted(-1)

    @pytest.mark.parametrize("attempts", [True, 1.0, "1"])
    def test_coercive_attempts_rejected(self, attempts: object) -> None:
        with pytest.raises(TypeError, match="exact integer"):
            dao_retry_exhausted(attempts)  # type: ignore[arg-type]


class TestIsValidDaoSequence:
    """Test DAO sequence validation."""

    def test_zero_invalid(self) -> None:
        # Must start above zero
        assert is_valid_dao_sequence(0) is False

    def test_one_valid(self) -> None:
        assert is_valid_dao_sequence(1) is True

    def test_normal_sequence_valid(self) -> None:
        assert is_valid_dao_sequence(12345) is True

    def test_max_minus_one_valid(self) -> None:
        assert is_valid_dao_sequence(DAO_SEQUENCE_MAX - 1) is True

    def test_max_valid_as_final_sequence(self) -> None:
        assert is_valid_dao_sequence(DAO_SEQUENCE_MAX) is True

    def test_negative_invalid(self) -> None:
        # Out of valid range
        assert is_valid_dao_sequence(-1) is False

    def test_above_max_invalid(self) -> None:
        assert is_valid_dao_sequence(DAO_SEQUENCE_MAX + 1) is False

    def test_coercive_values_invalid(self) -> None:
        assert is_valid_dao_sequence(True) is False
        assert is_valid_dao_sequence(1.0) is False  # type: ignore[arg-type]
        assert is_valid_dao_sequence("1") is False  # type: ignore[arg-type]


class TestIsValidDaoSequenceWithPrevMax:
    """Test DAO sequence validation with prev_max."""

    def test_greater_than_prev_valid(self) -> None:
        assert is_valid_dao_sequence(100, prev_max=50) is True

    def test_equal_to_prev_invalid(self) -> None:
        # Must advance
        assert is_valid_dao_sequence(50, prev_max=50) is False

    def test_less_than_prev_invalid(self) -> None:
        assert is_valid_dao_sequence(30, prev_max=50) is False

    def test_one_above_prev_valid(self) -> None:
        assert is_valid_dao_sequence(51, prev_max=50) is True

    def test_none_prev_max_valid(self) -> None:
        # No previous, any valid seq works
        assert is_valid_dao_sequence(1, prev_max=None) is True

    def test_max_with_lower_previous_is_valid_terminal_value(self) -> None:
        assert is_valid_dao_sequence(DAO_SEQUENCE_MAX, prev_max=100) is True

    def test_invalid_previous_floors_rejected(self) -> None:
        assert is_valid_dao_sequence(1, prev_max=True) is False
        assert is_valid_dao_sequence(1, prev_max=-1) is False
        assert is_valid_dao_sequence(1, prev_max=DAO_SEQUENCE_MAX + 1) is False
        assert is_valid_dao_sequence(1, prev_max=0.0) is False  # type: ignore[arg-type]


class TestDaoTimingScenarios:
    """Integration tests for DAO timing scenarios."""

    def test_retry_sequence(self) -> None:
        # Simulate retry sequence
        delays = []
        for attempt in range(10):
            delay = dao_retry_delay(attempt)
            if delay is None:
                break
            delays.append(delay)
        assert delays == [4000, 8000, 16000]

    def test_exponential_backoff(self) -> None:
        # Delays double each time
        d0 = dao_retry_delay(0)
        d1 = dao_retry_delay(1)
        d2 = dao_retry_delay(2)
        assert d0 is not None
        assert d1 is not None
        assert d2 is not None
        assert d1 == 2 * d0
        assert d2 == 2 * d1

    def test_total_retry_time(self) -> None:
        # Total time for all retries
        total = sum(DAO_RETRY_DELAYS_MS)
        assert total == 28000  # 4 + 8 + 16 = 28 seconds

    def test_refresh_half_lifetime(self) -> None:
        # Refresh = lifetime / 2
        assert DAO_REFRESH_S == DAO_SOFT_STATE_LIFETIME_S // 2

    def test_sequence_increment(self) -> None:
        # Normal sequence progression
        prev = None
        for seq in range(1, 100):
            assert is_valid_dao_sequence(seq, prev_max=prev) is True
            prev = seq
