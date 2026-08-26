# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.csma module."""

from __future__ import annotations

import pytest

from lichen.constants import LORA_CAD_SYMBOLS
from lichen.timing.csma import (
    CSMA_BACKOFF_MAX,
    CSMA_BACKOFF_UNIT_MS,
    CSMA_CAD_TIMEOUT_SYMBOLS,
    CSMA_RETRY_LIMIT,
    CsmaResult,
    CsmaState,
    cw_for_exponent,
)


class TestCsmaConstants:
    """Test CSMA constants match spec."""

    def test_cad_timeout_symbols(self) -> None:
        assert CSMA_CAD_TIMEOUT_SYMBOLS == 3
        assert LORA_CAD_SYMBOLS == CSMA_CAD_TIMEOUT_SYMBOLS

    def test_backoff_unit_ms(self) -> None:
        assert CSMA_BACKOFF_UNIT_MS == 10

    def test_backoff_max(self) -> None:
        assert CSMA_BACKOFF_MAX == 5

    def test_retry_limit(self) -> None:
        assert CSMA_RETRY_LIMIT == 3


class TestCwForExponent:
    """Test contention window calculation."""

    def test_exp_0_returns_0(self) -> None:
        assert cw_for_exponent(0) == 0

    def test_exp_1_returns_1(self) -> None:
        assert cw_for_exponent(1) == 1  # 2^1 - 1

    def test_exp_2_returns_3(self) -> None:
        assert cw_for_exponent(2) == 3  # 2^2 - 1

    def test_exp_3_returns_7(self) -> None:
        assert cw_for_exponent(3) == 7  # 2^3 - 1

    def test_exp_4_returns_15(self) -> None:
        assert cw_for_exponent(4) == 15  # 2^4 - 1

    def test_exp_5_returns_31(self) -> None:
        assert cw_for_exponent(5) == 31  # 2^5 - 1

    def test_negative_exp_raises(self) -> None:
        with pytest.raises(ValueError, match="exp out of range"):
            cw_for_exponent(-1)

    def test_exp_above_max_raises(self) -> None:
        with pytest.raises(ValueError, match="exp out of range"):
            cw_for_exponent(CSMA_BACKOFF_MAX + 1)

    @pytest.mark.parametrize("exp", [False, 1.0, "1"])
    def test_non_integer_exp_raises(self, exp: object) -> None:
        with pytest.raises(TypeError, match="exact integer"):
            cw_for_exponent(exp)  # type: ignore[arg-type]


class TestCsmaStateInit:
    """Test CsmaState initialization."""

    def test_default_backoff_exp(self) -> None:
        state = CsmaState()
        assert state.backoff_exp == 0

    def test_default_retries(self) -> None:
        state = CsmaState()
        assert state.retries == 0

    def test_custom_init(self) -> None:
        state = CsmaState(backoff_exp=2, retries=1)
        assert state.backoff_exp == 2
        assert state.retries == 1

    @pytest.mark.parametrize("backoff_exp", [-1, CSMA_BACKOFF_MAX + 1])
    def test_invalid_backoff_exp_raises(self, backoff_exp: int) -> None:
        with pytest.raises(ValueError, match="backoff_exp must be in"):
            CsmaState(backoff_exp=backoff_exp)

    @pytest.mark.parametrize("retries", [-1, CSMA_RETRY_LIMIT + 2])
    def test_invalid_retries_raises(self, retries: int) -> None:
        with pytest.raises(ValueError, match="retries must be in"):
            CsmaState(retries=retries)

    @pytest.mark.parametrize(
        ("field", "value"), [("backoff_exp", False), ("retries", 1.0)]
    )
    def test_non_integer_state_raises(self, field: str, value: object) -> None:
        with pytest.raises(TypeError, match="exact integer"):
            CsmaState(**{field: value})  # type: ignore[arg-type]


class TestCsmaNextBackoffSlots:
    """Test next_backoff_slots calculation."""

    def test_exp_0_always_0(self) -> None:
        state = CsmaState(backoff_exp=0)
        assert state.next_backoff_slots(0.0) == 0
        assert state.next_backoff_slots(0.5) == 0
        assert state.next_backoff_slots(0.999) == 0

    def test_exp_1_range_0_1(self) -> None:
        state = CsmaState(backoff_exp=1)
        # CW = 1, slots in [0, 1]
        assert state.next_backoff_slots(0.0) == 0
        assert state.next_backoff_slots(0.5) == 1
        assert state.next_backoff_slots(0.999) == 1

    def test_exp_2_range_0_3(self) -> None:
        state = CsmaState(backoff_exp=2)
        # CW = 3, slots in [0, 3]
        assert state.next_backoff_slots(0.0) == 0
        assert state.next_backoff_slots(0.25) == 1
        assert state.next_backoff_slots(0.5) == 2
        assert state.next_backoff_slots(0.75) == 3
        assert state.next_backoff_slots(0.999) == 3

    def test_exp_5_range_0_31(self) -> None:
        state = CsmaState(backoff_exp=5)
        # CW = 31, slots in [0, 31]
        assert state.next_backoff_slots(0.0) == 0
        assert state.next_backoff_slots(0.999) == 31

    def test_rng_value_below_0_raises(self) -> None:
        state = CsmaState(backoff_exp=2)
        with pytest.raises(ValueError, match="rng_value must be in"):
            state.next_backoff_slots(-0.1)

    def test_rng_value_at_1_raises(self) -> None:
        state = CsmaState(backoff_exp=2)
        with pytest.raises(ValueError, match="rng_value must be in"):
            state.next_backoff_slots(1.0)

    def test_rng_value_above_1_raises(self) -> None:
        state = CsmaState(backoff_exp=2)
        with pytest.raises(ValueError, match="rng_value must be in"):
            state.next_backoff_slots(1.5)


class TestCsmaBackoffMs:
    """Test slot to milliseconds conversion."""

    def test_0_slots_0_ms(self) -> None:
        state = CsmaState()
        assert state.backoff_ms(0) == 0

    def test_1_slot_10_ms(self) -> None:
        state = CsmaState()
        assert state.backoff_ms(1) == 10

    def test_10_slots_100_ms(self) -> None:
        state = CsmaState()
        assert state.backoff_ms(10) == 100

    def test_31_slots_310_ms(self) -> None:
        state = CsmaState()
        assert state.backoff_ms(31) == 310


class TestCsmaOnCadBusy:
    """Test CAD busy state transitions."""

    def test_first_busy_increments_retries(self) -> None:
        state = CsmaState()
        state.on_cad_busy()
        assert state.retries == 1

    def test_first_busy_increments_exp(self) -> None:
        state = CsmaState()
        state.on_cad_busy()
        assert state.backoff_exp == 1

    def test_first_busy_returns_cad_busy(self) -> None:
        state = CsmaState()
        result = state.on_cad_busy()
        assert result == CsmaResult.CAD_BUSY

    def test_successive_busy_increases_exp(self) -> None:
        state = CsmaState()
        state.on_cad_busy()
        assert state.backoff_exp == 1
        state.on_cad_busy()
        assert state.backoff_exp == 2
        state.on_cad_busy()
        assert state.backoff_exp == 3

    def test_exp_capped_at_max(self) -> None:
        state = CsmaState(backoff_exp=CSMA_BACKOFF_MAX - 1)
        state.on_cad_busy()
        assert state.backoff_exp == CSMA_BACKOFF_MAX
        state.on_cad_busy()
        # Should stay at max
        assert state.backoff_exp == CSMA_BACKOFF_MAX

    def test_retry_exhausted_after_limit(self) -> None:
        state = CsmaState()
        for _ in range(CSMA_RETRY_LIMIT):
            result = state.on_cad_busy()
            assert result == CsmaResult.CAD_BUSY
        # Next should be exhausted
        result = state.on_cad_busy()
        assert result == CsmaResult.RETRY_EXHAUSTED
        assert state.retries == CSMA_RETRY_LIMIT + 1

    def test_retry_exhaustion_is_terminal(self) -> None:
        state = CsmaState()
        for _ in range(CSMA_RETRY_LIMIT + 1):
            state.on_cad_busy()

        prior_state = (state.backoff_exp, state.retries)
        assert state.on_cad_busy() == CsmaResult.RETRY_EXHAUSTED
        assert (state.backoff_exp, state.retries) == prior_state


class TestCsmaCadTransitions:
    """Test clear and busy CAD indications through the unified transition API."""

    def test_busy_transition_advances_backoff(self) -> None:
        state = CsmaState()
        assert state.on_cad_result(channel_busy=True) == CsmaResult.CAD_BUSY
        assert (state.backoff_exp, state.retries) == (1, 1)

    def test_clear_transition_resets_and_grants_tx(self) -> None:
        state = CsmaState(backoff_exp=3, retries=2)
        assert state.on_cad_result(channel_busy=False) == CsmaResult.TX_SUCCESS
        assert (state.backoff_exp, state.retries) == (0, 0)

    def test_on_cad_clear_resets_and_grants_tx(self) -> None:
        state = CsmaState(backoff_exp=2, retries=1)
        assert state.on_cad_clear() == CsmaResult.TX_SUCCESS
        assert (state.backoff_exp, state.retries) == (0, 0)

    @pytest.mark.parametrize("channel_busy", [0, 1, None, "busy"])
    def test_non_boolean_cad_result_raises(self, channel_busy: object) -> None:
        state = CsmaState()
        with pytest.raises(TypeError, match="channel_busy must be a bool"):
            state.on_cad_result(channel_busy)  # type: ignore[arg-type]


class TestCsmaOnSuccess:
    """Test successful TX resets state."""

    def test_resets_backoff_exp(self) -> None:
        state = CsmaState(backoff_exp=3, retries=2)
        result = state.on_success()
        assert result == CsmaResult.TX_SUCCESS
        assert state.backoff_exp == 0

    def test_resets_retries(self) -> None:
        state = CsmaState(backoff_exp=3, retries=2)
        state.on_success()
        assert state.retries == 0


class TestCsmaStateMachine:
    """Integration tests for full CSMA state machine flow."""

    def test_successful_tx_first_attempt(self) -> None:
        state = CsmaState()
        # Channel clear, transmit
        state.on_success()
        assert state.backoff_exp == 0
        assert state.retries == 0

    def test_single_collision_then_success(self) -> None:
        state = CsmaState()
        # First CAD busy
        result = state.on_cad_busy()
        assert result == CsmaResult.CAD_BUSY
        assert state.backoff_exp == 1
        # Wait backoff, then success
        state.on_success()
        assert state.backoff_exp == 0
        assert state.retries == 0

    def test_multiple_collisions_then_success(self) -> None:
        state = CsmaState()
        # Three CAD busy
        state.on_cad_busy()
        state.on_cad_busy()
        result = state.on_cad_busy()
        assert result == CsmaResult.CAD_BUSY
        assert state.backoff_exp == 3
        assert state.retries == 3
        # Success
        state.on_success()
        assert state.backoff_exp == 0

    def test_all_retries_exhausted(self) -> None:
        state = CsmaState()
        # Exhaust all retries
        for _ in range(CSMA_RETRY_LIMIT + 1):
            result = state.on_cad_busy()
        assert result == CsmaResult.RETRY_EXHAUSTED

    def test_backoff_distribution_uniform(self) -> None:
        # Verify slots are uniformly distributed over [0, CW]
        state = CsmaState(backoff_exp=3)  # CW = 7
        slots = [state.next_backoff_slots(i / 10) for i in range(10)]
        # Should see increasing values
        assert slots[0] == 0
        assert slots[-1] == 7


class TestCsmaResult:
    """Test CsmaResult enum."""

    def test_tx_success_value(self) -> None:
        assert CsmaResult.TX_SUCCESS.value == "tx_success"

    def test_cad_busy_value(self) -> None:
        assert CsmaResult.CAD_BUSY.value == "cad_busy"

    def test_retry_exhausted_value(self) -> None:
        assert CsmaResult.RETRY_EXHAUSTED.value == "retry_exhausted"
