# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for lichen.timing.sfn module."""

from __future__ import annotations

import pytest

from lichen.timing.sfn import (
    DESYNC_CONSTANTS,
    TDMA_BEACON_TIMEOUT_SUPERFRAMES,
    TDMA_GUARD_MS,
    TDMA_GUARD_MS_ALT,
    TDMA_REJOIN_TIMEOUT_SUPERFRAMES,
    TDMA_SLOT_MS,
    CcpState,
    DesyncFSM,
    DesyncState,
    hash_32,
    initial_startup_delay,
    sfn_delta,
    slot_for,
)


class TestTdmaConstants:
    """Test TDMA constants match spec."""

    def test_guard_ms(self) -> None:
        assert TDMA_GUARD_MS == 50

    def test_guard_ms_alt(self) -> None:
        assert TDMA_GUARD_MS_ALT == 100

    def test_slot_ms(self) -> None:
        assert TDMA_SLOT_MS == 250

    def test_beacon_timeout(self) -> None:
        assert TDMA_BEACON_TIMEOUT_SUPERFRAMES == 3

    def test_rejoin_timeout(self) -> None:
        assert TDMA_REJOIN_TIMEOUT_SUPERFRAMES == 10


class TestDesyncConstants:
    """Test desync constants match spec."""

    def test_listen_period_min(self) -> None:
        assert DESYNC_CONSTANTS["LISTEN_PERIOD_MIN_S"] == 30

    def test_listen_period_max(self) -> None:
        assert DESYNC_CONSTANTS["LISTEN_PERIOD_MAX_S"] == 60

    def test_delay_per_node(self) -> None:
        assert DESYNC_CONSTANTS["DELAY_PER_NODE_S"] == 5

    def test_max_startup_delay(self) -> None:
        assert DESYNC_CONSTANTS["MAX_STARTUP_DELAY_S"] == 300


class TestHash32:
    """Test FNV-1a 32-bit hash."""

    def test_empty_bytes(self) -> None:
        result = hash_32(b"")
        # FNV-1a initial value
        assert result == 0x811C9DC5

    def test_single_byte(self) -> None:
        result = hash_32(b"\x00")
        assert isinstance(result, int)
        assert 0 <= result < 2**32

    def test_deterministic(self) -> None:
        data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        h1 = hash_32(data)
        h2 = hash_32(data)
        assert h1 == h2

    def test_different_data_different_hash(self) -> None:
        h1 = hash_32(b"\x00\x00\x00\x00\x00\x00\x00\x00")
        h2 = hash_32(b"\x00\x00\x00\x00\x00\x00\x00\x01")
        assert h1 != h2

    def test_returns_32_bit(self) -> None:
        result = hash_32(b"\xff" * 100)
        assert 0 <= result < 2**32


class TestSlotFor:
    """Test slot_for calculation."""

    def test_valid_eui64(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        result = slot_for(eui64, 0, 10)
        assert 0 <= result < 10

    def test_short_eui64_raises(self) -> None:
        with pytest.raises(ValueError, match="eui64 must be 8 bytes"):
            slot_for(b"\x01\x02\x03\x04\x05\x06\x07", 0, 10)

    def test_long_eui64_raises(self) -> None:
        with pytest.raises(ValueError, match="eui64 must be 8 bytes"):
            slot_for(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09", 0, 10)

    def test_zero_slots_raises(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        with pytest.raises(ValueError, match="num_slots must be positive"):
            slot_for(eui64, 0, 0)

    def test_negative_slots_raises(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        with pytest.raises(ValueError, match="num_slots must be positive"):
            slot_for(eui64, 0, -1)

    def test_deterministic(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        s1 = slot_for(eui64, 100, 16)
        s2 = slot_for(eui64, 100, 16)
        assert s1 == s2

    def test_sfn_affects_slot(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        s0 = slot_for(eui64, 0, 16)
        s1 = slot_for(eui64, 1, 16)
        # Different SFN should (usually) give different slot
        # This is probabilistic but num_slots=16 gives high chance
        # We test that adding 1 to SFN rotates the slot
        expected = (s0 + 1) % 16
        assert s1 == expected

    def test_slot_rotation_with_sfn(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        slots = [slot_for(eui64, sfn, 8) for sfn in range(16)]
        # Should see rotation pattern
        for i in range(8):
            assert slots[i] == slots[i + 8]  # Pattern repeats every num_slots

    def test_different_eui_different_slot(self) -> None:
        # Use EUIs known to produce different slots at sfn=0, num_slots=100
        eui1 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        eui2 = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
        s1 = slot_for(eui1, 0, 100)
        s2 = slot_for(eui2, 0, 100)
        # Different EUIs should hash to different slots (deterministic check)
        assert s1 != s2


class TestSlotForWraparound:
    """Test slot_for with SFN wraparound."""

    def test_sfn_at_max_u32(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        # SFN at max 32-bit
        result = slot_for(eui64, 0xFFFFFFFF, 10)
        assert 0 <= result < 10

    def test_sfn_wrap_continuity(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        # SFN just before and after wrap
        s_before = slot_for(eui64, 0xFFFFFFFF, 16)
        s_after = slot_for(eui64, 0, 16)
        # After wrap, should be one slot earlier (modular)
        expected = (s_before + 1) % 16
        assert s_after == expected

    def test_large_sfn_masked_to_32_bits(self) -> None:
        eui64 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        # Python allows large ints; slot_for should mask to 32 bits
        s1 = slot_for(eui64, 0, 10)
        s2 = slot_for(eui64, 0x100000000, 10)  # 2^32 = 0 mod 2^32
        assert s1 == s2


class TestSfnDelta:
    """Test SFN delta calculation."""

    def test_simple_delta(self) -> None:
        assert sfn_delta(10, 5) == 5

    def test_zero_delta(self) -> None:
        assert sfn_delta(100, 100) == 0

    def test_wrap_around(self) -> None:
        # curr=5, last=0xFFFFFFFE -> delta=7
        result = sfn_delta(5, 0xFFFFFFFE)
        assert result == 7

    def test_max_to_zero(self) -> None:
        result = sfn_delta(0, 0xFFFFFFFF)
        assert result == 1

    def test_negative_actual_positive_delta(self) -> None:
        # 2 - 10 = -8, but mod 2^32 wraps to large positive
        result = sfn_delta(2, 10)
        assert result == 0xFFFFFFF8


class TestInitialStartupDelay:
    """Test initial_startup_delay calculation."""

    def test_zero_nodes(self) -> None:
        result = initial_startup_delay(0)
        assert result == 0

    def test_one_node(self) -> None:
        result = initial_startup_delay(1)
        assert result == 5  # 1 * 5

    def test_ten_nodes(self) -> None:
        result = initial_startup_delay(10)
        assert result == 50  # 10 * 5

    def test_at_max(self) -> None:
        # 60 nodes * 5s = 300s = MAX
        result = initial_startup_delay(60)
        assert result == 300

    def test_above_max_capped(self) -> None:
        # 100 nodes * 5s = 500s, capped to 300
        result = initial_startup_delay(100)
        assert result == 300

    def test_large_value_capped(self) -> None:
        result = initial_startup_delay(10000)
        assert result == 300


class TestDesyncFSM:
    """Test DesyncFSM state machine."""

    def test_initial_state_synced(self) -> None:
        fsm = DesyncFSM()
        assert fsm.state == DesyncState.SYNCED

    def test_initial_consecutive_valid(self) -> None:
        fsm = DesyncFSM()
        assert fsm.consecutive_valid == 0

    def test_sfn_wrap_valid_stays_synced(self) -> None:
        fsm = DesyncFSM()
        state = fsm.on_sfn_wrap(time_valid=True)
        assert state == DesyncState.SYNCED

    def test_sfn_wrap_invalid_goes_desynced(self) -> None:
        fsm = DesyncFSM()
        state = fsm.on_sfn_wrap(time_valid=False)
        assert state == DesyncState.DESYNCED

    def test_beacon_valid_in_desynced_goes_recovering(self) -> None:
        fsm = DesyncFSM()
        fsm.on_sfn_wrap(time_valid=False)
        assert fsm.state == DesyncState.DESYNCED
        state = fsm.on_beacon(valid=True)
        assert state == DesyncState.RECOVERING
        assert fsm.consecutive_valid == 1

    def test_beacon_invalid_in_recovering_goes_desynced(self) -> None:
        fsm = DesyncFSM()
        fsm.state = DesyncState.RECOVERING
        fsm.consecutive_valid = 2
        state = fsm.on_beacon(valid=False)
        assert state == DesyncState.DESYNCED
        assert fsm.consecutive_valid == 0

    def test_three_valid_beacons_recovers(self) -> None:
        fsm = DesyncFSM()
        fsm.on_sfn_wrap(time_valid=False)
        # First valid beacon
        fsm.on_beacon(valid=True)
        assert fsm.state == DesyncState.RECOVERING
        assert fsm.consecutive_valid == 1
        # Second valid beacon
        fsm.on_beacon(valid=True)
        assert fsm.state == DesyncState.RECOVERING
        assert fsm.consecutive_valid == 2
        # Third valid beacon -> synced
        state = fsm.on_beacon(valid=True)
        assert state == DesyncState.SYNCED
        assert fsm.consecutive_valid == 0

    def test_beacon_in_synced_no_op(self) -> None:
        fsm = DesyncFSM()
        state = fsm.on_beacon(valid=True)
        assert state == DesyncState.SYNCED  # No change
        state = fsm.on_beacon(valid=False)
        assert state == DesyncState.SYNCED  # No change

    def test_recovery_interrupted_by_invalid(self) -> None:
        fsm = DesyncFSM()
        fsm.state = DesyncState.DESYNCED
        fsm.on_beacon(valid=True)  # -> RECOVERING, count=1
        fsm.on_beacon(valid=True)  # -> RECOVERING, count=2
        fsm.on_beacon(valid=False)  # -> DESYNCED, count=0
        assert fsm.state == DesyncState.DESYNCED
        assert fsm.consecutive_valid == 0


class TestDesyncState:
    """Test DesyncState enum."""

    def test_synced_exists(self) -> None:
        assert DesyncState.SYNCED is not None

    def test_desynced_exists(self) -> None:
        assert DesyncState.DESYNCED is not None

    def test_recovering_exists(self) -> None:
        assert DesyncState.RECOVERING is not None


class TestCcpState:
    """Test CcpState enum."""

    def test_unjoined_exists(self) -> None:
        assert CcpState.UNJOINED is not None

    def test_acquiring_exists(self) -> None:
        assert CcpState.ACQUIRING is not None

    def test_synced_exists(self) -> None:
        assert CcpState.SYNCED is not None

    def test_drifting_exists(self) -> None:
        assert CcpState.DRIFTING is not None

    def test_rejoining_exists(self) -> None:
        assert CcpState.REJOINING is not None
