# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for link-layer replay protection (spec section 4.4).

Oracles are the spec acceptance-rules table and standard anti-replay
sliding-window semantics, reasoned out per case.
"""

from __future__ import annotations

import pytest

from lichen.link.replay import (
    WINDOW_SIZE,
    ReplayProtector,
    ReplayWindow,
    logical_counter,
)


class TestLogicalCounter:
    def test_combines_epoch_and_seqnum(self) -> None:
        assert logical_counter(0, 0) == 0
        assert logical_counter(0, 0xFFFF) == 0xFFFF
        assert logical_counter(1, 0) == 0x10000  # epoch increment > any seqnum
        assert logical_counter(2, 5) == (2 << 16) | 5

    def test_monotonic_across_seqnum_wrap(self) -> None:
        # epoch 0 / seqnum 0xFFFF then epoch 1 / seqnum 0 must increase.
        assert logical_counter(1, 0) > logical_counter(0, 0xFFFF)

    @pytest.mark.parametrize("epoch,seqnum", [(-1, 0), (256, 0), (0, -1), (0, 0x10000)])
    def test_out_of_range(self, epoch: int, seqnum: int) -> None:
        with pytest.raises(ValueError):
            logical_counter(epoch, seqnum)


class TestReplayWindow:
    def test_first_frame_accepted(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(0, 0) is True

    def test_duplicate_rejected(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(0, 10) is True
        assert w.check_and_update(0, 10) is False  # exact replay

    def test_strictly_increasing_all_accepted(self) -> None:
        w = ReplayWindow()
        assert all(w.check_and_update(0, s) for s in range(1, 50))

    def test_higher_epoch_accepted_even_with_lower_seqnum(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(0, 5000) is True
        assert w.check_and_update(1, 0) is True  # epoch > last -> accept

    def test_lower_epoch_rejected(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(5, 0) is True
        assert w.check_and_update(2, 0) is False

    def test_lower_epoch_rejected_at_adjacent_boundary(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(5, 0) is True
        assert w.check_and_update(4, 0xFFFF) is False

    def test_ordinary_epoch_increment_accepted(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(4, 0xFFFF) is True
        assert w.check_and_update(5, 0) is True

    def test_higher_epoch_resets_sequence_window(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(4, 100) is True
        assert w.check_and_update(5, 100) is True
        assert w.check_and_update(5, 99) is True

    def test_same_epoch_sequence_wrap_rejected(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(7, 0xFFFF) is True
        assert w.check_and_update(7, 0) is False

    def test_terminal_counter_wrap_rejected(self) -> None:
        w = ReplayWindow()
        with pytest.warns(UserWarning, match="approaching 24-bit limit"):
            assert w.check_and_update(0xFF, 0xFFFF) is True
        assert w.check_and_update(0, 0) is False

    def test_out_of_order_within_window_accepted_once(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(0, 5) is True
        assert w.check_and_update(0, 3) is True  # within window, unseen
        assert w.check_and_update(0, 3) is False  # now seen -> replay
        assert w.check_and_update(0, 4) is True  # still fresh

    def test_below_window_floor_rejected(self) -> None:
        w = ReplayWindow()  # WINDOW_SIZE == 32
        assert w.check_and_update(0, 40) is True
        assert w.check_and_update(0, 1) is False  # offset 39 >= 32 -> too old

    def test_window_floor_edge(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(0, 32) is True
        assert w.check_and_update(0, 0) is False  # offset 32 == WINDOW_SIZE -> reject
        assert w.check_and_update(0, 1) is True  # offset 31 < WINDOW_SIZE -> accept

    def test_large_jump_resets_window(self) -> None:
        w = ReplayWindow()
        assert w.check_and_update(0, 1) is True
        assert w.check_and_update(0, 1000) is True  # jump > window
        # Old positions far behind are now below the floor.
        assert w.check_and_update(0, 1) is False
        assert w.check_and_update(0, 1000) is False  # the jump target itself is seen

    def test_highest_tracks_counter(self) -> None:
        w = ReplayWindow()
        w.check_and_update(2, 7)
        assert w.highest == logical_counter(2, 7)

    def test_invalid_window_size(self) -> None:
        with pytest.raises(ValueError):
            ReplayWindow(window_size=0)


class TestReplayProtector:
    def test_per_sender_isolation(self) -> None:
        p = ReplayProtector()
        assert p.check_and_update(b"A", 0, 1) is True
        assert p.check_and_update(b"B", 0, 1) is True  # different sender, same counter
        assert p.check_and_update(b"A", 0, 1) is False  # replay for A

    def test_reset_forgets_sender(self) -> None:
        p = ReplayProtector()
        assert p.check_and_update("node1", 0, 5) is True
        assert p.check_and_update("node1", 0, 5) is False
        p.reset("node1")
        assert p.check_and_update("node1", 0, 5) is True  # state cleared

    def test_reset_allows_fresh_state_after_terminal_counter(self) -> None:
        p = ReplayProtector()
        with pytest.warns(UserWarning, match="approaching 24-bit limit"):
            assert p.check_and_update("old-key", 0xFF, 0xFFFF) is True
        assert p.check_and_update("old-key", 0, 0) is False
        p.reset("old-key")
        assert p.check_and_update("old-key", 0, 0) is True

    def test_new_public_key_state_is_fresh(self) -> None:
        p = ReplayProtector()
        with pytest.warns(UserWarning, match="approaching 24-bit limit"):
            assert p.check_and_update(b"old-public-key", 0xFF, 0xFFFF) is True
        assert p.check_and_update(b"new-public-key", 0, 0) is True

    def test_non_profile_window_size_rejected(self) -> None:
        with pytest.raises(ValueError, match="window_size must be 32"):
            ReplayProtector(window_size=4)

    def test_window_size_constant(self) -> None:
        assert WINDOW_SIZE == 32
