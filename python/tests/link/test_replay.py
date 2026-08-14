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


class TestTwoPhaseReplayWindow:
    """Tests for two-phase check() + commit() replay protection.

    Per spec 06-security.md and 10-implementation.md, the replay floor must
    only be committed AFTER all validation passes. This prevents premature
    floor advancement when later validation fails.
    """

    def test_check_does_not_modify_state(self) -> None:
        """check() must be read-only - no state mutation."""
        w = ReplayWindow()
        assert w.highest == -1  # no frames yet
        assert w.check(0, 10) is True  # fresh
        assert w.highest == -1  # still no frames recorded
        assert w.check(0, 10) is True  # still fresh (not committed)

    def test_commit_advances_floor(self) -> None:
        """commit() must update replay state."""
        w = ReplayWindow()
        w.commit(0, 10)
        assert w.highest == logical_counter(0, 10)
        assert w.check(0, 10) is False  # now seen

    def test_two_phase_sequence(self) -> None:
        """Standard two-phase: check passes, validation passes, then commit."""
        w = ReplayWindow()
        # Phase 1: check (read-only)
        assert w.check(0, 5) is True
        # ... other validation would happen here ...
        # Phase 2: commit (after all validation passes)
        w.commit(0, 5)
        # Replay now rejected
        assert w.check(0, 5) is False

    def test_validation_failure_prevents_floor_commitment(self) -> None:
        """If validation fails after check(), floor should NOT be committed.

        This is the core bug that two-phase checking prevents. Scenario:
        1. Frame with counter=100 arrives
        2. check() returns True (fresh)
        3. Some later validation fails
        4. We do NOT call commit()
        5. A valid frame with counter=100 arrives later
        6. It should still be accepted because floor was not advanced
        """
        w = ReplayWindow()
        # Frame 1: check passes but "validation fails" - no commit
        assert w.check(0, 100) is True
        # Simulate validation failure - we intentionally don't commit
        # Frame 2: same counter should still be accepted
        assert w.check(0, 100) is True
        # This time validation passes, so we commit
        w.commit(0, 100)
        # Now it's seen
        assert w.check(0, 100) is False

    def test_check_and_update_equivalent_to_check_plus_commit(self) -> None:
        """check_and_update should behave identically to check+commit."""
        w1 = ReplayWindow()
        w2 = ReplayWindow()

        # w1: atomic approach
        result1 = w1.check_and_update(0, 10)

        # w2: two-phase approach
        result2 = w2.check(0, 10)
        if result2:
            w2.commit(0, 10)

        assert result1 == result2
        assert w1.highest == w2.highest

    def test_out_of_order_with_two_phase(self) -> None:
        """Out-of-order frames work correctly with two-phase checking."""
        w = ReplayWindow()
        # Accept frame 10
        assert w.check(0, 10) is True
        w.commit(0, 10)
        # Check frame 8 (within window)
        assert w.check(0, 8) is True
        # But validation fails - don't commit
        # Frame 8 arrives again, should still be fresh
        assert w.check(0, 8) is True
        w.commit(0, 8)
        # Now it's seen
        assert w.check(0, 8) is False


class TestTwoPhaseReplayProtector:
    """Tests for two-phase check() + commit() on ReplayProtector."""

    def test_check_does_not_modify_state(self) -> None:
        """check() must be read-only - no state mutation."""
        p = ReplayProtector()
        assert p.check(b"sender1", 0, 10) is True
        assert p.check(b"sender1", 0, 10) is True  # still fresh

    def test_commit_advances_floor(self) -> None:
        """commit() must update replay state."""
        p = ReplayProtector()
        p.check(b"sender1", 0, 10)  # creates window
        p.commit(b"sender1", 0, 10)
        assert p.check(b"sender1", 0, 10) is False  # now seen

    def test_per_sender_isolation_with_two_phase(self) -> None:
        """Two-phase works correctly across multiple senders."""
        p = ReplayProtector()
        # Check both senders
        assert p.check(b"A", 0, 5) is True
        assert p.check(b"B", 0, 5) is True
        # Commit only A
        p.commit(b"A", 0, 5)
        # A is now seen, B is still fresh
        assert p.check(b"A", 0, 5) is False
        assert p.check(b"B", 0, 5) is True

    def test_validation_failure_prevents_floor_commitment(self) -> None:
        """If validation fails after check(), floor should NOT be committed."""
        p = ReplayProtector()
        # Check passes but "validation fails"
        assert p.check(b"sender", 0, 100) is True
        # No commit - simulate validation failure
        # Same frame arrives again, should still be accepted
        assert p.check(b"sender", 0, 100) is True
        # This time validation passes
        p.commit(b"sender", 0, 100)
        # Now it's seen
        assert p.check(b"sender", 0, 100) is False


class TestThreadSafetyReplayWindow:
    """Tests for thread safety of ReplayWindow.check_and_update().

    The TOCTOU race condition: without proper locking, two threads could
    both pass check() for the same counter before either commits, causing
    duplicate acceptance. These tests verify the fix.
    """

    def test_concurrent_check_and_update_only_one_succeeds(self) -> None:
        """Multiple threads calling check_and_update with same counter.

        Only one thread should succeed; others should get False (replay).
        This is the core test for the TOCTOU fix.
        """
        import threading
        from collections import Counter

        w = ReplayWindow()
        results: list[bool] = []
        lock = threading.Lock()

        def try_update() -> None:
            result = w.check_and_update(0, 100)
            with lock:
                results.append(result)

        # Launch 10 threads all trying to accept the same counter
        threads = [threading.Thread(target=try_update) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one thread should succeed
        counts = Counter(results)
        assert counts[True] == 1, f"Expected exactly 1 True, got {counts}"
        assert counts[False] == 9, f"Expected 9 False, got {counts}"

    def test_concurrent_different_counters_all_succeed(self) -> None:
        """Multiple threads with different counters should all succeed."""
        import threading

        w = ReplayWindow()
        results: dict[int, bool] = {}
        lock = threading.Lock()

        def try_update(seqnum: int) -> None:
            result = w.check_and_update(0, seqnum)
            with lock:
                results[seqnum] = result

        # Launch threads with different sequence numbers
        threads = [threading.Thread(target=try_update, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed (different counters)
        assert all(results.values()), f"Expected all True, got {results}"


class TestThreadSafetyReplayProtector:
    """Tests for thread safety of ReplayProtector.check_and_update().

    Tests both per-sender atomicity and cross-sender isolation.
    """

    def test_concurrent_same_sender_same_counter_only_one_succeeds(self) -> None:
        """Multiple threads calling check_and_update for same sender/counter.

        Only one thread should succeed; this tests the TOCTOU fix at the
        ReplayProtector level (which also acquires its own lock for window
        table access).
        """
        import threading
        from collections import Counter

        p = ReplayProtector()
        results: list[bool] = []
        lock = threading.Lock()

        def try_update() -> None:
            result = p.check_and_update(b"sender", 0, 100)
            with lock:
                results.append(result)

        threads = [threading.Thread(target=try_update) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        counts = Counter(results)
        assert counts[True] == 1, f"Expected exactly 1 True, got {counts}"
        assert counts[False] == 9, f"Expected 9 False, got {counts}"

    def test_concurrent_different_senders_all_succeed(self) -> None:
        """Multiple threads with different senders should all succeed."""
        import threading

        p = ReplayProtector()
        results: dict[bytes, bool] = {}
        lock = threading.Lock()

        def try_update(sender: bytes) -> None:
            result = p.check_and_update(sender, 0, 100)
            with lock:
                results[sender] = result

        senders = [f"sender{i}".encode() for i in range(10)]
        threads = [threading.Thread(target=try_update, args=(s,)) for s in senders]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results.values()), f"Expected all True, got {results}"

    def test_concurrent_window_creation_no_race(self) -> None:
        """Concurrent first-contact from same sender creates exactly one window."""
        import threading

        p = ReplayProtector()
        results: list[bool] = []
        lock = threading.Lock()

        def first_contact(seqnum: int) -> None:
            # All threads try to be the "first contact" for same sender
            result = p.check_and_update(b"new-sender", 0, seqnum)
            with lock:
                results.append(result)

        # Launch threads with sequential sequence numbers
        threads = [threading.Thread(target=first_contact, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All should succeed since they have different sequence numbers
        # This verifies no race in window creation
        assert all(results), f"Expected all True, got {results}"
