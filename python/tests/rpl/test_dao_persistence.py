# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for crash-safe DAO persistence (spec section 8.6)."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.rpl.dao_manager import DaoManager
from lichen.rpl.dao_persistence import (
    DaoPersistenceError,
    MemoryPersistence,
    TwoSlotFilePersistence,
    compute_dao_digest,
)

ROOT = IPv6Address("fd00::1")
N1 = IPv6Address("fd00::11")
N2 = IPv6Address("fd00::12")

TEST_PUBKEY = bytes(32)  # 32 zero bytes for testing
TEST_DAO_BYTES = b"test dao bytes for persistence"


class TestMemoryPersistence:
    """Tests for in-memory persistence (non-crash-safe, for testing)."""

    def test_is_not_crash_safe(self) -> None:
        """MemoryPersistence explicitly reports it is NOT crash-safe."""
        persistence = MemoryPersistence()
        assert persistence.is_crash_safe is False

    def test_does_not_fail_closed(self) -> None:
        """MemoryPersistence explicitly reports it does NOT fail closed."""
        persistence = MemoryPersistence()
        assert persistence.fails_closed is False

    def test_tx_state_store_and_load(self) -> None:
        persistence = MemoryPersistence()
        assert persistence.load_tx_state() is None

        persistence.store_tx_state(42, b"dao bytes")
        state = persistence.load_tx_state()

        assert state is not None
        assert state.sequence == 42
        assert state.dao_bytes == b"dao bytes"

    def test_rx_floor_store_and_load(self) -> None:
        persistence = MemoryPersistence()
        digest = compute_dao_digest(b"test dao")
        assert persistence.load_rx_floor(TEST_PUBKEY) is None

        persistence.store_rx_floor(TEST_PUBKEY, 100, digest)
        floor = persistence.load_rx_floor(TEST_PUBKEY)

        assert floor is not None
        assert floor.sequence == 100
        assert floor.digest == digest

    def test_origin_replay_store_protocol(self) -> None:
        """MemoryPersistence implements OriginReplayStore protocol."""
        persistence = MemoryPersistence()
        digest = compute_dao_digest(b"test dao")

        # get_floor returns None initially
        assert persistence.get_floor(TEST_PUBKEY) is None

        # set_floor stores the floor
        persistence.set_floor(TEST_PUBKEY, 200, digest)
        result = persistence.get_floor(TEST_PUBKEY)

        assert result is not None
        assert result == (200, digest)

    def test_invalid_pubkey_length_rejected(self) -> None:
        """store_rx_floor rejects pubkeys that are not 16 or 32 bytes."""
        persistence = MemoryPersistence()
        digest = compute_dao_digest(b"test")

        with pytest.raises(ValueError, match="must be 16 or 32 bytes"):
            persistence.store_rx_floor(b"short", 1, digest)

        with pytest.raises(ValueError, match="must be 16 or 32 bytes"):
            persistence.store_rx_floor(b"x" * 64, 1, digest)

    def test_invalid_digest_length_rejected(self) -> None:
        """store_rx_floor rejects dao_digest that is not 64 bytes (SHA-512)."""
        persistence = MemoryPersistence()

        with pytest.raises(ValueError, match="must be 64 bytes"):
            persistence.store_rx_floor(TEST_PUBKEY, 1, b"short_digest")

        with pytest.raises(ValueError, match="must be 64 bytes"):
            persistence.store_rx_floor(TEST_PUBKEY, 1, b"x" * 32)

    def test_16_byte_pubkey_accepted(self) -> None:
        """IPv6 address (16 bytes) can be used as pubkey."""
        persistence = MemoryPersistence()
        digest = compute_dao_digest(b"test")
        key = N1.packed  # 16 bytes

        persistence.store_rx_floor(key, 50, digest)
        floor = persistence.load_rx_floor(key)

        assert floor is not None
        assert floor.sequence == 50


class TestTwoSlotFilePersistence:
    """Tests for crash-safe two-slot file persistence."""

    def test_is_crash_safe(self, tmp_path: Path) -> None:
        """TwoSlotFilePersistence explicitly reports it IS crash-safe."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        assert persistence.is_crash_safe is True

    def test_base_dir_is_file_raises(self, tmp_path: Path) -> None:
        """Init raises DaoPersistenceError if base_dir is an existing file.

        If base_dir points to a file instead of a directory, mkdir would fail
        with a confusing error. We detect this early and raise a clear error.
        """
        file_path = tmp_path / "some_file"
        file_path.write_bytes(b"not a directory")

        with pytest.raises(DaoPersistenceError, match="not a directory"):
            TwoSlotFilePersistence(file_path, fail_closed=False)

    def test_fails_closed_property(self, tmp_path: Path) -> None:
        """fails_closed property reflects the fail_closed constructor argument.

        Per spec section 8.6, fail-closed behavior is separate from crash-safe
        storage. A persistence backend can be crash-safe (durable storage) but
        not fail-closed (returns None on error for testing scenarios).
        """
        persistence_fail_closed = TwoSlotFilePersistence(tmp_path / "fc", fail_closed=True)
        persistence_fail_open = TwoSlotFilePersistence(tmp_path / "fo", fail_closed=False)

        assert persistence_fail_closed.fails_closed is True
        assert persistence_fail_open.fails_closed is False

        # Both are crash-safe regardless of fail_closed setting
        assert persistence_fail_closed.is_crash_safe is True
        assert persistence_fail_open.is_crash_safe is True

    def test_tx_state_survives_restart(self, tmp_path: Path) -> None:
        persistence1 = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        persistence1.store_tx_state(42, b"dao bytes")

        # Simulate restart by creating new instance
        persistence2 = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        state = persistence2.load_tx_state()

        assert state is not None
        assert state.sequence == 42
        assert state.dao_bytes == b"dao bytes"

    def test_rx_floor_survives_restart(self, tmp_path: Path) -> None:
        digest = compute_dao_digest(b"test dao")
        persistence1 = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        persistence1.store_rx_floor(TEST_PUBKEY, 100, digest)

        # Simulate restart
        persistence2 = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        floor = persistence2.load_rx_floor(TEST_PUBKEY)

        assert floor is not None
        assert floor.sequence == 100
        assert floor.digest == digest

    def test_two_slot_alternation(self, tmp_path: Path) -> None:
        """Verify slots alternate and newer generation wins."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)

        # Write first value
        persistence.store_tx_state(1, b"first")
        # Write second value (should go to other slot with higher gen)
        persistence.store_tx_state(2, b"second")
        # Write third value (should go back to first slot with highest gen)
        persistence.store_tx_state(3, b"third")

        state = persistence.load_tx_state()
        assert state is not None
        assert state.sequence == 3
        assert state.dao_bytes == b"third"

    def test_corrupt_slot_falls_back_to_other(self, tmp_path: Path) -> None:
        """If one slot is corrupt, the other valid slot is used.

        Per spec section 8.6: "use two independently validated slots with
        generation numbers so interruption cannot expose a partially written
        record." When the newer slot is corrupt, we must fall back to the
        older but still valid slot.
        """
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)

        # Write twice to populate both slots with known values:
        # - First write: slot0 gets gen=1, seq=10, payload="ten"
        # - Second write: slot1 gets gen=2, seq=20, payload="twenty"
        persistence.store_tx_state(10, b"ten")
        persistence.store_tx_state(20, b"twenty")

        # Verify initial state: should return newer slot (slot1, gen=2)
        state = persistence.load_tx_state()
        assert state is not None
        assert state.sequence == 20
        assert state.dao_bytes == b"twenty"

        # Now corrupt the NEWER slot (slot1) to test fallback
        slot1_path = tmp_path / "dao_tx_1.bin"
        with open(slot1_path, "wb") as f:
            f.write(b"corrupted data")

        # Create fresh persistence instance (simulates restart)
        persistence2 = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        state = persistence2.load_tx_state()

        # Should fall back to the older but valid slot (slot0)
        assert state is not None
        assert state.sequence == 10
        assert state.dao_bytes == b"ten"

    def test_both_slots_corrupt_fails_closed(self, tmp_path: Path) -> None:
        """If both slots are corrupt, fail_closed raises."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)
        persistence.store_tx_state(1, b"data")

        # Corrupt both slots
        for slot_path in tmp_path.glob("dao_tx_*.bin"):
            with open(slot_path, "wb") as f:
                f.write(b"corrupted")

        persistence2 = TwoSlotFilePersistence(tmp_path, fail_closed=True)
        with pytest.raises(DaoPersistenceError, match="TX state corrupt"):
            persistence2.load_tx_state()

    def test_missing_state_returns_none_when_not_fail_closed(self, tmp_path: Path) -> None:
        """Missing state returns None when fail_closed=False."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        assert persistence.load_tx_state() is None
        assert persistence.load_rx_floor(TEST_PUBKEY) is None

    def test_16_byte_key_accepted(self, tmp_path: Path) -> None:
        """IPv6 address (16 bytes) can be used as key."""
        digest = compute_dao_digest(b"test")
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        key = N1.packed  # 16 bytes

        persistence.store_rx_floor(key, 50, digest)
        floor = persistence.load_rx_floor(key)

        assert floor is not None
        assert floor.sequence == 50

    def test_invalid_key_length_rejected(self, tmp_path: Path) -> None:
        """Keys must be 16 or 32 bytes."""
        digest = compute_dao_digest(b"test")
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)

        with pytest.raises(ValueError, match="must be 16 or 32 bytes"):
            persistence.store_rx_floor(b"short", 1, digest)

        with pytest.raises(ValueError, match="must be 16 or 32 bytes"):
            persistence.load_rx_floor(b"short")

    def test_get_floor_fails_closed_on_corrupt_state(self, tmp_path: Path) -> None:
        """get_floor raises DaoPersistenceError when fail_closed=True and state is corrupt.

        Per spec section 8.6: "Missing, corrupt, or unavailable receive state
        MUST fail closed." The OriginReplayStore.get_floor() method must propagate
        DaoPersistenceError rather than returning None to ensure fail-closed behavior.
        """
        digest = compute_dao_digest(b"test dao")
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)

        # Store valid floor data
        persistence.store_rx_floor(TEST_PUBKEY, 100, digest)

        # Verify get_floor works initially
        result = persistence.get_floor(TEST_PUBKEY)
        assert result == (100, digest)

        # Corrupt both RX slots for this pubkey
        key_hex = TEST_PUBKEY.hex()
        for slot in [0, 1]:
            slot_path = tmp_path / f"dao_rx_{key_hex}_{slot}.bin"
            if slot_path.exists():
                with open(slot_path, "wb") as f:
                    f.write(b"corrupted")

        # Create new persistence instance (simulates restart)
        persistence2 = TwoSlotFilePersistence(tmp_path, fail_closed=True)

        # SECURITY: get_floor must raise, not return None, to fail closed
        with pytest.raises(DaoPersistenceError, match="RX floor corrupt"):
            persistence2.get_floor(TEST_PUBKEY)

    def test_get_floor_returns_none_on_corrupt_state_when_not_fail_closed(
        self, tmp_path: Path
    ) -> None:
        """get_floor returns None when fail_closed=False and state is corrupt.

        When fail_closed=False, corrupt state falls back to None (for testing).
        """
        digest = compute_dao_digest(b"test dao")
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)

        # Store valid floor data
        persistence.store_rx_floor(TEST_PUBKEY, 100, digest)

        # Corrupt both RX slots for this pubkey
        key_hex = TEST_PUBKEY.hex()
        for slot in [0, 1]:
            slot_path = tmp_path / f"dao_rx_{key_hex}_{slot}.bin"
            if slot_path.exists():
                with open(slot_path, "wb") as f:
                    f.write(b"corrupted")

        # Create new persistence instance
        persistence2 = TwoSlotFilePersistence(tmp_path, fail_closed=False)

        # Should return None (not raise) when fail_closed=False
        result = persistence2.get_floor(TEST_PUBKEY)
        assert result is None

    def test_concurrent_writes_no_data_loss(self, tmp_path: Path) -> None:
        """Concurrent writes must not lose data due to TOCTOU race.

        Without locking, concurrent writers could both read the same slot state,
        both determine the same slot is "older", both compute the same generation,
        and one write would silently overwrite the other. The lock in
        _write_to_older_slot prevents this race condition.
        """
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        num_writers = 10
        writes_per_thread = 50
        barrier = threading.Barrier(num_writers)
        results: list[int] = []
        results_lock = threading.Lock()

        def writer(thread_id: int) -> None:
            # Wait for all threads to be ready, then all start writing together
            barrier.wait()
            for i in range(writes_per_thread):
                seq = thread_id * 1000 + i
                persistence.store_tx_state(seq, f"thread{thread_id}_write{i}".encode())
                with results_lock:
                    results.append(seq)

        # Run concurrent writers
        with ThreadPoolExecutor(max_workers=num_writers) as executor:
            futures = [executor.submit(writer, tid) for tid in range(num_writers)]
            for f in futures:
                f.result()  # Raise any exceptions

        # All writes completed
        assert len(results) == num_writers * writes_per_thread

        # The final state must be one of the written values (not corrupted)
        state = persistence.load_tx_state()
        assert state is not None
        assert state.sequence in results

        # Verify alternation still works: both slots should have valid data
        # after many writes. Read raw slots to verify.
        slot0 = persistence._read_slot(tmp_path / "dao_tx_0.bin")
        slot1 = persistence._read_slot(tmp_path / "dao_tx_1.bin")

        # At least one slot must be valid
        assert slot0 is not None or slot1 is not None

        # If both are valid, generations should differ by 1 (alternation)
        if slot0 is not None and slot1 is not None:
            gen0, gen1 = slot0[0], slot1[0]
            assert abs(gen0 - gen1) == 1, f"Generations {gen0}, {gen1} should differ by 1"

    def test_concurrent_rx_floor_writes_no_data_loss(self, tmp_path: Path) -> None:
        """Concurrent RX floor writes must not lose data.

        Tests the same race condition fix for store_rx_floor.
        """
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        num_writers = 10
        writes_per_thread = 50
        barrier = threading.Barrier(num_writers)
        results: list[int] = []
        results_lock = threading.Lock()

        def writer(thread_id: int) -> None:
            barrier.wait()
            for i in range(writes_per_thread):
                seq = thread_id * 1000 + i
                digest = compute_dao_digest(f"thread{thread_id}_write{i}".encode())
                persistence.store_rx_floor(TEST_PUBKEY, seq, digest)
                with results_lock:
                    results.append(seq)

        with ThreadPoolExecutor(max_workers=num_writers) as executor:
            futures = [executor.submit(writer, tid) for tid in range(num_writers)]
            for f in futures:
                f.result()

        assert len(results) == num_writers * writes_per_thread

        floor = persistence.load_rx_floor(TEST_PUBKEY)
        assert floor is not None
        assert floor.sequence in results


class TestDaoManagerWithPersistence:
    """Tests for DaoManager integration with persistence."""

    def test_build_dao_persists_before_return(self, tmp_path: Path) -> None:
        """build_dao persists state before returning."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            persistence=persistence,
        )

        manager.build_dao(ROOT)  # Triggers persistence

        # Check persistence has the state
        state = persistence.load_tx_state()
        assert state is not None
        assert state.sequence == manager._path_sequence
        assert len(state.dao_bytes) > 0

    def test_manager_restores_state_from_persistence(self, tmp_path: Path) -> None:
        """DaoManager restores sequence from persistence on init."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        manager1 = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            persistence=persistence,
        )

        # Build some DAOs to advance sequence
        manager1.build_dao(ROOT)
        manager1.build_dao(ROOT)
        seq_after = manager1._path_sequence

        # Simulate restart
        manager2 = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            persistence=persistence,
        )

        # Sequence should be restored
        assert manager2._path_sequence >= seq_after - 1

    def test_get_last_dao_bytes_returns_persisted_bytes(self, tmp_path: Path) -> None:
        """get_last_dao_bytes returns persisted DAO for retransmission."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            persistence=persistence,
        )

        dao = manager.build_dao(ROOT)
        last_bytes = manager.get_last_dao_bytes()

        assert last_bytes is not None
        assert last_bytes == dao.to_bytes()

    def test_process_dao_persists_rx_floor(self, tmp_path: Path) -> None:
        """Root persists RX floor before accepting DAO."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        root = DaoManager(
            node_address=ROOT,
            is_root=True,
            persistence=persistence,
        )

        # Build and process a DAO from N1
        node1 = DaoManager(node_address=N1, dodag_id=ROOT)
        dao = node1.build_dao(ROOT)
        root.process_dao(dao)

        # Check RX floor was persisted (keyed by target address)
        floor = persistence.load_rx_floor(N1.packed)
        assert floor is not None
        assert floor.sequence > 0

    def test_rx_floor_survives_root_restart(self, tmp_path: Path) -> None:
        """RX floor persists across root restarts."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)

        # First root instance accepts DAO
        root1 = DaoManager(
            node_address=ROOT,
            is_root=True,
            persistence=persistence,
        )
        node1 = DaoManager(node_address=N1, dodag_id=ROOT)
        dao = node1.build_dao(ROOT)
        root1.process_dao(dao)

        floor_before = persistence.load_rx_floor(N1.packed)
        assert floor_before is not None

        # Simulate restart - create new root instance (unused, but shows restart scenario)
        DaoManager(
            node_address=ROOT,
            is_root=True,
            persistence=persistence,
        )

        # Floor should still be readable via persistence
        floor_after = persistence.load_rx_floor(N1.packed)
        assert floor_after is not None
        assert floor_after.sequence == floor_before.sequence


class TestComputeDaoDigest:
    """Tests for DAO digest computation."""

    def test_digest_is_sha512(self) -> None:
        """Digest uses SHA-512 (64 bytes)."""
        digest = compute_dao_digest(b"test data")
        assert len(digest) == 64

    def test_digest_is_deterministic(self) -> None:
        """Same input produces same digest."""
        data = b"test data for hashing"
        digest1 = compute_dao_digest(data)
        digest2 = compute_dao_digest(data)
        assert digest1 == digest2

    def test_digest_differs_for_different_input(self) -> None:
        """Different inputs produce different digests."""
        digest1 = compute_dao_digest(b"data1")
        digest2 = compute_dao_digest(b"data2")
        assert digest1 != digest2


class TestRequireCrashSafety:
    """Tests for spec 8.6 crash-safety enforcement.

    Per spec section 8.6:
    - TX: "the origin MUST crash-safely commit the greater sequence and complete
      signed DAO bytes before transmission"
    - RX: "Missing, corrupt, or unavailable receive state MUST fail closed"

    When require_crash_safety=True, operations fail if persistence is not configured.
    """

    def test_init_fails_without_persistence_when_required(self) -> None:
        """DaoManager init fails when require_crash_safety=True but no persistence."""
        from lichen.rpl.dao_types import DaoError

        with pytest.raises(DaoError, match="crash-safe persistence required"):
            DaoManager(
                node_address=N1,
                dodag_id=ROOT,
                require_crash_safety=True,
                persistence=None,
            )

    def test_init_succeeds_with_persistence_when_required(self, tmp_path: Path) -> None:
        """DaoManager init succeeds when crash-safe, fail-closed persistence is configured.

        Per spec section 8.6, require_crash_safety=True requires both:
        - Crash-safe storage (two-slot or atomic commit)
        - Fail-closed behavior (raises on missing/corrupt state)
        """
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=True,
            persistence=persistence,
        )
        assert manager.require_crash_safety is True

    def test_build_dao_fails_without_persistence_when_required(self) -> None:
        """build_dao fails when require_crash_safety=True but no persistence.

        This is a defense-in-depth check for cases where require_crash_safety
        might be set after init.
        """
        from lichen.rpl.dao_types import DaoError

        # Create manager without enforcement, then enable it
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=False,
            persistence=None,
        )
        # Simulate someone enabling crash safety after init
        manager.require_crash_safety = True

        with pytest.raises(DaoError, match="crash-safe persistence required"):
            manager.build_dao(ROOT)

    def test_process_dao_fails_without_persistence_when_required(self) -> None:
        """process_dao fails when require_crash_safety=True but no persistence."""
        from lichen.rpl.dao_types import DaoError

        # Create root without enforcement
        root = DaoManager(
            node_address=ROOT,
            is_root=True,
            require_crash_safety=False,
            persistence=None,
        )
        # Simulate enabling crash safety after init
        root.require_crash_safety = True

        # Build a DAO from a node
        node = DaoManager(node_address=N1, dodag_id=ROOT)
        dao = node.build_dao(ROOT)

        with pytest.raises(DaoError, match="crash-safe persistence required"):
            root.process_dao(dao)

    def test_memory_persistence_allowed_when_not_required(self) -> None:
        """MemoryPersistence works when crash safety is not required.

        This confirms backward compatibility for testing scenarios.
        """
        persistence = MemoryPersistence()
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=False,
            persistence=persistence,
        )

        # Should work without errors
        dao = manager.build_dao(ROOT)
        assert dao is not None

    def test_init_fails_with_non_crash_safe_persistence_when_required(self) -> None:
        """DaoManager init fails when require_crash_safety=True but persistence is not crash-safe.

        Per spec section 8.6, crash-safe persistence requires atomic commit semantics
        or two independently validated slots. MemoryPersistence is NOT crash-safe.
        """
        from lichen.rpl.dao_types import DaoError

        persistence = MemoryPersistence()
        with pytest.raises(DaoError, match="persistence backend is not crash-safe"):
            DaoManager(
                node_address=N1,
                dodag_id=ROOT,
                require_crash_safety=True,
                persistence=persistence,
            )

    def test_init_fails_with_non_fail_closed_persistence_when_required(
        self, tmp_path: Path
    ) -> None:
        """DaoManager init fails when require_crash_safety=True but not fail-closed.

        Per spec section 8.6: "Missing, corrupt, or unavailable receive state MUST
        fail closed." A persistence backend that returns None on corrupt state
        (fail_closed=False) does NOT satisfy this requirement.

        This is separate from crash-safe storage: TwoSlotFilePersistence is crash-safe
        (uses two slots with generation numbers), but fail_closed=False means it
        returns None instead of raising on corrupt state.
        """
        from lichen.rpl.dao_types import DaoError

        # Crash-safe but NOT fail-closed
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)

        with pytest.raises(DaoError, match="persistence backend does not fail closed"):
            DaoManager(
                node_address=N1,
                dodag_id=ROOT,
                require_crash_safety=True,
                persistence=persistence,
            )

    def test_build_dao_fails_with_non_fail_closed_persistence_when_required(
        self, tmp_path: Path
    ) -> None:
        """build_dao fails when require_crash_safety=True but persistence does not fail closed.

        Defense-in-depth check for cases where require_crash_safety is set after init.
        """
        from lichen.rpl.dao_types import DaoError

        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=False,
            persistence=persistence,
        )
        # Simulate enabling crash safety after init
        manager.require_crash_safety = True

        with pytest.raises(DaoError, match="persistence backend does not fail closed"):
            manager.build_dao(ROOT)

    def test_process_dao_fails_with_non_fail_closed_persistence_when_required(
        self, tmp_path: Path
    ) -> None:
        """process_dao fails when require_crash_safety=True but persistence does not fail closed."""
        from lichen.rpl.dao_types import DaoError

        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        root = DaoManager(
            node_address=ROOT,
            is_root=True,
            require_crash_safety=False,
            persistence=persistence,
        )
        # Simulate enabling crash safety after init
        root.require_crash_safety = True

        # Build a DAO from a node
        node = DaoManager(node_address=N1, dodag_id=ROOT)
        dao = node.build_dao(ROOT)

        with pytest.raises(DaoError, match="persistence backend does not fail closed"):
            root.process_dao(dao)

    def test_build_dao_fails_with_non_crash_safe_persistence_when_required(self) -> None:
        """build_dao fails when require_crash_safety=True but persistence is not crash-safe.

        This is a defense-in-depth check for cases where require_crash_safety
        might be set after init.
        """
        from lichen.rpl.dao_types import DaoError

        persistence = MemoryPersistence()
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=False,
            persistence=persistence,
        )
        # Simulate enabling crash safety after init
        manager.require_crash_safety = True

        with pytest.raises(DaoError, match="persistence backend is not crash-safe"):
            manager.build_dao(ROOT)

    def test_process_dao_fails_with_non_crash_safe_persistence_when_required(self) -> None:
        """process_dao fails when require_crash_safety=True but persistence is not crash-safe."""
        from lichen.rpl.dao_types import DaoError

        persistence = MemoryPersistence()
        root = DaoManager(
            node_address=ROOT,
            is_root=True,
            require_crash_safety=False,
            persistence=persistence,
        )
        # Simulate enabling crash safety after init
        root.require_crash_safety = True

        # Build a DAO from a node
        node = DaoManager(node_address=N1, dodag_id=ROOT)
        dao = node.build_dao(ROOT)

        with pytest.raises(DaoError, match="persistence backend is not crash-safe"):
            root.process_dao(dao)

    def test_crash_safe_persistence_with_enforcement(self, tmp_path: Path) -> None:
        """Full workflow works with crash-safe, fail-closed persistence and enforcement."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=True,
            persistence=persistence,
        )

        # Build DAO should persist and succeed
        dao = manager.build_dao(ROOT)
        assert dao is not None

        # State should be persisted
        state = persistence.load_tx_state()
        assert state is not None
        assert state.sequence == manager._path_sequence

    def test_root_crash_safe_persistence_with_enforcement(self, tmp_path: Path) -> None:
        """Root process_dao works with crash-safe, fail-closed persistence and enforcement."""
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)
        root = DaoManager(
            node_address=ROOT,
            is_root=True,
            require_crash_safety=True,
            persistence=persistence,
        )

        # Build a DAO from a node (without enforcement for simplicity)
        node = DaoManager(node_address=N1, dodag_id=ROOT)
        dao = node.build_dao(ROOT)

        # Root should accept and persist
        root.process_dao(dao)

        # RX floor should be persisted
        floor = persistence.load_rx_floor(N1.packed)
        assert floor is not None

    def test_init_fails_on_corrupt_tx_state_when_required(self, tmp_path: Path) -> None:
        """DaoManager init fails when require_crash_safety=True and TX state is corrupt.

        Per spec section 8.6: "Missing, corrupt, or unavailable state is a hard
        failure: the origin MUST NOT transmit until valid state is restored."
        """
        from lichen.rpl.dao_types import DaoError

        # First, create valid TX state (without crash safety requirement so fresh state works)
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=False)
        manager = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=False,
            persistence=persistence,
        )
        manager.build_dao(ROOT)  # Persist some TX state

        # Verify state was persisted
        assert persistence.load_tx_state() is not None

        # Corrupt both TX slots
        for slot_path in tmp_path.glob("dao_tx_*.bin"):
            with open(slot_path, "wb") as f:
                f.write(b"corrupted")

        # Creating new manager with require_crash_safety=True should fail
        with pytest.raises(DaoError, match="TX state corrupt or unavailable"):
            DaoManager(
                node_address=N1,
                dodag_id=ROOT,
                require_crash_safety=True,
                persistence=TwoSlotFilePersistence(tmp_path, fail_closed=True),
            )

    def test_init_succeeds_on_corrupt_tx_state_when_not_required(
        self, tmp_path: Path
    ) -> None:
        """DaoManager init succeeds when require_crash_safety=False and TX state is corrupt.

        Without crash safety enforcement, corrupt state falls back to defaults.
        Per spec section 8.6, missing/corrupt state is a hard failure only when
        crash safety is required. When not required, the exception is caught and
        the manager falls back to default sequence values.

        This test uses fail_closed=True to ensure DaoPersistenceError is raised
        (testing the exception-handling path in _restore_tx_state), rather than
        fail_closed=False which would return None without raising.
        """
        # First, create valid TX state
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)
        manager1 = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=False,
            persistence=persistence,
        )
        manager1.build_dao(ROOT)  # Persist some TX state

        # Verify state was persisted with sequence > 240
        state = persistence.load_tx_state()
        assert state is not None
        assert state.sequence > 240

        # Corrupt both TX slots
        for slot_path in tmp_path.glob("dao_tx_*.bin"):
            with open(slot_path, "wb") as f:
                f.write(b"corrupted")

        # Creating new manager with require_crash_safety=False should succeed
        # even with fail_closed=True persistence, because the manager catches
        # the DaoPersistenceError and falls back to default sequence.
        manager2 = DaoManager(
            node_address=N1,
            dodag_id=ROOT,
            require_crash_safety=False,
            persistence=TwoSlotFilePersistence(tmp_path, fail_closed=True),
        )
        # Should have default sequence (240) because corrupt state was caught.
        # Per spec 8.6, _restore_tx_state sets both _dao_sequence and _path_sequence
        # from persisted state; on fallback, both must remain at their defaults.
        assert manager2._dao_sequence == 240
        assert manager2._path_sequence == 240
        # Per spec 8.6, the TX API must expose the exact retained bytes after reboot.
        # When no valid state is restored, _last_dao_bytes must be None.
        assert manager2._last_dao_bytes is None

    def test_init_fails_with_non_crash_safe_replay_store_when_required(
        self, tmp_path: Path
    ) -> None:
        """DaoManager init fails when require_crash_safety=True but replay_store is not crash-safe.

        Per spec section 8.6, the origin validator's replay_store must be crash-safe
        when crash-safety is required. A non-crash-safe store (e.g., MemoryPersistence)
        would lose replay floors on restart, allowing replay attacks.
        """
        from lichen.rpl.dao_origin import DaoOriginValidator
        from lichen.rpl.dao_types import DaoError

        # Create a mock pin table for the validator
        class MockPinTable:
            def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
                return None

        # Use MemoryPersistence as replay_store (NOT crash-safe)
        memory_store = MemoryPersistence()
        # Use TwoSlotFilePersistence as persistence (crash-safe, fail-closed)
        file_persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)

        validator = DaoOriginValidator(
            pin_table=MockPinTable(),
            replay_store=memory_store,  # Different from persistence!
        )

        # Should fail because replay_store is not the same object as persistence
        with pytest.raises(DaoError, match="replay_store.*different objects"):
            DaoManager(
                node_address=ROOT,
                is_root=True,
                require_crash_safety=True,
                persistence=file_persistence,
                origin_validator=validator,
            )

    def test_init_succeeds_with_same_crash_safe_replay_store_when_required(
        self, tmp_path: Path
    ) -> None:
        """DaoManager init succeeds when replay_store is the same crash-safe persistence.

        Per spec section 8.6, the replay_store must be the same object as persistence
        to ensure read/write consistency for replay floors.
        """
        from lichen.rpl.dao_origin import DaoOriginValidator

        class MockPinTable:
            def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
                return None

        # Use the same crash-safe, fail-closed persistence for both
        persistence = TwoSlotFilePersistence(tmp_path, fail_closed=True)

        validator = DaoOriginValidator(
            pin_table=MockPinTable(),
            replay_store=persistence,  # Same object as persistence!
        )

        # Should succeed because both are the same crash-safe, fail-closed object
        manager = DaoManager(
            node_address=ROOT,
            is_root=True,
            require_crash_safety=True,
            persistence=persistence,
            origin_validator=validator,
        )
        assert manager.require_crash_safety is True

    def test_different_replay_store_rejected_even_when_crash_safety_not_required(self) -> None:
        """Different replay_store is ALWAYS rejected (spec 8.6 consistency).

        Per spec section 8.6, the replay_store and persistence must be the same
        object to prevent split-brain state where validation checks one store
        but commits write to another. This is a correctness issue that applies
        regardless of crash safety requirements.
        """
        from lichen.rpl.dao_origin import DaoOriginValidator
        from lichen.rpl.dao_types import DaoError

        class MockPinTable:
            def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
                return None

        class MockReplayStore:
            def get_floor(self, pubkey: bytes) -> tuple[int, bytes] | None:
                return None

            def set_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
                pass

        # Different objects for persistence and replay_store
        persistence = MemoryPersistence()
        replay_store = MockReplayStore()

        validator = DaoOriginValidator(
            pin_table=MockPinTable(),
            replay_store=replay_store,
        )

        # Should fail because replay_store must be same as persistence for consistency
        with pytest.raises(DaoError, match="replay_store.*different objects"):
            DaoManager(
                node_address=ROOT,
                is_root=True,
                require_crash_safety=False,
                persistence=persistence,
                origin_validator=validator,
            )
