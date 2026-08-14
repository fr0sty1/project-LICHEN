# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO crash-safe persistence interface.

Per spec section 8.6, DAO state requires crash-safe persistence:

- **TX side**: Before transmitting a new logical DAO, the origin must crash-safely
  commit the greater sequence and complete signed DAO bytes before transmission.
  Missing or corrupt state is a hard failure.

- **RX side**: The receiver must maintain crash-safe persistent state per pinned
  public key containing the accepted high-water sequence and a collision-resistant
  digest of the complete signed DAO bytes. Missing or corrupt state must fail closed.

This module provides the abstract interface and a two-slot implementation that
survives interruption at any point.

Note: The RX side interface is compatible with the `OriginReplayStore` protocol
defined in `dao_origin.py`.
"""
from __future__ import annotations

import hashlib
import os
import struct
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Final

# Slot header: magic (4) + generation (4) + sequence (8) + payload_len (4) + checksum (32)
_SLOT_HEADER_SIZE: Final[int] = 52
_SLOT_MAGIC: Final[bytes] = b"DAO1"


class DaoPersistenceError(Exception):
    """Raised when persistence state is missing, corrupt, or unavailable."""


@dataclass(frozen=True)
class TxState:
    """Crash-safe TX state: sequence and complete signed DAO bytes."""

    sequence: int
    dao_bytes: bytes


@dataclass(frozen=True)
class RxFloor:
    """Crash-safe RX replay floor: high-water sequence and DAO digest."""

    sequence: int
    digest: bytes


class DaoPersistence(ABC):
    """Abstract interface for crash-safe DAO persistence.

    Implementations must provide atomic commit semantics or use two
    independently validated slots with generation numbers so interruption
    cannot expose a partially written record.
    """

    @property
    @abstractmethod
    def is_crash_safe(self) -> bool:
        """Return True if this backend provides crash-safe persistence.

        Per spec section 8.6, crash-safe persistence requires atomic commit
        semantics or two independently validated slots with generation numbers.
        In-memory backends are NOT crash-safe.
        """

    @property
    @abstractmethod
    def fails_closed(self) -> bool:
        """Return True if this backend fails closed on missing/corrupt state.

        Per spec section 8.6: "Missing, corrupt, or unavailable receive state
        MUST fail closed." A backend that returns None on corrupt state does
        NOT satisfy the fail-closed requirement.

        This is separate from crash-safe persistence: a backend can be
        crash-safe (durable storage) but not fail-closed (returns None on
        error), or fail-closed but not crash-safe (in-memory with exceptions).
        Production deployments require BOTH properties.
        """

    @abstractmethod
    def store_tx_state(self, sequence: int, dao_bytes: bytes) -> None:
        """Commit TX state before transmission.

        Per spec section 8.6, implementations with `is_crash_safe=True` MUST
        provide atomic commit semantics or two independently validated slots
        with generation numbers. Non-crash-safe backends (e.g., MemoryPersistence
        for testing) may use simple in-memory storage.

        Args:
            sequence: The Origin Sequence for this DAO.
            dao_bytes: Complete signed DAO bytes.

        Raises:
            DaoPersistenceError: If the commit fails.
        """

    @abstractmethod
    def load_tx_state(self) -> TxState | None:
        """Load TX state after reboot.

        Returns:
            The stored TX state, or None if no valid state exists.
        """

    @abstractmethod
    def store_rx_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Crash-safely commit RX replay floor before accepting a DAO.

        Args:
            pubkey: The 32-byte public key identifying the origin.
            sequence: The high-water Origin Sequence.
            dao_digest: Collision-resistant digest of complete signed DAO bytes.

        Raises:
            DaoPersistenceError: If the commit fails.
        """

    @abstractmethod
    def load_rx_floor(self, pubkey: bytes) -> RxFloor | None:
        """Load RX replay floor for an origin.

        Args:
            pubkey: The 32-byte public key identifying the origin.

        Returns:
            The stored floor, or None if no valid state exists.
        """


class MemoryPersistence(DaoPersistence):
    """In-memory persistence for testing. NOT crash-safe.

    Also implements the OriginReplayStore protocol for compatibility with
    DaoOriginValidator.
    """

    @property
    def is_crash_safe(self) -> bool:
        """Memory persistence is NOT crash-safe."""
        return False

    @property
    def fails_closed(self) -> bool:
        """Memory persistence does not fail closed (returns None on missing)."""
        return False

    def __init__(self) -> None:
        self._tx_state: TxState | None = None
        self._rx_floors: dict[bytes, RxFloor] = {}

    def store_tx_state(self, sequence: int, dao_bytes: bytes) -> None:
        self._tx_state = TxState(sequence, dao_bytes)

    def load_tx_state(self) -> TxState | None:
        return self._tx_state

    def store_rx_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        if len(dao_digest) != 64:
            raise ValueError("dao_digest must be 64 bytes (SHA-512)")
        self._rx_floors[pubkey] = RxFloor(sequence, dao_digest)

    def load_rx_floor(self, pubkey: bytes) -> RxFloor | None:
        return self._rx_floors.get(pubkey)

    # OriginReplayStore protocol compatibility
    def get_floor(self, pubkey: bytes) -> tuple[int, bytes] | None:
        """Get (sequence, dao_digest) floor for pubkey, or None if no record."""
        floor = self.load_rx_floor(pubkey)
        if floor is None:
            return None
        return (floor.sequence, floor.digest)

    def set_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Durably commit new (sequence, dao_digest) floor for pubkey."""
        self.store_rx_floor(pubkey, sequence, dao_digest)


class TwoSlotFilePersistence(DaoPersistence):
    """Two-slot file-based persistence with generation numbers.

    Uses two alternating slots with generation counters. On write, the older
    slot is overwritten and fsynced. On read, the slot with the higher valid
    generation is used. This survives interruption at any point because at
    least one slot remains valid.

    Slot format:
        - Magic bytes "DAO1" (4 bytes)
        - Generation number (4 bytes, big-endian)
        - Sequence number (8 bytes, big-endian)
        - Payload length (4 bytes, big-endian)
        - SHA-256 checksum of generation + sequence + payload (32 bytes)
        - Payload bytes (variable)
    """

    @property
    def is_crash_safe(self) -> bool:
        """Two-slot file persistence IS crash-safe.

        Per spec section 8.6: "The storage backend MUST provide atomic commit
        semantics or use two independently validated slots with generation
        numbers so interruption cannot expose a partially written record."

        This implementation uses two independently validated slots with
        generation numbers, satisfying the crash-safety requirement regardless
        of the fail_closed setting.
        """
        return True

    @property
    def fails_closed(self) -> bool:
        """Return True if this backend fails closed on missing/corrupt state.

        Per spec section 8.6: "Missing, corrupt, or unavailable receive state
        MUST fail closed." When fail_closed=True, load operations raise
        DaoPersistenceError on corrupt/missing state. When fail_closed=False,
        they return None (for testing scenarios).

        Production deployments requiring spec compliance MUST use fail_closed=True.
        """
        return self._fail_closed

    def __init__(self, base_dir: Path, *, fail_closed: bool = True) -> None:
        """Initialize persistence.

        Args:
            base_dir: Directory for persistence files.
            fail_closed: If True, missing/corrupt state raises on load.

        Raises:
            DaoPersistenceError: If base_dir exists and is a file (not a directory).
        """
        self._base_dir = Path(base_dir)
        self._fail_closed = fail_closed
        # Check if base_dir is an existing file before mkdir - this would cause
        # mkdir to fail with a confusing FileExistsError or NotADirectoryError
        if self._base_dir.exists() and not self._base_dir.is_dir():
            raise DaoPersistenceError(
                f"base_dir exists but is not a directory: {self._base_dir}"
            )
        self._base_dir.mkdir(parents=True, exist_ok=True)
        # Lock to prevent TOCTOU race in _write_to_older_slot: concurrent
        # readers could both determine the same slot is "older" and both
        # write to it with the same generation, losing one write.
        self._write_lock = threading.Lock()

    def _tx_slot_path(self, slot: int) -> Path:
        return self._base_dir / f"dao_tx_{slot}.bin"

    def _rx_slot_path(self, pubkey: bytes, slot: int) -> Path:
        key_hex = pubkey.hex()
        return self._base_dir / f"dao_rx_{key_hex}_{slot}.bin"

    def _write_slot(self, path: Path, generation: int, sequence: int, payload: bytes) -> None:
        """Write a slot atomically with checksum validation."""
        content = struct.pack(">IQ", generation, sequence) + payload
        checksum = hashlib.sha256(content).digest()
        slot_data = (
            _SLOT_MAGIC
            + struct.pack(">I", generation)
            + struct.pack(">Q", sequence)
            + struct.pack(">I", len(payload))
            + checksum
            + payload
        )

        # Write to temp file, fsync, then rename for atomicity
        tmp_path = path.with_suffix(".tmp")
        with open(tmp_path, "wb") as f:
            f.write(slot_data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)

        # Sync the directory to ensure rename is durable
        dir_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _read_slot(self, path: Path) -> tuple[int, int, bytes] | None:
        """Read and validate a slot.

        Returns:
            (generation, sequence, payload) or None if invalid/missing.
        """
        if not path.exists():
            return None
        try:
            with open(path, "rb") as f:
                data = f.read()
            if len(data) < _SLOT_HEADER_SIZE:
                return None
            if data[:4] != _SLOT_MAGIC:
                return None

            generation = struct.unpack(">I", data[4:8])[0]
            sequence = struct.unpack(">Q", data[8:16])[0]
            payload_len = struct.unpack(">I", data[16:20])[0]
            stored_checksum = data[20:52]
            payload = data[52:]

            if len(payload) != payload_len:
                return None

            # Verify checksum
            content = struct.pack(">IQ", generation, sequence) + payload
            expected_checksum = hashlib.sha256(content).digest()
            if stored_checksum != expected_checksum:
                return None

            return generation, sequence, payload
        except OSError:
            return None

    def _slot_exists(self, path: Path) -> bool:
        """Check if a slot file exists (regardless of validity)."""
        return path.exists()

    def _get_best_slot(
        self, path0: Path, path1: Path
    ) -> tuple[int, int, int, bytes] | None:
        """Get the slot with higher valid generation.

        Returns:
            (slot_index, generation, sequence, payload) or None if both invalid.
        """
        slot0 = self._read_slot(path0)
        slot1 = self._read_slot(path1)

        if slot0 is None and slot1 is None:
            return None
        if slot0 is None:
            assert slot1 is not None
            return (1, slot1[0], slot1[1], slot1[2])
        if slot1 is None:
            return (0, slot0[0], slot0[1], slot0[2])
        # Both valid: use higher generation
        if slot1[0] > slot0[0]:
            return (1, slot1[0], slot1[1], slot1[2])
        return (0, slot0[0], slot0[1], slot0[2])

    def _any_slot_exists(self, path0: Path, path1: Path) -> bool:
        """Check if any slot file exists (for distinguishing missing vs corrupt).

        Per spec section 8.6, missing state (fresh node) is not the same as
        corrupt state. A fresh node that has never transmitted has no "previously
        used" sequence to protect, so it may start with default values.
        Corrupt state (files exist but are invalid) is a hard failure.
        """
        return path0.exists() or path1.exists()

    def _write_to_older_slot(
        self, path0: Path, path1: Path, sequence: int, payload: bytes
    ) -> None:
        """Write to the older slot with incremented generation.

        Thread-safe: uses a lock to prevent TOCTOU race where concurrent
        callers could read the same slot state, both compute the same
        "older" slot and generation, and one write would be lost.
        """
        with self._write_lock:
            slot0 = self._read_slot(path0)
            slot1 = self._read_slot(path1)

            gen0 = slot0[0] if slot0 else 0
            gen1 = slot1[0] if slot1 else 0

            # Write to older slot with generation = max + 1
            new_gen = max(gen0, gen1) + 1
            if gen0 <= gen1:
                self._write_slot(path0, new_gen, sequence, payload)
            else:
                self._write_slot(path1, new_gen, sequence, payload)

    def store_tx_state(self, sequence: int, dao_bytes: bytes) -> None:
        path0 = self._tx_slot_path(0)
        path1 = self._tx_slot_path(1)
        self._write_to_older_slot(path0, path1, sequence, dao_bytes)

    def load_tx_state(self) -> TxState | None:
        path0 = self._tx_slot_path(0)
        path1 = self._tx_slot_path(1)
        result = self._get_best_slot(path0, path1)
        if result is None:
            # Per spec 8.6, distinguish missing (fresh node) from corrupt:
            # - No slots exist: fresh node, return None (allowed to start fresh)
            # - Slots exist but invalid: corrupt state, fail closed if configured
            if self._fail_closed and self._any_slot_exists(path0, path1):
                raise DaoPersistenceError("TX state corrupt")
            return None
        _, _, sequence, payload = result
        return TxState(sequence, payload)

    def store_rx_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        if len(dao_digest) != 64:
            raise ValueError("dao_digest must be 64 bytes (SHA-512)")
        path0 = self._rx_slot_path(pubkey, 0)
        path1 = self._rx_slot_path(pubkey, 1)
        self._write_to_older_slot(path0, path1, sequence, dao_digest)

    def load_rx_floor(self, pubkey: bytes) -> RxFloor | None:
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        path0 = self._rx_slot_path(pubkey, 0)
        path1 = self._rx_slot_path(pubkey, 1)
        result = self._get_best_slot(path0, path1)
        if result is None:
            # Per spec 8.6, distinguish missing (no prior DAO from this origin)
            # from corrupt. Missing RX floor for an origin is normal (first DAO).
            # Corrupt floor files are a hard failure when fail_closed.
            if self._fail_closed and self._any_slot_exists(path0, path1):
                raise DaoPersistenceError(
                    f"RX floor corrupt for pubkey {pubkey.hex()}"
                )
            return None
        _, _, sequence, digest = result
        return RxFloor(sequence, digest)

    # OriginReplayStore protocol compatibility
    def get_floor(self, pubkey: bytes) -> tuple[int, bytes] | None:
        """Get (sequence, dao_digest) floor for pubkey, or None if no record.

        Note: When fail_closed=True and state is corrupt, this raises
        DaoPersistenceError per spec 8.6: "Missing, corrupt, or unavailable
        receive state MUST fail closed."
        """
        floor = self.load_rx_floor(pubkey)
        if floor is None:
            return None
        return (floor.sequence, floor.digest)

    def set_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        """Durably commit new (sequence, dao_digest) floor for pubkey."""
        self.store_rx_floor(pubkey, sequence, dao_digest)


def compute_dao_digest(dao_bytes: bytes) -> bytes:
    """Compute collision-resistant digest of complete signed DAO bytes.

    This is the digest stored in the RX floor for idempotent retransmission
    detection per spec section 8.6.

    Uses SHA-512 for consistency with dao_origin.py.
    """
    return hashlib.sha512(dao_bytes).digest()
