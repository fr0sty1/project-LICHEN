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

import contextlib
import fcntl
import hashlib
import os
import stat
import struct
import tempfile
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lichen.rollback_anchor import (
    AnchoredState,
    StateRevisionAnchor,
    advance_anchor,
    read_anchor,
)

# Slot header: magic (4) + generation (4) + sequence (8) + payload_len (4) + checksum (32)
_SLOT_HEADER_SIZE: Final[int] = 52
_SLOT_MAGIC: Final[bytes] = b"DAO1"
_MAX_PAYLOAD_SIZE: Final[int] = 64 * 1024
_MAX_GENERATION: Final[int] = (1 << 32) - 1
_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
_TX_INITIALIZED_MARKER: Final[bytes] = b"LICHEN-DAO-TX-INITIALIZED-v1\n"
_DAO_ANCHOR_DOMAIN: Final[bytes] = b"LICHEN-DAO-STATE-ANCHOR-v1\x00"


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

    def store_rx_floors_batch(self, floors: list[tuple[bytes, int, bytes]]) -> None:
        """Atomically commit multiple RX replay floors.

        Per spec section 8.6, partial commits violate atomicity requirements
        for crash-safe semantics. This method commits all floors atomically
        (all succeed or none succeed) to prevent inconsistent state across
        origins when a DAO targets multiple addresses.

        Args:
            floors: List of (pubkey, sequence, dao_digest) tuples.

        Raises:
            DaoPersistenceError: If the commit fails.

        The default rejects multi-floor requests because silently performing
        partial sequential commits would violate this method's contract.
        """
        if len(floors) > 1:
            raise DaoPersistenceError("backend does not support atomic multi-floor commits")
        for pubkey, sequence, dao_digest in floors:
            self.store_rx_floor(pubkey, sequence, dao_digest)


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

    def store_rx_floors_batch(self, floors: list[tuple[bytes, int, bytes]]) -> None:
        """In-memory batch is effectively atomic (no I/O failure points)."""
        for pubkey, sequence, dao_digest in floors:
            if type(pubkey) is not bytes or len(pubkey) not in (16, 32):
                raise ValueError("pubkey must be 16 or 32 immutable bytes")
            if type(sequence) is not int or not 0 <= sequence <= (1 << 64) - 1:
                raise ValueError("sequence must fit in u64")
            if type(dao_digest) is not bytes or len(dao_digest) != 64:
                raise ValueError("dao_digest must be 64 immutable bytes")
        for pubkey, sequence, dao_digest in floors:
            self.store_rx_floor(pubkey, sequence, dao_digest)

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

    def __init__(
        self,
        base_dir: Path,
        *,
        revision_anchor: StateRevisionAnchor,
        anchor_key: bytes,
        allow_tx_bootstrap: bool,
        fail_closed: bool = True,
    ) -> None:
        """Initialize persistence.

        Args:
            base_dir: Directory for persistence files.
            fail_closed: If True, missing/corrupt state raises on load.

        Raises:
            DaoPersistenceError: If base_dir exists and is a file (not a directory).
        """
        if type(fail_closed) is not bool or type(allow_tx_bootstrap) is not bool:
            raise ValueError("fail_closed and allow_tx_bootstrap must be exact booleans")
        if type(anchor_key) is not bytes or len(anchor_key) != 32:
            raise ValueError("anchor_key must be exact 32-byte bytes")
        self._base_dir = Path(base_dir)
        self._fail_closed = fail_closed
        self._allow_tx_bootstrap = allow_tx_bootstrap
        self._revision_anchor = revision_anchor
        self._anchor_key = hashlib.sha256(_DAO_ANCHOR_DOMAIN + anchor_key).digest()
        # Check if base_dir is an existing file before mkdir - this would cause
        # mkdir to fail with a confusing FileExistsError or NotADirectoryError
        if self._base_dir.exists() or self._base_dir.is_symlink():
            info = self._base_dir.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                raise DaoPersistenceError(
                    f"base_dir exists but is not an owned directory: {self._base_dir}"
                )
        if self._base_dir.exists() and not self._base_dir.is_dir():
            raise DaoPersistenceError(f"base_dir exists but is not a directory: {self._base_dir}")
        self._base_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self._base_dir, 0o700)
        self._process_lock_path = self._base_dir / ".dao.lock"
        # Lock to prevent TOCTOU race in _write_to_older_slot: concurrent
        # readers could both determine the same slot is "older" and both
        # write to it with the same generation, losing one write.
        self._write_lock = threading.Lock()

    def _state_anchor_key(self, kind: bytes, identity: bytes = b"") -> bytes:
        return hashlib.sha256(self._anchor_key + kind + identity).digest()

    @staticmethod
    def _slot_anchor(generation: int, sequence: int, payload: bytes) -> AnchoredState:
        digest = hashlib.sha256(struct.pack(">Q", sequence) + payload).digest()
        return AnchoredState(generation, digest)

    def _get_anchored_slot(
        self,
        path0: Path,
        path1: Path,
        anchor_key: bytes,
        *,
        allow_initial: bool,
        missing_message: str,
    ) -> tuple[int, int, int, bytes] | None:
        slot0 = self._read_slot(path0)
        slot1 = self._read_slot(path1)
        if (
            slot0 is not None
            and slot1 is not None
            and slot0[0] == slot1[0]
            and slot0[1:] != slot1[1:]
        ):
            raise DaoPersistenceError("DAO persistence slots have conflicting generations")
        external = read_anchor(self._revision_anchor, anchor_key, DaoPersistenceError)
        if external is not None:
            for index, candidate in enumerate((slot0, slot1)):
                if candidate is not None and self._slot_anchor(*candidate) == external:
                    return (index, *candidate)
            if slot0 is None and slot1 is None:
                raise DaoPersistenceError(missing_message)
            raise DaoPersistenceError("DAO persistence rollback or substitution detected")
        result = self._get_best_slot(path0, path1)
        if result is None:
            if external is not None:
                raise DaoPersistenceError(missing_message)
            return None
        _, generation, sequence, payload = result
        state = self._slot_anchor(generation, sequence, payload)
        if not allow_initial or generation != 1:
            raise DaoPersistenceError("DAO state is missing its rollback anchor")
        advance_anchor(
            self._revision_anchor,
            anchor_key,
            None,
            state,
            DaoPersistenceError,
        )
        return result

    def _tx_slot_path(self, slot: int) -> Path:
        return self._base_dir / f"dao_tx_{slot}.bin"

    def _tx_marker_path(self) -> Path:
        return self._base_dir / ".dao_tx_initialized"

    def _tx_marker_exists(self) -> bool:
        path = self._tx_marker_path()
        try:
            descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise DaoPersistenceError("DAO TX initialization marker is unreadable") from exc
        try:
            info = os.fstat(descriptor)
            marker = os.read(descriptor, len(_TX_INITIALIZED_MARKER) + 1)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or marker != _TX_INITIALIZED_MARKER
            ):
                raise DaoPersistenceError("DAO TX initialization marker is unsafe")
            return True
        finally:
            os.close(descriptor)

    def _ensure_tx_marker(self) -> None:
        if self._tx_marker_exists():
            return
        path = self._tx_marker_path()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".dao-tx-marker.", suffix=".tmp", dir=self._base_dir
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(_TX_INITIALIZED_MARKER)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(self._base_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(descriptor)
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise

    def _rx_slot_path(self, pubkey: bytes, slot: int) -> Path:
        key_hex = pubkey.hex()
        return self._base_dir / f"dao_rx_{key_hex}_{slot}.bin"

    def _write_slot(self, path: Path, generation: int, sequence: int, payload: bytes) -> None:
        """Write a slot atomically with checksum validation."""
        if len(payload) > _MAX_PAYLOAD_SIZE:
            raise DaoPersistenceError("DAO persistence payload exceeds size limit")
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

        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        tmp_path = Path(tmp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as file:
                file.write(slot_data)
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_path, path)
            os.chmod(path, 0o600)
        except BaseException:
            with contextlib.suppress(OSError):
                os.close(fd)
            with contextlib.suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise

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
        try:
            descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            return None
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size > _SLOT_HEADER_SIZE + _MAX_PAYLOAD_SIZE
            ):
                return None
            data = os.read(descriptor, _SLOT_HEADER_SIZE + _MAX_PAYLOAD_SIZE + 1)
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
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def _process_lock(self):  # type: ignore[no-untyped-def]
        try:
            descriptor = os.open(
                self._process_lock_path,
                os.O_RDWR | os.O_CREAT | _NOFOLLOW,
                0o600,
            )
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise DaoPersistenceError("DAO persistence lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as exc:
            if "descriptor" in locals():
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise DaoPersistenceError(f"DAO persistence lock failed: {exc}") from exc
        except BaseException:
            if "descriptor" in locals():
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            raise
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(descriptor)

    def _get_best_slot(self, path0: Path, path1: Path) -> tuple[int, int, int, bytes] | None:
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
        if slot0[0] == slot1[0] and slot0[1:] != slot1[1:]:
            raise DaoPersistenceError("DAO persistence slots have conflicting generations")
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
        return os.path.lexists(path0) or os.path.lexists(path1)

    def _write_to_older_slot(
        self,
        path0: Path,
        path1: Path,
        sequence: int,
        payload: bytes,
        anchor_key: bytes,
        *,
        allow_initial: bool,
    ) -> None:
        """Write to the older slot with incremented generation.

        Thread-safe: uses a lock to prevent TOCTOU race where concurrent
        callers could read the same slot state, both compute the same
        "older" slot and generation, and one write would be lost.
        """
        with self._write_lock, self._process_lock():
            current_result = self._get_anchored_slot(
                path0,
                path1,
                anchor_key,
                allow_initial=allow_initial,
                missing_message="initialized DAO state was deleted",
            )
            slot0 = self._read_slot(path0)
            slot1 = self._read_slot(path1)
            if (
                self._fail_closed
                and slot0 is None
                and slot1 is None
                and self._any_slot_exists(path0, path1)
            ):
                raise DaoPersistenceError("refusing to overwrite corrupt DAO persistence state")

            if current_result is not None:
                if sequence < current_result[2]:
                    raise DaoPersistenceError("DAO persistence sequence rollback")
                if sequence == current_result[2]:
                    if payload != current_result[3]:
                        raise DaoPersistenceError("DAO persistence sequence collision")
                    return

            # Write to older slot with generation = max + 1
            current_generation = 0 if current_result is None else current_result[1]
            if current_generation == _MAX_GENERATION:
                raise DaoPersistenceError("DAO persistence generation exhausted")
            new_gen = current_generation + 1
            if current_result is None or current_result[0] == 1:
                self._write_slot(path0, new_gen, sequence, payload)
            else:
                self._write_slot(path1, new_gen, sequence, payload)
            previous = read_anchor(self._revision_anchor, anchor_key, DaoPersistenceError)
            advance_anchor(
                self._revision_anchor,
                anchor_key,
                previous,
                self._slot_anchor(new_gen, sequence, payload),
                DaoPersistenceError,
            )

    def store_tx_state(self, sequence: int, dao_bytes: bytes) -> None:
        if type(sequence) is not int or not 0 <= sequence <= (1 << 64) - 1:
            raise ValueError("sequence must fit in u64")
        if type(dao_bytes) is not bytes:
            raise TypeError("dao_bytes must be immutable bytes")
        path0 = self._tx_slot_path(0)
        path1 = self._tx_slot_path(1)
        # Establish the legacy initialization sentinel before the anchored
        # state transaction.  A marker failure therefore cannot report a
        # failed store after the slot and external rollback anchor committed.
        self._ensure_tx_marker()
        self._write_to_older_slot(
            path0,
            path1,
            sequence,
            dao_bytes,
            self._state_anchor_key(b"tx"),
            allow_initial=self._allow_tx_bootstrap,
        )

    def load_tx_state(self) -> TxState | None:
        path0 = self._tx_slot_path(0)
        path1 = self._tx_slot_path(1)
        marker_exists = self._tx_marker_exists()
        with self._write_lock, self._process_lock():
            result = self._get_anchored_slot(
                path0,
                path1,
                self._state_anchor_key(b"tx"),
                allow_initial=self._allow_tx_bootstrap,
                missing_message="initialized TX state was deleted",
            )
        if result is None:
            # Per spec 8.6, distinguish missing (fresh node) from corrupt:
            # - No slots exist: fresh node, return None (allowed to start fresh)
            # - Slots exist but invalid: corrupt state, fail closed if configured
            if self._fail_closed and (self._any_slot_exists(path0, path1) or marker_exists):
                raise DaoPersistenceError("TX state corrupt")
            return None
        _, _, sequence, payload = result
        return TxState(sequence, payload)

    def store_rx_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        if type(pubkey) is not bytes:
            raise TypeError("pubkey must be immutable bytes")
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        if type(sequence) is not int or not 0 <= sequence <= (1 << 64) - 1:
            raise ValueError("sequence must fit in u64")
        if type(dao_digest) is not bytes:
            raise TypeError("dao_digest must be immutable bytes")
        if len(dao_digest) != 64:
            raise ValueError("dao_digest must be 64 bytes (SHA-512)")
        path0 = self._rx_slot_path(pubkey, 0)
        path1 = self._rx_slot_path(pubkey, 1)
        self._write_to_older_slot(
            path0,
            path1,
            sequence,
            dao_digest,
            self._state_anchor_key(b"rx", pubkey),
            allow_initial=True,
        )

    def store_rx_floors_batch(self, floors: list[tuple[bytes, int, bytes]]) -> None:
        """Atomically commit multiple RX replay floors.

        This backend deliberately rejects more than one floor because separate
        per-key slot files cannot provide an all-or-nothing multi-key commit.
        """
        if not floors:
            return
        if len(floors) > 1:
            raise DaoPersistenceError("two-slot backend rejects non-atomic multi-floor commit")
        # Validate all inputs before writing any
        for pubkey, _sequence, dao_digest in floors:
            if len(pubkey) not in (16, 32):
                raise ValueError("pubkey must be 16 or 32 bytes")
            if len(dao_digest) != 64:
                raise ValueError("dao_digest must be 64 bytes (SHA-512)")
        pubkey, sequence, dao_digest = floors[0]
        self.store_rx_floor(pubkey, sequence, dao_digest)

    def load_rx_floor(self, pubkey: bytes) -> RxFloor | None:
        if len(pubkey) not in (16, 32):
            raise ValueError("pubkey must be 16 or 32 bytes")
        path0 = self._rx_slot_path(pubkey, 0)
        path1 = self._rx_slot_path(pubkey, 1)
        with self._write_lock, self._process_lock():
            result = self._get_anchored_slot(
                path0,
                path1,
                self._state_anchor_key(b"rx", pubkey),
                allow_initial=True,
                missing_message=f"initialized RX floor was deleted for pubkey {pubkey.hex()}",
            )
        if result is None:
            # Per spec 8.6, distinguish missing (no prior DAO from this origin)
            # from corrupt. Missing RX floor for an origin is normal (first DAO).
            # Corrupt floor files are a hard failure when fail_closed.
            if self._fail_closed and self._any_slot_exists(path0, path1):
                raise DaoPersistenceError(f"RX floor corrupt for pubkey {pubkey.hex()}")
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
