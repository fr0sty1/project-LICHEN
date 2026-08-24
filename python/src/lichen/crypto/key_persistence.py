# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Secure key persistence interface and file-based implementation.

Per spec section 15.2, private keys MUST be stored in:
- Hardware secure element (preferred), OR
- Flash with readout protection

For the Python oracle (reference implementation), this module provides
file-based storage with restricted permissions (0600) suitable for
development and testing. Production embedded implementations should use
hardware secure elements or flash with readout protection.

This module provides:
- KeyStore: Abstract interface for secure seed/key storage
- FileKeyStore: Two-slot file-based implementation (crash-safe)
- TrustStorePersistence: File-based persistence for TrustStore entries

SECURITY: The Python runtime cannot guarantee secure memory erasure
(GC copies, no mlock, immutable bytes). For memory-forensics threat
models, use Rust/C implementations or HSMs.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import math
import os
import stat
import struct
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from lichen.rollback_anchor import (
    AnchoredState,
    StateRevisionAnchor,
    advance_anchor,
    read_anchor,
)

from .identity import Identity
from .trust import (
    TrustEntry,
    TrustLevel,
    TrustStore,
    verify_pubkey_derivation,
    verify_pubkey_to_ygg_addr,
)

# Slot header format (same as dao_persistence for consistency)
_SLOT_HEADER_SIZE: Final[int] = 52
_SLOT_MAGIC: Final[bytes] = b"KEY1"

# Trust store caps to prevent DoS via storage tampering
_MAX_TRUST_ENTRIES: Final[int] = 10000
_MAX_METADATA_KEYS: Final[int] = 32
_MAX_METADATA_KEY_LEN: Final[int] = 128
_MAX_METADATA_VALUE_LEN: Final[int] = 1024
_MAX_METADATA_TOTAL_LEN: Final[int] = 8192
_MAX_TRUST_FILE_SIZE: Final[int] = 4 * 1024 * 1024
_TRUST_FORMAT_VERSION: Final[int] = 2
_MAX_U32: Final[int] = (1 << 32) - 1
_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
_SEED_ANCHOR_DOMAIN: Final[bytes] = b"LICHEN-SEED-ANCHOR-v1\x00"
_TRUST_ANCHOR_DOMAIN: Final[bytes] = b"LICHEN-TRUST-ANCHOR-v1\x00"
_TRUST_AUTH_DOMAIN: Final[bytes] = b"LICHEN-TRUST-STATE-v1\x00"


def _prepare_private_directory(path: Path, error_type: type[Exception]) -> None:
    """Create or validate an owner-only, non-symlink persistence directory."""
    try:
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise error_type(f"base_dir is not a real directory: {path}")
            if info.st_uid != os.geteuid():
                raise error_type(f"base_dir is not owned by current user: {path}")
        else:
            path.mkdir(parents=True, mode=0o700)
        os.chmod(path, 0o700)
        info = path.lstat()
        if stat.S_IMODE(info.st_mode) != 0o700:
            raise error_type(f"base_dir permissions are not 0700: {path}")
    except OSError as exc:
        raise error_type(f"cannot prepare private directory {path}: {exc}") from exc


@contextmanager
def _exclusive_file_lock(path: Path, error_type: type[Exception]) -> Iterator[None]:
    """Hold an owner-private, no-follow inter-process lock."""
    flags = os.O_RDWR | os.O_CREAT | _NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise error_type(f"lock is not an owned regular file: {path}")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
    except OSError as exc:
        if "fd" in locals():
            with suppress(OSError):
                os.close(fd)
        raise error_type(f"cannot lock persistence state: {exc}") from exc
    except BaseException:
        if "fd" in locals():
            with suppress(OSError):
                os.close(fd)
        raise
    try:
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        with suppress(OSError):
            os.close(fd)


class KeyPersistenceError(Exception):
    """Raised when key storage state is missing, corrupt, or unavailable."""


class TrustStorePersistenceError(Exception):
    """Raised when trust store state is corrupt or tampered."""


class TrustStorePersistenceIndeterminateError(TrustStorePersistenceError):
    """A new trust snapshot may already be durable; the backend is terminal."""

    durable_state_may_have_advanced = True


@dataclass(frozen=True)
class StoredSeed:
    """Crash-safe stored seed state."""

    seed: bytes  # 32-byte secret seed
    generation: int  # Monotonic generation counter


class KeyStore(ABC):
    """Abstract interface for secure seed/key storage.

    Implementations MUST:
    - Never transmit seed/keys over the air (spec 15.2)
    - Use secure storage (file permissions, secure element, etc.)
    - Provide crash-safe semantics (atomic writes or two-slot)

    The seed is the canonical secret; all other key material (privkey,
    pubkey, IID, 02xx address) derives from it per spec 8.7.
    """

    @property
    @abstractmethod
    def is_crash_safe(self) -> bool:
        """Return True if this backend provides crash-safe persistence."""

    @abstractmethod
    def store_seed(self, seed: bytes) -> None:
        """Securely store the 32-byte node seed.

        Args:
            seed: 32-byte cryptographic seed.

        Raises:
            KeyPersistenceError: If storage fails.
            ValueError: If seed is not 32 bytes.
        """

    @abstractmethod
    def load_seed(self) -> bytes | None:
        """Load the stored seed.

        Returns:
            32-byte seed, or None if no valid seed exists.

        Raises:
            KeyPersistenceError: If state is corrupt (fail-closed mode).
        """

    def store_identity(self, identity: Identity) -> None:
        """Store an Identity by persisting its seed.

        The seed is the canonical secret from which all key material
        derives. Per spec 8.7, storing the seed is sufficient.

        Args:
            identity: Identity to persist.
        """
        self.store_seed(identity.seed)

    def load_identity(self) -> Identity | None:
        """Load a stored Identity.

        Returns:
            Identity derived from stored seed, or None if no seed exists.
        """
        seed = self.load_seed()
        if seed is None:
            return None
        return Identity.from_seed(seed)


class MemoryKeyStore(KeyStore):
    """In-memory key store for testing. NOT crash-safe.

    SECURITY: Only use for unit tests. Does not provide secure storage.
    """

    @property
    def is_crash_safe(self) -> bool:
        return False

    def __init__(self) -> None:
        self._seed: bytes | None = None

    def store_seed(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
        self._seed = seed

    def load_seed(self) -> bytes | None:
        return self._seed


class FileKeyStore(KeyStore):
    """Two-slot file-based key storage with restricted permissions.

    Uses two alternating slots with generation counters for crash-safety.
    On write, the older slot is overwritten and fsynced. On read, the slot
    with the higher valid generation is used.

    File permissions are set to 0600 (owner read/write only) per spec 15.2.

    Slot format (same as dao_persistence):
        - Magic bytes "KEY1" (4 bytes)
        - Generation number (4 bytes, big-endian)
        - Sequence (8 bytes, unused, set to 0)
        - Payload length (4 bytes, big-endian)
        - SHA-256 checksum of generation + sequence + payload (32 bytes)
        - Payload bytes (32-byte seed)
    """

    @property
    def is_crash_safe(self) -> bool:
        """Two-slot file storage IS crash-safe."""
        return True

    def __init__(
        self,
        base_dir: Path,
        *,
        revision_anchor: StateRevisionAnchor,
        anchor_key: bytes,
        allow_bootstrap: bool,
        fail_closed: bool = True,
    ) -> None:
        """Initialize key storage.

        Args:
            base_dir: Directory for key files. Will be created if needed.
            fail_closed: If True, corrupt state raises on load.

        Raises:
            KeyPersistenceError: If base_dir exists and is not a directory.
        """
        if type(fail_closed) is not bool or type(allow_bootstrap) is not bool:
            raise ValueError("fail_closed and allow_bootstrap must be exact booleans")
        if type(anchor_key) is not bytes or len(anchor_key) != 32:
            raise ValueError("anchor_key must be exact 32-byte bytes")
        self._base_dir = Path(base_dir)
        self._fail_closed = fail_closed
        self._allow_bootstrap = allow_bootstrap
        self._revision_anchor = revision_anchor
        self._anchor_key = hashlib.sha256(_SEED_ANCHOR_DOMAIN + anchor_key).digest()
        _prepare_private_directory(self._base_dir, KeyPersistenceError)
        self._lock_path = self._base_dir / ".node_seed.lock"

    def _slot_path(self, slot: int) -> Path:
        return self._base_dir / f"node_seed_{slot}.bin"

    def _write_slot(self, path: Path, generation: int, payload: bytes) -> None:
        """Write a slot atomically with checksum validation."""
        sequence = 0  # unused for key storage
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

        # Use an exclusive unique staging file so concurrent/crashed writers
        # cannot clobber or follow a predictable temporary path.
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        tmp_path = Path(tmp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as f:
                f.write(slot_data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, path)
            os.chmod(path, 0o600)
        except BaseException:
            with suppress(OSError):
                os.close(fd)
            with suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            raise

        # Sync directory to ensure rename is durable
        dir_fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _read_slot(self, path: Path) -> tuple[int, bytes] | None:
        """Read and validate a slot.

        Returns:
            (generation, payload) or None if invalid/missing.
        """
        try:
            fd = os.open(path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            return None
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size != _SLOT_HEADER_SIZE + 32
            ):
                return None
            data = os.read(fd, _SLOT_HEADER_SIZE + 33)
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
            if payload_len != 32:  # seed must be 32 bytes
                return None

            # Verify checksum
            content = struct.pack(">IQ", generation, sequence) + payload
            expected_checksum = hashlib.sha256(content).digest()
            if stored_checksum != expected_checksum:
                return None

            return generation, payload
        finally:
            os.close(fd)

    def _any_slot_exists(self) -> bool:
        """Check if any slot file exists (for distinguishing missing vs corrupt)."""
        return os.path.lexists(self._slot_path(0)) or os.path.lexists(self._slot_path(1))

    @staticmethod
    def _slot_anchor(slot: tuple[int, bytes]) -> AnchoredState:
        generation, seed = slot
        return AnchoredState(generation, hashlib.sha256(seed).digest())

    def _best_slot_locked(self) -> tuple[int, bytes] | None:
        slot0 = self._read_slot(self._slot_path(0))
        slot1 = self._read_slot(self._slot_path(1))
        external = read_anchor(self._revision_anchor, self._anchor_key, KeyPersistenceError)
        if slot0 is None and slot1 is None:
            if external is not None:
                raise KeyPersistenceError("initialized seed state was deleted")
            if self._fail_closed and self._any_slot_exists():
                raise KeyPersistenceError("seed state corrupt")
            if not self._allow_bootstrap:
                raise KeyPersistenceError("seed state requires explicit bootstrap")
            return None
        if (
            slot0 is not None
            and slot1 is not None
            and slot0[0] == slot1[0]
            and slot0[1] != slot1[1]
        ):
            raise KeyPersistenceError("seed slots have conflicting generations")
        if external is not None:
            for candidate in (slot0, slot1):
                if candidate is not None and self._slot_anchor(candidate) == external:
                    return candidate
            raise KeyPersistenceError("seed state rollback or substitution detected")
        if slot0 is not None and slot1 is not None and slot0[0] == slot1[0]:
            best = slot0
        elif slot0 is None:
            assert slot1 is not None
            best = slot1
        elif slot1 is None or slot0[0] > slot1[0]:
            best = slot0
        else:
            best = slot1
        state = self._slot_anchor(best)
        if not self._allow_bootstrap or state.revision != 1:
            raise KeyPersistenceError("seed state is missing its rollback anchor")
        advance_anchor(
            self._revision_anchor,
            self._anchor_key,
            None,
            state,
            KeyPersistenceError,
        )
        return best

    def store_seed(self, seed: bytes) -> None:
        if type(seed) is not bytes:
            raise TypeError("seed must be bytes")
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
        with _exclusive_file_lock(self._lock_path, KeyPersistenceError):
            path0 = self._slot_path(0)
            path1 = self._slot_path(1)
            slot1 = self._read_slot(path1)
            current = self._best_slot_locked()

            current_generation = 0 if current is None else current[0]
            if current_generation == _MAX_U32:
                raise KeyPersistenceError("seed generation exhausted")

            new_gen = current_generation + 1
            if current is None or current == slot1:
                self._write_slot(path0, new_gen, seed)
            else:
                self._write_slot(path1, new_gen, seed)
            previous = read_anchor(self._revision_anchor, self._anchor_key, KeyPersistenceError)
            advance_anchor(
                self._revision_anchor,
                self._anchor_key,
                previous,
                AnchoredState(new_gen, hashlib.sha256(seed).digest()),
                KeyPersistenceError,
            )

    def load_seed(self) -> bytes | None:
        with _exclusive_file_lock(self._lock_path, KeyPersistenceError):
            return self._load_seed_locked()

    def _load_seed_locked(self) -> bytes | None:
        best = self._best_slot_locked()
        return None if best is None else best[1]


class TrustStorePersistence:
    """File-based persistence for TrustStore entries.

    Stores trust entries as JSON for simplicity and debuggability.
    Uses atomic write (temp + rename) for crash-safety.

    Note: This is a simple reference implementation. Production
    implementations may use more efficient binary formats.
    """

    def __init__(
        self,
        base_dir: Path,
        *,
        authentication_key: bytes,
        revision_anchor: StateRevisionAnchor,
        anchor_key: bytes,
        allow_bootstrap: bool,
    ) -> None:
        """Initialize trust store persistence.

        Args:
            base_dir: Directory for trust store file.
        """
        if type(authentication_key) is not bytes or len(authentication_key) != 32:
            raise ValueError("authentication_key must be exact 32-byte bytes")
        if type(anchor_key) is not bytes or len(anchor_key) != 32:
            raise ValueError("anchor_key must be exact 32-byte bytes")
        if type(allow_bootstrap) is not bool:
            raise ValueError("allow_bootstrap must be an exact boolean")
        self._base_dir = Path(base_dir)
        self._authentication_key = authentication_key
        self._revision_anchor = revision_anchor
        self._anchor_key = hashlib.sha256(_TRUST_ANCHOR_DOMAIN + anchor_key).digest()
        self._allow_bootstrap = allow_bootstrap
        self._terminal_error: TrustStorePersistenceError | None = None
        _prepare_private_directory(self._base_dir, TrustStorePersistenceError)
        self._file_path = self._base_dir / "trust_store.json"
        self._lock_path = self._base_dir / ".trust_store.lock"

    @property
    def is_crash_safe(self) -> bool:
        return True

    @property
    def fails_closed(self) -> bool:
        return True

    def save(self, store: TrustStore) -> None:
        """Save TrustStore entries to file.

        Args:
            store: TrustStore to persist.
        """
        with _exclusive_file_lock(self._lock_path, TrustStorePersistenceError):
            self._raise_if_terminal()
            existing_data = self._read_and_validate_locked(missing_ok=True)
            current_revision = 0
            if existing_data is not None:
                current_revision = self._decode_document(existing_data)._persistence_revision
            expected_revision = getattr(store, "_persistence_revision", 0)
            if expected_revision != current_revision:
                raise TrustStorePersistenceError(
                    f"stale trust-store revision: {expected_revision} != {current_revision}"
                )
            if current_revision == (1 << 64) - 1:
                raise TrustStorePersistenceError("trust-store revision exhausted")

            entries = []
            for entry in store.list_entries(include_revoked=True):
                entries.append(
                    {
                        "pubkey_hex": entry.pubkey.hex(),
                        "iid_hex": entry.iid.hex(),
                        "ygg_addr_hex": entry.ygg_addr.hex(),
                        "trust_level": entry.trust_level.name,
                        "first_seen": entry.first_seen,
                        "last_seen": entry.last_seen,
                        "revoked": entry.revoked,
                        "metadata": dict(entry.metadata),
                        "rotation_sequence": entry.rotation_sequence,
                    }
                )
            new_revision = current_revision + 1
            body: dict[str, object] = {
                "format_version": _TRUST_FORMAT_VERSION,
                "revision": new_revision,
                "auto_pin": store.auto_pin,
                "entries": entries,
            }
            authentication = hmac.new(
                self._authentication_key,
                _TRUST_AUTH_DOMAIN + self._canonical(body),
                hashlib.sha256,
            ).hexdigest()
            document = {**body, "authentication": authentication}
            encoded = (
                json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n"
            ).encode("utf-8")
            if len(encoded) > _MAX_TRUST_FILE_SIZE:
                raise TrustStorePersistenceError("trust store exceeds size limit")
            previous_anchor = read_anchor(
                self._revision_anchor,
                self._anchor_key,
                TrustStorePersistenceError,
            )
            state = AnchoredState(new_revision, hashlib.sha256(encoded).digest())
            written = False
            try:
                self._write_json_locked(encoded)
                written = True
                advance_anchor(
                    self._revision_anchor,
                    self._anchor_key,
                    previous_anchor,
                    state,
                    TrustStorePersistenceError,
                )
            except BaseException as exc:
                if isinstance(exc, TrustStorePersistenceIndeterminateError) or written:
                    store._persistence_revision = new_revision
                    terminal = TrustStorePersistenceIndeterminateError(
                        "trust-store persistence transition is indeterminate"
                    )
                    self._terminal_error = terminal
                    raise terminal from exc
                raise
            store._persistence_revision = new_revision

    def load(self) -> TrustStore | None:
        """Load TrustStore from file with validation.

        Returns:
            TrustStore with loaded entries, or None if file doesn't exist.

        Raises:
            TrustStorePersistenceError: If file is corrupt, tampered, or invalid.
        """
        with _exclusive_file_lock(self._lock_path, TrustStorePersistenceError):
            self._raise_if_terminal()
            data = self._read_and_validate_locked(missing_ok=True)
            if data is None:
                return None
            return self._decode_document(data)

    def _raise_if_terminal(self) -> None:
        if self._terminal_error is not None:
            raise self._terminal_error

    @staticmethod
    def _canonical(document: object) -> bytes:
        return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )

    def _read_and_validate_locked(self, *, missing_ok: bool) -> object | None:
        document = self._read_json_locked(missing_ok=missing_ok)
        external = read_anchor(
            self._revision_anchor,
            self._anchor_key,
            TrustStorePersistenceError,
        )
        if document is None:
            if external is not None:
                raise TrustStorePersistenceError("initialized trust store was deleted")
            if not self._allow_bootstrap:
                raise TrustStorePersistenceError("trust store requires explicit bootstrap")
            return None
        decoded = self._decode_document(document)
        encoded = (json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
            "utf-8"
        )
        state = AnchoredState(decoded._persistence_revision, hashlib.sha256(encoded).digest())
        if external is None:
            if not self._allow_bootstrap or state.revision != 1:
                raise TrustStorePersistenceError("trust store is missing its rollback anchor")
            advance_anchor(
                self._revision_anchor,
                self._anchor_key,
                None,
                state,
                TrustStorePersistenceError,
            )
        elif state == external:
            pass
        elif state.revision == external.revision + 1:
            advance_anchor(
                self._revision_anchor,
                self._anchor_key,
                external,
                state,
                TrustStorePersistenceError,
            )
        else:
            raise TrustStorePersistenceError("trust-store rollback or substitution detected")
        return document

    def _read_json_locked(self, *, missing_ok: bool) -> object | None:
        try:
            fd = os.open(self._file_path, os.O_RDONLY | _NOFOLLOW)
        except FileNotFoundError:
            if missing_ok:
                return None
            raise TrustStorePersistenceError("trust store is missing") from None
        except OSError as exc:
            raise TrustStorePersistenceError(f"unreadable: {exc}") from exc
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise TrustStorePersistenceError("trust store is not an owned regular file")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise TrustStorePersistenceError("trust store permissions are not private")
            if info.st_size > _MAX_TRUST_FILE_SIZE:
                raise TrustStorePersistenceError("trust store exceeds size limit")
            raw = os.read(fd, _MAX_TRUST_FILE_SIZE + 1)
        finally:
            os.close(fd)
        try:
            document: object = json.loads(raw)
            return document
        except (ValueError, UnicodeDecodeError) as exc:
            raise TrustStorePersistenceError(f"corrupt JSON: {exc}") from exc

    def _write_json_locked(self, encoded: bytes) -> None:
        fd, tmp_name = tempfile.mkstemp(prefix=".trust_store.", suffix=".tmp", dir=self._base_dir)
        tmp_path = Path(tmp_name)
        replaced = False
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as file:
                file.write(encoded)
                file.flush()
                os.fsync(file.fileno())
            os.replace(tmp_path, self._file_path)
            replaced = True
            os.chmod(self._file_path, 0o600)
            dir_fd = os.open(self._base_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException as exc:
            with suppress(OSError):
                os.close(fd)
            with suppress(OSError):
                tmp_path.unlink(missing_ok=True)
            if replaced:
                raise TrustStorePersistenceIndeterminateError(
                    "trust-store replacement completed before persistence failure"
                ) from exc
            raise

    def _decode_document(self, data: object) -> TrustStore:

        if not isinstance(data, dict):
            raise TrustStorePersistenceError("root must be object")

        expected_root = {
            "format_version",
            "revision",
            "auto_pin",
            "entries",
            "authentication",
        }
        if set(data) != expected_root:
            raise TrustStorePersistenceError("root fields must match exact versioned schema")
        if (
            type(data["format_version"]) is not int
            or data["format_version"] != _TRUST_FORMAT_VERSION
        ):
            raise TrustStorePersistenceError("unsupported trust-store format_version")
        authentication = data["authentication"]
        if type(authentication) is not str:
            raise TrustStorePersistenceError("authentication must be hex")
        try:
            supplied_authentication = bytes.fromhex(authentication)
        except ValueError:
            raise TrustStorePersistenceError("authentication must be hex") from None
        body = {key: value for key, value in data.items() if key != "authentication"}
        expected_authentication = hmac.new(
            self._authentication_key,
            _TRUST_AUTH_DOMAIN + self._canonical(body),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied_authentication, expected_authentication):
            raise TrustStorePersistenceError("trust store authentication failed")
        revision = data["revision"]
        if type(revision) is not int or not 1 <= revision <= (1 << 64) - 1:
            raise TrustStorePersistenceError("revision must be a nonzero u64")

        auto_pin = data["auto_pin"]
        if type(auto_pin) is not bool:
            raise TrustStorePersistenceError("auto_pin must be bool")

        entries_raw = data["entries"]
        if not isinstance(entries_raw, list):
            raise TrustStorePersistenceError("entries must be array")
        if len(entries_raw) > _MAX_TRUST_ENTRIES:
            raise TrustStorePersistenceError(
                f"too many entries: {len(entries_raw)} > {_MAX_TRUST_ENTRIES}"
            )

        store = TrustStore(auto_pin=auto_pin, persistence=self)
        seen_iids: set[bytes] = set()

        for i, entry_data in enumerate(entries_raw):
            if not isinstance(entry_data, dict):
                raise TrustStorePersistenceError(f"entry[{i}] must be object")
            expected_entry = {
                "pubkey_hex",
                "iid_hex",
                "ygg_addr_hex",
                "trust_level",
                "first_seen",
                "last_seen",
                "revoked",
                "metadata",
                "rotation_sequence",
            }
            if set(entry_data) != expected_entry:
                raise TrustStorePersistenceError(f"entry[{i}]: fields do not match schema")

            try:
                pubkey = self._parse_hex_field(entry_data, "pubkey_hex", 32, i)
                iid = self._parse_hex_field(entry_data, "iid_hex", 8, i)
                ygg_addr = self._parse_hex_field(entry_data, "ygg_addr_hex", 16, i)
            except (KeyError, ValueError) as e:
                raise TrustStorePersistenceError(f"entry[{i}]: {e}") from e

            # SECURITY: Verify derivation bindings - pubkey must derive to iid/ygg_addr
            if not verify_pubkey_derivation(pubkey, iid):
                raise TrustStorePersistenceError(f"entry[{i}]: pubkey does not derive to iid")
            if not verify_pubkey_to_ygg_addr(pubkey, ygg_addr):
                raise TrustStorePersistenceError(f"entry[{i}]: pubkey does not derive to ygg_addr")

            # Duplicate detection
            if iid in seen_iids:
                raise TrustStorePersistenceError(f"entry[{i}]: duplicate iid")
            seen_iids.add(iid)

            # Trust level
            trust_level_name = entry_data["trust_level"]
            if type(trust_level_name) is not str:
                raise TrustStorePersistenceError(f"entry[{i}]: trust_level must be string")
            try:
                trust_level = TrustLevel[trust_level_name]
            except KeyError:
                raise TrustStorePersistenceError(
                    f"entry[{i}]: invalid trust_level '{trust_level_name}'"
                ) from None

            # Timestamps
            first_seen = entry_data["first_seen"]
            last_seen = entry_data["last_seen"]
            if type(first_seen) not in (int, float):
                raise TrustStorePersistenceError(f"entry[{i}]: first_seen must be number")
            if type(last_seen) not in (int, float):
                raise TrustStorePersistenceError(f"entry[{i}]: last_seen must be number")
            if (type(first_seen) is int and first_seen > (1 << 64) - 1) or (
                type(last_seen) is int and last_seen > (1 << 64) - 1
            ):
                raise TrustStorePersistenceError(f"entry[{i}]: timestamps must be finite")
            if (type(first_seen) is float and not math.isfinite(first_seen)) or (
                type(last_seen) is float and not math.isfinite(last_seen)
            ):
                raise TrustStorePersistenceError(f"entry[{i}]: timestamps must be finite")
            if first_seen < 0 or last_seen < 0:
                raise TrustStorePersistenceError(f"entry[{i}]: timestamps must be non-negative")
            if last_seen < first_seen:
                raise TrustStorePersistenceError(f"entry[{i}]: last_seen < first_seen")

            # Revoked flag
            revoked = entry_data["revoked"]
            if type(revoked) is not bool:
                raise TrustStorePersistenceError(f"entry[{i}]: revoked must be bool")

            # Metadata validation
            metadata = entry_data["metadata"]
            if not isinstance(metadata, dict):
                raise TrustStorePersistenceError(f"entry[{i}]: metadata must be object")
            if len(metadata) > _MAX_METADATA_KEYS:
                raise TrustStorePersistenceError(f"entry[{i}]: too many metadata keys")
            metadata_total = 0
            for k, v in metadata.items():
                if type(k) is not str or type(v) is not str:
                    raise TrustStorePersistenceError(
                        f"entry[{i}]: metadata keys/values must be strings"
                    )
                if len(k) > _MAX_METADATA_KEY_LEN or len(v) > _MAX_METADATA_VALUE_LEN:
                    raise TrustStorePersistenceError(f"entry[{i}]: metadata key/value too long")
                metadata_total += len(k.encode("utf-8")) + len(v.encode("utf-8"))
            if metadata_total > _MAX_METADATA_TOTAL_LEN:
                raise TrustStorePersistenceError(f"entry[{i}]: metadata exceeds size limit")

            # Rotation sequence (anti-replay for key rotation)
            rotation_sequence = entry_data["rotation_sequence"]
            if type(rotation_sequence) is not int:
                raise TrustStorePersistenceError(f"entry[{i}]: rotation_sequence must be integer")
            if not 0 <= rotation_sequence <= (1 << 64) - 1:
                raise TrustStorePersistenceError(
                    f"entry[{i}]: rotation_sequence must be non-negative"
                )

            try:
                entry = TrustEntry(
                    pubkey=pubkey,
                    iid=iid,
                    ygg_addr=ygg_addr,
                    trust_level=trust_level,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    revoked=revoked,
                    metadata=metadata,
                    rotation_sequence=rotation_sequence,
                )
            except (TypeError, ValueError) as exc:
                raise TrustStorePersistenceError(f"entry[{i}]: {exc}") from exc
            store._entries[entry.iid] = entry

        store._persistence_revision = revision
        return store

    @staticmethod
    def _parse_hex_field(data: dict[str, object], key: str, expected_len: int, idx: int) -> bytes:
        """Parse and validate a hex-encoded bytes field."""
        value = data.get(key)
        if value is None:
            raise KeyError(f"missing {key}")
        if not isinstance(value, str):
            raise ValueError(f"{key} must be string")
        try:
            result = bytes.fromhex(value)
        except ValueError:
            raise ValueError(f"{key} invalid hex") from None
        if len(result) != expected_len:
            raise ValueError(f"{key} must be {expected_len} bytes, got {len(result)}")
        return result
