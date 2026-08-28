# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Link layer persistence with signed journal and rollback protection.

This module provides durable persistence for link layer security state,
including transmit counters, pinned keys, and replay windows. All persisted
records are cryptographically signed to prevent tampering, and revision
anchors detect rollback attacks.

Threading model: A file lock serializes writes across processes; internal
locks coordinate concurrent access within a process.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from .._sync_callbacks import reject_awaitable_result
from ..crypto.schnorr48 import sign, verify
from .protocols import LinkPersistenceError, PersistenceRevisionAnchor

if TYPE_CHECKING:
    pass


class SecurityStateExporter(Protocol):
    """Protocol for exporting security state from the link layer."""

    def export_state(self) -> dict[str, object]:
        """Export current security state for persistence."""
        ...

    def export_bootstrap_state(self) -> dict[str, object]:
        """Export initial bootstrap state for persistence."""
        ...


class SecurityStateRestorer(Protocol):
    """Protocol for restoring security state to the link layer."""

    def restore_state(self, state: dict[str, object]) -> None:
        """Restore security state from persistence."""
        ...


class PersistenceFailureHandler(Protocol):
    """Protocol for handling persistence failures."""

    def on_persistence_failure(self) -> None:
        """Handle terminal persistence failure by disabling the link layer."""
        ...


@dataclass
class LinkPersistence:
    """Manages durable persistence for link layer security state.

    This class handles:
    - Loading and validating persisted state on startup
    - Saving state with signed journal entries and revision anchors
    - Rollback detection via independent revision anchors
    - Process-safe file locking for concurrent writers

    The persistence format uses a dual-slot journal with an anchor file:
    - Two alternating slot files (.0, .1) hold signed state snapshots
    - An anchor file tracks the current revision and digest
    - An external revision anchor provides rollback detection

    All files are signed with the node's Schnorr key pair and validated
    on load to detect tampering.

    Args:
        persist_path: Base path for persistence files (slots, anchor, lock).
        local_privkey: Node's 32-byte Schnorr private key for signing.
        local_pubkey: Node's 32-byte Schnorr public key for verification.
        security_lock: Lock protecting security state during export/restore.
        revision_anchor: External monotonic revision anchor for rollback detection.
        allow_bootstrap: Whether to allow creating initial persistence files.
        state_exporter: Callback to export current security state.
        state_restorer: Callback to restore security state.
        failure_handler: Callback to handle terminal persistence failures.
    """

    persist_path: str | None
    local_privkey: bytes
    local_pubkey: bytes
    security_lock: threading.Lock
    revision_anchor: PersistenceRevisionAnchor | None
    allow_bootstrap: bool
    state_exporter: SecurityStateExporter
    state_restorer: SecurityStateRestorer
    failure_handler: PersistenceFailureHandler

    # Internal state
    _persistence_revision: int = field(default=0, init=False)
    _persistence_failed: bool = field(default=False, init=False)
    _persistence_meta_lock: threading.Lock = field(
        default_factory=threading.Lock, init=False
    )
    _persistence_transition_guard: threading.Semaphore = field(
        default_factory=lambda: threading.Semaphore(1), init=False
    )
    _persistence_hook_active: bool = field(default=False, init=False)
    _persistence_reentry: bool = field(default=False, init=False)
    _persistence_transition_owner: int | None = field(default=None, init=False)

    @property
    def revision(self) -> int:
        """Current persistence revision number."""
        return self._persistence_revision

    @property
    def failed(self) -> bool:
        """Whether persistence has terminally failed."""
        return self._persistence_failed

    def load_state(self) -> None:
        """Load persisted state from disk.

        Validates signatures, checks revision anchors for rollback, and
        restores security state via the configured restorer callback.

        Raises:
            RuntimeError: If persistence files are missing, corrupt, or
                show evidence of rollback.
        """
        if self.persist_path is None:
            return
        with self._persistence_file_lock():
            self._load_persisted_state_unlocked()

    def _load_persisted_state_unlocked(self) -> None:
        """Restore one journal snapshot while the cross-writer lock is held."""
        assert self.persist_path is not None
        slot_paths = [f"{self.persist_path}.0", f"{self.persist_path}.1"]
        anchor_path = f"{self.persist_path}.anchor"
        external_revision = self._read_persistence_revision_anchor()
        if not any(os.path.exists(path) for path in (*slot_paths, anchor_path)):
            if external_revision is not None:
                raise RuntimeError(
                    "link security persistence was deleted after bootstrap"
                )
            if not self.allow_bootstrap:
                raise RuntimeError(
                    "link security persistence requires explicit bootstrap"
                )
            # Bootstrap owns the file lock already; avoid recursively acquiring it.
            self._save_persisted_state_bootstrap_unlocked()
            return

        valid_slots: list[tuple[int, dict[str, object], bytes]] = []
        for path in slot_paths:
            if not os.path.exists(path):
                continue
            try:
                record, canonical = self._read_signed_persistence_record(
                    path, b"state"
                )
                revision = record.get("revision")
                if type(revision) is not int or revision < 1:
                    raise ValueError("invalid persistence revision")
                valid_slots.append(
                    (revision, record, hashlib.sha256(canonical).digest())
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
        if not valid_slots:
            raise RuntimeError("link security persistence is missing or corrupt")
        revision, state, digest = max(valid_slots, key=lambda item: item[0])

        if external_revision is None:
            if not self.allow_bootstrap or revision != 1:
                raise RuntimeError(
                    "independent persistence revision anchor is uninitialized"
                )
        elif revision < external_revision or revision > external_revision + 1:
            raise RuntimeError("link security persistence rollback detected")

        if os.path.exists(anchor_path):
            anchor, _ = self._read_signed_persistence_record(anchor_path, b"anchor")
            anchor_revision = anchor.get("revision")
            anchor_digest = anchor.get("digest")
            if type(anchor_revision) is not int or type(anchor_digest) is not str:
                raise RuntimeError("link security persistence anchor is corrupt")
            if revision < anchor_revision or revision > anchor_revision + 1:
                raise RuntimeError("link security persistence rollback detected")
            if revision == anchor_revision and anchor_digest != digest.hex():
                raise RuntimeError("link security persistence anchor mismatch")
        elif revision != 1 and revision != external_revision:
            raise RuntimeError("link security persistence anchor is missing")

        self.state_restorer.restore_state(state)
        self._persistence_revision = revision
        self._write_persistence_anchor(anchor_path, revision, digest)
        if external_revision != revision:
            self._advance_persistence_revision_anchor(external_revision, revision)

    def _save_persisted_state_bootstrap_unlocked(self) -> None:
        """Create revision one while initialization owns the persistence file lock."""
        assert self.persist_path is not None
        with self.security_lock:
            state = self.state_exporter.export_bootstrap_state()
            state["revision"] = 1
        canonical = self._write_signed_persistence_record(
            f"{self.persist_path}.1", state, b"state"
        )
        digest = hashlib.sha256(canonical).digest()
        self._write_persistence_anchor(f"{self.persist_path}.anchor", 1, digest)
        self._advance_persistence_revision_anchor(None, 1)
        self._persistence_revision = 1

    def save_state(self) -> None:
        """Persist current security state or disable on failure.

        Acquires the transition guard, exports state, writes signed journal
        entries, and updates revision anchors. On any failure, the link
        layer is permanently disabled via the failure handler.

        Raises:
            LinkPersistenceError: If persistence fails or was previously
                disabled.
            RuntimeError: If called during a persistence callback or
                another transition is in progress.
        """
        if self.persist_path is None:
            return
        if self._persistence_failed:
            raise LinkPersistenceError(
                "LinkLayer is disabled after a persistence failure"
            )
        with self._persistence_meta_lock:
            if self._persistence_hook_active:
                self._persistence_reentry = True
                raise RuntimeError("LinkLayer operation during persistence callback")
        if not self._persistence_transition_guard.acquire(blocking=False):
            with self._persistence_meta_lock:
                if self._persistence_hook_active:
                    self._persistence_reentry = True
                    raise RuntimeError(
                        "link persistence transition already in progress"
                    )
                if self._persistence_transition_owner == threading.get_ident():
                    raise RuntimeError("recursive link persistence transition")
            self._persistence_transition_guard.acquire()
        with self._persistence_meta_lock:
            self._persistence_transition_owner = threading.get_ident()
        try:
            self.ensure_healthy()
            self._save_persisted_state_unchecked()
        except BaseException as exc:
            self._persistence_failed = True
            self.failure_handler.on_persistence_failure()
            raise LinkPersistenceError(
                "link security persistence failed; LinkLayer is permanently disabled"
            ) from exc
        finally:
            with self._persistence_meta_lock:
                self._persistence_transition_owner = None
            self._persistence_transition_guard.release()

    def ensure_healthy(self) -> None:
        """Verify persistence is healthy and no transition is in progress.

        Raises:
            LinkPersistenceError: If persistence has terminally failed.
            RuntimeError: If called during a persistence transition or callback.
        """
        with self._persistence_meta_lock:
            transition_owner = self._persistence_transition_owner
            if (
                transition_owner is not None
                and transition_owner != threading.get_ident()
            ):
                if self._persistence_hook_active:
                    self._persistence_reentry = True
                raise RuntimeError("LinkLayer operation during persistence transition")
            if self._persistence_hook_active:
                self._persistence_reentry = True
                raise RuntimeError("LinkLayer operation during persistence callback")
        if self._persistence_failed:
            raise LinkPersistenceError(
                "LinkLayer is disabled after a persistence failure"
            )

    def _save_persisted_state_unchecked(self) -> None:
        """Save state assuming transition guard is held."""
        assert self.persist_path is not None
        with self.security_lock:
            revision = self._persistence_revision + 1
            state = self.state_exporter.export_state()
            state["revision"] = revision
        with self._persistence_file_lock():
            expected_revision = (
                None if self._persistence_revision == 0 else self._persistence_revision
            )
            external_revision = self._read_persistence_revision_anchor()
            if external_revision != expected_revision:
                raise RuntimeError("stale LinkLayer persistence writer")
            canonical = self._write_signed_persistence_record(
                f"{self.persist_path}.{revision % 2}", state, b"state"
            )
            digest = hashlib.sha256(canonical).digest()
            self._write_persistence_anchor(
                f"{self.persist_path}.anchor", revision, digest
            )
            self._advance_persistence_revision_anchor(expected_revision, revision)
            with self.security_lock:
                self._persistence_revision = revision

    @contextlib.contextmanager
    def _persistence_file_lock(self):  # type: ignore[no-untyped-def]
        """Serialize prepare/write/CAS across every writer of one journal."""
        assert self.persist_path is not None
        parent = os.path.dirname(os.path.abspath(self.persist_path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        parent_stat = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & 0o022
        ):
            raise PermissionError(
                "persistence directory must be private and owned by this user"
            )
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(f"{self.persist_path}.lock", flags, 0o600)
        try:
            lock_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_uid != os.geteuid()
                or lock_stat.st_mode & 0o077
            ):
                raise PermissionError("persistence lock file is not private")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _call_persistence_anchor(
        self, callback: Callable[..., object], *args: object
    ) -> object:
        """Call an anchor callback with reentry detection."""
        with self._persistence_meta_lock:
            self._persistence_hook_active = True
            self._persistence_reentry = False
        try:
            result = reject_awaitable_result(
                callback(*args), "persistence revision anchor callback"
            )
        finally:
            with self._persistence_meta_lock:
                self._persistence_hook_active = False
        with self._persistence_meta_lock:
            if self._persistence_reentry:
                raise RuntimeError("link persistence callback reentry")
        return result

    def _read_persistence_revision_anchor(self) -> int | None:
        """Read the current revision from the external anchor."""
        anchor = self.revision_anchor
        if anchor is None:
            raise RuntimeError(
                "independent persistence revision anchor is unavailable"
            )
        revision = self._call_persistence_anchor(anchor.read, self.local_pubkey)
        if revision is not None and (type(revision) is not int or revision < 1):
            raise RuntimeError("independent persistence revision anchor is invalid")
        return revision

    def _advance_persistence_revision_anchor(
        self,
        expected: int | None,
        revision: int,
    ) -> None:
        """Advance the external revision anchor with verification."""
        anchor = self.revision_anchor
        if anchor is None:
            raise RuntimeError(
                "independent persistence revision anchor is unavailable"
            )
        self._call_persistence_anchor(
            anchor.advance, self.local_pubkey, expected, revision
        )
        if self._read_persistence_revision_anchor() != revision:
            raise RuntimeError(
                "independent persistence revision anchor did not advance"
            )

    def _persistence_message(self, domain: bytes, payload: dict[str, object]) -> bytes:
        """Construct a signed message envelope."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return b"LICHEN-LINK-PERSIST-v2\0" + domain + b"\0" + canonical

    def _write_signed_persistence_record(
        self,
        path: str,
        payload: dict[str, object],
        domain: bytes,
    ) -> bytes:
        """Write a signed persistence record atomically.

        Args:
            path: Destination file path.
            payload: JSON-serializable dict to persist.
            domain: Signature domain (b"state" or b"anchor").

        Returns:
            The canonical JSON bytes that were signed.

        Raises:
            PermissionError: If directory permissions are incorrect.
        """
        message = self._persistence_message(domain, payload)
        canonical = message.split(b"\0", 2)[2]
        envelope = {
            "payload": payload,
            "signature": sign(self.local_privkey, self.local_pubkey, message).hex(),
        }
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, mode=0o700, exist_ok=True)
        parent_stat = os.stat(parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or parent_stat.st_mode & 0o022
        ):
            raise PermissionError(
                "persistence directory must be private and owned by this user"
            )
        basename = os.path.basename(path)
        descriptor, temporary = tempfile.mkstemp(prefix=f".{basename}.tmp-", dir=parent)
        try:
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "w")
            descriptor = -1
            with handle:
                json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
            raise
        return canonical

    def _read_signed_persistence_record(
        self,
        path: str,
        domain: bytes,
    ) -> tuple[dict[str, object], bytes]:
        """Read and verify a signed persistence record.

        Args:
            path: Path to the persistence file.
            domain: Expected signature domain.

        Returns:
            Tuple of (payload dict, canonical JSON bytes).

        Raises:
            PermissionError: If file permissions are incorrect.
            ValueError: If signature verification fails or envelope is invalid.
        """
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        record_stat = os.fstat(descriptor)
        if not stat.S_ISREG(record_stat.st_mode):
            os.close(descriptor)
            raise PermissionError("persistence record is not a regular file")
        if record_stat.st_uid != os.geteuid() or record_stat.st_mode & 0o077:
            os.close(descriptor)
            raise PermissionError("persistence record is not private")
        with os.fdopen(descriptor) as handle:
            envelope = json.load(handle)
        if type(envelope) is not dict or set(envelope) != {"payload", "signature"}:
            raise ValueError("invalid persistence envelope")
        payload, signature_hex = envelope["payload"], envelope["signature"]
        if type(payload) is not dict or type(signature_hex) is not str:
            raise ValueError("invalid persistence envelope")
        signature = bytes.fromhex(signature_hex)
        message = self._persistence_message(domain, payload)
        if not verify(self.local_pubkey, message, signature):
            raise ValueError("invalid persistence signature")
        return payload, message.split(b"\0", 2)[2]

    def _write_persistence_anchor(
        self, path: str, revision: int, digest: bytes
    ) -> None:
        """Write the persistence anchor file."""
        self._write_signed_persistence_record(
            path,
            {"revision": revision, "digest": digest.hex()},
            b"anchor",
        )
