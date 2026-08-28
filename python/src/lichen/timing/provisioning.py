# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Board provisioning and epoch floor enforcement for authenticated time sync.

This module provides cryptographically authenticated provisioning records that
establish a rollback-resistant epoch floor. The epoch floor ensures that replay
attacks cannot use expired timestamps from before the device's provisioning date.

Key components:
- ProvisionRecord: Canonical identity/version/epoch record with integrity binding
- ProvisionVerifier: Admin-gated install with atomic persistent rollback protection
- EpochFloorAuthority: Immutable capability binding build epoch and verifier state
"""

from __future__ import annotations

import hashlib
import threading
import warnings
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from .source import (
    _UINT64_MAX,
    DEFAULT_MAX_PROVISION_LEAD_S,
    PROVISION_VIRGIN_MARKER,
    _call_sync,
    _epoch,
    _require_sync_callable,
    _uint,
)

if TYPE_CHECKING:
    from .time_sync import TimeAdmin


class ProvisionEpochStatus(StrEnum):
    MISSING = "missing"
    CLEARED = "cleared"
    ACCEPTED = "accepted"
    ZERO = "zero"
    MALFORMED = "malformed"
    UNAUTHENTICATED = "unauthenticated"
    IDENTITY_MISMATCH = "identity-mismatch"
    ROLLBACK = "rollback"
    BEFORE_BUILD = "before-build"
    BEYOND_LEAD = "beyond-lead"
    PERSISTENCE_FAILED = "persistence-failed"


def _get_time_admin_class() -> type:
    """Deferred import to avoid circular dependency."""
    from .time_sync import TimeAdmin
    return TimeAdmin


@dataclass(frozen=True, init=False, eq=False)
class ProvisionVirginState:
    """Admin-issued proof that persistent storage was initialized empty."""

    marker_digest: bytes
    _admin: TimeAdmin = field(repr=False, compare=False)

    def __new__(cls) -> ProvisionVirginState:
        raise TypeError("ProvisionVirginState is issued only by TimeAdmin")


@dataclass(frozen=True)
class ProvisionRecord:
    """Untrusted canonical identity/version/epoch record."""

    board_identity: bytes
    record_version: int
    epoch: int

    def __post_init__(self) -> None:
        if type(self.board_identity) is not bytes or len(self.board_identity) != 32:
            raise ValueError("board_identity must be 32 bytes")
        version = _uint(self.record_version, "record_version")
        if version == 0 or version > _UINT64_MAX:
            raise ValueError("record_version must be non-zero uint64")
        _epoch(self.epoch, "epoch", nonzero=True)

    def encode(self) -> bytes:
        return (
            self.board_identity
            + self.record_version.to_bytes(8, "big")
            + self.epoch.to_bytes(4, "big")
        )

    @classmethod
    def decode(cls, encoded: bytes) -> ProvisionRecord:
        if type(encoded) is not bytes or len(encoded) != 44:
            raise ValueError("provision record must be exactly 44 bytes")
        return cls(
            encoded[:32], int.from_bytes(encoded[32:40], "big"), int.from_bytes(encoded[40:], "big")
        )


@dataclass(frozen=True)
class ProvisionRollbackState:
    record_version: int
    epoch: int
    record_digest: bytes
    encoded_record: bytes

    def __post_init__(self) -> None:
        version = _uint(self.record_version, "record_version")
        if version > _UINT64_MAX:
            raise ValueError("record_version must be uint64")
        _epoch(self.epoch, "epoch", nonzero=True)
        if type(self.record_digest) is not bytes or len(self.record_digest) != 32:
            raise ValueError("record_digest must be 32 bytes")
        if type(self.encoded_record) is not bytes or len(self.encoded_record) != 44:
            raise ValueError("encoded_record must be a canonical provision record")
        record = ProvisionRecord.decode(self.encoded_record)
        if (
            record.record_version != self.record_version
            or record.epoch != self.epoch
            or hashlib.sha256(self.encoded_record).digest() != self.record_digest
        ):
            raise ValueError("persisted provision state does not match encoded_record")


def _detach_rollback_state(value: ProvisionRollbackState) -> ProvisionRollbackState:
    """Copy untrusted/hook-visible state into verifier-owned immutable primitives."""
    return ProvisionRollbackState(
        value.record_version,
        value.epoch,
        bytes(value.record_digest),
        bytes(value.encoded_record),
    )


def _rollback_state_snapshot(value: ProvisionRollbackState) -> tuple[object, ...]:
    return (
        value.record_version,
        value.epoch,
        value.record_digest,
        value.encoded_record,
    )


_PROVISION_CLEAR_DOMAIN: Final[bytes] = b"LICHEN-PROVISION-CLEARED-V1\x00"


def _provision_clear_digest(
    record_version: int,
    epoch: int,
    record_digest: bytes,
    encoded_record: bytes,
    reason: str,
) -> bytes:
    reason_wire = reason.encode("utf-8")
    return hashlib.sha256(
        _PROVISION_CLEAR_DOMAIN
        + record_version.to_bytes(8, "big")
        + epoch.to_bytes(4, "big")
        + record_digest
        + len(encoded_record).to_bytes(2, "big")
        + encoded_record
        + len(reason_wire).to_bytes(4, "big")
        + reason_wire
    ).digest()


@dataclass(frozen=True)
class ProvisionClearedState:
    """Canonical persisted inactive state retaining the rollback floor."""

    record_version: int
    epoch: int
    record_digest: bytes
    encoded_record: bytes
    reason: str
    state_digest: bytes

    def __post_init__(self) -> None:
        version = _uint(self.record_version, "record_version")
        if version > _UINT64_MAX:
            raise ValueError("record_version must be uint64")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("clear reason must be non-empty")
        if type(self.record_digest) is not bytes or len(self.record_digest) != 32:
            raise ValueError("record_digest must be 32 bytes")
        if type(self.encoded_record) is not bytes:
            raise TypeError("encoded_record must be bytes")
        if version == 0:
            if (
                self.epoch != 0
                or self.encoded_record
                or self.record_digest != hashlib.sha256(PROVISION_VIRGIN_MARKER).digest()
            ):
                raise ValueError("empty cleared state must bind the virgin-store marker")
        else:
            _detach_rollback_state(
                ProvisionRollbackState(
                    version, self.epoch, self.record_digest, self.encoded_record
                )
            )
        if (
            type(self.state_digest) is not bytes
            or self.state_digest
            != _provision_clear_digest(
                version,
                self.epoch,
                self.record_digest,
                self.encoded_record,
                self.reason,
            )
        ):
            raise ValueError("cleared provision state digest mismatch")

    def encode(self) -> bytes:
        """Return the exact canonical bytes authenticated by persistent storage."""
        reason_wire = self.reason.encode("utf-8")
        return (
            _PROVISION_CLEAR_DOMAIN
            + self.record_version.to_bytes(8, "big")
            + self.epoch.to_bytes(4, "big")
            + self.record_digest
            + len(self.encoded_record).to_bytes(2, "big")
            + self.encoded_record
            + len(reason_wire).to_bytes(4, "big")
            + reason_wire
            + self.state_digest
        )


def _new_cleared_state(
    rollback: ProvisionRollbackState | None, reason: str
) -> ProvisionClearedState:
    if rollback is None:
        version, epoch = 0, 0
        record_digest = hashlib.sha256(PROVISION_VIRGIN_MARKER).digest()
        encoded_record = b""
    else:
        version, epoch = rollback.record_version, rollback.epoch
        record_digest = bytes(rollback.record_digest)
        encoded_record = bytes(rollback.encoded_record)
    return ProvisionClearedState(
        version,
        epoch,
        record_digest,
        encoded_record,
        reason,
        _provision_clear_digest(version, epoch, record_digest, encoded_record, reason),
    )


@dataclass(frozen=True, init=False)
class ProvisionEpochMetadata:
    epoch: int
    board_identity: bytes
    record_version: int
    record_digest: bytes
    generation: int
    _verifier: object = field(repr=False, compare=False)

    def __new__(cls) -> ProvisionEpochMetadata:
        raise TypeError("ProvisionEpochMetadata is issued only by ProvisionVerifier")

    @property
    def integrity_valid(self) -> bool:
        return True


def _metadata_snapshot(value: ProvisionEpochMetadata) -> tuple[object, ...]:
    return (
        value.epoch,
        value.board_identity,
        value.record_version,
        value.record_digest,
        value.generation,
    )


@dataclass(frozen=True)
class EpochFloorResult:
    floor: int
    provision_status: ProvisionEpochStatus

    @property
    def provision_accepted(self) -> bool:
        return self.provision_status is ProvisionEpochStatus.ACCEPTED


@dataclass(frozen=True)
class EpochFloorSnapshot:
    """One floor and verifier generation held stable for a complete transition."""

    result: EpochFloorResult
    generation: int


class ProvisionVerifier:
    """Admin/integrity-gated install with atomic persistent rollback binding."""

    def __init__(
        self,
        *,
        expected_board_identity: bytes,
        rollback_state: ProvisionRollbackState | ProvisionClearedState | ProvisionVirginState,
        verify_integrity: Callable[[bytes], bool],
        persist_rollback_state: Callable[[ProvisionRollbackState], None],
        persist_clear: Callable[[ProvisionClearedState], None],
        admin: TimeAdmin,
    ) -> None:
        TimeAdmin = _get_time_admin_class()  # noqa: N806
        if type(expected_board_identity) is not bytes or len(expected_board_identity) != 32:
            raise ValueError("expected_board_identity must be 32 bytes")
        if type(rollback_state) not in (
            ProvisionRollbackState,
            ProvisionClearedState,
            ProvisionVirginState,
        ):
            raise TypeError("rollback_state must be an explicit persisted provision state")
        _require_sync_callable(verify_integrity, "verify_integrity")
        _require_sync_callable(persist_rollback_state, "persist_rollback_state")
        _require_sync_callable(persist_clear, "persist_clear")
        if type(admin) is not TimeAdmin:
            raise TypeError("admin must be exact TimeAdmin")
        if type(rollback_state) is ProvisionVirginState and (
            rollback_state._admin is not admin
            or rollback_state.marker_digest != hashlib.sha256(PROVISION_VIRGIN_MARKER).digest()
            or not admin._consume_virgin_state(rollback_state)
        ):
            raise ValueError("virgin provision state is not bound to the configured admin")
        if type(rollback_state) is ProvisionClearedState:
            try:
                rollback_state = ProvisionClearedState(
                    rollback_state.record_version,
                    rollback_state.epoch,
                    bytes(rollback_state.record_digest),
                    bytes(rollback_state.encoded_record),
                    rollback_state.reason,
                    bytes(rollback_state.state_digest),
                )
                if _call_sync(
                    verify_integrity,
                    "verify_integrity",
                    rollback_state.encode(),
                ) is not True:
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid-persisted-cleared-state") from exc
        self.__expected_identity = bytes(expected_board_identity)
        if type(rollback_state) is ProvisionRollbackState:
            initial_rollback: ProvisionRollbackState | None = _detach_rollback_state(
                rollback_state
            )
        elif type(rollback_state) is ProvisionClearedState and rollback_state.record_version:
            initial_rollback = ProvisionRollbackState(
                rollback_state.record_version,
                rollback_state.epoch,
                bytes(rollback_state.record_digest),
                bytes(rollback_state.encoded_record),
            )
        else:
            initial_rollback = None
        self.__rollback = initial_rollback
        self.__verify_integrity = verify_integrity
        self.__persist_rollback = persist_rollback_state
        self.__persist_clear = persist_clear
        self.__admin = admin
        self.__generation = 0
        self.__cleared = type(rollback_state) is ProvisionClearedState
        self.__current: ProvisionEpochMetadata | None = None
        self.__active_floor_primitives: tuple[int, bytes, int, bytes] | None = None
        self.__issued: weakref.WeakValueDictionary[int, ProvisionEpochMetadata] = (
            weakref.WeakValueDictionary()
        )
        self.__snapshots: dict[int, tuple[object, ...]] = {}
        self.__lock = threading.RLock()
        self.__transition_guard = threading.Lock()
        self.__transition_meta_lock = threading.Lock()
        self.__external_hook_active = False
        self.__transition_violation = False
        self.__persistence_failed = False
        if initial_rollback is not None:
            try:
                record = ProvisionRecord.decode(initial_rollback.encoded_record)
                if (
                    record.board_identity != self.__expected_identity
                    or record.record_version != initial_rollback.record_version
                    or record.epoch != initial_rollback.epoch
                    or hashlib.sha256(initial_rollback.encoded_record).digest()
                    != initial_rollback.record_digest
                    or _call_sync(
                        self.__verify_integrity,
                        "verify_integrity",
                        initial_rollback.encoded_record,
                    )
                    is not True
                ):
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid-persisted-provision-state") from exc
            self.__generation = 1
            if not self.__cleared:
                self.__current = self._issue_locked(record, initial_rollback.record_digest)
                self.__active_floor_primitives = (
                    record.epoch,
                    bytes(record.board_identity),
                    record.record_version,
                    bytes(initial_rollback.record_digest),
                )

    @property
    def expected_board_identity(self) -> bytes:
        return self.__expected_identity

    @property
    def minimum_record_version(self) -> int:
        with self.__lock:
            return self.__rollback.record_version if self.__rollback is not None else 0

    @property
    def cleared(self) -> bool:
        with self.__lock:
            return self.__cleared

    def _poison_after_persistence_failure(self) -> None:
        """Irreversibly revoke all live authority after an ambiguous write."""
        with self.__lock:
            self.__persistence_failed = True
            self.__generation += 1
            self.__current = None
            self.__active_floor_primitives = None
            self.__cleared = True

    def _ensure_persistence_healthy_locked(self) -> None:
        if self.__persistence_failed:
            raise RuntimeError("provision verifier is poisoned after persistence failure")

    def _begin_transition(self) -> None:
        if self.__transition_guard.acquire(blocking=False):
            with self.__transition_meta_lock:
                self.__transition_violation = False
            return
        with self.__transition_meta_lock:
            if self.__external_hook_active:
                self.__transition_violation = True
                raise RuntimeError("provision transition reentry")
        raise RuntimeError("provision transition already in progress")

    def _end_transition(self) -> None:
        self.__transition_guard.release()

    def _call_transition_hook(
        self, callback: Callable[..., object], name: str, *args: object
    ) -> object:
        with self.__transition_meta_lock:
            self.__external_hook_active = True
        try:
            result = _call_sync(callback, name, *args)
        finally:
            with self.__transition_meta_lock:
                self.__external_hook_active = False
        with self.__transition_meta_lock:
            if self.__transition_violation:
                raise RuntimeError("provision transition reentry")
        return result

    def _assert_transition_clean(self) -> None:
        with self.__transition_meta_lock:
            if self.__transition_violation:
                raise RuntimeError("provision transition reentry")

    def _issue_locked(self, record: ProvisionRecord, digest: bytes) -> ProvisionEpochMetadata:
        metadata = object.__new__(ProvisionEpochMetadata)
        for key, value in (
            ("epoch", record.epoch),
            ("board_identity", record.board_identity),
            ("record_version", record.record_version),
            ("record_digest", digest),
            ("generation", self.__generation),
            ("_verifier", self),
        ):
            object.__setattr__(metadata, key, value)
        item_id = id(metadata)
        self.__issued[item_id] = metadata
        self.__snapshots[item_id] = _metadata_snapshot(metadata)
        weakref.finalize(metadata, self.__snapshots.pop, item_id, None)
        return metadata

    def install(self, admin: TimeAdmin, encoded_record: bytes) -> ProvisionEpochMetadata:
        if admin is not self.__admin:
            raise PermissionError("provision install requires bound admin")
        if type(encoded_record) is not bytes:
            raise TypeError("encoded_record must be bytes")
        self._begin_transition()
        persistence_invoked = False
        try:
            record = ProvisionRecord.decode(encoded_record)
            if record.board_identity != self.__expected_identity:
                raise ValueError("identity-mismatch")
            if (
                self._call_transition_hook(
                    self.__verify_integrity,
                    "verify_integrity",
                    encoded_record,
                )
                is not True
            ):
                raise ValueError("unauthenticated")
            digest = hashlib.sha256(encoded_record).digest()
            candidate = ProvisionRollbackState(
                record.record_version, record.epoch, digest, encoded_record
            )
            with self.__lock:
                self._ensure_persistence_healthy_locked()
                current = self.__rollback
                was_cleared = self.__cleared
                if current is None and candidate.record_version == 0:
                    raise ValueError("record-version-must-advance")
                if current is not None:
                    if candidate.record_version < current.record_version:
                        raise ValueError("rollback")
                    if candidate.record_version == current.record_version:
                        if candidate != current:
                            raise ValueError("same-version-content-mismatch")
                        if self.__current is not None and self.accepts(self.__current):
                            return self.__current
            # Reactivation after clear is itself durable state and MUST be
            # persisted even when the canonical record is unchanged.
            if candidate != current or was_cleared:
                persisted_candidate = _detach_rollback_state(candidate)
                persisted_snapshot = _rollback_state_snapshot(persisted_candidate)
                persistence_invoked = True
                self._call_transition_hook(
                    self.__persist_rollback,
                    "persist_rollback_state",
                    persisted_candidate,
                )
                if _rollback_state_snapshot(persisted_candidate) != persisted_snapshot:
                    raise RuntimeError("persistence hook mutated rollback state")
            self._assert_transition_clean()
            with self.__lock:
                self.__rollback = _detach_rollback_state(candidate)
                self.__generation += 1
                metadata = self._issue_locked(record, digest)
                self.__current = metadata
                self.__active_floor_primitives = (
                    record.epoch,
                    bytes(record.board_identity),
                    record.record_version,
                    bytes(digest),
                )
                self.__cleared = False
                return metadata
        except BaseException:
            if persistence_invoked:
                self._poison_after_persistence_failure()
            raise
        finally:
            self._end_transition()

    def accepts(self, metadata: ProvisionEpochMetadata) -> bool:
        with self.__lock:
            item_id = id(metadata)
            return (
                type(metadata) is ProvisionEpochMetadata
                and metadata._verifier is self
                and metadata.generation == self.__generation
                and self.__issued.get(item_id) is metadata
                and self.__snapshots.get(item_id) == _metadata_snapshot(metadata)
                and self.__current is metadata
                and not self.__cleared
                and not self.__persistence_failed
            )

    def current(self) -> ProvisionEpochMetadata | None:
        with self.__lock:
            return (
                self.__current
                if self.__current is not None and self.accepts(self.__current)
                else None
            )

    def _with_floor_snapshot(
        self,
        build: int,
        lead: int,
        transition: Callable[[EpochFloorSnapshot], object],
    ) -> object:
        """Run one synchronous floor-dependent operation under the verifier lock."""
        with self.__lock:
            result = self._floor_result_locked(build, lead)
            return transition(EpochFloorSnapshot(result, self.__generation))

    def _floor_result_locked(self, build: int, lead: int) -> EpochFloorResult:
        if self.__persistence_failed:
            return EpochFloorResult(build, ProvisionEpochStatus.PERSISTENCE_FAILED)
        primitives = self.__active_floor_primitives
        if primitives is None or self.__cleared:
            return EpochFloorResult(
                build,
                ProvisionEpochStatus.CLEARED
                if self.__cleared
                else ProvisionEpochStatus.MISSING,
            )
        epoch, board_identity, _version, _digest = primitives
        if board_identity != self.__expected_identity:
            return EpochFloorResult(build, ProvisionEpochStatus.IDENTITY_MISMATCH)
        if epoch < build:
            return EpochFloorResult(build, ProvisionEpochStatus.BEFORE_BUILD)
        if epoch - build > lead:
            return EpochFloorResult(build, ProvisionEpochStatus.BEYOND_LEAD)
        return EpochFloorResult(epoch, ProvisionEpochStatus.ACCEPTED)

    def _evaluate_metadata_floor(
        self,
        metadata: ProvisionEpochMetadata,
        build: int,
        lead: int,
    ) -> EpochFloorResult:
        """Evaluate one exact live facade solely from verifier-owned primitives."""
        with self.__lock:
            if not self.accepts(metadata):
                return EpochFloorResult(build, ProvisionEpochStatus.UNAUTHENTICATED)
            return self._floor_result_locked(build, lead)

    def _missing_metadata_floor(self, build: int) -> EpochFloorResult:
        with self.__lock:
            if self.__persistence_failed:
                return EpochFloorResult(build, ProvisionEpochStatus.PERSISTENCE_FAILED)
            return EpochFloorResult(
                build,
                ProvisionEpochStatus.CLEARED
                if self.__cleared
                else ProvisionEpochStatus.MISSING,
            )

    def clear(self, admin: TimeAdmin, *, reason: str) -> None:
        if admin is not self.__admin:
            raise PermissionError("provision clear requires bound admin")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("clear reason must be non-empty")
        self._begin_transition()
        persistence_invoked = False
        try:
            with self.__lock:
                self._ensure_persistence_healthy_locked()
                cleared = _new_cleared_state(self.__rollback, reason)
            persisted_clear = ProvisionClearedState(
                cleared.record_version,
                cleared.epoch,
                bytes(cleared.record_digest),
                bytes(cleared.encoded_record),
                cleared.reason,
                bytes(cleared.state_digest),
            )
            clear_snapshot = (
                persisted_clear.record_version,
                persisted_clear.epoch,
                persisted_clear.record_digest,
                persisted_clear.encoded_record,
                persisted_clear.reason,
                persisted_clear.state_digest,
            )
            persistence_invoked = True
            self._call_transition_hook(
                self.__persist_clear, "persist_clear", persisted_clear
            )
            if (
                persisted_clear.record_version,
                persisted_clear.epoch,
                persisted_clear.record_digest,
                persisted_clear.encoded_record,
                persisted_clear.reason,
                persisted_clear.state_digest,
            ) != clear_snapshot:
                raise RuntimeError("persistence hook mutated cleared state")
            self._assert_transition_clean()
            with self.__lock:
                self.__generation += 1
                self.__current = None
                self.__active_floor_primitives = None
                self.__cleared = True
        except BaseException:
            if persistence_invoked:
                self._poison_after_persistence_failure()
            raise
        finally:
            self._end_transition()


def evaluate_epoch_floor(
    firmware_build_epoch: int,
    board_provision: ProvisionEpochMetadata | None,
    *,
    verifier: ProvisionVerifier | None = None,
    max_provision_lead_s: int = DEFAULT_MAX_PROVISION_LEAD_S,
) -> EpochFloorResult:
    build = _epoch(firmware_build_epoch, "firmware_build_epoch", nonzero=True)
    lead = _uint(max_provision_lead_s, "max_provision_lead_s")
    if verifier is not None and type(verifier) is not ProvisionVerifier:
        raise TypeError("verifier must be an exact ProvisionVerifier or None")
    if board_provision is None:
        return (
            verifier._missing_metadata_floor(build)
            if verifier is not None
            else EpochFloorResult(build, ProvisionEpochStatus.MISSING)
        )
    if type(board_provision) is not ProvisionEpochMetadata:
        raise TypeError("board_provision must be ProvisionEpochMetadata or None")
    if verifier is None:
        return EpochFloorResult(build, ProvisionEpochStatus.UNAUTHENTICATED)
    return verifier._evaluate_metadata_floor(board_provision, build, lead)


def effective_epoch_floor(
    firmware_build_epoch: int,
    board_provision_epoch: int | ProvisionEpochMetadata | None,
    *,
    verifier: ProvisionVerifier | None = None,
    max_provision_lead_s: int = DEFAULT_MAX_PROVISION_LEAD_S,
) -> int:
    if verifier is not None and type(verifier) is not ProvisionVerifier:
        raise TypeError("verifier must be an exact ProvisionVerifier or None")
    if isinstance(board_provision_epoch, int) and not isinstance(board_provision_epoch, bool):
        warnings.warn(
            "raw board provision is unauthenticated and ignored", DeprecationWarning, stacklevel=2
        )
        return _epoch(firmware_build_epoch, "firmware_build_epoch", nonzero=True)
    if isinstance(board_provision_epoch, bool):
        raise TypeError("board_provision_epoch must be metadata, int, or None")
    return evaluate_epoch_floor(
        firmware_build_epoch,
        board_provision_epoch,
        verifier=verifier,
        max_provision_lead_s=max_provision_lead_s,
    ).floor


class EpochFloorAuthority:
    """Immutable build epoch plus current verifier-issued provision state."""

    __slots__ = ("__weakref__",)

    def __init__(
        self,
        firmware_build_epoch: int,
        *,
        verifier: ProvisionVerifier | None = None,
        max_provision_lead_s: int = DEFAULT_MAX_PROVISION_LEAD_S,
    ) -> None:
        build = _epoch(firmware_build_epoch, "firmware_build_epoch", nonzero=True)
        if verifier is not None and type(verifier) is not ProvisionVerifier:
            raise TypeError("verifier must be exact ProvisionVerifier or None")
        lead = _uint(max_provision_lead_s, "max_provision_lead_s")
        with _FLOOR_AUTHORITY_BINDINGS_LOCK:
            if self in _FLOOR_AUTHORITY_BINDINGS:
                raise RuntimeError("EpochFloorAuthority is already initialized")
            _FLOOR_AUTHORITY_BINDINGS[self] = (build, verifier, lead)

    def _binding_snapshot(self) -> tuple[object, ...]:
        with _FLOOR_AUTHORITY_BINDINGS_LOCK:
            build, verifier, lead = _FLOOR_AUTHORITY_BINDINGS[self]
            return (build, id(verifier), lead)

    def _with_snapshot(
        self, transition: Callable[[EpochFloorSnapshot], object]
    ) -> object:
        with _FLOOR_AUTHORITY_BINDINGS_LOCK:
            build, verifier, lead = _FLOOR_AUTHORITY_BINDINGS[self]
        if verifier is None:
            return transition(
                EpochFloorSnapshot(
                    evaluate_epoch_floor(build, None, max_provision_lead_s=lead), 0
                )
            )
        return verifier._with_floor_snapshot(build, lead, transition)

    def current(self) -> EpochFloorResult:
        result = self._with_snapshot(lambda snapshot: snapshot.result)
        assert isinstance(result, EpochFloorResult)
        return result


_FLOOR_AUTHORITY_BINDINGS_LOCK = threading.RLock()
_FLOOR_AUTHORITY_BINDINGS: weakref.WeakKeyDictionary[
    EpochFloorAuthority, tuple[int, ProvisionVerifier | None, int]
] = weakref.WeakKeyDictionary()
