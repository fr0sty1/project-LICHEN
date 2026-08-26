# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Coordinator-managed short addresses carried by RPL DAO/DAO-ACK.

The generic RPL codec deliberately knows nothing about LICHEN extensions.  This
module places a compact, versioned assignment payload in one RPL option and
provides the state machine around it.  Option type 252 is project-private; it
does not claim an IANA allocation.

Coordinator state is serialized before an allocation or release becomes
visible in memory.  A storage adapter can therefore provide atomic durable
``save`` semantics without coupling the protocol to a filesystem.
"""

from __future__ import annotations

import binascii
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv6Address
from typing import Final, Protocol

from lichen.link.short_addr import derive_short_addr, derive_short_addr_with_seed
from lichen.rpl.messages import DAO, DAOAck, RplOption

SHORT_ADDRESS_OPTION_TYPE: Final[int] = 252
SHORT_ADDRESS_OPTION_VERSION: Final[int] = 1
SHORT_ADDRESS_NONE: Final[int] = 0xFFFF
_REQUEST_KIND: Final[int] = 0
_ACK_KIND: Final[int] = 1
_REQUEST_LENGTH: Final[int] = 13
_ACK_LENGTH: Final[int] = 14
_STATE_MAGIC: Final[bytes] = b"SAA1"
_STATE_RECORD_LENGTH: Final[int] = 10
_TABLE_STATE_MAGIC: Final[bytes] = b"SAT2"
_TABLE_STATE_RECORD_LENGTH: Final[int] = 20
_NO_EXPIRY: Final[int] = (1 << 64) - 1
_NO_SEQUENCE: Final[int] = 256
_FIRST_SHORT: Final[int] = 1
_LAST_SHORT: Final[int] = 0xFFFD
_SHORT_POOL_SIZE: Final[int] = _LAST_SHORT


class AssignmentProtocolError(ValueError):
    """An assignment message or persisted state is malformed."""


class AssignmentPersistenceError(RuntimeError):
    """Coordinator assignment state could not be loaded or committed."""


class AssignmentOperation(IntEnum):
    """Operation requested in a DAO assignment option."""

    ALLOCATE = 0
    RELEASE = 1


class AssignmentStatus(IntEnum):
    """Status mirrored in the DAO-ACK base object and assignment option."""

    SUCCESS = 0
    EXHAUSTED = 1
    INVALID = 2


class AddressAssignmentStore(Protocol):
    """Persistence adapter whose ``save`` operation is atomic."""

    def load(self) -> bytes | None:
        """Return the last complete state blob, or ``None`` on first boot."""

    def save(self, state: bytes) -> None:
        """Atomically replace the durable state blob."""


class MemoryAddressAssignmentStore:
    """In-memory persistence adapter for simulation and restart tests."""

    def __init__(self, state: bytes | None = None) -> None:
        self._state = None if state is None else bytes(state)

    def load(self) -> bytes | None:
        return self._state

    def save(self, state: bytes) -> None:
        self._state = bytes(state)


def _check_eui64(eui64: bytes) -> bytes:
    if type(eui64) is not bytes or len(eui64) != 8:
        raise AssignmentProtocolError("EUI-64 must be exactly 8 immutable bytes")
    return eui64


def _check_short(short_addr: int) -> int:
    if isinstance(short_addr, bool) or not isinstance(short_addr, int):
        raise AssignmentProtocolError("short address must be an integer")
    if not _FIRST_SHORT <= short_addr <= _LAST_SHORT:
        raise AssignmentProtocolError("short address must be in 0x0001..0xfffd")
    return short_addr


def _one_assignment_option(options: list[RplOption]) -> RplOption:
    matches = [option for option in options if option.type == SHORT_ADDRESS_OPTION_TYPE]
    if len(matches) != 1:
        raise AssignmentProtocolError("message must contain exactly one short-address option")
    return matches[0]


@dataclass(frozen=True)
class AddressAssignmentRequest:
    """A node's allocation or release request."""

    eui64: bytes
    operation: AssignmentOperation = AssignmentOperation.ALLOCATE
    requested_short: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "eui64", _check_eui64(self.eui64))
        try:
            operation = AssignmentOperation(self.operation)
        except (TypeError, ValueError) as exc:
            raise AssignmentProtocolError("unknown assignment operation") from exc
        object.__setattr__(self, "operation", operation)
        if operation is AssignmentOperation.RELEASE and self.requested_short is not None:
            raise AssignmentProtocolError("release request cannot carry a preferred address")
        if self.requested_short is not None:
            object.__setattr__(self, "requested_short", _check_short(self.requested_short))

    def to_option(self) -> RplOption:
        short_addr = self.requested_short
        if short_addr is None:
            short_addr = SHORT_ADDRESS_NONE
        payload = bytes(
            (
                SHORT_ADDRESS_OPTION_VERSION,
                _REQUEST_KIND,
                int(self.operation),
            )
        ) + self.eui64 + short_addr.to_bytes(2, "big")
        return RplOption(SHORT_ADDRESS_OPTION_TYPE, payload)

    @classmethod
    def from_option(cls, option: RplOption) -> AddressAssignmentRequest:
        if option.type != SHORT_ADDRESS_OPTION_TYPE or len(option.data) != _REQUEST_LENGTH:
            raise AssignmentProtocolError("invalid short-address request option")
        version, kind, operation = option.data[:3]
        if version != SHORT_ADDRESS_OPTION_VERSION or kind != _REQUEST_KIND:
            raise AssignmentProtocolError("unsupported short-address request encoding")
        requested = int.from_bytes(option.data[11:13], "big")
        return cls(
            eui64=bytes(option.data[3:11]),
            operation=AssignmentOperation(operation),
            requested_short=None if requested == SHORT_ADDRESS_NONE else requested,
        )

    def to_dao(
        self,
        rpl_instance_id: int,
        dao_sequence: int,
        *,
        dodag_id: IPv6Address | None = None,
    ) -> DAO:
        """Build an ACK-requesting RPL DAO containing this request."""
        return DAO(
            rpl_instance_id=rpl_instance_id,
            dao_sequence=dao_sequence,
            dodag_id=dodag_id,
            ack_requested=True,
            options=[self.to_option()],
        )

    @classmethod
    def from_dao(cls, dao: DAO) -> AddressAssignmentRequest:
        if not dao.ack_requested:
            raise AssignmentProtocolError("address-assignment DAO must request an ACK")
        return cls.from_option(_one_assignment_option(dao.options))


@dataclass(frozen=True)
class AddressAssignmentAck:
    """Coordinator result carried by an RPL DAO-ACK."""

    eui64: bytes
    operation: AssignmentOperation
    status: AssignmentStatus
    assigned_short: int | None
    dao_sequence: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "eui64", _check_eui64(self.eui64))
        try:
            operation = AssignmentOperation(self.operation)
            status = AssignmentStatus(self.status)
        except (TypeError, ValueError) as exc:
            raise AssignmentProtocolError("unknown assignment ACK value") from exc
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "status", status)
        if isinstance(self.dao_sequence, bool) or not isinstance(self.dao_sequence, int):
            raise AssignmentProtocolError("DAO sequence must be an integer")
        if not 0 <= self.dao_sequence <= 0xFF:
            raise AssignmentProtocolError("DAO sequence must fit in uint8")
        if self.assigned_short is not None:
            object.__setattr__(self, "assigned_short", _check_short(self.assigned_short))
        should_assign = (
            operation is AssignmentOperation.ALLOCATE and status is AssignmentStatus.SUCCESS
        )
        if should_assign != (self.assigned_short is not None):
            raise AssignmentProtocolError("ACK address is inconsistent with operation/status")

    def to_option(self) -> RplOption:
        short_addr = self.assigned_short
        if short_addr is None:
            short_addr = SHORT_ADDRESS_NONE
        payload = bytes(
            (
                SHORT_ADDRESS_OPTION_VERSION,
                _ACK_KIND,
                int(self.operation),
                int(self.status),
            )
        ) + self.eui64 + short_addr.to_bytes(2, "big")
        return RplOption(SHORT_ADDRESS_OPTION_TYPE, payload)

    @classmethod
    def from_option(cls, option: RplOption, dao_sequence: int) -> AddressAssignmentAck:
        if option.type != SHORT_ADDRESS_OPTION_TYPE or len(option.data) != _ACK_LENGTH:
            raise AssignmentProtocolError("invalid short-address ACK option")
        version, kind, operation, status = option.data[:4]
        if version != SHORT_ADDRESS_OPTION_VERSION or kind != _ACK_KIND:
            raise AssignmentProtocolError("unsupported short-address ACK encoding")
        assigned = int.from_bytes(option.data[12:14], "big")
        return cls(
            eui64=bytes(option.data[4:12]),
            operation=AssignmentOperation(operation),
            status=AssignmentStatus(status),
            assigned_short=None if assigned == SHORT_ADDRESS_NONE else assigned,
            dao_sequence=dao_sequence,
        )

    def to_dao_ack(
        self,
        rpl_instance_id: int,
        *,
        dodag_id: IPv6Address | None = None,
    ) -> DAOAck:
        return DAOAck(
            rpl_instance_id=rpl_instance_id,
            dao_sequence=self.dao_sequence,
            status=int(self.status),
            dodag_id=dodag_id,
            options=[self.to_option()],
        )

    @classmethod
    def from_dao_ack(cls, ack: DAOAck) -> AddressAssignmentAck:
        result = cls.from_option(_one_assignment_option(ack.options), ack.dao_sequence)
        if ack.status != int(result.status):
            raise AssignmentProtocolError("DAO-ACK status disagrees with assignment option")
        return result


def encode_assignment_state(assignments: Mapping[int, bytes]) -> bytes:
    """Encode a deterministic, checksummed coordinator snapshot."""
    if len(assignments) > _SHORT_POOL_SIZE:
        raise AssignmentProtocolError("too many short-address assignments")
    seen_euis: set[bytes] = set()
    records = bytearray()
    for short_addr, raw_eui64 in sorted(assignments.items()):
        short_addr = _check_short(short_addr)
        eui64 = _check_eui64(raw_eui64)
        if eui64 in seen_euis:
            raise AssignmentProtocolError("one EUI-64 cannot own multiple short addresses")
        seen_euis.add(eui64)
        records.extend(short_addr.to_bytes(2, "big"))
        records.extend(eui64)
    body = _STATE_MAGIC + len(assignments).to_bytes(2, "big") + bytes(records)
    checksum = binascii.crc32(body).to_bytes(4, "big")
    return body + checksum


def decode_assignment_state(state: bytes) -> dict[int, bytes]:
    """Decode a snapshot, failing closed on truncation, corruption, or collision."""
    if type(state) is not bytes:
        raise AssignmentProtocolError("assignment state must be immutable bytes")
    if len(state) < 10 or state[:4] != _STATE_MAGIC:
        raise AssignmentProtocolError("invalid assignment state header")
    count = int.from_bytes(state[4:6], "big")
    expected_length = 6 + count * _STATE_RECORD_LENGTH + 4
    if len(state) != expected_length:
        raise AssignmentProtocolError("assignment state length does not match record count")
    if binascii.crc32(state[:-4]).to_bytes(4, "big") != state[-4:]:
        raise AssignmentProtocolError("assignment state checksum mismatch")
    assignments: dict[int, bytes] = {}
    seen_euis: set[bytes] = set()
    previous = 0
    offset = 6
    for _ in range(count):
        short_addr = int.from_bytes(state[offset : offset + 2], "big")
        eui64 = bytes(state[offset + 2 : offset + 10])
        offset += _STATE_RECORD_LENGTH
        _check_short(short_addr)
        if short_addr <= previous:
            raise AssignmentProtocolError("assignment state records are not strictly sorted")
        if eui64 in seen_euis:
            raise AssignmentProtocolError("assignment state contains duplicate EUI-64")
        previous = short_addr
        seen_euis.add(eui64)
        assignments[short_addr] = eui64
    return assignments


def _encode_table_state(
    assignments: Mapping[int, bytes],
    expiries: Mapping[bytes, int],
    sequences: Mapping[bytes, int],
) -> bytes:
    if len(assignments) > _SHORT_POOL_SIZE:
        raise AssignmentProtocolError("too many short-address assignments")
    seen_euis: set[bytes] = set()
    records = bytearray()
    for short_addr, raw_eui64 in sorted(assignments.items()):
        short_addr = _check_short(short_addr)
        eui64 = _check_eui64(raw_eui64)
        if eui64 in seen_euis:
            raise AssignmentProtocolError("one EUI-64 cannot own multiple short addresses")
        seen_euis.add(eui64)
        expiry = expiries.get(eui64)
        if expiry is None:
            expiry = _NO_EXPIRY
        if isinstance(expiry, bool) or not isinstance(expiry, int) or not 0 <= expiry <= _NO_EXPIRY:
            raise AssignmentProtocolError("lease expiry must fit in uint64")
        sequence = sequences.get(eui64, _NO_SEQUENCE)
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 256:
            raise AssignmentProtocolError("last DAO sequence is invalid")
        records.extend(short_addr.to_bytes(2, "big"))
        records.extend(eui64)
        records.extend(expiry.to_bytes(8, "big"))
        records.extend(sequence.to_bytes(2, "big"))
    body = _TABLE_STATE_MAGIC + len(assignments).to_bytes(2, "big") + bytes(records)
    return body + binascii.crc32(body).to_bytes(4, "big")


def _decode_table_state(
    state: bytes,
) -> tuple[dict[int, bytes], dict[bytes, int], dict[bytes, int]]:
    if not state.startswith(_TABLE_STATE_MAGIC):
        return decode_assignment_state(state), {}, {}
    if len(state) < 10:
        raise AssignmentProtocolError("invalid coordinator table state header")
    count = int.from_bytes(state[4:6], "big")
    expected_length = 6 + count * _TABLE_STATE_RECORD_LENGTH + 4
    if len(state) != expected_length:
        raise AssignmentProtocolError("coordinator table state length mismatch")
    if binascii.crc32(state[:-4]).to_bytes(4, "big") != state[-4:]:
        raise AssignmentProtocolError("coordinator table state checksum mismatch")
    assignments: dict[int, bytes] = {}
    expiries: dict[bytes, int] = {}
    sequences: dict[bytes, int] = {}
    seen_euis: set[bytes] = set()
    previous = 0
    offset = 6
    for _ in range(count):
        short_addr = int.from_bytes(state[offset : offset + 2], "big")
        eui64 = bytes(state[offset + 2 : offset + 10])
        expiry = int.from_bytes(state[offset + 10 : offset + 18], "big")
        sequence = int.from_bytes(state[offset + 18 : offset + 20], "big")
        offset += _TABLE_STATE_RECORD_LENGTH
        _check_short(short_addr)
        _check_eui64(eui64)
        if short_addr <= previous:
            raise AssignmentProtocolError("coordinator table records are not strictly sorted")
        if eui64 in seen_euis:
            raise AssignmentProtocolError("coordinator table contains duplicate EUI-64")
        if sequence > _NO_SEQUENCE:
            raise AssignmentProtocolError("persisted DAO sequence is invalid")
        previous = short_addr
        seen_euis.add(eui64)
        assignments[short_addr] = eui64
        if expiry != _NO_EXPIRY:
            expiries[eui64] = expiry
        if sequence != _NO_SEQUENCE:
            sequences[eui64] = sequence
    return assignments, expiries, sequences


class ShortAddressCoordinator:
    """Allocates unique addresses and returns wire-ready DAO-ACKs."""

    def __init__(
        self,
        *,
        store: AddressAssignmentStore | None = None,
        initial_assignments: Mapping[int, bytes] | None = None,
        capacity: int = _SHORT_POOL_SIZE,
        lease_seconds: int | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if store is not None and initial_assignments is not None:
            raise ValueError("store and initial_assignments are mutually exclusive")
        if isinstance(capacity, bool) or not isinstance(capacity, int):
            raise TypeError("capacity must be an integer")
        if not 1 <= capacity <= _SHORT_POOL_SIZE:
            raise ValueError(f"capacity must be in 1..{_SHORT_POOL_SIZE}")
        if lease_seconds is not None:
            if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
                raise TypeError("lease_seconds must be an integer or None")
            if lease_seconds < 1:
                raise ValueError("lease_seconds must be positive")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._lock = threading.RLock()
        self._store = store
        self._capacity = capacity
        self._lease_seconds = lease_seconds
        self._clock = clock
        try:
            stored = None if store is None else store.load()
        except Exception as exc:
            raise AssignmentPersistenceError("could not load assignment state") from exc
        if stored is not None:
            assignments, expiries, sequences = _decode_table_state(stored)
        elif initial_assignments is not None:
            assignments = decode_assignment_state(encode_assignment_state(initial_assignments))
            expiries = {}
            sequences = {}
        else:
            assignments = {}
            expiries = {}
            sequences = {}
        if len(assignments) > capacity:
            raise AssignmentProtocolError("persisted assignments exceed coordinator capacity")
        self._by_short = assignments
        self._by_eui = {eui64: short_addr for short_addr, eui64 in assignments.items()}
        self._expires_by_eui = expiries
        self._last_sequence_by_eui = sequences
        self.prune_expired()

    def _commit(
        self,
        assignments: dict[int, bytes],
        expiries: dict[bytes, int],
        sequences: dict[bytes, int],
    ) -> None:
        blob = _encode_table_state(assignments, expiries, sequences)
        if self._store is not None:
            try:
                self._store.save(blob)
            except Exception as exc:
                raise AssignmentPersistenceError("could not commit assignment state") from exc
        self._by_short = assignments
        self._by_eui = {eui64: short_addr for short_addr, eui64 in assignments.items()}
        self._expires_by_eui = expiries
        self._last_sequence_by_eui = sequences

    def lookup_by_short(self, short_addr: int) -> bytes | None:
        with self._lock:
            return self._by_short.get(short_addr)

    def lookup_by_eui(self, eui64: bytes) -> int | None:
        eui64 = _check_eui64(eui64)
        with self._lock:
            return self._by_eui.get(eui64)

    def expires_at(self, eui64: bytes) -> int | None:
        """Return a peer's absolute lease deadline, if leases are enabled."""
        eui64 = _check_eui64(eui64)
        with self._lock:
            return self._expires_by_eui.get(eui64)

    def prune_expired(self, now: int | None = None) -> int:
        """Release all leases whose deadlines are at or before ``now``."""
        if now is None:
            now = int(self._clock())
        if isinstance(now, bool) or not isinstance(now, int):
            raise TypeError("now must be an integer Unix timestamp")
        if now < 0:
            raise ValueError("now must be non-negative")
        with self._lock:
            expired = {
                eui64 for eui64, deadline in self._expires_by_eui.items() if deadline <= now
            }
            if not expired:
                return 0
            assignments = {
                short_addr: eui64
                for short_addr, eui64 in self._by_short.items()
                if eui64 not in expired
            }
            expiries = {
                eui64: deadline
                for eui64, deadline in self._expires_by_eui.items()
                if eui64 not in expired
            }
            sequences = {
                eui64: sequence
                for eui64, sequence in self._last_sequence_by_eui.items()
                if eui64 not in expired
            }
            self._commit(assignments, expiries, sequences)
            return len(expired)

    @staticmethod
    def _fallback(start: int, occupied: set[int]) -> int | None:
        if len(occupied) >= _SHORT_POOL_SIZE:
            return None
        for offset in range(_SHORT_POOL_SIZE):
            candidate = _FIRST_SHORT + ((start - _FIRST_SHORT + offset) % _SHORT_POOL_SIZE)
            if candidate not in occupied:
                return candidate
        return None

    def _candidate(self, eui64: bytes, preferred: int | None) -> int | None:
        occupied = set(self._by_short)
        if preferred is not None and preferred not in occupied:
            return preferred
        derived = derive_short_addr(eui64)
        if _FIRST_SHORT <= derived <= _LAST_SHORT and derived not in occupied:
            return derived
        for seed in range(1, 256):
            candidate = derive_short_addr_with_seed(eui64, seed)
            if _FIRST_SHORT <= candidate <= _LAST_SHORT and candidate not in occupied:
                return candidate
        start = preferred if preferred is not None else max(derived, _FIRST_SHORT)
        return self._fallback(start, occupied)

    def process(self, request: AddressAssignmentRequest, dao_sequence: int) -> AddressAssignmentAck:
        """Apply one request; retransmission is idempotent."""
        if isinstance(dao_sequence, bool) or not isinstance(dao_sequence, int):
            raise AssignmentProtocolError("DAO sequence must be an integer")
        if not 0 <= dao_sequence <= 0xFF:
            raise AssignmentProtocolError("DAO sequence must fit in uint8")
        with self._lock:
            now = int(self._clock())
            self.prune_expired(now)
            current = self._by_eui.get(request.eui64)
            if request.operation is AssignmentOperation.RELEASE:
                if current is not None:
                    updated = dict(self._by_short)
                    del updated[current]
                    expiries = dict(self._expires_by_eui)
                    expiries.pop(request.eui64, None)
                    sequences = dict(self._last_sequence_by_eui)
                    sequences.pop(request.eui64, None)
                    self._commit(updated, expiries, sequences)
                return AddressAssignmentAck(
                    request.eui64,
                    request.operation,
                    AssignmentStatus.SUCCESS,
                    None,
                    dao_sequence,
                )
            if current is None:
                if len(self._by_short) >= self._capacity:
                    return AddressAssignmentAck(
                        request.eui64,
                        request.operation,
                        AssignmentStatus.EXHAUSTED,
                        None,
                        dao_sequence,
                    )
                current = self._candidate(request.eui64, request.requested_short)
                if current is None:
                    return AddressAssignmentAck(
                        request.eui64,
                        request.operation,
                        AssignmentStatus.EXHAUSTED,
                        None,
                        dao_sequence,
                    )
                updated = dict(self._by_short)
                updated[current] = request.eui64
                expiries = dict(self._expires_by_eui)
                if self._lease_seconds is not None:
                    expiries[request.eui64] = now + self._lease_seconds
                sequences = dict(self._last_sequence_by_eui)
                sequences[request.eui64] = dao_sequence
                self._commit(updated, expiries, sequences)
            elif self._last_sequence_by_eui.get(request.eui64) != dao_sequence:
                expiries = dict(self._expires_by_eui)
                if self._lease_seconds is not None:
                    expiries[request.eui64] = now + self._lease_seconds
                sequences = dict(self._last_sequence_by_eui)
                sequences[request.eui64] = dao_sequence
                self._commit(dict(self._by_short), expiries, sequences)
            return AddressAssignmentAck(
                request.eui64,
                request.operation,
                AssignmentStatus.SUCCESS,
                current,
                dao_sequence,
            )

    def handle_dao(self, dao: DAO) -> DAOAck:
        request = AddressAssignmentRequest.from_dao(dao)
        result = self.process(request, dao.dao_sequence)
        return result.to_dao_ack(dao.rpl_instance_id, dodag_id=dao.dodag_id)

    def snapshot(self) -> dict[int, bytes]:
        with self._lock:
            return dict(self._by_short)

    @property
    def capacity(self) -> int:
        return self._capacity

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_short)


class ShortAddressAssignmentClient:
    """Node-side DAO-ACK validator and assignment state."""

    def __init__(self, eui64: bytes) -> None:
        self.eui64 = _check_eui64(eui64)
        self.assigned_short: int | None = None
        self._last_ack: bytes | None = None
        self._last_sequence: int | None = None

    def apply_dao_ack(self, ack: DAOAck, expected_sequence: int) -> bool:
        """Apply only an ACK for this identity and outstanding DAO sequence."""
        result = AddressAssignmentAck.from_dao_ack(ack)
        if result.dao_sequence != expected_sequence:
            return False
        if result.eui64 != self.eui64:
            return False
        fingerprint = ack.to_bytes()
        if self._last_ack is not None and self._last_sequence == result.dao_sequence:
            if fingerprint == self._last_ack:
                return True
            raise AssignmentProtocolError("conflicting DAO-ACK for one sequence")
        if result.status is not AssignmentStatus.SUCCESS:
            return False
        self.assigned_short = result.assigned_short
        self._last_ack = fingerprint
        self._last_sequence = result.dao_sequence
        return True


__all__ = [
    "SHORT_ADDRESS_OPTION_TYPE",
    "SHORT_ADDRESS_OPTION_VERSION",
    "AddressAssignmentAck",
    "AddressAssignmentRequest",
    "AddressAssignmentStore",
    "AssignmentOperation",
    "AssignmentPersistenceError",
    "AssignmentProtocolError",
    "AssignmentStatus",
    "MemoryAddressAssignmentStore",
    "ShortAddressAssignmentClient",
    "ShortAddressCoordinator",
    "decode_assignment_state",
    "encode_assignment_state",
]
