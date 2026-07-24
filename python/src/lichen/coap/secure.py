# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""OSCORE-protected transport layer for LICHEN CoAP (spec section 8.7).

Provides transparent OSCORE encryption/decryption for CoAP datagrams.
Security contexts can be pre-provisioned or established via EDHOC.

Usage:
    # Wrap any DatagramChannel with OSCORE protection
    secure = SecureDatagramChannel(
        inner_channel,
        local_identity,
        context_store,
    )

    # Use with aiocoap as normal
    ctx = await create_lichen_context(secure, local_host)

Architecture:
    This module operates at the datagram layer, below aiocoap's message
    handling. When a datagram arrives, we:
    1. Parse enough to detect OSCORE option
    2. Unprotect using stored security context
    3. Pass plaintext to aiocoap

    On send, we:
    1. Receive plaintext from aiocoap
    2. Protect with OSCORE
    3. Send ciphertext via inner channel

    EDHOC key establishment (spec 8.8) runs as CoAP POSTs to
    /.well-known/edhoc before the first protected exchange.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import stat
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, TypeGuard, TypeVar, cast, runtime_checkable

import aiocoap
from aiocoap import Message
from aiocoap.numbers.codes import EMPTY, POST
from aiocoap.numbers.types import ACK, CON, RST
from aiocoap.oscore import Direction

from lichen.crypto.edhoc import EdhocInitiator, OscoreContext
from lichen.crypto.oscore import (
    MAX_OSCORE_SEQUENCE_NUMBER,
    MemorySecurityContext,
    OscoreContextParameters,
)

from .transport import (
    DatagramChannel,
    Endpoint,
    EndpointPolicy,
    LichenRemote,
    LichenTransport,
    ReceiveCallback,
    parse_channel_endpoint,
)

if TYPE_CHECKING:
    from lichen.crypto.identity import Identity

logger = logging.getLogger(__name__)
_T = TypeVar("_T")

# OSCORE option number (RFC 8613 Section 2)
OSCORE_OPTION_NUMBER = 9


class _EdhocChannel(DatagramChannel):
    """A channel wrapper for EDHOC exchange that bypasses OSCORE.

    EDHOC messages are sent as raw CoAP over the inner channel. This
    wrapper ensures EDHOC traffic doesn't get OSCORE-protected (which
    would fail since we don't have a context yet).

    The SecureDatagramChannel holds a reference to this channel and
    dispatches EDHOC-related plaintext to it.
    """

    def __init__(self, inner: DatagramChannel) -> None:
        self._inner = inner
        self._receiver: ReceiveCallback | None = None

    def send_datagram(self, data: bytes, dest: str) -> None:
        self._inner.send_datagram(data, dest)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver == receiver:
            self._receiver = None

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._inner.endpoint_policy

    def dispatch(self, data: bytes, source: str) -> None:
        """Dispatch received data to the registered receiver.

        Called by SecureDatagramChannel when EDHOC-related plaintext arrives.
        """
        if self._receiver is not None:
            self._receiver(data, source)

    def close(self) -> None:
        pass  # Don't close the inner channel


def _monotonic_time() -> float:
    """Get monotonic time, usable with or without event loop."""
    try:
        loop = asyncio.get_running_loop()
        return loop.time()
    except RuntimeError:
        # No running event loop, use time.monotonic()
        import time

        return time.monotonic()


@dataclass
class PeerContext:
    """OSCORE context and metadata for a peer."""

    oscore: MemorySecurityContext
    peer_pubkey: bytes
    generation: int = 1
    established_at: float = field(default_factory=_monotonic_time)
    outbound_requests: dict[bytes, _RequestCorrelation] = field(default_factory=dict)
    inbound_requests: dict[bytes, _RequestCorrelation] = field(default_factory=dict)


@dataclass
class _RequestCorrelation:
    request_id: object | None
    observe: bool
    lifecycle_id: object = field(default_factory=object)
    interested: bool = True
    cancelled_observe: bool = False
    cancellation_timer: asyncio.TimerHandle | None = None
    cancellation_deadline: float | None = None
    terminal: bool = False
    pending_sends: int = 0
    con_mids: set[int] = field(default_factory=set)


@dataclass
class _ProtectedCon:
    data: bytes
    token: bytes
    locally_originated: bool
    correlation: _RequestCorrelation | None = None
    plaintext: bytes = b""


@dataclass
class _SendOperation:
    correlation: _RequestCorrelation
    token: bytes
    locally_originated: bool
    finished: bool = False


@dataclass
class _UnprotectedDatagram:
    data: bytes
    message: Message
    added_correlation: _RequestCorrelation | None = None
    matched_correlation: _RequestCorrelation | None = None


@dataclass(frozen=True)
class SequenceReservation:
    """A durably committed half-open sender sequence range."""

    start: int
    end: int
    generation: int


class PeerKeyConflictError(ValueError):
    """A peer host is already bound to a different public key."""


class ContextGenerationError(RuntimeError):
    """A context publication or reservation used a stale generation."""


class SequenceReservationError(RuntimeError):
    """A sender sequence range could not be reserved."""


class ForkSafetyError(RuntimeError):
    """An inherited in-memory security lease was used after fork."""


class ReplayWindowConflictError(RuntimeError):
    """A replay-window compare-and-set lost to another authenticated packet."""

    def __init__(self, index: int, bitfield: int) -> None:
        super().__init__("OSCORE replay window changed concurrently")
        self.current_state = (index, bitfield)


class EndpointPolicyConflictError(RuntimeError):
    """A store was bound to an incompatible endpoint namespace."""


def validate_endpoint_key(endpoint: str) -> str:
    """Validate and canonicalize a DatagramChannel endpoint key."""
    if not endpoint:
        raise ValueError("endpoint key must not be empty")
    if len(endpoint) > 4096:
        raise ValueError("endpoint key is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in endpoint):
        raise ValueError("endpoint key must not contain control characters")
    try:
        endpoint.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("endpoint key must be valid UTF-8") from error
    return parse_channel_endpoint(endpoint).authority


def normalize_host(host: str) -> str:
    """Compatibility alias for canonical endpoint handling."""
    return validate_endpoint_key(host)


def _encode_nonnegative_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("integer must be non-negative")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


@dataclass
class _HostRecord:
    peer_pubkey: bytes
    context: PeerContext | None = None
    generation: int = 0


def _host_records_semantically_equal(left: _HostRecord, right: _HostRecord) -> bool:
    if left.peer_pubkey != right.peer_pubkey or left.generation != right.generation:
        return False
    if left.context is None or right.context is None:
        return left.context is right.context
    return (
        left.context.peer_pubkey == right.context.peer_pubkey
        and left.context.generation == right.context.generation
        and left.context.oscore.export_parameters()
        == right.context.oscore.export_parameters()
        and left.context.oscore.sender_sequence_number
        == right.context.oscore.sender_sequence_number
        and left.context.oscore.export_replay_window()
        == right.context.oscore.export_replay_window()
    )


def _sqlite_host_values_semantically_equal(
    left: tuple[Any, ...], right: tuple[Any, ...]
) -> bool:
    """Compare persisted host rows by reconstructed security meaning."""
    if len(left) != 12 or len(right) != 12:
        return False
    blob_indexes = {0, 1, 2, 3, 4, 8, 9, 10}
    for index, (left_value, right_value) in enumerate(zip(left, right, strict=True)):
        if index == 5:
            if left_value is None or right_value is None:
                if left_value is not right_value:
                    return False
            elif json.loads(str(left_value)) != json.loads(str(right_value)):
                return False
        elif index in blob_indexes:
            if left_value is None or right_value is None:
                if left_value is not right_value:
                    return False
            elif bytes(left_value) != bytes(right_value):
                return False
        elif left_value != right_value:
            return False
    return True


@runtime_checkable
class TransactionalOscoreContextStore(Protocol):
    """Transactional OSCORE store contract.

    Implementations MUST normalize endpoint keys under their bound
    :class:`EndpointPolicy`. ``put`` MUST atomically verify/create the peer binding,
    compare ``expected_generation``,
    advance generation, publish reconstructable context material, and recover the
    permanent sender/replay ledgers. A different bound key or stale generation MUST
    leave all state unchanged. ``reserve_sender_sequences`` MUST durably advance one
    sender-identity high-water before returning a disjoint half-open range.

    ``compare_and_set_replay_window`` MUST atomically verify host generation and
    recipient identity, compare the exact expected replay state, and replace it with
    the new state. A mismatch MUST raise :class:`ReplayWindowConflictError` carrying
    the authoritative state without mutation. ``pin_peer`` MUST be idempotent for the
    same key and reject a different key without mutation. ``remove`` MUST tombstone
    only active context state while preserving the pin, generation history, and all
    identity ledgers.

    Durable methods MUST not expose success before commit. Cancellation before a
    transaction starts MUST expose old state; after work starts the definitive
    committed result or failure MUST remain observable. Forked implementations MUST
    either reload durable state or fail closed.
    """

    def check_process(self) -> None: ...
    def get_sync(self, host: str) -> PeerContext | None: ...
    async def get(self, host: str) -> PeerContext | None: ...
    async def get_generation(self, host: str) -> int | None: ...
    async def put(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext: ...
    def put_sync(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext: ...
    async def reserve_sender_sequences(
        self, host: str, generation: int, count: int
    ) -> SequenceReservation: ...
    async def compare_and_set_replay_window(
        self,
        host: str,
        generation: int,
        recipient_identity: bytes,
        expected_index: int,
        expected_bitfield: int,
        new_index: int,
        new_bitfield: int,
    ) -> None: ...
    async def get_peer_pubkey(self, host: str) -> bytes | None: ...
    async def pin_peer(self, host: str, pubkey: bytes) -> None: ...
    async def pin_peers(self, pins: Mapping[str, bytes]) -> None: ...
    def migrate_endpoint_keys(
        self,
        policy: EndpointPolicy,
        pending_pins: Mapping[str, bytes],
    ) -> None: ...
    async def remove(self, host: str) -> None: ...
    def has_context_sync(self, host: str) -> bool: ...
    async def has_context(self, host: str) -> bool: ...


class InMemoryOscoreContextStore:
    """Transactional in-memory implementation of the context-store contract.

    A host record atomically binds a peer key, serializable context, generation,
    and permanent sender/replay identity ledgers. Publications never replace a
    different key. The store fails closed if inherited by a forked child.

    Note: This class can be instantiated before the event loop starts.
    The internal lock is created lazily on first async access.
    """

    def __init__(self) -> None:
        self._records: dict[str, _HostRecord] = {}
        self._sender_ledgers: dict[bytes, int] = {}
        self._replay_ledgers: dict[bytes, tuple[int, int]] = {}
        self._lock: asyncio.Lock | None = None
        self._endpoint_policy: EndpointPolicy | None = None
        self._pid = os.getpid()

    def _normalize_key(self, host: str) -> str:
        return (self._endpoint_policy or EndpointPolicy()).normalize(host).authority

    def check_process(self) -> None:
        if os.getpid() != self._pid:
            raise ForkSafetyError("in-memory OSCORE store cannot be used after fork")

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the asyncio lock (must be called from async context)."""
        self.check_process()
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def get_sync(self, host: str) -> PeerContext | None:
        """Get a context synchronously; supported by the in-memory store only."""
        self.check_process()
        record = self._records.get(self._normalize_key(host))
        return None if record is None else record.context

    async def get(self, host: str) -> PeerContext | None:
        """Get OSCORE context for a peer, or None if not established."""
        async with self._get_lock():
            record = self._records.get(self._normalize_key(host))
            return None if record is None else record.context

    async def get_generation(self, host: str) -> int | None:
        async with self._get_lock():
            record = self._records.get(self._normalize_key(host))
            return None if record is None or record.generation == 0 else record.generation

    async def put(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext:
        """Store OSCORE context for a peer."""
        self.check_process()
        key = self._normalize_key(host)
        async with self._get_lock():
            record = self._records.get(key)
            if record is None:
                record = _HostRecord(bytes(peer_pubkey))
                self._records[key] = record
            if record.peer_pubkey != bytes(peer_pubkey):
                raise PeerKeyConflictError(f"peer {key} is already bound to a different key")
            if expected_generation is not None and record.generation != expected_generation:
                raise ContextGenerationError(f"context generation changed for {key}")
            context = PeerContext(
                oscore=oscore_ctx,
                peer_pubkey=bytes(peer_pubkey),
                generation=record.generation + 1 if record.generation else 1,
            )
            record.context = context
            record.generation = context.generation
            return context

    def put_sync(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext:
        """Store OSCORE context (synchronous)."""
        self.check_process()
        key = self._normalize_key(host)
        record = self._records.get(key)
        if record is None:
            record = _HostRecord(bytes(peer_pubkey))
            self._records[key] = record
        if record.peer_pubkey != bytes(peer_pubkey):
            raise PeerKeyConflictError(f"peer {key} is already bound to a different key")
        if expected_generation is not None and record.generation != expected_generation:
            raise ContextGenerationError(f"context generation changed for {key}")
        context = PeerContext(
            oscore=oscore_ctx,
            peer_pubkey=bytes(peer_pubkey),
            generation=record.generation + 1 if record.generation else 1,
        )
        record.context = context
        record.generation = context.generation
        return context

    async def reserve_sender_sequences(
        self, host: str, generation: int, count: int
    ) -> SequenceReservation:
        """Atomically reserve and commit a sender sequence block."""
        self.check_process()
        if count <= 0:
            raise ValueError("reservation count must be positive")
        async with self._get_lock():
            key = self._normalize_key(host)
            record = self._records.get(key)
            if record is not None and record.generation != generation:
                raise ContextGenerationError(f"context generation changed for {key}")
            if record is None or record.context is None:
                raise SequenceReservationError(f"no context exists for {key}")
            sender_identity = record.context.oscore.sender_cryptographic_identity()
            start = self._sender_ledgers[sender_identity]
            limit = MAX_OSCORE_SEQUENCE_NUMBER + 1
            if start >= limit:
                raise SequenceReservationError("OSCORE sender sequence space is exhausted")
            end = min(start + count, limit)
            self._sender_ledgers[sender_identity] = end
            return SequenceReservation(start, end, generation)

    async def compare_and_set_replay_window(
        self,
        host: str,
        generation: int,
        recipient_identity: bytes,
        expected_index: int,
        expected_bitfield: int,
        new_index: int,
        new_bitfield: int,
    ) -> None:
        async with self._get_lock():
            key = self._normalize_key(host)
            record = self._records.get(key)
            if record is None or record.context is None:
                raise ContextGenerationError(f"no context exists for {key}")
            if record.generation != generation:
                raise ContextGenerationError(f"context generation changed for {key}")
            if record.context.oscore.recipient_cryptographic_identity() != recipient_identity:
                raise ContextGenerationError(f"recipient identity changed for {key}")
            if min(expected_index, expected_bitfield, new_index, new_bitfield) < 0:
                raise ValueError("invalid OSCORE replay window state")
            current = self._replay_ledgers[bytes(recipient_identity)]
            if current != (expected_index, expected_bitfield):
                raise ReplayWindowConflictError(*current)
            self._replay_ledgers[bytes(recipient_identity)] = (new_index, new_bitfield)

    async def get_peer_pubkey(self, host: str) -> bytes | None:
        """Return the authoritative peer binding, if present."""
        async with self._get_lock():
            record = self._records.get(self._normalize_key(host))
            return None if record is None else record.peer_pubkey

    async def pin_peer(self, host: str, pubkey: bytes) -> None:
        """Atomically create or verify a peer key binding."""
        await self.pin_peers({host: pubkey})

    async def pin_peers(self, pins: Mapping[str, bytes]) -> None:
        """Atomically create or verify a batch of peer bindings."""
        async with self._get_lock():
            staged = dict(self._records)
            for host, pubkey in pins.items():
                key = self._normalize_key(host)
                value = bytes(pubkey)
                existing = staged.get(key)
                if existing is not None and existing.peer_pubkey != value:
                    raise PeerKeyConflictError(f"TOFU violation: peer {key} key changed")
                if existing is None:
                    staged[key] = _HostRecord(value)
            self._records = staged

    def migrate_endpoint_keys(
        self,
        policy: EndpointPolicy,
        pending_pins: Mapping[str, bytes],
    ) -> None:
        """Atomically normalize all host records and merge pending pins."""
        self.check_process()
        if self._lock is not None and self._lock.locked():
            raise RuntimeError("context store is busy")
        if self._endpoint_policy is not None and self._endpoint_policy != policy:
            raise EndpointPolicyConflictError(
                "in-memory context store is bound to an incompatible endpoint policy"
            )
        staged: dict[str, tuple[str, _HostRecord]] = {}
        for old_key, record in self._records.items():
            key = policy.normalize(old_key).authority
            existing = staged.get(key)
            if existing is not None and not _host_records_semantically_equal(
                existing[1], record
            ):
                raise PeerKeyConflictError(
                    f"endpoint aliases normalize to conflicting record {key}"
                )
            if existing is None or (old_key == key and existing[0] != key):
                staged[key] = (old_key, record)
        for old_key, pubkey in pending_pins.items():
            key = policy.normalize(old_key).authority
            value = bytes(pubkey)
            existing = staged.get(key)
            if existing is not None and existing[1].peer_pubkey != value:
                raise PeerKeyConflictError(
                    f"endpoint aliases normalize to {key} with different keys"
                )
            if existing is None:
                staged[key] = (old_key, _HostRecord(value))
        self._records = {key: value[1] for key, value in staged.items()}
        self._endpoint_policy = policy

    async def remove(self, host: str) -> None:
        """Tombstone a context while preserving peer binding and identity ledgers."""
        async with self._get_lock():
            record = self._records.get(self._normalize_key(host))
            if record is not None and record.context is not None:
                record.context = None
                record.generation += 1

    def has_context_sync(self, host: str) -> bool:
        """Check if we have a context (synchronous)."""
        self.check_process()
        record = self._records.get(self._normalize_key(host))
        return record is not None and record.context is not None

    async def has_context(self, host: str) -> bool:
        """Check if we have a context for a peer."""
        async with self._get_lock():
            record = self._records.get(self._normalize_key(host))
            return record is not None and record.context is not None


class OscoreContextStore(InMemoryOscoreContextStore):
    """Backward-compatible public in-memory OSCORE context store."""


class SqliteStoreHooks:
    """Optional deterministic lifecycle hooks for SQLite store observability."""

    async def before_transaction(self, operation: str, host: str) -> None:
        """Run before a transaction worker starts; cancellation is still safe."""

    def transaction_step(self, operation: str, step: str) -> None:
        """Observe a worker transaction step; raising rolls the transaction back."""


class SqliteOscoreContextStore:
    """Durable SQLite implementation of the transactional context-store contract."""

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS oscore_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS oscore_hosts (
            host TEXT PRIMARY KEY,
            peer_pubkey BLOB NOT NULL,
            master_secret BLOB,
            master_salt BLOB,
            sender_id BLOB,
            recipient_id BLOB,
            algorithm_json TEXT,
            hashfun TEXT,
            window_size INTEGER,
            id_context BLOB,
            sender_identity BLOB,
            recipient_identity BLOB,
            generation INTEGER NOT NULL DEFAULT 0,
            CHECK (generation >= 0)
        );
        CREATE TABLE IF NOT EXISTS oscore_sender_ledgers (
            sender_identity BLOB PRIMARY KEY,
            high_water INTEGER NOT NULL,
            CHECK (high_water >= 0 AND high_water <= 1099511627776)
        );
        CREATE TABLE IF NOT EXISTS oscore_replay_ledgers (
            recipient_identity BLOB PRIMARY KEY,
            window_index INTEGER NOT NULL,
            bitfield BLOB NOT NULL,
            CHECK (window_index >= 0)
        );
    """

    def __init__(self, path: str | Path, *, hooks: SqliteStoreHooks | None = None) -> None:
        self._path = str(path)
        if self._path == ":memory:":
            raise ValueError("SQLite context store requires a durable filesystem path")
        self._pid = os.getpid()
        self._thread_lock = threading.Lock()
        self._hooks = hooks or SqliteStoreHooks()
        self._cache: dict[str, PeerContext] = {}
        self._endpoint_policy: EndpointPolicy | None = None
        self._prepare_database_file()
        self._initialize()

    def _policy_locked(self, connection: sqlite3.Connection) -> EndpointPolicy:
        row = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
        if row is None:
            policy = EndpointPolicy()
            rows = connection.execute(
                "SELECT host, peer_pubkey, master_secret, master_salt, sender_id, "
                "recipient_id, algorithm_json, hashfun, window_size, id_context, "
                "sender_identity, recipient_identity, generation "
                "FROM oscore_hosts ORDER BY host"
            ).fetchall()
            staged: dict[str, tuple[str, tuple[Any, ...]]] = {}
            for legacy_row in rows:
                old_key = str(legacy_row[0])
                key = policy.normalize(old_key).authority
                values = tuple(legacy_row[1:])
                existing = staged.get(key)
                if existing is not None and not _sqlite_host_values_semantically_equal(
                    existing[1], values
                ):
                    raise PeerKeyConflictError(
                        f"legacy endpoint aliases normalize to conflicting record {key}"
                    )
                if existing is None or (old_key == key and existing[0] != key):
                    staged[key] = (old_key, values)
            current = {str(legacy_row[0]): tuple(legacy_row[1:]) for legacy_row in rows}
            replacement = {key: values for key, (_old, values) in staged.items()}
            if current != replacement:
                connection.execute("DELETE FROM oscore_hosts")
                connection.executemany(
                    "INSERT INTO oscore_hosts (host, peer_pubkey, master_secret, master_salt, "
                    "sender_id, recipient_id, algorithm_json, hashfun, window_size, "
                    "id_context, sender_identity, recipient_identity, generation) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(key, *values) for key, values in replacement.items()],
                )
            connection.execute(
                "INSERT INTO oscore_metadata (key, value) VALUES ('endpoint_policy', ?)",
                (policy.serialize(),),
            )
            self._hooks.transaction_step("migrate", "after_write")
            self._cache.clear()
            return policy
        persisted = EndpointPolicy.deserialize(str(row[0]))
        if self._endpoint_policy is not None and self._endpoint_policy != persisted:
            raise EndpointPolicyConflictError(
                "SQLite context store endpoint policy changed incompatibly"
            )
        if self._endpoint_policy is None:
            self._cache.clear()
            self._endpoint_policy = persisted
        return persisted

    def _normalize_key_locked(self, connection: sqlite3.Connection, host: str) -> str:
        return self._policy_locked(connection).normalize(host).authority

    def check_process(self) -> None:
        pid = os.getpid()
        if pid != self._pid:
            self._pid = pid
            self._thread_lock = threading.Lock()
            self._cache = {}

    def _prepare_database_file(self) -> None:
        path = Path(self._path)
        parent = path.parent
        try:
            parent_metadata = parent.lstat()
        except FileNotFoundError as error:
            raise FileNotFoundError("SQLite context store parent must exist") from error
        if not stat.S_ISDIR(parent_metadata.st_mode):
            raise ValueError("SQLite context store parent must be a real directory")
        if parent_metadata.st_uid != os.geteuid():
            raise PermissionError("SQLite context store parent must be owned by the current user")
        if stat.S_IMODE(parent_metadata.st_mode) & 0o022:
            raise PermissionError("SQLite context store parent must not be group/other writable")
        protected_child = parent.absolute()
        for ancestor in protected_child.parents:
            ancestor_metadata = ancestor.lstat()
            if not stat.S_ISDIR(ancestor_metadata.st_mode):
                raise ValueError("SQLite context store ancestors must be real directories")
            if stat.S_IMODE(ancestor_metadata.st_mode) & 0o022:
                child_metadata = protected_child.lstat()
                sticky = bool(ancestor_metadata.st_mode & stat.S_ISVTX)
                if not sticky or child_metadata.st_uid != os.geteuid():
                    raise PermissionError(
                        "SQLite context store path has an unsafe writable ancestor"
                    )
            protected_child = ancestor
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags, 0o600)
            os.close(descriptor)
            metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("SQLite context store path must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise PermissionError("SQLite context store must be owned by the current user")
        os.chmod(path, 0o600, follow_symlinks=False)
        if stat.S_IMODE(path.stat(follow_symlinks=False).st_mode) != 0o600:
            raise PermissionError("SQLite context store permissions must be 0600")

    def _connect(self) -> sqlite3.Connection:
        self._prepare_database_file()
        connection = sqlite3.connect(self._path, timeout=30.0)
        journal_mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        if journal_mode is None or str(journal_mode[0]).lower() != "delete":
            connection.close()
            raise RuntimeError("SQLite context store requires DELETE journal mode")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("PRAGMA journal_size_limit = 0")
        return connection

    def _initialize(self) -> None:
        with self._thread_lock, self._connect() as connection:
            connection.executescript(self._SCHEMA)
            row = connection.execute(
                "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
            ).fetchone()
            if row is not None:
                self._endpoint_policy = EndpointPolicy.deserialize(str(row[0]))

    async def _transaction(self, operation: str, host: str, worker: Callable[[], _T]) -> _T:
        self.check_process()
        await self._hooks.before_transaction(operation, host)
        task = asyncio.create_task(asyncio.to_thread(worker))
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                current = asyncio.current_task()
                if current is not None:
                    while current.cancelling():
                        current.uncancel()
            except BaseException:
                break
        return task.result()

    @staticmethod
    def _row_context(row: tuple[Any, ...] | None) -> PeerContext | None:
        if row is None or row[1] is None:
            return None
        parameters = OscoreContextParameters(
            master_secret=bytes(row[1]),
            master_salt=bytes(row[2]),
            sender_id=bytes(row[3]),
            recipient_id=bytes(row[4]),
            algorithm=json.loads(row[5]),
            hashfun=str(row[6]),
            window_size=int(row[7]),
            id_context=None if row[8] is None else bytes(row[8]),
        )
        if row[12] is None or row[13] is None or row[14] is None:
            raise RuntimeError("OSCORE context ledger is incomplete")
        high_water = int(row[12])
        oscore = MemorySecurityContext.from_parameters(
            parameters, starting_sequence_number=high_water
        )
        oscore.restore_replay_window(int(row[13]), int.from_bytes(bytes(row[14]), "big"))
        return PeerContext(oscore, bytes(row[0]), generation=int(row[11]))

    async def get(self, host: str) -> PeerContext | None:
        self.check_process()

        def worker() -> PeerContext | None:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                policy = self._policy_locked(connection)
                key = policy.normalize(host).authority
                row = connection.execute(
                    "SELECT peer_pubkey, master_secret, master_salt, sender_id, "
                    "recipient_id, algorithm_json, hashfun, window_size, id_context, "
                    "h.sender_identity, h.recipient_identity, generation, n.high_water, "
                    "r.window_index, r.bitfield FROM oscore_hosts AS h "
                    "LEFT JOIN oscore_sender_ledgers AS n "
                    "ON n.sender_identity = h.sender_identity "
                    "LEFT JOIN oscore_replay_ledgers AS r "
                    "ON r.recipient_identity = h.recipient_identity WHERE host = ?",
                    (key,),
                ).fetchone()
                self._hooks.transaction_step("get", "after_read")
                connection.commit()
                self._endpoint_policy = policy
                if row is None or row[1] is None:
                    self._cache.pop(key, None)
                    return None
                cached = self._cache.get(key)
                if cached is not None and cached.generation == int(row[11]):
                    persisted_replay = (
                        int(row[13]),
                        int.from_bytes(bytes(row[14]), "big"),
                    )
                    if cached.oscore.export_replay_window() != persisted_replay:
                        cached.oscore.restore_replay_window(*persisted_replay)
                    return cached
                context = self._row_context(cast(tuple[Any, ...], row))
                if context is not None:
                    self._cache[key] = context
                return context

        return await self._transaction("get", host, worker)

    async def get_generation(self, host: str) -> int | None:
        self.check_process()

        def worker() -> int | None:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                policy = self._policy_locked(connection)
                key = policy.normalize(host).authority
                row = connection.execute(
                    "SELECT generation FROM oscore_hosts WHERE host = ?", (key,)
                ).fetchone()
                self._hooks.transaction_step("get_generation", "after_read")
                connection.commit()
                self._endpoint_policy = policy
                return None if row is None or int(row[0]) == 0 else int(row[0])

        return await self._transaction("get_generation", host, worker)

    def get_sync(self, host: str) -> PeerContext | None:
        self.check_process()
        raise RuntimeError("durable context stores require asynchronous access")

    async def put(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext:
        self.check_process()
        pubkey = bytes(peer_pubkey)
        parameters = oscore_ctx.export_parameters()
        high_water = oscore_ctx.sender_sequence_number
        sender_identity = oscore_ctx.sender_cryptographic_identity()
        recipient_identity = oscore_ctx.recipient_cryptographic_identity()
        initial_replay = oscore_ctx.export_replay_window()

        def worker() -> PeerContext:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                key = self._normalize_key_locked(connection, host)
                cached = self._cache.get(key)
                same_object_generation = (
                    cached.generation
                    if cached is not None and cached.oscore is oscore_ctx
                    else None
                )
                row = connection.execute(
                    "SELECT peer_pubkey, generation FROM oscore_hosts WHERE host = ?",
                    (key,),
                ).fetchone()
                if row is not None and bytes(row[0]) != pubkey:
                    raise PeerKeyConflictError(f"peer {key} is already bound to a different key")
                current_generation = 0 if row is None else int(row[1])
                if current_generation:
                    if expected_generation != current_generation:
                        raise ContextGenerationError(
                            f"context generation changed for {key}: expected "
                            f"{expected_generation}, found {current_generation}"
                        )
                    idempotent = same_object_generation == current_generation
                    generation = current_generation if idempotent else current_generation + 1
                else:
                    if expected_generation is not None:
                        raise ContextGenerationError(f"no context generation exists for {key}")
                    idempotent = False
                    generation = 1
                nonce_row = connection.execute(
                    "SELECT high_water FROM oscore_sender_ledgers WHERE sender_identity = ?",
                    (sender_identity,),
                ).fetchone()
                committed_high_water = max(
                    high_water, 0 if nonce_row is None else int(nonce_row[0])
                )
                connection.execute(
                    "INSERT INTO oscore_sender_ledgers (sender_identity, high_water) "
                    "VALUES (?, ?) ON CONFLICT(sender_identity) DO UPDATE SET "
                    "high_water = MAX(high_water, excluded.high_water)",
                    (sender_identity, committed_high_water),
                )
                replay_row = connection.execute(
                    "SELECT window_index, bitfield FROM oscore_replay_ledgers "
                    "WHERE recipient_identity = ?",
                    (recipient_identity,),
                ).fetchone()
                if replay_row is None:
                    replay_index, replay_bitfield = initial_replay
                    connection.execute(
                        "INSERT INTO oscore_replay_ledgers "
                        "(recipient_identity, window_index, bitfield) VALUES (?, ?, ?)",
                        (
                            recipient_identity,
                            replay_index,
                            _encode_nonnegative_integer(replay_bitfield),
                        ),
                    )
                else:
                    replay_index = int(replay_row[0])
                    replay_bitfield = int.from_bytes(bytes(replay_row[1]), "big")
                if idempotent:
                    connection.commit()
                    self._endpoint_policy = self._policy_locked(connection)
                    if cached is None:
                        raise RuntimeError("idempotent SQLite context cache entry disappeared")
                    return cached
                values = (
                    pubkey,
                    parameters.master_secret,
                    parameters.master_salt,
                    parameters.sender_id,
                    parameters.recipient_id,
                    json.dumps(parameters.algorithm),
                    parameters.hashfun,
                    parameters.window_size,
                    parameters.id_context,
                    sender_identity,
                    recipient_identity,
                    generation,
                    key,
                )
                if row is None:
                    connection.execute(
                        "INSERT INTO oscore_hosts (peer_pubkey, master_secret, master_salt, "
                        "sender_id, recipient_id, algorithm_json, hashfun, window_size, "
                        "id_context, sender_identity, recipient_identity, generation, host) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        values,
                    )
                else:
                    connection.execute(
                        "UPDATE oscore_hosts SET peer_pubkey = ?, master_secret = ?, "
                        "master_salt = ?, sender_id = ?, recipient_id = ?, algorithm_json = ?, "
                        "hashfun = ?, window_size = ?, id_context = ?, sender_identity = ?, "
                        "recipient_identity = ?, generation = ? WHERE host = ?",
                        values,
                    )
                self._hooks.transaction_step("put", "after_write")
                connection.commit()
                self._endpoint_policy = self._policy_locked(connection)
                oscore_ctx.clear_sender_sequence_reservation(committed_high_water)
                oscore_ctx.restore_replay_window(replay_index, replay_bitfield)
                context = PeerContext(oscore_ctx, pubkey, generation=generation)
                self._cache[key] = context
                return context

        return await self._transaction("put", host, worker)

    def put_sync(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext:
        raise RuntimeError("SQLite context publication must be awaited")

    async def reserve_sender_sequences(
        self, host: str, generation: int, count: int
    ) -> SequenceReservation:
        if count <= 0:
            raise ValueError("reservation count must be positive")
        def worker() -> SequenceReservation:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                key = self._normalize_key_locked(connection, host)
                row = connection.execute(
                    "SELECT h.generation, h.sender_identity, n.high_water "
                    "FROM oscore_hosts AS h LEFT JOIN oscore_sender_ledgers AS n "
                    "ON n.sender_identity = h.sender_identity WHERE h.host = ?",
                    (key,),
                ).fetchone()
                if row is not None and int(row[0]) != generation:
                    raise ContextGenerationError(f"context generation changed for {key}")
                if row is None or row[1] is None or row[2] is None:
                    raise SequenceReservationError(f"no context exists for {key}")
                start = int(row[2])
                limit = MAX_OSCORE_SEQUENCE_NUMBER + 1
                if start >= limit:
                    raise SequenceReservationError("OSCORE sender sequence space is exhausted")
                end = min(start + count, limit)
                connection.execute(
                    "UPDATE oscore_sender_ledgers SET high_water = ? WHERE sender_identity = ?",
                    (end, bytes(row[1])),
                )
                self._hooks.transaction_step("reserve", "after_write")
                connection.commit()
                self._endpoint_policy = self._policy_locked(connection)
                return SequenceReservation(start, end, generation)

        return await self._transaction("reserve", host, worker)

    async def compare_and_set_replay_window(
        self,
        host: str,
        generation: int,
        recipient_identity: bytes,
        expected_index: int,
        expected_bitfield: int,
        new_index: int,
        new_bitfield: int,
    ) -> None:
        if min(expected_index, expected_bitfield, new_index, new_bitfield) < 0:
            raise ValueError("invalid OSCORE replay window state")
        self.check_process()
        identity = bytes(recipient_identity)

        def worker() -> None:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                policy = self._policy_locked(connection)
                key = policy.normalize(host).authority
                row = connection.execute(
                    "SELECT h.generation, h.recipient_identity, r.window_index, r.bitfield "
                    "FROM oscore_hosts AS h JOIN oscore_replay_ledgers AS r "
                    "ON r.recipient_identity = h.recipient_identity "
                    "WHERE host = ? AND master_secret IS NOT NULL",
                    (key,),
                ).fetchone()
                if row is None or int(row[0]) != generation:
                    raise ContextGenerationError(f"context generation changed for {key}")
                if row[1] is None or bytes(row[1]) != identity:
                    raise ContextGenerationError(f"recipient identity changed for {key}")
                current = (int(row[2]), int.from_bytes(bytes(row[3]), "big"))
                if current != (expected_index, expected_bitfield):
                    raise ReplayWindowConflictError(*current)
                connection.execute(
                    "UPDATE oscore_replay_ledgers SET window_index = ?, bitfield = ? "
                    "WHERE recipient_identity = ?",
                    (new_index, _encode_nonnegative_integer(new_bitfield), identity),
                )
                if connection.total_changes != 1:
                    raise RuntimeError("OSCORE replay ledger is missing")
                self._hooks.transaction_step("replay_cas", "after_write")
                connection.commit()
                self._endpoint_policy = self._policy_locked(connection)

        await self._transaction("replay_cas", host, worker)

    async def get_peer_pubkey(self, host: str) -> bytes | None:
        self.check_process()

        def worker() -> bytes | None:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                policy = self._policy_locked(connection)
                key = policy.normalize(host).authority
                row = connection.execute(
                    "SELECT peer_pubkey FROM oscore_hosts WHERE host = ?", (key,)
                ).fetchone()
                self._hooks.transaction_step("get_peer_pubkey", "after_read")
                connection.commit()
                self._endpoint_policy = policy
                return None if row is None else bytes(row[0])

        return await self._transaction("get_peer_pubkey", host, worker)

    async def pin_peer(self, host: str, pubkey: bytes) -> None:
        await self.pin_peers({host: pubkey})

    async def pin_peers(self, pins: Mapping[str, bytes]) -> None:
        self.check_process()
        pending = [(host, bytes(pubkey)) for host, pubkey in pins.items()]

        def worker() -> None:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                policy = self._policy_locked(connection)
                normalized: dict[str, bytes] = {}
                for host, value in pending:
                    key = policy.normalize(host).authority
                    if key in normalized and normalized[key] != value:
                        raise PeerKeyConflictError(
                            f"TOFU violation: peer aliases normalize to {key} "
                            "with different keys"
                        )
                    normalized[key] = value
                additions: list[tuple[str, bytes]] = []
                for key, value in normalized.items():
                    row = connection.execute(
                        "SELECT peer_pubkey FROM oscore_hosts WHERE host = ?", (key,)
                    ).fetchone()
                    if row is not None and bytes(row[0]) != value:
                        raise PeerKeyConflictError(
                            f"TOFU violation: peer {key} key changed"
                        )
                    if row is None:
                        additions.append((key, value))
                for key, value in additions:
                    connection.execute(
                        "INSERT INTO oscore_hosts (host, peer_pubkey) VALUES (?, ?)",
                        (key, value),
                    )
                self._hooks.transaction_step("pin_batch", "after_write")
                connection.commit()
                self._endpoint_policy = policy

        await self._transaction("pin_batch", "<batch>", worker)

    def migrate_endpoint_keys(
        self,
        policy: EndpointPolicy,
        pending_pins: Mapping[str, bytes],
    ) -> None:
        """Normalize all persisted host rows and merge pins in one transaction."""
        self.check_process()
        selected_sources: dict[str, str | None] = {}

        with self._thread_lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            policy_row = connection.execute(
                "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
            ).fetchone()
            if policy_row is not None:
                persisted = EndpointPolicy.deserialize(str(policy_row[0]))
                if persisted != policy:
                    raise EndpointPolicyConflictError(
                        "SQLite context store is bound to an incompatible endpoint policy"
                    )
            rows = connection.execute(
                "SELECT host, peer_pubkey, master_secret, master_salt, sender_id, "
                "recipient_id, algorithm_json, hashfun, window_size, id_context, "
                "sender_identity, recipient_identity, generation "
                "FROM oscore_hosts ORDER BY host"
            ).fetchall()
            staged: dict[str, tuple[str | None, tuple[Any, ...]]] = {}
            for row in rows:
                old_key = str(row[0])
                key = policy.normalize(old_key).authority
                values = tuple(row[1:])
                existing = staged.get(key)
                if existing is not None and not _sqlite_host_values_semantically_equal(
                    existing[1], values
                ):
                    raise PeerKeyConflictError(
                        f"endpoint aliases normalize to conflicting record {key}"
                    )
                if existing is None or (old_key == key and existing[0] != key):
                    staged[key] = (old_key, values)
            for old_key, pubkey in pending_pins.items():
                key = policy.normalize(old_key).authority
                value = bytes(pubkey)
                existing = staged.get(key)
                if existing is not None and bytes(existing[1][0]) != value:
                    raise PeerKeyConflictError(
                        f"endpoint aliases normalize to {key} with different keys"
                    )
                if existing is None:
                    staged[key] = (
                        None,
                        (value, None, None, None, None, None, None, None, None, None, None, 0),
                    )

            current = {str(row[0]): tuple(row[1:]) for row in rows}
            replacement = {key: values for key, (_old, values) in staged.items()}
            changed = current != replacement or policy_row is None
            if current != replacement:
                connection.execute("DELETE FROM oscore_hosts")
                connection.executemany(
                    "INSERT INTO oscore_hosts (host, peer_pubkey, master_secret, master_salt, "
                    "sender_id, recipient_id, algorithm_json, hashfun, window_size, "
                    "id_context, sender_identity, recipient_identity, generation) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(key, *values) for key, values in replacement.items()],
                )
            if policy_row is None:
                connection.execute(
                    "INSERT INTO oscore_metadata (key, value) VALUES ('endpoint_policy', ?)",
                    (policy.serialize(),),
                )
            if changed:
                self._hooks.transaction_step("migrate", "after_write")
            connection.commit()
            self._endpoint_policy = policy
            selected_sources = {key: old for key, (old, _values) in staged.items()}
            migrated_cache: dict[str, PeerContext] = {}
            for key, source_key in selected_sources.items():
                if source_key is not None and source_key in self._cache:
                    migrated_cache[key] = self._cache[source_key]
            self._cache = migrated_cache

    async def remove(self, host: str) -> None:
        self.check_process()

        def worker() -> None:
            with self._thread_lock, self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                policy = self._policy_locked(connection)
                key = policy.normalize(host).authority
                connection.execute(
                    "UPDATE oscore_hosts SET master_secret = NULL, master_salt = NULL, "
                    "sender_id = NULL, recipient_id = NULL, algorithm_json = NULL, "
                    "hashfun = NULL, window_size = NULL, id_context = NULL, "
                    "sender_identity = NULL, recipient_identity = NULL, "
                    "generation = generation + 1 "
                    "WHERE host = ? AND master_secret IS NOT NULL",
                    (key,),
                )
                self._hooks.transaction_step("remove", "after_write")
                connection.commit()
                self._endpoint_policy = policy
                self._cache.pop(key, None)

        await self._transaction("remove", host, worker)

    def has_context_sync(self, host: str) -> bool:
        self.check_process()
        raise RuntimeError("durable context stores require asynchronous access")

    async def has_context(self, host: str) -> bool:
        return await self.get(host) is not None


class EdhocPeerResolver:
    """Resolves peer public keys for EDHOC authentication.

    Override this to implement custom peer discovery (TOFU, directory, etc.).
    """

    async def get_peer_pubkey(self, host: str) -> bytes | None:
        """Get the Ed25519 public key for a peer host.

        Returns None if the peer is unknown. For TOFU, this would
        accept any peer on first contact and pin the key.
        """
        raise NotImplementedError("Subclass must implement peer resolution")

    def bind_context_store(self, context_store: TransactionalOscoreContextStore) -> None:
        """Bind resolver authority to a context store when applicable."""

    def bind_authority(
        self,
        context_store: TransactionalOscoreContextStore,
        policy: EndpointPolicy,
    ) -> None:
        """Bind storage and channel endpoint identity when applicable."""
        self.bind_context_store(context_store)

    async def ensure_bound(self) -> None:
        """Complete any asynchronous authority migration before use."""

    def ensure_bound_sync(self) -> None:
        """Verify that synchronous use needs no asynchronous migration."""


class TofuPeerResolver(EdhocPeerResolver):
    """Trust-On-First-Use peer resolution per spec section 8.6.

    Accepts any peer on first contact and pins their public key.

    Note: This class can be instantiated before the event loop starts.
    The internal lock is created lazily on first async access.
    """

    def __init__(self, context_store: TransactionalOscoreContextStore | None = None) -> None:
        self._context_store = context_store
        self._pending_context_store: TransactionalOscoreContextStore | None = None
        self._pinned: dict[str, bytes] = {}
        self._endpoint_policy: EndpointPolicy | None = None
        self._lock: asyncio.Lock | None = None

    def bind_authority(
        self,
        context_store: TransactionalOscoreContextStore,
        policy: EndpointPolicy,
    ) -> None:
        if self._lock is not None and self._lock.locked():
            raise RuntimeError("TOFU resolver is busy")
        if self._context_store is not None and self._context_store is not context_store:
            raise ValueError("TOFU resolver is already bound to a different context store")
        if (
            self._pending_context_store is not None
            and self._pending_context_store is not context_store
        ):
            raise ValueError("TOFU resolver is pending migration to a different context store")
        if (
            self._endpoint_policy is not None
            and self._endpoint_policy != policy
        ):
            raise ValueError("TOFU resolver is already bound to a different endpoint policy")

        if (
            self._context_store is context_store
            and self._pending_context_store is None
            and self._endpoint_policy == policy
            and not self._pinned
        ):
            return
        context_store.migrate_endpoint_keys(policy, self._pinned)
        self._endpoint_policy = policy
        self._pinned = {}
        self._context_store = context_store
        self._pending_context_store = None

    def bind_context_store(self, context_store: TransactionalOscoreContextStore) -> None:
        if self._context_store is context_store:
            return
        if self._context_store is not None:
            raise ValueError("TOFU resolver is already bound to a different context store")
        if (
            self._pending_context_store is not None
            and self._pending_context_store is not context_store
        ):
            raise ValueError("TOFU resolver is pending migration to a different context store")
        if self._pinned:
            self._pending_context_store = context_store
        else:
            self._context_store = context_store

    async def ensure_bound(self) -> None:
        if self._pending_context_store is None:
            return
        async with self._get_lock():
            store = self._pending_context_store
            if store is None:
                return
            await store.pin_peers(self._pinned)
            self._pinned.clear()
            self._context_store = store
            self._pending_context_store = None

    def ensure_bound_sync(self) -> None:
        if self._pending_context_store is not None:
            raise RuntimeError("prepopulated TOFU migration requires asynchronous provisioning")

    def _get_lock(self) -> asyncio.Lock:
        """Get or create the asyncio lock (must be called from async context)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def get_peer_pubkey(self, host: str) -> bytes | None:
        """Get pinned public key for a peer."""
        await self.ensure_bound()
        key = self._normalize_key(host)
        if self._context_store is not None:
            return await self._context_store.get_peer_pubkey(key)
        async with self._get_lock():
            return self._pinned.get(key)

    async def pin_peer(self, host: str, pubkey: bytes) -> None:
        """Pin a peer's public key (TOFU)."""
        await self.ensure_bound()
        key = self._normalize_key(host)
        if self._context_store is not None:
            await self._context_store.pin_peer(key, pubkey)
            return
        async with self._get_lock():
            if key in self._pinned:
                if self._pinned[key] != pubkey:
                    raise ValueError(
                        f"TOFU violation: peer {host} key changed (possible MITM or hardware swap)"
                    )
            else:
                self._pinned[key] = bytes(pubkey)
                logger.info("TOFU: pinned key for %s", key)

    def _normalize_key(self, host: str) -> str:
        if self._endpoint_policy is None:
            return validate_endpoint_key(host)
        return self._endpoint_policy.normalize(host).authority


class SecureDatagramChannel(DatagramChannel):
    """A DatagramChannel wrapper that applies OSCORE protection.

    Transparently encrypts outgoing datagrams and decrypts incoming ones
    using OSCORE security contexts. Contexts can be pre-provisioned or
    established via EDHOC on first contact.

    SECURITY: This channel requires OSCORE contexts to be established
    before messages can be exchanged. For lazy EDHOC establishment,
    the first send to an unknown peer will trigger handshake.

    Note on aiocoap integration:
        aiocoap's OSCORE machinery operates on Message objects with direction
        and request_id tracking. We handle this by:
        1. Decoding incoming bytes to Message with Direction.INCOMING
        2. On unprotect: getting a plaintext Message, re-encoding it
        3. On protect: decoding plaintext, setting Direction.OUTGOING, protecting

    Attributes:
        identity: Our cryptographic identity (for EDHOC signing).
        context_store: Storage for OSCORE contexts.
        peer_resolver: Resolver for peer public keys.
    """

    _STORE_METHODS = (
        "check_process",
        "get_sync",
        "get",
        "get_generation",
        "put",
        "put_sync",
        "reserve_sender_sequences",
        "compare_and_set_replay_window",
        "get_peer_pubkey",
        "pin_peer",
        "pin_peers",
        "migrate_endpoint_keys",
        "remove",
        "has_context_sync",
        "has_context",
    )

    def __init__(
        self,
        inner: DatagramChannel,
        identity: Identity,
        context_store: TransactionalOscoreContextStore | None = None,
        peer_resolver: EdhocPeerResolver | None = None,
        *,
        require_oscore: bool = True,
        local_host: str | None = None,
        edhoc_timeout: float = 30.0,
        sequence_reservation_size: int = 32,
    ) -> None:
        """Create a secure channel wrapping an inner channel.

        Args:
            inner: The underlying DatagramChannel.
            identity: Our Identity for signing EDHOC messages.
            context_store: Where to store OSCORE contexts. Created if None.
            peer_resolver: How to look up peer public keys. Uses TOFU if None.
            require_oscore: If True, reject plaintext messages. If False,
                allow passthrough for unprotected messages (useful for
                transitional deployments).
            local_host: Our host identifier for CoAP context (required for EDHOC).
            edhoc_timeout: Timeout in seconds for EDHOC message exchange.
        """
        self._inner = inner
        self._identity = identity
        if sequence_reservation_size <= 0:
            raise ValueError("sequence_reservation_size must be positive")
        candidate_store = context_store if context_store is not None else OscoreContextStore()
        missing = [
            method
            for method in self._STORE_METHODS
            if not callable(getattr(candidate_store, method, None))
        ]
        if missing or not isinstance(candidate_store, TransactionalOscoreContextStore):
            details = ", ".join(missing) if missing else "protocol-incompatible attributes"
            raise TypeError(f"incomplete OSCORE context store: {details}")
        candidate_resolver = peer_resolver if peer_resolver is not None else TofuPeerResolver()
        candidate_resolver.bind_authority(candidate_store, inner.endpoint_policy)
        self._context_store = candidate_store
        self._peer_resolver = candidate_resolver
        self._require_oscore = require_oscore
        self._local_host = local_host
        self._edhoc_timeout = edhoc_timeout
        self._receiver: ReceiveCallback | None = None
        self._inner_receiver_registered = False
        self._pending_edhoc: dict[str, asyncio.Future[None]] = {}
        # Temporary CoAP context and channel for EDHOC exchange (created lazily)
        self._edhoc_ctx: aiocoap.Context | None = None
        self._edhoc_channel: _EdhocChannel | None = None
        # Set of peers with active EDHOC exchange (allow plaintext from these)
        self._edhoc_active_peers: set[str] = set()
        self._sequence_reservation_size = sequence_reservation_size
        self._peer_locks: dict[str, asyncio.Lock] = {}
        self._active_peer_contexts: dict[str, PeerContext] = {}
        self._pending_outbound: dict[tuple[str, bytes], _RequestCorrelation] = {}
        self._message_admissions: dict[int, tuple[str, _SendOperation]] = {}
        self._protected_cons: dict[tuple[str, int], _ProtectedCon] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._closing = False
        self._inner_teardown_started = False
        self._shutdown_task: asyncio.Task[None] | None = None
        self._pid = os.getpid()

    def _check_process(self) -> None:
        self._context_store.check_process()
        pid = os.getpid()
        if pid != self._pid:
            self._pid = pid
            self._peer_locks = {}
            self._clear_lifecycle_state()
            self._pending_edhoc = {}
            self._edhoc_active_peers = set()
            self._edhoc_ctx = None
            self._edhoc_channel = None

    async def _get_peer_context(self, host: str) -> PeerContext | None:
        self._check_process()
        key = self._endpoint_key(host)
        context = await self._context_store.get(key)
        self._publish_peer_context(key, context)
        return context

    def _publish_peer_context(self, key: str, context: PeerContext | None) -> None:
        previous = self._active_peer_contexts.get(key)
        if previous is context:
            return
        if (
            previous is not None
            and context is not None
            and previous.generation == context.generation
        ):
            context.outbound_requests = previous.outbound_requests
            context.inbound_requests = previous.inbound_requests
            self._active_peer_contexts[key] = context
            return
        if previous is not None:
            self._abandon_peer_admissions(key)
            self._clear_context_lifecycle(previous)
        self._active_peer_contexts.pop(key, None)
        if previous is not None:
            self._pending_outbound = {
                pending_key: correlation
                for pending_key, correlation in self._pending_outbound.items()
                if pending_key[0] != key
            }
            for con_key in [
                con_key for con_key in self._protected_cons if con_key[0] == key
            ]:
                self._protected_cons.pop(con_key, None)
        if context is not None:
            self._active_peer_contexts[key] = context

    def _clear_context_lifecycle(self, context: PeerContext) -> None:
        for correlation in context.outbound_requests.values():
            self._cancel_cancellation_timer(correlation)
        context.outbound_requests.clear()
        context.inbound_requests.clear()

    def _clear_peer_lifecycle(self, peer: str, context: PeerContext | None = None) -> None:
        self._abandon_peer_admissions(peer)
        active = self._active_peer_contexts.pop(peer, None)
        if context is not None:
            self._clear_context_lifecycle(context)
        if active is not None and active is not context:
            self._clear_context_lifecycle(active)
        self._pending_outbound = {
            key: correlation
            for key, correlation in self._pending_outbound.items()
            if key[0] != peer
        }
        for key in [key for key in self._protected_cons if key[0] == peer]:
            self._protected_cons.pop(key, None)

    def _clear_lifecycle_state(self) -> None:
        for peer in {peer for peer, _operation in self._message_admissions.values()}:
            self._abandon_peer_admissions(peer)
        for context in self._active_peer_contexts.values():
            self._clear_context_lifecycle(context)
        self._active_peer_contexts.clear()
        self._pending_outbound.clear()
        self._message_admissions.clear()
        self._protected_cons.clear()

    def _abandon_peer_admissions(self, peer: str) -> None:
        context = self._active_peer_contexts.get(peer)
        for message_id, (admission_peer, operation) in tuple(
            self._message_admissions.items()
        ):
            if admission_peer == peer:
                self._message_admissions.pop(message_id, None)
                self._finish_send_operation(peer, context, operation)

    def _track_task(
        self, coroutine: Any, on_done: Callable[[], None] | None = None
    ) -> None:
        task = asyncio.get_running_loop().create_task(coroutine)
        self._tasks.add(task)

        def done(completed: asyncio.Task[Any]) -> None:
            self._tasks.discard(completed)
            if on_done is not None:
                on_done()
            if not completed.cancelled():
                completed.exception()

        task.add_done_callback(done)

    @staticmethod
    def _correlations(
        context: PeerContext, locally_originated: bool
    ) -> dict[bytes, _RequestCorrelation]:
        return context.outbound_requests if locally_originated else context.inbound_requests

    @staticmethod
    def _matches_lifecycle(
        correlation: _RequestCorrelation | None, lifecycle_id: object | None
    ) -> TypeGuard[_RequestCorrelation]:
        return correlation is not None and correlation.lifecycle_id is lifecycle_id

    @staticmethod
    def _cancel_cancellation_timer(correlation: _RequestCorrelation) -> None:
        if correlation.cancellation_timer is not None:
            correlation.cancellation_timer.cancel()
            correlation.cancellation_timer = None
        correlation.cancellation_deadline = None

    def _retire_outbound(
        self, context: PeerContext, token: bytes, correlation: _RequestCorrelation
    ) -> None:
        if context.outbound_requests.get(token) is correlation:
            context.outbound_requests.pop(token, None)
            self._cancel_cancellation_timer(correlation)

    def _schedule_cancellation_expiry(
        self, delay: float, callback: Callable[[], None]
    ) -> asyncio.TimerHandle:
        return asyncio.get_running_loop().call_later(delay, callback)

    def _expire_cancelled_observation(
        self,
        peer: str,
        generation: int,
        token: bytes,
        correlation: _RequestCorrelation,
    ) -> None:
        context = self._active_peer_contexts.get(peer)
        if (
            context is None
            or context.generation != generation
            or context.outbound_requests.get(token) is not correlation
        ):
            self._cancel_cancellation_timer(correlation)
            return
        correlation.cancellation_timer = None
        correlation.cancellation_deadline = None
        context.outbound_requests.pop(token, None)

    def _retire_inbound_if_done(
        self, context: PeerContext, token: bytes, correlation: _RequestCorrelation
    ) -> None:
        if context.inbound_requests.get(token) is not correlation:
            return
        ended_observation = correlation.observe and not correlation.interested
        if (
            correlation.pending_sends == 0
            and not correlation.con_mids
            and (correlation.terminal or ended_observation)
        ):
            context.inbound_requests.pop(token, None)

    def request_started(
        self, peer: str, token: bytes, *, locally_originated: bool
    ) -> object | None:
        key = self._endpoint_key(peer)
        if locally_originated:
            correlation = self._pending_outbound.get((key, token))
        else:
            context = self._active_peer_contexts.get(key)
            correlation = None if context is None else context.inbound_requests.get(token)
        return None if correlation is None else correlation.lifecycle_id

    def message_admitted(self, message: Message, peer: str) -> object | None:
        if self._closing:
            return None
        key = self._endpoint_key(peer)
        correlation = None
        locally_originated = message.code.is_request()
        if locally_originated:
            correlation = _RequestCorrelation(
                None, observe=message.opt.observe == 0
            )
            self._pending_outbound[(key, message.token)] = correlation
        elif message.code.is_response():
            context = self._active_peer_contexts.get(key)
            if context is not None:
                correlation = context.inbound_requests.get(message.token)
        if correlation is None:
            return None
        correlation.pending_sends += 1
        self._message_admissions[id(message)] = (
            key,
            _SendOperation(correlation, message.token, locally_originated),
        )
        return correlation.lifecycle_id

    def message_abandoned(self, message: Message) -> None:
        admission = self._message_admissions.pop(id(message), None)
        if admission is None:
            return
        key, operation = admission
        if (
            not operation.locally_originated
            and message.code.is_response()
            and message.opt.observe is None
        ):
            if not operation.finished:
                operation.finished = True
                operation.correlation.pending_sends -= 1
            return
        self._finish_send_operation(
            key, self._active_peer_contexts.get(key), operation
        )

    def request_interest_ended(
        self,
        peer: str,
        token: bytes,
        lifecycle_id: object | None,
        *,
        locally_originated: bool,
    ) -> None:
        key = self._endpoint_key(peer)
        context = self._active_peer_contexts.get(key)
        if locally_originated:
            correlation = self._pending_outbound.get((key, token))
            if not self._matches_lifecycle(correlation, lifecycle_id) and context is not None:
                correlation = context.outbound_requests.get(token)
            if not self._matches_lifecycle(correlation, lifecycle_id):
                return
            correlation.interested = False
            if correlation.cancelled_observe:
                return
            if self._pending_outbound.get((key, token)) is correlation:
                self._pending_outbound.pop((key, token), None)
            if context is not None and context.outbound_requests.get(token) is correlation:
                self._retire_outbound(context, token, correlation)
            return

        if context is None:
            return
        correlation = context.inbound_requests.get(token)
        if not self._matches_lifecycle(correlation, lifecycle_id):
            return
        correlation.interested = False
        self._retire_inbound_if_done(context, token, correlation)

    def observation_cancelled(
        self,
        peer: str,
        token: bytes,
        lifecycle_id: object | None,
        exchange_lifetime: float,
    ) -> None:
        key = self._endpoint_key(peer)
        context = self._active_peer_contexts.get(key)
        correlation = self._pending_outbound.get((key, token))
        if not self._matches_lifecycle(correlation, lifecycle_id) and context is not None:
            correlation = context.outbound_requests.get(token)
        if not self._matches_lifecycle(correlation, lifecycle_id):
            return
        correlation.interested = False
        correlation.cancelled_observe = True
        if context is None or correlation.cancellation_timer is not None:
            return
        delay = max(0.0, exchange_lifetime)
        correlation.cancellation_deadline = asyncio.get_running_loop().time() + delay
        correlation.cancellation_timer = self._schedule_cancellation_expiry(
            delay,
            lambda: self._expire_cancelled_observation(
                key, context.generation, token, correlation
            ),
        )

    def response_completed(
        self, peer: str, token: bytes, lifecycle_id: object | None
    ) -> None:
        context = self._active_peer_contexts.get(self._endpoint_key(peer))
        if context is None:
            return
        correlation = context.inbound_requests.get(token)
        if not self._matches_lifecycle(correlation, lifecycle_id):
            return
        correlation.terminal = True
        self._retire_inbound_if_done(context, token, correlation)

    def exchange_ended(self, peer: str, mid: int, *, reset: bool) -> None:
        key = (self._endpoint_key(peer), mid)
        cached = self._protected_cons.pop(key, None)
        if cached is None:
            return
        context = self._active_peer_contexts.get(key[0])
        if context is None:
            return
        correlations = self._correlations(context, cached.locally_originated)
        correlation = correlations.get(cached.token)
        if correlation is None or correlation is not cached.correlation:
            return
        correlation.con_mids.discard(mid)
        if reset:
            correlation.interested = False
        if (
            cached.locally_originated
            and not correlation.interested
            and not correlation.cancelled_observe
        ):
            self._retire_outbound(context, cached.token, correlation)
        elif not cached.locally_originated:
            self._retire_inbound_if_done(context, cached.token, correlation)

    def exchange_expired(self, peer: str, mid: int) -> None:
        self.exchange_ended(peer, mid, reset=True)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        """Register a callback for received (unprotected) datagrams."""
        if self._closing:
            raise RuntimeError("secure datagram channel is closing")
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._inner.set_receiver(self._on_datagram)
        self._inner_receiver_registered = True
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver == receiver:
            if self._inner_receiver_registered:
                self._inner.clear_receiver(self._on_datagram)
                self._inner_receiver_registered = False
            self._receiver = None

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._inner.endpoint_policy

    def normalize_endpoint(self, endpoint: str | Endpoint) -> Endpoint:
        try:
            return self.endpoint_policy.normalize(endpoint)
        except ValueError as exc:
            raise ValueError(f"invalid endpoint: {exc}") from exc

    def _endpoint_key(self, endpoint: str | Endpoint) -> str:
        return self.normalize_endpoint(endpoint).authority

    @staticmethod
    def _has_oscore_option(data: bytes) -> bool:
        """Check if a CoAP datagram contains an OSCORE option without full decode.

        OSCORE is option number 9. In the CoAP option encoding, options are
        delta-encoded: the option delta is the cumulative sum of previous
        deltas. This method scans the option section (between the fixed header
        and payload marker 0xFF) for cumulative delta == 9, stopping early
        if the sum exceeds 9 or the payload marker is hit.

        Returns False for any datagram shorter than the 4-byte CoAP header.
        """
        if len(data) < 4:
            return False
        token_len = data[0] & 0x0F
        pos = 4 + token_len
        cum_delta = 0
        while pos < len(data):
            if data[pos] == 0xFF:
                break
            # Extended option delta if needed (13, 14)
            delta = data[pos] >> 4
            if delta == 13:
                if pos + 1 >= len(data):
                    return False
                delta = data[pos + 1] + 13
                skip = 1
            elif delta == 14:
                if pos + 2 >= len(data):
                    return False
                delta = int.from_bytes(data[pos + 1:pos + 3], "big") + 269
                skip = 2
            elif delta == 15:
                return False
            else:
                skip = 0
            cum_delta += delta
            if cum_delta == 9:
                return True
            if cum_delta > 9:
                return False
            # Advance past option delta/len and option value
            option_len = data[pos] & 0x0F
            if option_len == 13:
                slice_len = data[pos + 1 + skip] + 13
                skip_value = 1
            elif option_len == 14:
                slice_len = int.from_bytes(
                    data[pos + 1 + skip:pos + 3 + skip], "big"
                ) + 269
                skip_value = 2
            elif option_len == 15:
                return False
            else:
                slice_len = option_len
                skip_value = 0
            pos += 1 + skip + skip_value + slice_len
        return False

    def _on_datagram(self, data: bytes, source: str) -> None:
        """Handle an incoming datagram, unprotecting if OSCORE.

        This is synchronous since DatagramChannel callback is sync.
        We schedule async work for OSCORE processing.
        """
        if self._closing:
            return
        self._track_task(self._process_incoming(data, source))

    async def _process_incoming(self, data: bytes, source: str) -> None:
        """Process an incoming datagram asynchronously."""
        if self._closing:
            return
        try:
            remote = LichenRemote(source)

            # Fast-path: check for OSCORE marker before full decode
            # CoAP OSCORE option is Elective (0) at option number 9.
            # A minimal scan for option delta=9 before the payload marker
            # avoids a full Message decode for non-OSCORE traffic.
            has_oscore = self._has_oscore_option(data)

            if has_oscore:
                # Full decode needed for OSCORE unprotection
                msg = Message.decode(data, remote)
                msg.direction = Direction.INCOMING
                plaintext = await self._unprotect(msg, source)
                if plaintext is not None and self._receiver is not None:
                    self._receiver(plaintext, source)
            elif source in self._edhoc_active_peers:
                # EDHOC in progress with this peer - allow plaintext
                # (EDHOC responses are not OSCORE-protected).
                # Dispatch raw bytes to EDHOC channel where LichenTransport
                # will decode and route to the EDHOC CoAP context.
                logger.debug("Allowing plaintext from %s (EDHOC in progress)", source)
                if self._edhoc_channel is not None:
                    self._edhoc_channel.dispatch(data, source)
            else:
                # Non-OSCORE path: decode just enough to classify the message
                msg = Message.decode(data, remote)
                if msg.code is EMPTY and msg.mtype in (ACK, RST):
                    if self._receiver is not None:
                        self._receiver(data, source)
                elif self._require_oscore:
                    logger.warning("Rejected plaintext message from %s (OSCORE required)", source)
                elif self._receiver is not None:
                    self._receiver(data, source)

        except Exception as e:
            logger.debug("Failed to process datagram from %s: %s", source, e)
            # Drop malformed datagrams

    async def _unprotect(self, msg: Message, source: str) -> bytes | None:
        """Unprotect an OSCORE-encrypted message.

        Returns the plaintext CoAP bytes, or None if unprotection fails.
        """
        result = await self._unprotect_datagram(msg, source)
        return None if result is None else result.data

    async def _unprotect_datagram(
        self, msg: Message, source: str
    ) -> _UnprotectedDatagram | None:
        """Unprotect and stage correlation state for synchronous dispatch."""
        key = self._endpoint_key(source)
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self._closing:
                return None
            peer_ctx = await self._get_peer_context(key)
            if peer_ctx is None:
                logger.warning("No OSCORE context for %s, dropping message", source)
                return None

            try:
                request_id: object | None = None
                correlation: _RequestCorrelation | None = None
                if msg.code.is_response():
                    correlation = peer_ctx.outbound_requests.get(msg.token)
                    if correlation is not None:
                        request_id = correlation.request_id

                expected_replay_index, expected_replay_bitfield = (
                    peer_ctx.oscore.export_replay_window()
                )
                unprotected_msg, new_request_id = peer_ctx.oscore.unprotect(msg, request_id)
                replay_index, replay_bitfield = peer_ctx.oscore.export_replay_window()
                try:
                    await self._context_store.compare_and_set_replay_window(
                        key,
                        peer_ctx.generation,
                        peer_ctx.oscore.recipient_cryptographic_identity(),
                        expected_replay_index,
                        expected_replay_bitfield,
                        replay_index,
                        replay_bitfield,
                    )
                except ReplayWindowConflictError as error:
                    peer_ctx.oscore.restore_replay_window(*error.current_state)
                    raise
                except BaseException:
                    peer_ctx.oscore.restore_replay_window(
                        expected_replay_index, expected_replay_bitfield
                    )
                    raise
                if unprotected_msg.mtype is None:
                    unprotected_msg.mtype = msg.mtype
                if unprotected_msg.mid is None:
                    unprotected_msg.mid = msg.mid
                if unprotected_msg.remote is None:
                    unprotected_msg.remote = msg.remote
                unprotected_msg.token = msg.token
                unprotected_msg.direction = Direction.OUTGOING

                encoded = cast(bytes, unprotected_msg.encode())
                added_correlation = None
                if not msg.code.is_response() and new_request_id is not None:
                    added_correlation = _RequestCorrelation(
                        new_request_id, observe=unprotected_msg.opt.observe == 0
                    )
                    peer_ctx.inbound_requests[msg.token] = added_correlation

                return _UnprotectedDatagram(
                    encoded,
                    unprotected_msg,
                    added_correlation,
                    correlation,
                )
            except Exception as e:
                logger.warning("OSCORE unprotection failed for %s: %r", source, e)
                return None

    def send_datagram(self, data: bytes, dest: str) -> None:
        """Send a datagram, protecting with OSCORE if context exists.

        If no OSCORE context exists for dest, this will trigger EDHOC
        handshake (if peer resolver can provide their public key).
        """
        if self._closing:
            raise RuntimeError("secure datagram channel is closing")
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest)
        operation = self._prepare_send_operation(data, dest, key)
        self._schedule_send(data, dest, key, operation)

    def send_message(self, message: Message, dest: str) -> None:
        """Schedule an aiocoap message using its admission lifecycle identity."""
        if self._closing:
            raise RuntimeError("secure datagram channel is closing")
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest)
        try:
            data = cast(bytes, message.encode())
        except Exception:
            self.message_abandoned(message)
            raise
        operation: _SendOperation | None
        admission = self._message_admissions.pop(id(message), None)
        if admission is not None:
            admission_key, operation = admission
            if admission_key != key:
                self._finish_send_operation(
                    admission_key,
                    self._active_peer_contexts.get(admission_key),
                    operation,
                )
                return
        else:
            operation = None
            if hasattr(message, "_lichen_lifecycle_id"):
                return
            if operation is None:
                operation = self._prepare_send_operation(data, dest, key)
        if operation is not None and message.mtype is CON:
            self._stage_con(
                key,
                message,
                data,
                operation.correlation,
                operation.locally_originated,
            )
        if (
            operation is not None
            and operation.locally_originated
            and not operation.correlation.interested
        ):
            self._finish_send_operation(
                key, self._active_peer_contexts.get(key), operation
            )
            return
        self._schedule_send(data, dest, key, operation)

    def _schedule_send(
        self,
        data: bytes,
        dest: str,
        key: str,
        operation: _SendOperation | None,
    ) -> None:
        self._track_task(
            self._send_protected(data, dest, key, operation),
            lambda: self._finish_send_operation(
                key, self._active_peer_contexts.get(key), operation
            ),
        )

    def _prepare_send_operation(
        self, data: bytes, dest: str, key: str
    ) -> _SendOperation | None:
        try:
            message = Message.decode(data, LichenRemote(dest))
        except Exception:
            return None
        if message.code.is_request():
            cached = (
                self._protected_cons.get((key, message.mid))
                if message.mtype is CON
                else None
            )
            if (
                cached is not None
                and cached.locally_originated
                and cached.plaintext == data
                and cached.correlation is not None
            ):
                correlation = cached.correlation
            else:
                correlation = _RequestCorrelation(
                    None, observe=message.opt.observe == 0
                )
                self._pending_outbound[(key, message.token)] = correlation
            if message.mtype is CON:
                self._stage_con(key, message, data, correlation, True)
            correlation.pending_sends += 1
            return _SendOperation(correlation, message.token, True)
        if message.code.is_response():
            context = self._active_peer_contexts.get(key)
            response_correlation = (
                None if context is None else context.inbound_requests.get(message.token)
            )
            if response_correlation is not None:
                if message.mtype is CON:
                    self._stage_con(key, message, data, response_correlation, False)
                response_correlation.pending_sends += 1
                return _SendOperation(response_correlation, message.token, False)
        return None

    def _stage_con(
        self,
        key: str,
        message: Message,
        data: bytes,
        correlation: _RequestCorrelation,
        locally_originated: bool,
    ) -> None:
        con_key = (key, message.mid)
        cached = self._protected_cons.get(con_key)
        if (
            cached is not None
            and cached.plaintext == data
            and cached.correlation is correlation
            and cached.locally_originated == locally_originated
        ):
            return
        if cached is not None and cached.correlation is not None:
            cached.correlation.con_mids.discard(message.mid)
            context = self._active_peer_contexts.get(key)
            if context is not None and not cached.locally_originated:
                self._retire_inbound_if_done(context, cached.token, cached.correlation)
        self._protected_cons[con_key] = _ProtectedCon(
            b"", message.token, locally_originated, correlation, data
        )
        correlation.con_mids.add(message.mid)

    def _finish_send_operation(
        self,
        key: str,
        context: PeerContext | None,
        operation: _SendOperation | None,
    ) -> None:
        if operation is None:
            return
        if operation.finished:
            return
        operation.finished = True
        correlation = operation.correlation
        correlation.pending_sends -= 1
        if operation.locally_originated:
            if not correlation.interested and not correlation.cancelled_observe:
                if self._pending_outbound.get((key, operation.token)) is correlation:
                    self._pending_outbound.pop((key, operation.token), None)
                if (
                    context is not None
                    and context.outbound_requests.get(operation.token) is correlation
                ):
                    self._retire_outbound(context, operation.token, correlation)
        elif context is not None:
            self._retire_inbound_if_done(context, operation.token, correlation)

    async def _send_protected(
        self,
        data: bytes,
        dest: str,
        key: str | None = None,
        operation: _SendOperation | None = None,
    ) -> None:
        """Send with OSCORE protection (async implementation)."""
        if self._closing:
            return
        self._check_process()
        dest = self.normalize_endpoint(dest).authority
        key = self._endpoint_key(dest) if key is None else key
        if operation is None:
            operation = self._prepare_send_operation(data, dest, key)
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            peer_ctx: PeerContext | None = None
            try:
                if self._closing:
                    return
                remote = LichenRemote(dest)
                msg = Message.decode(data, remote)
                msg.direction = Direction.OUTGOING

                if msg.code is EMPTY and msg.mtype in (ACK, RST):
                    self._inner.send_datagram(data, dest)
                    return

                peer_ctx = await self._get_peer_context(key)
                if peer_ctx is None:
                    await self._establish_context(dest, key)
                    peer_ctx = await self._get_peer_context(key)
                if peer_ctx is None:
                    raise RuntimeError("context lost after establishment")

                if operation is not None:
                    correlations = self._correlations(
                        peer_ctx, operation.locally_originated
                    )
                    current = correlations.get(operation.token)
                    if operation.locally_originated:
                        pending = self._pending_outbound.get((key, operation.token))
                        if (
                            current is not operation.correlation
                            and pending is not operation.correlation
                        ):
                            return
                    elif current is not operation.correlation:
                        return

                con_key = (key, msg.mid)
                cached = self._protected_cons.get(con_key) if msg.mtype is CON else None
                if cached is not None and cached.plaintext == data and cached.data:
                    if operation is None or cached.correlation is not operation.correlation:
                        return
                    self._inner.send_datagram(cached.data, dest)
                    if (
                        cached.locally_originated
                        and cached.correlation is not None
                        and cached.correlation.interested
                        and self._pending_outbound.get((key, cached.token))
                        is cached.correlation
                    ):
                        peer_ctx.outbound_requests[cached.token] = cached.correlation
                        self._pending_outbound.pop((key, cached.token), None)
                    return
                if cached is not None and cached.plaintext != data:
                    if cached.correlation is not None:
                        cached.correlation.con_mids.discard(msg.mid)
                        if not cached.locally_originated:
                            self._retire_inbound_if_done(
                                peer_ctx, cached.token, cached.correlation
                            )
                    self._protected_cons.pop(con_key, None)

                if not peer_ctx.oscore.has_reserved_sender_sequence:
                    reservation = await self._context_store.reserve_sender_sequences(
                        key, peer_ctx.generation, self._sequence_reservation_size
                    )
                    peer_ctx.oscore.set_sender_sequence_reservation(
                        reservation.start, reservation.end
                    )
                self._check_process()
                # Determine request_id for responses
                request_id = None
                inbound = peer_ctx.inbound_requests.get(msg.token)
                if msg.code.is_response() and inbound is not None:
                    request_id = inbound.request_id

                # Protect with OSCORE
                protected_msg, new_request_id = peer_ctx.oscore.protect(msg, request_id)

                # OSCORE creates a new message but doesn't preserve mtype/mid/remote.
                # Copy outer header fields from the original message for encoding.
                if protected_msg.mtype is None:
                    protected_msg.mtype = msg.mtype
                if protected_msg.mid is None:
                    protected_msg.mid = msg.mid
                if protected_msg.remote is None:
                    protected_msg.remote = msg.remote
                protected_msg.token = msg.token

                # Encode and send
                protected_data = cast(bytes, protected_msg.encode())
                correlation = None
                locally_originated = msg.code.is_request()
                if locally_originated and new_request_id is not None:
                    if operation is None:
                        raise RuntimeError("outgoing request has no lifecycle operation")
                    correlation = operation.correlation
                    correlation.request_id = new_request_id
                elif msg.code.is_response():
                    correlation = inbound
                if msg.mtype is CON:
                    staged = self._protected_cons.get(con_key)
                    if staged is None or staged.correlation is not correlation:
                        raise RuntimeError("CON lifecycle ownership changed during protection")
                    staged.data = protected_data
                self._inner.send_datagram(protected_data, dest)

                if (
                    locally_originated
                    and correlation is not None
                    and correlation.interested
                    and self._pending_outbound.get((key, msg.token)) is correlation
                ):
                    peer_ctx.outbound_requests[msg.token] = correlation
                    self._pending_outbound.pop((key, msg.token), None)

            except Exception as e:
                logger.error("Failed to protect message for %s: %s", key, e)
            finally:
                self._finish_send_operation(key, peer_ctx, operation)

    async def _establish_context(self, dest: str, key: str) -> None:
        """Establish an OSCORE context with a peer via EDHOC.

        This implements lazy EDHOC establishment per spec section 8.8.
        """
        # Check if handshake already in progress
        if key in self._pending_edhoc:
            await self._pending_edhoc[key]
            return

        await self._peer_resolver.ensure_bound()

        # Get peer's public key
        peer_pubkey = await self._peer_resolver.get_peer_pubkey(key)
        if peer_pubkey is None:
            raise ValueError(f"Unknown peer: {dest}")

        # Create a future for others to wait on
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._pending_edhoc[key] = future

        # Mark peer as having active EDHOC (allow plaintext responses)
        self._edhoc_active_peers.add(dest)

        try:
            # Run EDHOC as initiator
            initiator = EdhocInitiator.create(self._identity)

            # Message 1: Initiator -> Responder
            msg1 = initiator.create_message_1()

            # Send and wait for response
            msg2 = await self._edhoc_exchange(dest, msg1)

            # Process Message 2 and create Message 3
            msg3 = initiator.process_message_2(msg2, peer_pubkey)

            # Send Message 3
            await self._edhoc_send(dest, msg3)

            # Export OSCORE context
            edhoc_ctx = initiator.export_oscore()
            oscore_ctx = MemorySecurityContext.from_edhoc(edhoc_ctx)

            # Pin the peer key if using TOFU (do this BEFORE storing context
            # to avoid leaving invalid context if pin_peer raises on key mismatch)
            if isinstance(self._peer_resolver, TofuPeerResolver):
                await self._peer_resolver.pin_peer(dest, peer_pubkey)

            # Store the context (only after TOFU check passes)
            await self._context_store.put(dest, oscore_ctx, peer_pubkey)

            logger.info("Established OSCORE context with %s via EDHOC", dest)
            future.set_result(None)

        except Exception as e:
            future.set_exception(e)
            raise
        finally:
            self._pending_edhoc.pop(key, None)
            self._edhoc_active_peers.discard(dest)

    async def _get_edhoc_context(self) -> aiocoap.Context:
        """Get or create a temporary CoAP context for EDHOC exchange.

        EDHOC messages are sent as raw CoAP (not OSCORE-protected) over
        the inner channel. This context is separate from the main CoAP
        context that uses OSCORE.
        """
        if self._edhoc_ctx is None:
            if self._local_host is None:
                raise ValueError(
                    "local_host required for EDHOC exchange; "
                    "pass local_host to SecureDatagramChannel"
                )
            # Create a dedicated channel for EDHOC that bypasses OSCORE
            # We use a wrapper that just forwards to the inner channel
            self._edhoc_channel = _EdhocChannel(self._inner)
            self._edhoc_ctx = aiocoap.Context()
            await self._edhoc_ctx._append_tokenmanaged_messagemanaged_transport(
                lambda mm: LichenTransport.create(
                    mm,
                    self._edhoc_channel,
                    self.normalize_endpoint(self._local_host).authority,
                )
            )
        return self._edhoc_ctx

    async def _edhoc_exchange(self, dest: str, msg: bytes) -> bytes:
        """Send EDHOC message and wait for response.

        Sends a CoAP POST to coap://[dest]/.well-known/edhoc with the
        EDHOC message as payload. Returns the response payload.

        Args:
            dest: Target host string.
            msg: EDHOC message bytes (Message 1 or Message 3).

        Returns:
            Response payload (Message 2 or empty for Message 3 response).

        Raises:
            ValueError: If EDHOC exchange fails.
        """
        dest = self.normalize_endpoint(dest).authority
        ctx = await self._get_edhoc_context()

        request = Message(
            code=POST,
            uri=f"{self.normalize_endpoint(dest).uri}/.well-known/edhoc",
            payload=msg,
        )

        try:
            response = await asyncio.wait_for(
                ctx.request(request).response,
                timeout=self._edhoc_timeout,
            )
        except TimeoutError:
            raise ValueError(f"EDHOC exchange with {dest} timed out") from None
        except Exception as e:
            raise ValueError(f"EDHOC exchange with {dest} failed: {e}") from e

        if not response.code.is_successful():
            raise ValueError(f"EDHOC exchange with {dest} returned error: {response.code}")

        return response.payload or b""

    async def _edhoc_send(self, dest: str, msg: bytes) -> None:
        """Send EDHOC message without waiting for response.

        Used for the final Message 3 when we don't need to wait for
        a response (the context is already derived).
        """
        # For Message 3, we still do a full exchange to ensure delivery
        # The response is empty (2.04 Changed) but confirms receipt
        await self._edhoc_exchange(dest, msg)

    def close(self) -> None:
        """Close the channel."""
        for future in list(self._pending_edhoc.values()):
            if not future.done():
                future.cancel()
        self._pending_edhoc.clear()
        self._edhoc_active_peers.clear()
        edhoc_ctx = self._edhoc_ctx
        self._edhoc_ctx = None
        self._edhoc_channel = None
        if edhoc_ctx is not None:
            asyncio.create_task(edhoc_ctx.shutdown())
        error: BaseException | None = None
        teardown_was_started = self._inner_teardown_started
        inner: DatagramChannel | None = None
        try:
            inner = self._begin_teardown()
        except BaseException as exc:
            error = exc
            if not teardown_was_started and self._inner_teardown_started:
                inner = self._inner
        if inner is not None:
            try:
                inner.close()
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    async def shutdown(self) -> None:
        """Cancel and drain packet work before releasing the inner channel."""
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.create_task(self._shutdown_once())
        await asyncio.shield(self._shutdown_task)

    async def _shutdown_once(self) -> None:
        error: BaseException | None = None
        teardown_was_started = self._inner_teardown_started
        inner: DatagramChannel | None = None
        try:
            inner = self._begin_teardown()
        except BaseException as exc:
            error = exc
            if not teardown_was_started and self._inner_teardown_started:
                inner = self._inner

        tasks = tuple(self._tasks)
        if tasks:
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except BaseException as exc:
                if error is None:
                    error = exc

        edhoc_ctx = self._edhoc_ctx
        self._edhoc_ctx = None
        self._edhoc_channel = None
        if edhoc_ctx is not None:
            try:
                await edhoc_ctx.shutdown()
            except BaseException as exc:
                if error is None:
                    error = exc

        try:
            self._clear_lifecycle_state()
        except BaseException as exc:
            if error is None:
                error = exc
        if inner is not None:
            try:
                await inner.shutdown()
            except BaseException as exc:
                if error is None:
                    error = exc
        if error is not None:
            raise error

    def _begin_teardown(self) -> DatagramChannel | None:
        if not self._closing:
            self._closing = True
            for task in tuple(self._tasks):
                task.cancel()
            self._clear_lifecycle_state()
            for future in list(self._pending_edhoc.values()):
                if not future.done():
                    future.cancel()
            self._pending_edhoc.clear()
            self._edhoc_active_peers.clear()
        if self._inner_teardown_started:
            return None
        self._inner_teardown_started = True
        if self._inner_receiver_registered:
            try:
                self._inner.clear_receiver(self._on_datagram)
            finally:
                self._inner_receiver_registered = False
                self._receiver = None
        else:
            self._receiver = None
        return self._inner

    # --- Context provisioning API ---

    def add_context_sync(
        self,
        host: str,
        oscore_ctx: OscoreContext | MemorySecurityContext,
        peer_pubkey: bytes,
    ) -> None:
        """Add a pre-provisioned OSCORE context (synchronous).

        Use this during setup before the event loop starts.
        """
        if isinstance(oscore_ctx, OscoreContext):
            oscore_ctx = MemorySecurityContext.from_edhoc(oscore_ctx)
        self._peer_resolver.ensure_bound_sync()
        key = self._endpoint_key(host)
        context = self._context_store.put_sync(key, oscore_ctx, peer_pubkey)
        self._publish_peer_context(key, context)

    async def add_context(
        self,
        host: str,
        oscore_ctx: OscoreContext | MemorySecurityContext,
        peer_pubkey: bytes,
    ) -> None:
        """Add a pre-provisioned OSCORE context for a peer.

        Use this when contexts are established out-of-band (e.g., via
        external key exchange or commissioning).

        Args:
            host: The peer's host string (IPv6 address).
            oscore_ctx: OSCORE context from EDHOC or pre-shared.
            peer_pubkey: Peer's Ed25519 public key.
        """
        if isinstance(oscore_ctx, OscoreContext):
            oscore_ctx = MemorySecurityContext.from_edhoc(oscore_ctx)
        await self._peer_resolver.ensure_bound()
        key = self._endpoint_key(host)
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self._closing:
                raise RuntimeError("secure datagram channel is closing")
            expected_generation = await self._context_store.get_generation(key)
            context = await self._context_store.put(
                key,
                oscore_ctx,
                peer_pubkey,
                expected_generation=expected_generation,
            )
            self._publish_peer_context(key, context)

    async def remove_context(self, host: str) -> None:
        """Remove a peer context after draining in-flight packet state."""
        key = self._endpoint_key(host)
        lock = self._peer_locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self._closing:
                raise RuntimeError("secure datagram channel is closing")
            await self._context_store.remove(key)
            self._publish_peer_context(key, None)

    def has_context_sync(self, host: str) -> bool:
        """Check if we have an OSCORE context (synchronous)."""
        return self._context_store.has_context_sync(self._endpoint_key(host))

    async def has_context(self, host: str) -> bool:
        """Check if we have an OSCORE context for a peer."""
        return await self._context_store.has_context(self._endpoint_key(host))


def create_secure_channel(
    inner: DatagramChannel,
    identity: Identity,
    *,
    context_store: TransactionalOscoreContextStore | None = None,
    peer_resolver: EdhocPeerResolver | None = None,
    require_oscore: bool = True,
    local_host: str | None = None,
    edhoc_timeout: float = 30.0,
    sequence_reservation_size: int = 32,
) -> SecureDatagramChannel:
    """Create an OSCORE-protected DatagramChannel.

    This is the main entry point for adding security to a channel.

    Args:
        inner: The channel to wrap (InMemoryChannel, NodeChannel, etc.).
        identity: Our cryptographic identity.
        context_store: Optional custom context storage.
        peer_resolver: Optional custom peer resolution.
        require_oscore: Whether to reject plaintext messages.
        local_host: Our host identifier (required for EDHOC lazy establishment).
        edhoc_timeout: Timeout in seconds for EDHOC message exchange.
        sequence_reservation_size: Sender sequence numbers committed per block.

    Returns:
        A SecureDatagramChannel that encrypts/decrypts transparently.
    """
    return SecureDatagramChannel(
        inner,
        identity,
        context_store=context_store,
        peer_resolver=peer_resolver,
        require_oscore=require_oscore,
        local_host=local_host,
        edhoc_timeout=edhoc_timeout,
        sequence_reservation_size=sequence_reservation_size,
    )
