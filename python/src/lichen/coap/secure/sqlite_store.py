# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SQLite-backed OSCORE context store implementation."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, TypeVar, cast

from lichen.crypto.oscore import (
    MAX_OSCORE_SEQUENCE_NUMBER,
    MemorySecurityContext,
    OscoreContextParameters,
)

from ..transport import EndpointPolicy
from .types import (
    MAX_OSCORE_GENERATION,
    ContextGenerationError,
    EndpointPolicyConflictError,
    GenerationOverflowError,
    PeerContext,
    PeerKeyConflictError,
    ReplayWindowConflictError,
    SequenceReservation,
    SequenceReservationError,
)
from .utils import _encode_nonnegative_integer, _sqlite_host_values_semantically_equal

_T = TypeVar("_T")


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
                if generation > MAX_OSCORE_GENERATION:
                    raise GenerationOverflowError(
                        f"context generation for {key} has reached maximum "
                        f"({MAX_OSCORE_GENERATION}); re-key via EDHOC required"
                    )
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
                row = connection.execute(
                    "SELECT generation FROM oscore_hosts "
                    "WHERE host = ? AND master_secret IS NOT NULL",
                    (key,),
                ).fetchone()
                if row is not None:
                    current_generation = int(row[0])
                    next_generation = current_generation + 1
                    if next_generation > MAX_OSCORE_GENERATION:
                        raise GenerationOverflowError(
                            f"context generation for {key} has reached maximum "
                            f"({MAX_OSCORE_GENERATION}); re-key via EDHOC required"
                        )
                    connection.execute(
                        "UPDATE oscore_hosts SET master_secret = NULL, master_salt = NULL, "
                        "sender_id = NULL, recipient_id = NULL, algorithm_json = NULL, "
                        "hashfun = NULL, window_size = NULL, id_context = NULL, "
                        "sender_identity = NULL, recipient_identity = NULL, "
                        "generation = ? "
                        "WHERE host = ? AND master_secret IS NOT NULL",
                        (next_generation, key),
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
