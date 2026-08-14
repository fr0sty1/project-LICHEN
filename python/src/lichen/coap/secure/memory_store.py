# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""In-memory OSCORE context store implementation."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping

from lichen.crypto.oscore import MAX_OSCORE_SEQUENCE_NUMBER, MemorySecurityContext

from ..transport import EndpointPolicy
from .types import (
    MAX_OSCORE_GENERATION,
    ContextGenerationError,
    EndpointPolicyConflictError,
    ForkSafetyError,
    GenerationOverflowError,
    PeerContext,
    PeerKeyConflictError,
    ReplayWindowConflictError,
    SequenceReservation,
    SequenceReservationError,
)
from .utils import _host_records_semantically_equal, _HostRecord


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

            # Check for idempotent operation (same context object being re-published)
            idempotent = (
                record.context is not None
                and record.context.oscore is oscore_ctx
                and record.generation == expected_generation
            )
            if idempotent:
                return record.context

            # Initialize/update sender and replay ledgers
            sender_identity = oscore_ctx.sender_cryptographic_identity()
            recipient_identity = oscore_ctx.recipient_cryptographic_identity()
            high_water = oscore_ctx.sender_sequence_number
            committed_high_water = max(
                high_water, self._sender_ledgers.get(sender_identity, 0)
            )
            self._sender_ledgers[sender_identity] = committed_high_water
            initial_replay = oscore_ctx.export_replay_window()
            replay_state = self._replay_ledgers.get(bytes(recipient_identity))
            if replay_state is None:
                replay_index, replay_bitfield = initial_replay
                self._replay_ledgers[bytes(recipient_identity)] = (replay_index, replay_bitfield)
            else:
                replay_index, replay_bitfield = replay_state

            # Signal reservation state to the context
            oscore_ctx.clear_sender_sequence_reservation(committed_high_water)
            oscore_ctx.restore_replay_window(replay_index, replay_bitfield)

            next_generation = record.generation + 1 if record.generation else 1
            if next_generation > MAX_OSCORE_GENERATION:
                raise GenerationOverflowError(
                    f"context generation for {key} has reached maximum ({MAX_OSCORE_GENERATION}); "
                    "re-key via EDHOC required"
                )
            context = PeerContext(
                oscore=oscore_ctx,
                peer_pubkey=bytes(peer_pubkey),
                generation=next_generation,
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
        if self._lock is not None:
            raise RuntimeError("put_sync must be called before async store use")
        key = self._normalize_key(host)
        record = self._records.get(key)
        if record is None:
            record = _HostRecord(bytes(peer_pubkey))
            self._records[key] = record
        if record.peer_pubkey != bytes(peer_pubkey):
            raise PeerKeyConflictError(f"peer {key} is already bound to a different key")
        if expected_generation is not None and record.generation != expected_generation:
            raise ContextGenerationError(f"context generation changed for {key}")

        # Check for idempotent operation (same context object being re-published)
        idempotent = (
            record.context is not None
            and record.context.oscore is oscore_ctx
            and record.generation == expected_generation
        )
        if idempotent:
            return record.context

        # Initialize/update sender and replay ledgers
        sender_identity = oscore_ctx.sender_cryptographic_identity()
        recipient_identity = oscore_ctx.recipient_cryptographic_identity()
        high_water = oscore_ctx.sender_sequence_number
        committed_high_water = max(
            high_water, self._sender_ledgers.get(sender_identity, 0)
        )
        self._sender_ledgers[sender_identity] = committed_high_water
        initial_replay = oscore_ctx.export_replay_window()
        replay_state = self._replay_ledgers.get(bytes(recipient_identity))
        if replay_state is None:
            replay_index, replay_bitfield = initial_replay
            self._replay_ledgers[bytes(recipient_identity)] = (replay_index, replay_bitfield)
        else:
            replay_index, replay_bitfield = replay_state

        # Signal reservation state to the context
        oscore_ctx.clear_sender_sequence_reservation(committed_high_water)
        oscore_ctx.restore_replay_window(replay_index, replay_bitfield)

        next_generation = record.generation + 1 if record.generation else 1
        if next_generation > MAX_OSCORE_GENERATION:
            raise GenerationOverflowError(
                f"context generation for {key} has reached maximum ({MAX_OSCORE_GENERATION}); "
                "re-key via EDHOC required"
            )
        context = PeerContext(
            oscore=oscore_ctx,
            peer_pubkey=bytes(peer_pubkey),
            generation=next_generation,
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
            key = self._normalize_key(host)
            record = self._records.get(key)
            if record is not None and record.context is not None:
                next_generation = record.generation + 1
                if next_generation > MAX_OSCORE_GENERATION:
                    raise GenerationOverflowError(
                        f"context generation for {key} has reached maximum "
                        f"({MAX_OSCORE_GENERATION}); re-key via EDHOC required"
                    )
                record.context = None
                record.generation = next_generation

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
