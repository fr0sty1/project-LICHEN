# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Core types, protocols, and exceptions for OSCORE-protected transport."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from aiocoap import Message

    from lichen.crypto.oscore import MemorySecurityContext

    from ..transport import EndpointPolicy

# OSCORE option number (RFC 8613 Section 2)
OSCORE_OPTION_NUMBER = 9


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
