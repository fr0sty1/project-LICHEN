# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Memory-based OSCORE security context for use with aiocoap.

Bridges the EDHOC-exported OscoreContext to aiocoap's OSCORE machinery without
requiring filesystem persistence. For constrained/embedded use where ephemeral
contexts are acceptable.

Usage:
    # After EDHOC handshake
    edhoc_ctx = initiator.export_oscore()
    oscore_ctx = MemorySecurityContext.from_edhoc(edhoc_ctx)

    # Use with aiocoap for protected messaging
    protected_msg, request_id = oscore_ctx.protect(request)
    response = oscore_ctx.unprotect(protected_response, request_id)

SECURITY WARNING:
    Each (master_secret, master_salt) pair MUST produce exactly ONE context
    instance over its entire lifetime. Creating a new MemorySecurityContext
    with the same key material (e.g., from replayed EDHOC, same ephemeral keys,
    or state recovery without preserving sequence numbers) causes nonce reuse,
    which breaks AEAD security and enables plaintext recovery attacks.

    For state recovery scenarios, use the starting_sequence_number parameter
    to resume from a persisted sequence number. The starting value MUST be
    strictly greater than any sequence number previously used with this context.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING

from aiocoap.oscore import (
    DEFAULT_ALGORITHM,
    DEFAULT_HASHFUNCTION,
    DEFAULT_WINDOWSIZE,
    CanProtect,
    CanUnprotect,
    ReplayWindow,
    SecurityContextUtils,
    algorithms,
    hashfunctions,
)

if TYPE_CHECKING:
    from .edhoc import OscoreContext


# SECURITY: Maximum partial IV per RFC 8613 Section 5.2 (5 bytes = 40 bits).
# Exceeding this would cause nonce reuse, breaking AEAD security.
_MAX_SEQUENCE_NUMBER = (1 << 40) - 1
MAX_OSCORE_SEQUENCE_NUMBER = _MAX_SEQUENCE_NUMBER
OSCORE_SEQUENCE_EXHAUSTED = _MAX_SEQUENCE_NUMBER + 1


def _frame_identity_parts(domain: bytes, *parts: bytes) -> bytes:
    digest = sha256()
    digest.update(domain)
    for part in parts:
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.digest()


@dataclass(frozen=True)
class OscoreContextParameters:
    """Serializable inputs needed to reconstruct an OSCORE context."""

    master_secret: bytes
    master_salt: bytes
    sender_id: bytes
    recipient_id: bytes
    algorithm: int
    hashfun: str
    window_size: int
    id_context: bytes | None


class MemorySecurityContext(CanProtect, CanUnprotect, SecurityContextUtils):
    """In-memory OSCORE security context for aiocoap.

    Unlike FilesystemSecurityContext, this stores all state in memory. Suitable
    for ephemeral sessions established via EDHOC.

    Compatible with aiocoap==0.4.17 (pinned in pyproject.toml). Explicitly
    declares interface elements from CanProtect/CanUnprotect/SecurityContextUtils
    to prevent silent breakage on library updates.

    Attributes:
        sender_id: Our ID (from EDHOC connection ID).
        recipient_id: Peer's ID (from EDHOC connection ID).
        sender_sequence_number: Next outgoing sequence number.
        recipient_replay_window: Replay protection for incoming messages.
    """

    is_signing = False
    responses_send_kid = False
    external_aad_is_group = False
    authenticated_claims: list[str] = []
    sender_key: bytes
    recipient_key: bytes
    common_iv: bytes

    @property
    def context_id(self) -> bytes | None:
        return self.id_context

    @property
    def kid_context(self) -> bytes | None:
        return self.id_context

    def __init__(
        self,
        master_secret: bytes,
        master_salt: bytes,
        sender_id: bytes,
        recipient_id: bytes,
        *,
        algorithm: str | int = DEFAULT_ALGORITHM,
        hashfun: str = DEFAULT_HASHFUNCTION,
        window_size: int = DEFAULT_WINDOWSIZE,
        id_context: bytes | None = None,
        starting_sequence_number: int = 0,
    ) -> None:
        """Create a security context from master key material.

        Args:
            master_secret: OSCORE master secret (from EDHOC export).
            master_salt: OSCORE master salt (from EDHOC export).
            sender_id: Our connection ID.
            recipient_id: Peer's connection ID.
            algorithm: COSE algorithm ID (default: AES-CCM-16-64-128).
            hashfun: KDF hash function (default: SHA-256).
            window_size: Replay window size.
            id_context: Optional ID context for multi-context scenarios.
            starting_sequence_number: Initial sender sequence number. For state
                recovery, this MUST be strictly greater than any sequence number
                previously used with this (master_secret, master_salt) pair to
                prevent nonce reuse. See module docstring for security details.

        Raises:
            ValueError: If starting_sequence_number is negative or exceeds the
                RFC 8613 limit (2^40 - 1), or if algorithm or hashfun is invalid.
        """
        if starting_sequence_number < 0:
            raise ValueError("starting_sequence_number must be non-negative")
        if starting_sequence_number > _MAX_SEQUENCE_NUMBER:
            raise ValueError(
                f"starting_sequence_number exceeds RFC 8613 limit ({_MAX_SEQUENCE_NUMBER})"
            )
        if hashfun not in hashfunctions:
            raise ValueError(
                f"unknown hashfun {hashfun!r}. "
                f"Valid values: {sorted(hashfunctions.keys())}"
            )
        if isinstance(algorithm, int):
            matching_algorithms = [
                candidate for candidate in algorithms.values() if int(candidate.value) == algorithm
            ]
            if len(matching_algorithms) != 1:
                raise ValueError(
                    f"unknown or ambiguous COSE algorithm ID: {algorithm}. "
                    f"Valid: {sorted(algorithms.keys())}"
                )
            self.alg_aead = matching_algorithms[0]
        else:
            if algorithm not in algorithms:
                raise ValueError(
                    f"unknown algorithm {algorithm!r}. "
                    f"Valid: {sorted(algorithms.keys())}"
                )
            self.alg_aead = algorithms[algorithm]
        algorithm_id = int(self.alg_aead.value)
        self.hashfun = hashfunctions[hashfun]
        self.sender_id = bytes(sender_id)
        self.recipient_id = bytes(recipient_id)
        self.id_context = bytes(id_context) if id_context is not None else None
        self._parameters = OscoreContextParameters(
            master_secret=bytes(master_secret),
            master_salt=bytes(master_salt),
            sender_id=self.sender_id,
            recipient_id=self.recipient_id,
            algorithm=algorithm_id,
            hashfun=hashfun,
            window_size=window_size,
            id_context=self.id_context,
        )

        # Validate ID lengths (RFC 8613 constraint)
        max_id_len = self.alg_aead.iv_bytes - 6
        if len(sender_id) > max_id_len or len(recipient_id) > max_id_len:
            raise ValueError(f"ID too long (max {max_id_len} bytes for this algorithm)")

        # Derive sender_key, recipient_key, common_iv
        self.derive_keys(master_salt, master_secret)

        # SECURITY: Sequence number for outgoing messages. When recovering state,
        # the caller MUST provide a starting value greater than any previously used
        # to prevent nonce reuse (which breaks AEAD security).
        self.sender_sequence_number = starting_sequence_number
        # Standalone contexts are ephemeral and retain the historical in-process
        # behavior. A context store clears this range when publishing the context.
        self._sender_sequence_reservation_end = _MAX_SEQUENCE_NUMBER + 1

        # Replay window for incoming messages
        self.recipient_replay_window = ReplayWindow(window_size, lambda: None)
        self.recipient_replay_window.initialize_empty()

        # Echo recovery token for B.1.2 (random, re-generated each startup)
        self.echo_recovery = secrets.token_bytes(8)

    @classmethod
    def from_edhoc(
        cls,
        edhoc_ctx: OscoreContext,
        *,
        algorithm: str | int = DEFAULT_ALGORITHM,
        hashfun: str = DEFAULT_HASHFUNCTION,
        window_size: int = DEFAULT_WINDOWSIZE,
        starting_sequence_number: int = 0,
    ) -> MemorySecurityContext:
        """Create a security context from an EDHOC-exported OscoreContext.

        Args:
            edhoc_ctx: The OscoreContext from EdhocInitiator/Responder.export_oscore().
            algorithm: COSE algorithm ID.
            hashfun: KDF hash function.
            window_size: Replay window size.
            starting_sequence_number: Initial sender sequence number for state
                recovery. See __init__ for security requirements.

        Returns:
            A ready-to-use MemorySecurityContext.

        SECURITY:
            Each EDHOC handshake MUST produce unique key material. If the same
            master_secret/master_salt could be derived again (e.g., ephemeral key
            reuse in testing, or EDHOC message replay), a new context MUST use a
            starting_sequence_number greater than any previously used value.
        """
        return cls(
            master_secret=edhoc_ctx.master_secret,
            master_salt=edhoc_ctx.master_salt,
            sender_id=edhoc_ctx.sender_id,
            recipient_id=edhoc_ctx.recipient_id,
            algorithm=algorithm,
            hashfun=hashfun,
            window_size=window_size,
            starting_sequence_number=starting_sequence_number,
        )

    @classmethod
    def from_parameters(
        cls,
        parameters: OscoreContextParameters,
        *,
        starting_sequence_number: int,
    ) -> MemorySecurityContext:
        """Reconstruct a context from exported parameters and durable state."""
        if starting_sequence_number < 0 or starting_sequence_number > OSCORE_SEQUENCE_EXHAUSTED:
            raise ValueError("invalid persisted OSCORE sender sequence high-water")
        context = cls(
            master_secret=parameters.master_secret,
            master_salt=parameters.master_salt,
            sender_id=parameters.sender_id,
            recipient_id=parameters.recipient_id,
            algorithm=parameters.algorithm,
            hashfun=parameters.hashfun,
            window_size=parameters.window_size,
            id_context=parameters.id_context,
            starting_sequence_number=min(starting_sequence_number, _MAX_SEQUENCE_NUMBER),
        )
        context.clear_sender_sequence_reservation(starting_sequence_number)
        return context

    def export_parameters(self) -> OscoreContextParameters:
        """Return immutable copies of all context reconstruction inputs."""
        return self._parameters

    def _canonical_algorithm_id(self) -> bytes:
        return int(self.alg_aead.value).to_bytes(8, "big", signed=True)

    def sender_cryptographic_identity(self) -> bytes:
        """Return the canonical identity of this context's sender nonce space."""
        id_context = b"\x00" if self.id_context is None else b"\x01" + self.id_context
        return _frame_identity_parts(
            b"LICHEN-OSCORE-SENDER-NONCE-IDENTITY-v1\x00",
            self._canonical_algorithm_id(),
            bytes(self.sender_key),
            bytes(self.common_iv),
            self.sender_id,
            id_context,
        )

    def recipient_cryptographic_identity(self) -> bytes:
        """Return the canonical identity of this context's replay space."""
        id_context = b"\x00" if self.id_context is None else b"\x01" + self.id_context
        return _frame_identity_parts(
            b"LICHEN-OSCORE-RECIPIENT-REPLAY-IDENTITY-v1\x00",
            self._canonical_algorithm_id(),
            bytes(self.recipient_key),
            bytes(self.common_iv),
            self.recipient_id,
            id_context,
        )

    def export_replay_window(self) -> tuple[int, int]:
        """Return the recipient replay window index and bitfield."""
        persisted = self.recipient_replay_window.persist()
        return int(persisted["index"]), int(persisted["bitfield"])

    def restore_replay_window(self, index: int, bitfield: int) -> None:
        """Restore a validated recipient replay window snapshot."""
        if index < 0 or bitfield < 0:
            raise ValueError("invalid OSCORE replay window state")
        self.recipient_replay_window.initialize_from_persisted(
            {"index": index, "bitfield": bitfield}
        )

    def set_sender_sequence_reservation(self, start: int, end: int) -> None:
        """Install a committed half-open sender sequence range ``[start, end)``."""
        if start < 0 or end < start or end > OSCORE_SEQUENCE_EXHAUSTED:
            raise ValueError("invalid OSCORE sender sequence reservation")
        if start < self.sender_sequence_number:
            raise ValueError("reservation starts before the next sender sequence")
        self.sender_sequence_number = start
        self._sender_sequence_reservation_end = end

    def clear_sender_sequence_reservation(self, high_water: int) -> None:
        """Set the durable high-water and fail closed until a range is reserved."""
        if high_water < 0 or high_water > OSCORE_SEQUENCE_EXHAUSTED:
            raise ValueError("invalid OSCORE sender sequence high-water")
        self.sender_sequence_number = high_water
        self._sender_sequence_reservation_end = high_water

    @property
    def has_reserved_sender_sequence(self) -> bool:
        """Whether at least one committed sender sequence remains available."""
        return self.sender_sequence_number < self._sender_sequence_reservation_end

    def new_sequence_number(self) -> int:
        """Allocate and return the next sender sequence number.

        Raises:
            OverflowError: If sequence number would exceed RFC 8613 limit (2^40 - 1).
                This prevents nonce reuse which would break AEAD security.
        """
        # SECURITY: Check BEFORE returning to prevent nonce reuse
        if self.sender_sequence_number > _MAX_SEQUENCE_NUMBER:
            raise OverflowError("OSCORE sequence number exhausted; context must be re-established")
        if not self.has_reserved_sender_sequence:
            raise OverflowError("no durable OSCORE sender sequence is reserved")
        seqno = self.sender_sequence_number
        self.sender_sequence_number += 1
        return seqno

    def post_seqnoincrease(self) -> None:
        """Hook called after sequence number increment (no-op for memory context)."""
        pass

    def get_persisted_sequence_number(self) -> int:
        """Return the sequence number to persist for state recovery.

        When recovering state, pass this value as starting_sequence_number to
        the new context. To provide margin for any in-flight messages, callers
        may add a safety buffer (e.g., +100) before persisting.

        Returns:
            The current sender_sequence_number.

        SECURITY:
            The persisted value MUST be written to stable storage BEFORE any
            message using that sequence number is transmitted. Otherwise, a
            crash between transmission and persistence could cause the same
            sequence number to be reused after recovery.
        """
        return self.sender_sequence_number
