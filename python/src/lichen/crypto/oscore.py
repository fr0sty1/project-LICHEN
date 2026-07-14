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


class MemorySecurityContext(CanProtect, CanUnprotect, SecurityContextUtils):
    """In-memory OSCORE security context for aiocoap.

    Unlike FilesystemSecurityContext, this stores all state in memory. Suitable
    for ephemeral sessions established via EDHOC.

    Attributes:
        sender_id: Our ID (from EDHOC connection ID).
        recipient_id: Peer's ID (from EDHOC connection ID).
        sender_sequence_number: Next outgoing sequence number.
        recipient_replay_window: Replay protection for incoming messages.
    """

    def __init__(
        self,
        master_secret: bytes,
        master_salt: bytes,
        sender_id: bytes,
        recipient_id: bytes,
        *,
        algorithm: int = DEFAULT_ALGORITHM,
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
                RFC 8613 limit (2^40 - 1).
        """
        # SECURITY: Validate starting_sequence_number to prevent invalid state
        if starting_sequence_number < 0:
            raise ValueError("starting_sequence_number must be non-negative")
        if starting_sequence_number > _MAX_SEQUENCE_NUMBER:
            raise ValueError(
                f"starting_sequence_number exceeds RFC 8613 limit ({_MAX_SEQUENCE_NUMBER})"
            )
        self.alg_aead = algorithms[algorithm]
        self.hashfun = hashfunctions[hashfun]
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.id_context = id_context

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
        algorithm: int = DEFAULT_ALGORITHM,
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

    def new_sequence_number(self) -> int:
        """Allocate and return the next sender sequence number.

        Raises:
            OverflowError: If sequence number would exceed RFC 8613 limit (2^40 - 1).
                This prevents nonce reuse which would break AEAD security.
        """
        # SECURITY: Check BEFORE returning to prevent nonce reuse
        if self.sender_sequence_number > _MAX_SEQUENCE_NUMBER:
            raise OverflowError(
                "OSCORE sequence number exhausted; context must be re-established"
            )
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
