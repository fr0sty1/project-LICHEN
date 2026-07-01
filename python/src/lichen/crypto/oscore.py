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
        """
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

        # Sequence number for outgoing messages
        self.sender_sequence_number = 0

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
    ) -> MemorySecurityContext:
        """Create a security context from an EDHOC-exported OscoreContext.

        Args:
            edhoc_ctx: The OscoreContext from EdhocInitiator/Responder.export_oscore().
            algorithm: COSE algorithm ID.
            hashfun: KDF hash function.
            window_size: Replay window size.

        Returns:
            A ready-to-use MemorySecurityContext.
        """
        return cls(
            master_secret=edhoc_ctx.master_secret,
            master_salt=edhoc_ctx.master_salt,
            sender_id=edhoc_ctx.sender_id,
            recipient_id=edhoc_ctx.recipient_id,
            algorithm=algorithm,
            hashfun=hashfun,
            window_size=window_size,
        )

    def new_sequence_number(self) -> int:
        """Allocate and return the next sender sequence number."""
        seqno = self.sender_sequence_number
        self.sender_sequence_number += 1
        return seqno

    def post_seqnoincrease(self) -> None:
        """Hook called after sequence number increment (no-op for memory context)."""
        pass
