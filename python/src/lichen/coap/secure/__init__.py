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

from .channel import SecureDatagramChannel, create_secure_channel
from .memory_store import InMemoryOscoreContextStore, OscoreContextStore
from .resolvers import EdhocPeerResolver, TofuPeerResolver
from .sqlite_store import SqliteOscoreContextStore, SqliteStoreHooks
from .types import (
    OSCORE_OPTION_NUMBER,
    ContextGenerationError,
    EndpointPolicyConflictError,
    ForkSafetyError,
    PeerContext,
    PeerKeyConflictError,
    ReplayWindowConflictError,
    SequenceReservation,
    SequenceReservationError,
    TransactionalOscoreContextStore,
)
from .utils import normalize_host, validate_endpoint_key

__all__ = [
    # Channel
    "SecureDatagramChannel",
    "create_secure_channel",
    # Context stores
    "InMemoryOscoreContextStore",
    "OscoreContextStore",
    "SqliteOscoreContextStore",
    "SqliteStoreHooks",
    "TransactionalOscoreContextStore",
    # Peer resolvers
    "EdhocPeerResolver",
    "TofuPeerResolver",
    # Types
    "OSCORE_OPTION_NUMBER",
    "PeerContext",
    "SequenceReservation",
    # Exceptions
    "ContextGenerationError",
    "EndpointPolicyConflictError",
    "ForkSafetyError",
    "PeerKeyConflictError",
    "ReplayWindowConflictError",
    "SequenceReservationError",
    # Utils
    "normalize_host",
    "validate_endpoint_key",
]
