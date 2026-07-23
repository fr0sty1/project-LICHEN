# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN cryptographic primitives.

- schnorr48: Link-layer signatures (Ed25519-based, 48-byte)
- identity: Node identity management
- edhoc: EDHOC RFC 9528 Suite 0 for OSCORE key establishment
- oscore: Memory-based OSCORE context for aiocoap integration
"""

from .edhoc import EdhocInitiator, EdhocResponder, OscoreContext
from .identity import Identity, PeerIdentity
from .oscore import (
    MAX_OSCORE_SEQUENCE_NUMBER,
    OSCORE_SEQUENCE_EXHAUSTED,
    MemorySecurityContext,
    OscoreContextParameters,
)

__all__ = [
    "EdhocInitiator",
    "EdhocResponder",
    "Identity",
    "MAX_OSCORE_SEQUENCE_NUMBER",
    "MemorySecurityContext",
    "OSCORE_SEQUENCE_EXHAUSTED",
    "OscoreContext",
    "OscoreContextParameters",
    "PeerIdentity",
]
