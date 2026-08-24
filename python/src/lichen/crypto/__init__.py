# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN cryptographic primitives.

- schnorr48: Link-layer signatures (Ed25519-based, 48-byte)
- identity: Node identity management
- edhoc: EDHOC RFC 9528 Suite 0 for OSCORE key establishment
- oscore: Memory-based OSCORE context for aiocoap integration
- provisioning: BR provisioning channel encryption (spec 8.7)
- key_persistence: Secure key storage (spec 15.2)
"""

from .edhoc import EdhocInitiator, EdhocResponder, OscoreContext
from .identity import Identity, PeerIdentity
from .key_persistence import (
    FileKeyStore,
    KeyPersistenceError,
    KeyStore,
    MemoryKeyStore,
    StoredSeed,
    TrustStorePersistence,
)
from .trust import (
    DerivationMismatchError,
    KeyMismatchError,
    RevokedPeerError,
    TrustEntry,
    TrustError,
    TrustLevel,
    TrustStore,
    UnknownPeerError,
    generate_trust_vector,
    verify_pubkey_derivation,
    verify_pubkey_to_ygg_addr,
    verify_trust_vector,
)
from .oscore import (
    MAX_OSCORE_SEQUENCE_NUMBER,
    OSCORE_SEQUENCE_EXHAUSTED,
    MemorySecurityContext,
    OscoreContextParameters,
)
from .provisioning import (
    AuthenticationFailedError,
    BRProvisioningSession,
    ChannelNotEstablishedError,
    DecryptionFailedError,
    NodeProvisioningSession,
    ProvisioningError,
    ProvisioningPayload,
    ProvisioningState,
)

__all__ = [
    "AuthenticationFailedError",
    "BRProvisioningSession",
    "ChannelNotEstablishedError",
    "DecryptionFailedError",
    "DerivationMismatchError",
    "EdhocInitiator",
    "EdhocResponder",
    "FileKeyStore",
    "Identity",
    "KeyMismatchError",
    "KeyPersistenceError",
    "KeyStore",
    "MAX_OSCORE_SEQUENCE_NUMBER",
    "MemoryKeyStore",
    "MemorySecurityContext",
    "NodeProvisioningSession",
    "OSCORE_SEQUENCE_EXHAUSTED",
    "OscoreContext",
    "OscoreContextParameters",
    "PeerIdentity",
    "ProvisioningError",
    "ProvisioningPayload",
    "ProvisioningState",
    "RevokedPeerError",
    "StoredSeed",
    "TrustEntry",
    "TrustError",
    "TrustLevel",
    "TrustStore",
    "TrustStorePersistence",
    "UnknownPeerError",
    "generate_trust_vector",
    "verify_pubkey_derivation",
    "verify_pubkey_to_ygg_addr",
    "verify_trust_vector",
]
