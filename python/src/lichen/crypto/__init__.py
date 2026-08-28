# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN cryptographic primitives.

- schnorr48: Link-layer signatures (Ed25519-based, 48-byte)
- identity: Node identity management
- edhoc: EDHOC RFC 9528 Suite 0 for OSCORE key establishment
- oscore: Memory-based OSCORE context for aiocoap integration
- provisioning: BR provisioning channel encryption (spec 8.7)
- key_persistence: Secure key storage (spec 15.2)
- capability_announcements: COSE_Sign1 capability announcements (spec 8.12)
- root_dio_signature: COSE_Sign1 root DIO signatures (spec 8.10.1)
- delegation_tokens: COSE_Sign1 delegation tokens (spec 18.8.6)
- key_rotation_attestation: COSE_Sign1 key rotation attestations (spec 8.7.4)
"""

from .capability_announcements import (
    Capability,
    CapabilityAnnouncement,
    CapabilityPayload,
    SCHNORR48_ED25519_ALG,
    create_capability_announcement,
    decode_cose_sign1_announcement,
    verify_capability_announcement,
)
from .delegation_tokens import (
    ADMIN_DELEGATABLE_SCOPE,
    DelegationScope,
    DelegationToken,
    DelegationTokenPayload,
    check_delegation_scope,
    create_delegation_token,
    decode_delegation_token,
    verify_delegation_token,
)
from .edhoc import EdhocInitiator, EdhocResponder, OscoreContext
from .identity import Identity, PeerIdentity
from .root_dio_signature import (
    RootDioSignature,
    RootDioSignaturePayload,
    create_root_dio_signature,
    decode_root_dio_signature,
    verify_root_dio_signature,
)
from .key_rotation_attestation import (
    KeyRotationAttestation,
    KeyRotationAttestationPayload,
    create_key_rotation_attestation,
    decode_key_rotation_attestation,
    get_new_iid,
    verify_key_rotation_attestation,
)
from .key_persistence import (
    FileKeyStore,
    KeyPersistenceError,
    KeyStore,
    MemoryKeyStore,
    StoredSeed,
    TrustStorePersistence,
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

__all__ = [
    "ADMIN_DELEGATABLE_SCOPE",
    "AuthenticationFailedError",
    "BRProvisioningSession",
    "Capability",
    "CapabilityAnnouncement",
    "CapabilityPayload",
    "ChannelNotEstablishedError",
    "DecryptionFailedError",
    "DelegationScope",
    "DelegationToken",
    "DelegationTokenPayload",
    "DerivationMismatchError",
    "EdhocInitiator",
    "EdhocResponder",
    "FileKeyStore",
    "Identity",
    "KeyMismatchError",
    "KeyPersistenceError",
    "KeyRotationAttestation",
    "KeyRotationAttestationPayload",
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
    "RootDioSignature",
    "RootDioSignaturePayload",
    "SCHNORR48_ED25519_ALG",
    "StoredSeed",
    "TrustEntry",
    "TrustError",
    "TrustLevel",
    "TrustStore",
    "TrustStorePersistence",
    "UnknownPeerError",
    "check_delegation_scope",
    "create_capability_announcement",
    "create_delegation_token",
    "create_key_rotation_attestation",
    "create_root_dio_signature",
    "decode_cose_sign1_announcement",
    "decode_delegation_token",
    "decode_key_rotation_attestation",
    "decode_root_dio_signature",
    "generate_trust_vector",
    "get_new_iid",
    "verify_capability_announcement",
    "verify_delegation_token",
    "verify_key_rotation_attestation",
    "verify_pubkey_derivation",
    "verify_pubkey_to_ygg_addr",
    "verify_root_dio_signature",
    "verify_trust_vector",
]
