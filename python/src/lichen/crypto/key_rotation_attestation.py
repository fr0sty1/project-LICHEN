# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Key Rotation Attestation using COSE_Sign1 per spec section 8.7.4.

Key rotation announcements use COSE_Sign1 to provide a verifiable attestation
that a new public key is the legitimate successor to an old key. The OLD key
signs the attestation, proving continuity of identity across the rotation.

COSE Algorithm: Schnorr48-Ed25519 (algorithm ID -65537)

Sig_structure = [
    "Signature1",           ; context string
    protected,              ; protected header bytes
    h'',                    ; external_aad (empty)
    payload                 ; payload bytes
]
sig = Schnorr48(old_privkey, SHA256(CBOR(Sig_structure)))
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING

import cbor2

from . import schnorr48
from .identity import _pubkey_to_iid

if TYPE_CHECKING:
    from .identity import Identity

# COSE algorithm ID for Schnorr48-Ed25519 (private use range)
SCHNORR48_ED25519_ALG = -65537

# COSE header labels
COSE_ALG_LABEL = 1  # Algorithm
COSE_KID_LABEL = 4  # Key ID

# Payload map keys (integer keys per spec to minimize size)
_PAYLOAD_OLD_PUBKEY = 1
_PAYLOAD_NEW_PUBKEY = 2
_PAYLOAD_ROTATION_SEQ = 3
_PAYLOAD_EXPIRY = 4

# Maximum rotation sequence value (u64)
_MAX_ROTATION_SEQUENCE = (1 << 64) - 1


def _encode_protected_header() -> bytes:
    """Encode the protected header for COSE_Sign1.

    Returns:
        CBOR-encoded protected header bytes: {1: -65537} (alg: Schnorr48-Ed25519)
    """
    return cbor2.dumps({COSE_ALG_LABEL: SCHNORR48_ED25519_ALG})


def _build_sig_structure(protected: bytes, payload: bytes) -> bytes:
    """Build COSE Sig_structure per RFC 9052 section 4.4.

    Sig_structure = [
        "Signature1",     ; context string
        protected,        ; protected header bytes
        h'',              ; external_aad (empty)
        payload           ; payload bytes
    ]

    Returns:
        CBOR-encoded Sig_structure
    """
    sig_structure = [
        "Signature1",  # context string
        protected,  # protected header (already CBOR-encoded)
        b"",  # external_aad (empty)
        payload,  # payload bytes
    ]
    return cbor2.dumps(sig_structure)


@dataclass
class KeyRotationAttestationPayload:
    """Key Rotation Attestation payload per spec section 8.7.4.

    Attributes:
        old_pubkey: 32-byte Ed25519 public key being retired.
        new_pubkey: 32-byte Ed25519 public key being activated.
        rotation_seq: Monotonic sequence, strictly increasing.
        expiry: Unix timestamp when attestation expires.
    """

    old_pubkey: bytes
    new_pubkey: bytes
    rotation_seq: int
    expiry: int

    def __post_init__(self) -> None:
        # Validate old_pubkey
        if not isinstance(self.old_pubkey, bytes) or len(self.old_pubkey) != 32:
            raise ValueError(f"old_pubkey must be 32 bytes, got {len(self.old_pubkey)}")

        # Validate new_pubkey
        if not isinstance(self.new_pubkey, bytes) or len(self.new_pubkey) != 32:
            raise ValueError(f"new_pubkey must be 32 bytes, got {len(self.new_pubkey)}")

        # Keys must be different
        if self.old_pubkey == self.new_pubkey:
            raise ValueError("key rotation must change the public key")

        # Validate rotation_seq (must be positive u64)
        if not isinstance(self.rotation_seq, int):
            raise TypeError("rotation_seq must be int")
        if not 1 <= self.rotation_seq <= _MAX_ROTATION_SEQUENCE:
            raise ValueError(f"rotation_seq must be 1..{_MAX_ROTATION_SEQUENCE}")

        # Validate expiry is positive
        if not isinstance(self.expiry, int):
            raise TypeError("expiry must be int")
        if self.expiry <= 0:
            raise ValueError(f"expiry must be positive, got {self.expiry}")

    def to_cbor(self) -> bytes:
        """Encode payload as CBOR map with integer keys."""
        payload_map = {
            _PAYLOAD_OLD_PUBKEY: self.old_pubkey,
            _PAYLOAD_NEW_PUBKEY: self.new_pubkey,
            _PAYLOAD_ROTATION_SEQ: self.rotation_seq,
            _PAYLOAD_EXPIRY: self.expiry,
        }
        return cbor2.dumps(payload_map)

    @classmethod
    def from_cbor(cls, data: bytes) -> KeyRotationAttestationPayload:
        """Decode payload from CBOR bytes."""
        payload_map = cbor2.loads(data)
        return cls(
            old_pubkey=payload_map[_PAYLOAD_OLD_PUBKEY],
            new_pubkey=payload_map[_PAYLOAD_NEW_PUBKEY],
            rotation_seq=payload_map[_PAYLOAD_ROTATION_SEQ],
            expiry=payload_map[_PAYLOAD_EXPIRY],
        )


@dataclass
class KeyRotationAttestation:
    """COSE_Sign1 Key Rotation Attestation per spec section 8.7.4.

    COSE_Sign1 structure:
    [
        h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
        {4: h'<old-iid>'},      ; unprotected: {kid: old key's 8-byte IID}
        h'<payload>',           ; CBOR-encoded KeyRotationAttestationPayload
        h'<48-byte signature>'  ; Schnorr48 signature (by OLD key)
    ]
    """

    payload: KeyRotationAttestationPayload
    old_iid: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.old_iid, bytes) or len(self.old_iid) != 8:
            raise ValueError(f"old_iid must be 8 bytes, got {len(self.old_iid)}")
        if not isinstance(self.signature, bytes) or len(self.signature) != 48:
            raise ValueError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_cose_sign1(self) -> bytes:
        """Encode as COSE_Sign1 structure.

        Returns:
            CBOR-encoded COSE_Sign1 array
        """
        protected = _encode_protected_header()
        unprotected = {COSE_KID_LABEL: self.old_iid}
        payload_bytes = self.payload.to_cbor()

        cose_sign1 = [protected, unprotected, payload_bytes, self.signature]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> KeyRotationAttestation:
        """Decode from COSE_Sign1 structure.

        Args:
            data: CBOR-encoded COSE_Sign1 array

        Returns:
            KeyRotationAttestation

        Raises:
            ValueError: If structure is invalid
        """
        cose_array = cbor2.loads(data)

        if not isinstance(cose_array, list) or len(cose_array) != 4:
            raise ValueError("COSE_Sign1 must be a 4-element array")

        protected_bytes, unprotected, payload_bytes, signature = cose_array

        # Validate protected header
        protected = cbor2.loads(protected_bytes)
        if protected.get(COSE_ALG_LABEL) != SCHNORR48_ED25519_ALG:
            raise ValueError(
                f"Algorithm must be {SCHNORR48_ED25519_ALG}, "
                f"got {protected.get(COSE_ALG_LABEL)}"
            )

        # Extract old_iid from unprotected header
        old_iid = unprotected.get(COSE_KID_LABEL)
        if not isinstance(old_iid, bytes) or len(old_iid) != 8:
            raise ValueError("kid in unprotected header must be 8-byte IID")

        # Decode payload
        payload = KeyRotationAttestationPayload.from_cbor(payload_bytes)

        # Validate signature length
        if not isinstance(signature, bytes) or len(signature) != 48:
            raise ValueError("signature must be 48 bytes")

        return cls(payload=payload, old_iid=old_iid, signature=signature)


def create_key_rotation_attestation(
    old_identity: Identity,
    new_pubkey: bytes,
    rotation_seq: int,
    expiry: int,
) -> KeyRotationAttestation:
    """Create a signed Key Rotation Attestation.

    The OLD identity signs the attestation, attesting that the new public key
    is its legitimate successor.

    Args:
        old_identity: The identity being rotated (contains old signing key)
        new_pubkey: 32-byte Ed25519 public key being activated
        rotation_seq: Monotonically increasing sequence number (must be > 0)
        expiry: Unix timestamp when attestation expires

    Returns:
        Signed KeyRotationAttestation ready for transmission
    """
    payload = KeyRotationAttestationPayload(
        old_pubkey=old_identity.pubkey,
        new_pubkey=new_pubkey,
        rotation_seq=rotation_seq,
        expiry=expiry,
    )

    # Build COSE Sig_structure
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)

    # Sign SHA-256 hash of Sig_structure with Schnorr48 using OLD key
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(old_identity.privkey, old_identity.pubkey, to_sign)

    return KeyRotationAttestation(
        payload=payload, old_iid=old_identity.iid, signature=signature
    )


def verify_key_rotation_attestation(
    attestation: KeyRotationAttestation,
    old_pubkey: bytes,
    current_time: int,
    cached_rotation_seq: int | None = None,
) -> tuple[bool, str | None]:
    """Verify a Key Rotation Attestation.

    Performs validation steps from spec section 8.7.4:
    1. Verify algorithm in protected header is -65537
    2. Verify old_iid (kid) matches derived IID from old_pubkey
    3. Verify old_pubkey in payload matches the provided old_pubkey
    4. Verify signature using Schnorr48 and old_pubkey
    5. Verify expiry > current_time
    6. Verify rotation_seq > cached_rotation_seq (if provided)
    7. Derive new IID from new_pubkey (returned in result)

    Args:
        attestation: The Key Rotation Attestation to verify
        old_pubkey: 32-byte Ed25519 public key of the old identity
        current_time: Current Unix timestamp
        cached_rotation_seq: Previously cached sequence number (optional)

    Returns:
        (valid, error): Tuple of (True, None) if valid, or (False, error_string)
    """
    payload = attestation.payload

    # Step 2: Verify old_iid matches derived IID from old_pubkey
    derived_iid = _pubkey_to_iid(old_pubkey)
    if attestation.old_iid != derived_iid:
        return False, "IID_MISMATCH"

    # Step 3: Verify old_pubkey in payload matches provided old_pubkey
    if payload.old_pubkey != old_pubkey:
        return False, "OLD_PUBKEY_MISMATCH"

    # Step 4: Verify signature
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_verify = sha256(sig_structure).digest()

    if not schnorr48.verify(old_pubkey, to_verify, attestation.signature):
        return False, "SIGNATURE_INVALID"

    # Step 5: Verify expiry > current_time
    if payload.expiry <= current_time:
        return False, "EXPIRED"

    # Step 6: Verify rotation_seq > cached_rotation_seq
    if cached_rotation_seq is not None and payload.rotation_seq <= cached_rotation_seq:
        return False, "REPLAY_DETECTED"

    return True, None


def decode_key_rotation_attestation(data: bytes) -> KeyRotationAttestation:
    """Decode a COSE_Sign1 Key Rotation Attestation from bytes.

    This is a convenience wrapper around KeyRotationAttestation.from_cose_sign1().

    Args:
        data: CBOR-encoded COSE_Sign1 structure

    Returns:
        Decoded KeyRotationAttestation
    """
    return KeyRotationAttestation.from_cose_sign1(data)


def get_new_iid(attestation: KeyRotationAttestation) -> bytes:
    """Derive the new IID from a valid attestation.

    Call this after successful verification to get the new IID
    that should be pinned in the trust store.

    Args:
        attestation: A verified KeyRotationAttestation

    Returns:
        8-byte IID derived from new_pubkey
    """
    return _pubkey_to_iid(attestation.payload.new_pubkey)
