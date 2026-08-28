# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Capability Announcements using COSE_Sign1 per spec section 8.12.

Mesh nodes announce their capabilities (egress, prefix-delegation) to the
DODAG root via COSE_Sign1 signed messages. The root uses these announcements
to determine which nodes can serve as egress points or delegate prefixes.

COSE Algorithm: Schnorr48-Ed25519 (algorithm ID -65537)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from hashlib import sha256
from typing import TYPE_CHECKING

import cbor2

from . import schnorr48
from .identity import Identity, _pubkey_to_iid

if TYPE_CHECKING:
    pass

# COSE algorithm ID for Schnorr48-Ed25519 (private use range)
SCHNORR48_ED25519_ALG = -65537

# COSE header labels
COSE_ALG_LABEL = 1  # Algorithm
COSE_KID_LABEL = 4  # Key ID


class Capability(IntFlag):
    """Capability bits per spec section 8.12."""

    EGRESS = 1 << 0  # Node can decapsulate and forward to external networks
    PREFIX_DELEGATION = 1 << 1  # Node can delegate prefixes to downstream nodes
    # Bits 2-7 reserved, must be zero


# Payload map keys (integer keys per spec to minimize size)
_PAYLOAD_CAPABILITIES = 1
_PAYLOAD_PREFIX = 2
_PAYLOAD_PREFIX_LEN = 3
_PAYLOAD_EXPIRY = 4
_PAYLOAD_SEQ = 5
_PAYLOAD_ANNOUNCER_IID = 6


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
class CapabilityPayload:
    """Capability announcement payload per spec section 8.12.

    Attributes:
        capabilities: Bitmask of announced capabilities (see Capability enum)
        prefix: Prefix bytes (prefix_len/8 bytes, zero-padded)
        prefix_len: Prefix length in bits (0-128)
        expiry: Unix timestamp when announcement expires
        seq: Sequence number for replay protection
        announcer_iid: 8-byte IID of the announcing node
    """

    capabilities: int
    prefix: bytes
    prefix_len: int
    expiry: int
    seq: int
    announcer_iid: bytes

    def __post_init__(self) -> None:
        # Validate capability bits (bits 2-7 are reserved, must be zero)
        # Per spec 8.12: bits 0 = egress, 1 = prefix-delegation, 2-7 = reserved
        valid_bits = int(Capability.EGRESS) | int(Capability.PREFIX_DELEGATION)
        reserved_bits = 0xFF & ~valid_bits  # 0xFC = bits 2-7
        if self.capabilities & reserved_bits:
            raise ValueError(
                f"Reserved capability bits (2-7) must be zero, got {self.capabilities}"
            )

        # Validate prefix_len
        if not 0 <= self.prefix_len <= 128:
            raise ValueError(f"prefix_len must be 0-128, got {self.prefix_len}")

        # Validate prefix length matches prefix_len
        expected_prefix_bytes = (self.prefix_len + 7) // 8
        if len(self.prefix) != expected_prefix_bytes:
            raise ValueError(
                f"prefix must be {expected_prefix_bytes} bytes for prefix_len {self.prefix_len}, "
                f"got {len(self.prefix)}"
            )

        # Validate announcer_iid
        if len(self.announcer_iid) != 8:
            raise ValueError(
                f"announcer_iid must be 8 bytes, got {len(self.announcer_iid)}"
            )

        # Validate expiry is positive
        if self.expiry <= 0:
            raise ValueError(f"expiry must be positive, got {self.expiry}")

        # Validate seq is non-negative
        if self.seq < 0:
            raise ValueError(f"seq must be non-negative, got {self.seq}")

    def to_cbor(self) -> bytes:
        """Encode payload as CBOR map with integer keys."""
        payload_map = {
            _PAYLOAD_CAPABILITIES: self.capabilities,
            _PAYLOAD_PREFIX: self.prefix,
            _PAYLOAD_PREFIX_LEN: self.prefix_len,
            _PAYLOAD_EXPIRY: self.expiry,
            _PAYLOAD_SEQ: self.seq,
            _PAYLOAD_ANNOUNCER_IID: self.announcer_iid,
        }
        return cbor2.dumps(payload_map)

    @classmethod
    def from_cbor(cls, data: bytes) -> CapabilityPayload:
        """Decode payload from CBOR bytes."""
        payload_map = cbor2.loads(data)
        return cls(
            capabilities=payload_map[_PAYLOAD_CAPABILITIES],
            prefix=payload_map[_PAYLOAD_PREFIX],
            prefix_len=payload_map[_PAYLOAD_PREFIX_LEN],
            expiry=payload_map[_PAYLOAD_EXPIRY],
            seq=payload_map[_PAYLOAD_SEQ],
            announcer_iid=payload_map[_PAYLOAD_ANNOUNCER_IID],
        )


@dataclass
class CapabilityAnnouncement:
    """COSE_Sign1 capability announcement per spec section 8.12.

    COSE_Sign1 structure:
    [
        protected,          ; {1: -65537} encoded
        {4: <announcer-iid>}, ; unprotected: kid
        payload,            ; CBOR-encoded CapabilityPayload
        signature           ; 48-byte Schnorr48 signature
    ]
    """

    payload: CapabilityPayload
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.signature) != 48:
            raise ValueError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_cose_sign1(self) -> bytes:
        """Encode as COSE_Sign1 structure.

        Returns:
            CBOR-encoded COSE_Sign1 array
        """
        protected = _encode_protected_header()
        unprotected = {COSE_KID_LABEL: self.payload.announcer_iid}
        payload_bytes = self.payload.to_cbor()

        cose_sign1 = [protected, unprotected, payload_bytes, self.signature]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> CapabilityAnnouncement:
        """Decode from COSE_Sign1 structure.

        Args:
            data: CBOR-encoded COSE_Sign1 array

        Returns:
            CapabilityAnnouncement

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

        # Decode payload
        payload = CapabilityPayload.from_cbor(payload_bytes)

        # Validate kid matches announcer_iid
        kid = unprotected.get(COSE_KID_LABEL)
        if kid != payload.announcer_iid:
            raise ValueError("kid in unprotected header must match announcer_iid")

        return cls(payload=payload, signature=signature)


def create_capability_announcement(
    identity: Identity,
    capabilities: Capability | int,
    prefix: bytes,
    prefix_len: int,
    expiry: int,
    seq: int,
) -> CapabilityAnnouncement:
    """Create a signed capability announcement.

    Args:
        identity: The announcing node's identity (contains signing key)
        capabilities: Bitmask of capabilities being announced
        prefix: Prefix bytes (zero-padded to ceil(prefix_len/8) bytes)
        prefix_len: Prefix length in bits (0-128)
        expiry: Unix timestamp when announcement expires
        seq: Monotonically increasing sequence number

    Returns:
        Signed CapabilityAnnouncement ready for transmission
    """
    payload = CapabilityPayload(
        capabilities=int(capabilities),
        prefix=prefix,
        prefix_len=prefix_len,
        expiry=expiry,
        seq=seq,
        announcer_iid=identity.iid,
    )

    # Build COSE Sig_structure
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)

    # Sign SHA-256 hash of Sig_structure with Schnorr48
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(identity.privkey, identity.pubkey, to_sign)

    return CapabilityAnnouncement(payload=payload, signature=signature)


def verify_capability_announcement(
    announcement: CapabilityAnnouncement,
    pubkey: bytes,
    current_time: int,
    cached_seq: int | None = None,
) -> tuple[bool, str | None]:
    """Verify a capability announcement.

    Performs all validation steps from spec section 8.12:
    1. Verify signature using Schnorr48 and provided pubkey
    2. Verify announcer_iid matches derived IID from pubkey
    3. Verify expiry > current_time
    4. Verify seq > cached_seq (if provided)
    5. Verify reserved capability bits (2-7) are zero

    Args:
        announcement: The announcement to verify
        pubkey: 32-byte Ed25519 public key of the announcer
        current_time: Current Unix timestamp
        cached_seq: Previously cached sequence number for this announcer (optional)

    Returns:
        (valid, error): Tuple of (True, None) if valid, or (False, error_string) if invalid
    """
    payload = announcement.payload

    # Step 5 (early): Verify reserved capability bits are zero
    reserved_bits = ~(Capability.EGRESS | Capability.PREFIX_DELEGATION) & 0xFF
    if payload.capabilities & reserved_bits:
        return False, "RESERVED_BITS_SET"

    # Step 2: Verify announcer_iid matches derived IID from pubkey
    derived_iid = _pubkey_to_iid(pubkey)
    if payload.announcer_iid != derived_iid:
        return False, "IID_MISMATCH"

    # Step 1: Verify signature
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_verify = sha256(sig_structure).digest()

    if not schnorr48.verify(pubkey, to_verify, announcement.signature):
        return False, "SIGNATURE_INVALID"

    # Step 3: Verify expiry > current_time
    if payload.expiry <= current_time:
        return False, "EXPIRED"

    # Step 4: Verify seq > cached_seq
    if cached_seq is not None and payload.seq <= cached_seq:
        return False, "REPLAY_DETECTED"

    return True, None


def decode_cose_sign1_announcement(data: bytes) -> CapabilityAnnouncement:
    """Decode a COSE_Sign1 capability announcement from bytes.

    This is a convenience wrapper around CapabilityAnnouncement.from_cose_sign1().

    Args:
        data: CBOR-encoded COSE_Sign1 structure

    Returns:
        Decoded CapabilityAnnouncement
    """
    return CapabilityAnnouncement.from_cose_sign1(data)
