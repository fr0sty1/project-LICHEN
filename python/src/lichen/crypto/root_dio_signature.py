# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Root DIO Signature using COSE_Sign1 per spec section 8.10.1.

Root DIOs MAY carry an additional COSE_Sign1 signature as optional
defense-in-depth over the link-layer baseline. This provides cryptographic
proof that a DIO originates from the current DODAG root, not merely a node
that received and forwarded it.

COSE Algorithm: Schnorr48-Ed25519 (algorithm ID -65537)

Sig_structure = [
    "Signature1",           ; context string
    protected,              ; protected header bytes
    h'',                    ; external_aad (empty)
    payload                 ; payload bytes
]
sig = Schnorr48(root_privkey, SHA256(CBOR(Sig_structure)))
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from ipaddress import IPv6Address
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
_PAYLOAD_DODAG_ID = 1
_PAYLOAD_INSTANCE = 2
_PAYLOAD_VERSION = 3
_PAYLOAD_RANK = 4
_PAYLOAD_EXPIRY = 5
_PAYLOAD_ROOT_SEQ = 6
_PAYLOAD_MOP = 7


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
class RootDioSignaturePayload:
    """Root DIO Signature payload per spec section 8.10.1.

    Attributes:
        dodag_id: 16-byte DODAGID (128-bit IPv6 address)
        instance: RPLInstanceID
        version: DODAGVersionNumber
        rank: Root rank (normally 256 / ROOT_RANK)
        expiry: Unix timestamp when signature expires
        root_seq: Monotonic sequence, increments each DIO
        mop: Mode of Operation (0-7)
    """

    dodag_id: bytes
    instance: int
    version: int
    rank: int
    expiry: int
    root_seq: int
    mop: int

    def __post_init__(self) -> None:
        # Validate dodag_id
        if len(self.dodag_id) != 16:
            raise ValueError(f"dodag_id must be 16 bytes, got {len(self.dodag_id)}")

        # Validate instance (RPLInstanceID: 0-255, global instances are 0-127)
        if not 0 <= self.instance <= 255:
            raise ValueError(f"instance must be 0-255, got {self.instance}")

        # Validate version (DODAGVersionNumber: 0-255)
        if not 0 <= self.version <= 255:
            raise ValueError(f"version must be 0-255, got {self.version}")

        # Validate rank (16-bit unsigned)
        if not 0 <= self.rank <= 0xFFFF:
            raise ValueError(f"rank must be 0-65535, got {self.rank}")

        # Validate expiry is positive
        if self.expiry <= 0:
            raise ValueError(f"expiry must be positive, got {self.expiry}")

        # Validate root_seq is non-negative
        if self.root_seq < 0:
            raise ValueError(f"root_seq must be non-negative, got {self.root_seq}")

        # Validate mop (Mode of Operation: 0-7)
        if not 0 <= self.mop <= 7:
            raise ValueError(f"mop must be 0-7, got {self.mop}")

    def to_cbor(self) -> bytes:
        """Encode payload as CBOR map with integer keys."""
        payload_map = {
            _PAYLOAD_DODAG_ID: self.dodag_id,
            _PAYLOAD_INSTANCE: self.instance,
            _PAYLOAD_VERSION: self.version,
            _PAYLOAD_RANK: self.rank,
            _PAYLOAD_EXPIRY: self.expiry,
            _PAYLOAD_ROOT_SEQ: self.root_seq,
            _PAYLOAD_MOP: self.mop,
        }
        return cbor2.dumps(payload_map)

    @classmethod
    def from_cbor(cls, data: bytes) -> RootDioSignaturePayload:
        """Decode payload from CBOR bytes."""
        payload_map = cbor2.loads(data)
        return cls(
            dodag_id=payload_map[_PAYLOAD_DODAG_ID],
            instance=payload_map[_PAYLOAD_INSTANCE],
            version=payload_map[_PAYLOAD_VERSION],
            rank=payload_map[_PAYLOAD_RANK],
            expiry=payload_map[_PAYLOAD_EXPIRY],
            root_seq=payload_map[_PAYLOAD_ROOT_SEQ],
            mop=payload_map[_PAYLOAD_MOP],
        )


@dataclass
class RootDioSignature:
    """COSE_Sign1 Root DIO Signature per spec section 8.10.1.

    COSE_Sign1 structure:
    [
        h'a10139ffff',          ; protected: {1: -65537} (alg: Schnorr48-Ed25519)
        {4: h'<root-iid>'},     ; unprotected: {kid: root 8-byte IID}
        h'<payload>',           ; CBOR-encoded RootDioSignaturePayload
        h'<48-byte signature>'  ; Schnorr48 signature
    ]
    """

    payload: RootDioSignaturePayload
    root_iid: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.root_iid) != 8:
            raise ValueError(f"root_iid must be 8 bytes, got {len(self.root_iid)}")
        if len(self.signature) != 48:
            raise ValueError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_cose_sign1(self) -> bytes:
        """Encode as COSE_Sign1 structure.

        Returns:
            CBOR-encoded COSE_Sign1 array
        """
        protected = _encode_protected_header()
        unprotected = {COSE_KID_LABEL: self.root_iid}
        payload_bytes = self.payload.to_cbor()

        cose_sign1 = [protected, unprotected, payload_bytes, self.signature]
        return cbor2.dumps(cose_sign1)

    @classmethod
    def from_cose_sign1(cls, data: bytes) -> RootDioSignature:
        """Decode from COSE_Sign1 structure.

        Args:
            data: CBOR-encoded COSE_Sign1 array

        Returns:
            RootDioSignature

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

        # Extract root_iid from unprotected header
        root_iid = unprotected.get(COSE_KID_LABEL)
        if not isinstance(root_iid, bytes) or len(root_iid) != 8:
            raise ValueError("kid in unprotected header must be 8-byte IID")

        # Decode payload
        payload = RootDioSignaturePayload.from_cbor(payload_bytes)

        # Validate signature length
        if not isinstance(signature, bytes) or len(signature) != 48:
            raise ValueError("signature must be 48 bytes")

        return cls(payload=payload, root_iid=root_iid, signature=signature)


def create_root_dio_signature(
    identity: Identity,
    dodag_id: IPv6Address | bytes,
    instance: int,
    version: int,
    rank: int,
    expiry: int,
    root_seq: int,
    mop: int,
) -> RootDioSignature:
    """Create a signed Root DIO Signature.

    Args:
        identity: The root node's identity (contains signing key)
        dodag_id: 16-byte DODAGID (or IPv6Address)
        instance: RPLInstanceID
        version: DODAGVersionNumber
        rank: Root rank (normally 256)
        expiry: Unix timestamp when signature expires
        root_seq: Monotonically increasing sequence number
        mop: Mode of Operation (0-7)

    Returns:
        Signed RootDioSignature ready for transmission
    """
    dodag_id_bytes = dodag_id.packed if isinstance(dodag_id, IPv6Address) else dodag_id

    payload = RootDioSignaturePayload(
        dodag_id=dodag_id_bytes,
        instance=instance,
        version=version,
        rank=rank,
        expiry=expiry,
        root_seq=root_seq,
        mop=mop,
    )

    # Build COSE Sig_structure
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)

    # Sign SHA-256 hash of Sig_structure with Schnorr48
    to_sign = sha256(sig_structure).digest()
    signature = schnorr48.sign(identity.privkey, identity.pubkey, to_sign)

    return RootDioSignature(payload=payload, root_iid=identity.iid, signature=signature)


def verify_root_dio_signature(
    root_dio_sig: RootDioSignature,
    pubkey: bytes,
    current_time: int,
    cached_root_seq: int | None = None,
    dio_dodag_id: IPv6Address | bytes | None = None,
    dio_instance: int | None = None,
    dio_version: int | None = None,
    dio_rank: int | None = None,
    dio_mop: int | None = None,
) -> tuple[bool, str | None]:
    """Verify a Root DIO Signature.

    Performs validation steps from spec section 8.10.1:
    1. Verify signature using Schnorr48 and provided pubkey
    2. Verify root_iid (kid) matches derived IID from pubkey
    3. Verify expiry > current_time
    4. Verify root_seq > cached_root_seq (if provided)
    5. Verify payload fields match DIO fields (if provided)

    Args:
        root_dio_sig: The Root DIO Signature to verify
        pubkey: 32-byte Ed25519 public key of the root
        current_time: Current Unix timestamp
        cached_root_seq: Previously cached sequence number for this DODAG (optional)
        dio_dodag_id: DODAGID from DIO message to cross-check (optional)
        dio_instance: RPLInstanceID from DIO to cross-check (optional)
        dio_version: DODAGVersionNumber from DIO to cross-check (optional)
        dio_rank: Rank from DIO to cross-check (optional)
        dio_mop: MOP from DIO to cross-check (optional)

    Returns:
        (valid, error): Tuple of (True, None) if valid, or (False, error_string) if invalid
    """
    payload = root_dio_sig.payload

    # Step 2: Verify root_iid matches derived IID from pubkey
    derived_iid = _pubkey_to_iid(pubkey)
    if root_dio_sig.root_iid != derived_iid:
        return False, "IID_MISMATCH"

    # Step 1: Verify signature
    protected = _encode_protected_header()
    payload_bytes = payload.to_cbor()
    sig_structure = _build_sig_structure(protected, payload_bytes)
    to_verify = sha256(sig_structure).digest()

    if not schnorr48.verify(pubkey, to_verify, root_dio_sig.signature):
        return False, "SIGNATURE_INVALID"

    # Step 3: Verify expiry > current_time
    if payload.expiry <= current_time:
        return False, "EXPIRED"

    # Step 4: Verify root_seq > cached_root_seq
    if cached_root_seq is not None and payload.root_seq <= cached_root_seq:
        return False, "REPLAY_DETECTED"

    # Step 5: Verify payload matches DIO fields
    if dio_dodag_id is not None:
        expected_dodag_id = (
            dio_dodag_id.packed if isinstance(dio_dodag_id, IPv6Address) else dio_dodag_id
        )
        if payload.dodag_id != expected_dodag_id:
            return False, "DODAG_ID_MISMATCH"

    if dio_instance is not None and payload.instance != dio_instance:
        return False, "INSTANCE_MISMATCH"

    if dio_version is not None and payload.version != dio_version:
        return False, "VERSION_MISMATCH"

    if dio_rank is not None and payload.rank != dio_rank:
        return False, "RANK_MISMATCH"

    if dio_mop is not None and payload.mop != dio_mop:
        return False, "MOP_MISMATCH"

    return True, None


def decode_root_dio_signature(data: bytes) -> RootDioSignature:
    """Decode a COSE_Sign1 Root DIO Signature from bytes.

    This is a convenience wrapper around RootDioSignature.from_cose_sign1().

    Args:
        data: CBOR-encoded COSE_Sign1 structure

    Returns:
        Decoded RootDioSignature
    """
    return RootDioSignature.from_cose_sign1(data)
