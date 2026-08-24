# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SOS origin signature generation (spec section 18.4.1).

This module provides origin signatures for SOS messages. The origin signature
authenticates the original sender across relays - while the link-layer signature
provides hop-by-hop authentication, the origin signature persists through
rebroadcasts so recipients can verify who initiated the emergency.

The signature covers:
1. A domain separator (prevents cross-protocol signature reuse)
2. The originator's IPv6 address
3. A monotonic sequence number (replay protection)
4. The canonical CBOR encoding of the SOS payload

Per spec 18.4.1: "SOS messages MUST carry a valid link-layer signature from
the originating node. The Ed25519/Schnorr signature is verified at each
receiving node before rebroadcast."
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from ipaddress import IPv6Address

import cbor2

from lichen.crypto.schnorr48 import sign, verify

# Domain separator for SOS origin signature (20 ASCII octets, matches DAO pattern)
SOS_ORIGIN_DOMAIN: bytes = b"LICHEN-SOS-ORIGIN-v1"

# SOS signature length: 8 bytes sequence + 48 bytes Schnorr48
SOS_ORIGIN_SIGNATURE_LENGTH: int = 56


@dataclass(frozen=True)
class SosOriginSignature:
    """Parsed SOS Origin Signature.

    Attributes:
        origin_sequence: 64-bit unsigned monotonic counter.
        signature: 48-byte Schnorr48 signature.
    """

    origin_sequence: int
    signature: bytes

    def __post_init__(self) -> None:
        if not 0 <= self.origin_sequence <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("origin_sequence must fit in 64 bits")
        if len(self.signature) != 48:
            raise ValueError(f"signature must be 48 bytes, got {len(self.signature)}")

    def to_bytes(self) -> bytes:
        """Serialize to wire format: 8-byte sequence + 48-byte signature."""
        return struct.pack(">Q", self.origin_sequence) + self.signature

    @classmethod
    def from_bytes(cls, data: bytes) -> SosOriginSignature:
        """Parse from wire format."""
        if len(data) != SOS_ORIGIN_SIGNATURE_LENGTH:
            raise ValueError(
                f"SOS Origin Signature must be {SOS_ORIGIN_SIGNATURE_LENGTH} bytes, "
                f"got {len(data)}"
            )
        origin_sequence = struct.unpack(">Q", data[:8])[0]
        signature = data[8:]
        return cls(origin_sequence=origin_sequence, signature=signature)


def canonicalize_sos_payload(payload: dict) -> bytes:
    """Canonicalize SOS payload to deterministic CBOR.

    The payload is sorted by key to ensure consistent signing/verification
    across implementations. Per RFC 8949 section 4.2.1, deterministic CBOR
    requires sorted keys with shortest-form encoding.

    Args:
        payload: SOS payload dict with keys like "type", "node", "ts", etc.

    Returns:
        Deterministic CBOR encoding of the payload.
    """
    return cbor2.dumps(payload, canonical=True)


def compute_sos_transcript(
    origin_address: IPv6Address,
    origin_sequence: int,
    payload_cbor: bytes,
) -> bytes:
    """Compute the SHA-512 digest for SOS origin signature.

    Transcript format:
        SHA-512("LICHEN-SOS-ORIGIN-v1" || origin IPv6 address ||
                Origin Sequence || canonical CBOR payload)

    Args:
        origin_address: The originator's 02xx IPv6 address (16 bytes).
        origin_sequence: 64-bit origin sequence in network byte order.
        payload_cbor: Canonical CBOR encoding of the SOS payload.

    Returns:
        64-byte SHA-512 digest.
    """
    transcript = (
        SOS_ORIGIN_DOMAIN
        + origin_address.packed
        + struct.pack(">Q", origin_sequence)
        + payload_cbor
    )
    return hashlib.sha512(transcript).digest()


def sign_sos_origin(
    privkey: bytes,
    pubkey: bytes,
    origin_address: IPv6Address,
    origin_sequence: int,
    payload: dict,
) -> SosOriginSignature:
    """Generate SOS origin signature.

    Signs the SOS message with a domain-separated Schnorr48 signature.
    The signature authenticates that the message originated from the
    holder of the private key corresponding to origin_address.

    Args:
        privkey: 32-byte Ed25519 private scalar (clamped).
        pubkey: 32-byte Ed25519 public key.
        origin_address: The originator's 02xx IPv6 address.
        origin_sequence: Monotonic 64-bit sequence number for replay protection.
        payload: SOS payload dict (will be canonicalized).

    Returns:
        SosOriginSignature containing sequence and signature.

    Raises:
        ValueError: If keys are not 32 bytes each.
    """
    if len(privkey) != 32 or len(pubkey) != 32:
        raise ValueError("Keys must be 32 bytes")

    payload_cbor = canonicalize_sos_payload(payload)
    transcript = compute_sos_transcript(origin_address, origin_sequence, payload_cbor)
    signature = sign(privkey, pubkey, transcript)

    return SosOriginSignature(origin_sequence=origin_sequence, signature=signature)


def verify_sos_origin(
    pubkey: bytes,
    origin_addr: bytes,
    payload: bytes,
    signature: SosOriginSignature,
) -> bool:
    """Verify SOS origin signature.

    Verifies that the SOS message was signed by the holder of the private key
    corresponding to the given public key.

    Args:
        pubkey: 32-byte Ed25519 public key.
        origin_addr: 16-byte packed IPv6 address of the originator.
        payload: Canonical CBOR encoding of the SOS payload.
        signature: SosOriginSignature containing sequence and signature.

    Returns:
        True if signature is valid, False otherwise.
    """
    transcript = compute_sos_transcript(
        IPv6Address(origin_addr), signature.origin_sequence, payload
    )
    return verify(pubkey, transcript, signature.signature)


__all__ = [
    "SOS_ORIGIN_DOMAIN",
    "SOS_ORIGIN_SIGNATURE_LENGTH",
    "SosOriginSignature",
    "canonicalize_sos_payload",
    "compute_sos_transcript",
    "sign_sos_origin",
    "verify_sos_origin",
]
