#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Independent PyNaCl-backed Schnorr-48 vector primitives.

This module intentionally imports no ``lichen`` package.  It implements the
algorithm in draft-lichen-schnorr-00 directly with libsodium group/scalar
operations so vector generation does not reuse the signer or identity code
being tested by Python and Rust consumers.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from nacl.bindings import (
    crypto_core_ed25519_is_valid_point,
    crypto_core_ed25519_scalar_add,
    crypto_core_ed25519_scalar_mul,
    crypto_core_ed25519_scalar_reduce,
    crypto_core_ed25519_sub,
    crypto_scalarmult_ed25519_base_noclamp,
    crypto_scalarmult_ed25519_noclamp,
)

_GROUP_ORDER = 2**252 + 27742317777372353535851937790883648493
LINK_SIGNATURE_DOMAIN = b"LICHEN-LINK-v1\x00"


def _private_scalar(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Schnorr-48 seed must be exactly 32 bytes")
    scalar = bytearray(hashlib.sha512(seed).digest()[:32])
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    return bytes(scalar)


def _canonical_scalar(value: bytes) -> bytes:
    return (int.from_bytes(value, "little") % _GROUP_ORDER).to_bytes(32, "little")


@dataclass(frozen=True, slots=True)
class ReferenceIdentity:
    """Spec-derived deterministic identity used only by vector tooling."""

    seed: bytes
    private_scalar: bytes
    pubkey: bytes
    iid: bytes
    ygg_addr: bytes

    @property
    def eui64(self) -> bytes:
        """Return the canonical link-wire EUI-64 for this key-derived IID."""
        value = bytearray(self.iid)
        value[0] ^= 0x02
        return bytes(value)

    @classmethod
    def from_seed(cls, seed: bytes) -> ReferenceIdentity:
        private = _private_scalar(seed)
        public = crypto_scalarmult_ed25519_base_noclamp(private)
        digest = hashlib.sha512(public).digest()
        iid = bytearray(digest[:8])
        iid[0] &= 0xFD
        address = bytes((0x02,)) + digest[:7] + bytes(iid)
        return cls(bytes(seed), private, public, bytes(iid), address)


def sign(identity: ReferenceIdentity, message: bytes) -> bytes:
    """Sign ``message`` using the draft algorithm and libsodium primitives."""

    nonce = crypto_core_ed25519_scalar_reduce(
        hashlib.sha512(identity.private_scalar + message).digest()
    )
    commitment = crypto_scalarmult_ed25519_base_noclamp(nonce)
    challenge = hashlib.sha512(commitment + identity.pubkey + message).digest()[:16]
    challenge_scalar = challenge + bytes(16)
    response = crypto_core_ed25519_scalar_add(
        nonce,
        crypto_core_ed25519_scalar_mul(
            challenge_scalar, _canonical_scalar(identity.private_scalar)
        ),
    )
    return challenge + response


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify with an independent reconstruction of ``R = sB - eA``."""

    if len(public_key) != 32 or len(signature) != 48:
        return False
    if not crypto_core_ed25519_is_valid_point(public_key):
        return False
    challenge, response = signature[:16], signature[16:]
    if int.from_bytes(response, "little") >= _GROUP_ORDER:
        return False
    try:
        response_base = crypto_scalarmult_ed25519_base_noclamp(response)
        challenge_key = crypto_scalarmult_ed25519_noclamp(challenge + bytes(16), public_key)
        commitment = crypto_core_ed25519_sub(response_base, challenge_key)
    except Exception:
        return False
    expected = hashlib.sha512(commitment + public_key + message).digest()[:16]
    return hmac.compare_digest(expected, challenge)


def signature_transcript(wire_without_mic: bytes, destination_length: int) -> bytes:
    """Insert the non-wire DST_LEN octet into an exact link-frame prefix."""

    if destination_length not in (0, 2, 8):
        raise ValueError("destination length must be 0, 2, or 8")
    if len(wire_without_mic) < 5 + destination_length:
        raise ValueError("truncated link frame prefix")
    destination_end = 5 + destination_length
    return (
        LINK_SIGNATURE_DOMAIN
        + wire_without_mic[:5]
        + bytes((destination_length,))
        + wire_without_mic[5:destination_end]
        + wire_without_mic[destination_end:]
    )


__all__ = [
    "LINK_SIGNATURE_DOMAIN",
    "ReferenceIdentity",
    "sign",
    "signature_transcript",
    "verify",
]
