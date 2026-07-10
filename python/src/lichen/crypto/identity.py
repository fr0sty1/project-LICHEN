# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Node identity and keypair management.

Every LICHEN node needs a stable cryptographic identity for:
1. Signing outgoing frames (authentication)
2. Verifying signatures from known peers
3. Building the trust graph (TOFU model)

The identity is derived from a 32-byte seed (typically from secure storage or
hardware RNG). The seed MUST be kept secret; the public key can be shared freely.

Note: Python cannot securely erase memory (GC copies, no mlock, immutable bytes).
For memory-forensics threat models, use Rust/C implementations or HSMs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from hashlib import sha256

from .schnorr48 import derive_keypair


@dataclass(slots=True)
class Identity:
    """A node's cryptographic identity.

    Attributes:
        seed: 32-byte secret seed. NEVER log, transmit, or expose this.
        privkey: 32-byte Ed25519 private scalar (derived from seed).
        pubkey: 32-byte Ed25519 public point (can be shared).
        iid: 8-byte Interface Identifier derived from pubkey (for IPv6).
    """

    seed: bytes
    privkey: bytes
    pubkey: bytes
    iid: bytes

    def __post_init__(self) -> None:
        if len(self.seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(self.seed)}")
        if len(self.privkey) != 32:
            raise ValueError(f"privkey must be 32 bytes, got {len(self.privkey)}")
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")

    @classmethod
    def from_seed(cls, seed: bytes) -> Identity:
        """Create an identity from a 32-byte seed.

        Args:
            seed: 32 bytes of secret randomness. Use os.urandom(32) for real keys.

        Returns:
            A new Identity with derived keys.
        """
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")

        privkey, pubkey = derive_keypair(seed)
        iid = _pubkey_to_iid(pubkey)

        return cls(seed=seed, privkey=privkey, pubkey=pubkey, iid=iid)

    @classmethod
    def generate(cls) -> Identity:
        """Generate a new random identity.

        Returns:
            A new Identity with cryptographically random keys.
        """
        return cls.from_seed(os.urandom(32))

    def __repr__(self) -> str:
        return f"Identity(pubkey={self.pubkey.hex()[:16]}..., iid={self.iid.hex()})"


def _pubkey_to_iid(pubkey: bytes) -> bytes:
    """Derive 8-byte Interface Identifier from public key.

    SHA-256 truncation matches ORCHID (RFC 7343). Bit 6 cleared per RFC 4291
    for locally-assigned addresses.
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")

    digest = sha256(pubkey).digest()
    iid = bytearray(digest[:8])
    iid[0] &= 0b1111_1101  # clear "u" bit
    return bytes(iid)


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """A remote peer's public identity (no secret material).

    Attributes:
        pubkey: 32-byte Ed25519 public key.
        iid: 8-byte Interface Identifier.
    """

    pubkey: bytes
    iid: bytes

    def __post_init__(self) -> None:
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")

    @classmethod
    def from_pubkey(cls, pubkey: bytes) -> PeerIdentity:
        """Create a peer identity from their public key."""
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
        return cls(pubkey=pubkey, iid=_pubkey_to_iid(pubkey))

    def __repr__(self) -> str:
        return f"PeerIdentity(pubkey={self.pubkey.hex()[:16]}..., iid={self.iid.hex()})"
