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
from hashlib import sha256, sha512
from ipaddress import IPv6Address

from nacl.bindings import crypto_scalarmult_base

from .schnorr48 import clamp, derive_keypair


@dataclass
class Identity:
    """A node's cryptographic identity.

    Attributes:
        seed: 32-byte secret seed. NEVER log, transmit, or expose this.
        privkey: 32-byte Ed25519 private scalar (derived from seed).
        pubkey: 32-byte Ed25519 public point (can be shared).
        iid: 8-byte Interface Identifier derived from pubkey.
        ygg_addr: 16-byte Yggdrasil-derived primary IPv6 address (02xx::/7).
    """

    seed: bytes
    privkey: bytes
    pubkey: bytes
    iid: bytes
    ygg_addr: bytes

    def __post_init__(self) -> None:
        if len(self.seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(self.seed)}")
        if len(self.privkey) != 32:
            raise ValueError(f"privkey must be 32 bytes, got {len(self.privkey)}")
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")
        if len(self.ygg_addr) != 16:
            raise ValueError(f"ygg_addr must be 16 bytes, got {len(self.ygg_addr)}")

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
        ygg_addr = yggdrasil_address(pubkey).packed

        return cls(seed=seed, privkey=privkey, pubkey=pubkey, iid=iid, ygg_addr=ygg_addr)

    @classmethod
    def generate(cls) -> Identity:
        """Generate a new random identity.

        Returns:
            A new Identity with cryptographically random keys.
        """
        return cls.from_seed(os.urandom(32))

    def __repr__(self) -> str:
        ygg = self.ygg_addr.hex()[:16]
        return f"Identity(pubkey={self.pubkey.hex()[:16]}..., iid={self.iid.hex()}, ygg={ygg})"

    @property
    def x25519_private(self) -> bytes:
        """Derive X25519 private key from Ed25519 seed (for static DH).

        x25519_private = clamp(SHA-512(seed)[0:32]) per RFC 7748 §5,
        standards/crypto.md and draft-lichen-security. Clamping is required
        to place scalar in correct subgroup (avoids small subgroup attacks
        in static DH for EDHOC/OSCORE).

        Returns:
            32-byte clamped X25519 private key.
        """
        h = sha512(self.seed).digest()[:32]
        return clamp(h)

    @property
    def x25519_public(self) -> bytes:
        """Derive X25519 public key from Ed25519 seed (for static DH).

        Returns:
            32-byte X25519 public key for ECDH key agreement.
        """
        return crypto_scalarmult_base(self.x25519_private)


def _pubkey_to_iid(pubkey: bytes) -> bytes:
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")

    digest = sha512(pubkey).digest()
    iid = bytearray(digest[:8])
    iid[0] &= 0b1111_1101
    return bytes(iid)


@dataclass(frozen=True)
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
        return f"PeerIdentity(iid={self.iid.hex()[:8]}, human={self.human_address})"

    @property
    def human_address(self) -> str:
        """Human-readable node address (Base32 of IID, 13 chars with dashes)."""
        return iid_to_human_address(self.iid)


def iid_to_human_address(iid: bytes) -> str:
    """Convert 8-byte IID (from SHA256 of Ed25519 pubkey) to 13-char
    human-readable Crockford Base32 address with dashes (XXXX-XXXX-XXXXX).

    Matches spec/03-addressing.md. Collision-resistant at planetary scale.
    """
    if len(iid) != 8:
        raise ValueError(f"IID must be 8 bytes, got {len(iid)}")
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    n = int.from_bytes(iid, "big")
    chars: list[str] = []
    for _ in range(13):
        n, rem = divmod(n, 32)
        chars.append(alphabet[rem])
    s = "".join(reversed(chars))
    return f"{s[:4]}-{s[4:8]}-{s[8:]}"


def yggdrasil_address(pubkey: bytes) -> IPv6Address:
    """Derive Yggdrasil 02xx::/7 address from Ed25519 pubkey.

    Matches Rust `yggdrasil_addr_from_pubkey` and spec/06-security.md:152
    (section 8.6 derivation): addr[0]=0x02, addr[1:8]=SHA-512(pubkey)[0:7],
    addr[8:16]=IID from _pubkey_to_iid (MUST bind lower 64 bits to prevent
    key substitution). See test/vectors/yggdrasil-derivation.json.
    """
    if len(pubkey) != 32:
        raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
    h = sha512(pubkey).digest()
    iid = bytearray(h[:8])
    iid[0] &= 0b1111_1101
    addr_bytes = bytearray(16)
    addr_bytes[0] = 0x02
    addr_bytes[1:8] = h[0:7]
    addr_bytes[8:16] = iid
    return IPv6Address(bytes(addr_bytes))
