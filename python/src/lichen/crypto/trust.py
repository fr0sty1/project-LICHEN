# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Trust Models oracle (GCP-3) - TOFU key pinning and trust management.

Per spec section 8.7, trust is established per-peer using one of:
- TOFU: Pin pubkey on first contact, verify derivation matches IID/02xx
- BR-Provisioned: Trust anchors from border router (managed fleets)
- DANE: DNSSEC-verified TLSA records (optional)
- PKIX: CA-issued certificates (optional, enterprise)

The cryptographic binding ensures pubkey -> IID/02xx is verifiable:
  iid = SHA-512(pubkey)[0:8] with U/L bit cleared
  02xx = [0x02] || SHA-512(pubkey)[0:7] || iid

Key rotation: A key change with valid signature from old key is accepted.
Otherwise, key/IID mismatch is rejected as potential MITM.

SECURITY: This is the Python oracle for test vectors. Production
implementations should use constant-time comparisons throughout.
"""

from __future__ import annotations

import hmac
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import IntEnum
from ipaddress import IPv6Address
from types import MappingProxyType
from typing import Protocol

from .identity import PeerIdentity, _pubkey_to_iid, yggdrasil_address
from .schnorr48 import verify as schnorr_verify

# Domain separation tag for key rotation transcripts
KEY_ROTATION_DOMAIN: bytes = b"LICHEN-KEY-ROTATION-v1\x00"
_MAX_ROTATION_SEQUENCE = (1 << 64) - 1


class TrustLevel(IntEnum):
    """Trust establishment method per spec 8.7.

    Values ordered by verification strength (TOFU lowest, PKIX highest).
    """

    TOFU = 1  # Pinned on first contact, fully offline
    BR_PROVISIONED = 2  # Delegated trust from border router
    DANE = 3  # DNSSEC + TLSA verified
    PKIX = 4  # CA certificate verified


class TrustError(Exception):
    """Base class for trust model errors."""


class KeyMismatchError(TrustError):
    """Pubkey does not match pinned key for this IID/02xx."""


class DerivationMismatchError(TrustError):
    """Pubkey does not derive to the claimed IID/02xx address."""


class UnknownPeerError(TrustError):
    """Peer not in trust store and auto-pinning disabled."""


class RevokedPeerError(TrustError):
    """Peer has been revoked."""


class TrustPersistence(Protocol):
    """Durable backend required for security-sensitive trust transitions."""

    @property
    def is_crash_safe(self) -> bool: ...

    @property
    def fails_closed(self) -> bool: ...

    def save(self, store: TrustStore) -> None: ...


@dataclass(frozen=True)
class TrustEntry:
    """A pinned peer in the trust store.

    Attributes:
        pubkey: 32-byte Ed25519 public key.
        iid: 8-byte Interface Identifier (derived from pubkey).
        ygg_addr: 16-byte Yggdrasil 02xx address (derived from pubkey).
        trust_level: How trust was established.
        first_seen: Unix timestamp of first contact.
        last_seen: Unix timestamp of most recent verification.
        revoked: True if peer has been revoked.
        metadata: Optional application-specific data.
        rotation_sequence: Anti-replay counter for key rotation (monotonic).
    """

    pubkey: bytes
    iid: bytes
    ygg_addr: bytes
    trust_level: TrustLevel
    first_seen: float
    last_seen: float
    revoked: bool = False
    metadata: Mapping[str, str] = field(default_factory=dict)
    rotation_sequence: int = 0

    def __post_init__(self) -> None:
        for bytes_name, bytes_value in (
            ("pubkey", self.pubkey),
            ("iid", self.iid),
            ("ygg_addr", self.ygg_addr),
        ):
            if type(bytes_value) is not bytes:
                raise TypeError(f"{bytes_name} must be bytes")
        if len(self.pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(self.pubkey)}")
        if len(self.iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(self.iid)}")
        if len(self.ygg_addr) != 16:
            raise ValueError(f"ygg_addr must be 16 bytes, got {len(self.ygg_addr)}")
        if not verify_pubkey_derivation(self.pubkey, self.iid):
            raise ValueError("pubkey does not derive to iid")
        if not verify_pubkey_to_ygg_addr(self.pubkey, self.ygg_addr):
            raise ValueError("pubkey does not derive to ygg_addr")
        if type(self.trust_level) is not TrustLevel:
            raise TypeError("trust_level must be TrustLevel")
        for timestamp_name, timestamp_value in (
            ("first_seen", self.first_seen),
            ("last_seen", self.last_seen),
        ):
            if (
                type(timestamp_value) not in (int, float)
                or not math.isfinite(timestamp_value)
                or timestamp_value < 0
            ):
                raise ValueError(f"{timestamp_name} must be a finite non-negative number")
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        if type(self.revoked) is not bool:
            raise TypeError("revoked must be bool")
        if type(self.rotation_sequence) is not int:
            raise TypeError("rotation_sequence must be int")
        if not 0 <= self.rotation_sequence <= _MAX_ROTATION_SEQUENCE:
            raise ValueError("rotation_sequence must fit in u64")
        if not isinstance(self.metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        copied_metadata: dict[str, str] = {}
        for metadata_key, metadata_value in self.metadata.items():
            if type(metadata_key) is not str or type(metadata_value) is not str:
                raise TypeError("metadata keys and values must be str")
            copied_metadata[metadata_key] = metadata_value
        object.__setattr__(self, "metadata", MappingProxyType(copied_metadata))

    @classmethod
    def from_pubkey(
        cls,
        pubkey: bytes,
        trust_level: TrustLevel = TrustLevel.TOFU,
        metadata: dict[str, str] | None = None,
    ) -> TrustEntry:
        """Create a trust entry from a public key.

        The IID and 02xx address are derived per spec 8.5/8.7.

        Args:
            pubkey: 32-byte Ed25519 public key.
            trust_level: How trust was established.
            metadata: Optional application-specific data.

        Returns:
            New TrustEntry with derived IID and 02xx address.
        """
        if type(pubkey) is not bytes:
            raise TypeError("pubkey must be bytes")
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")

        now = time.time()
        iid = _pubkey_to_iid(pubkey)
        ygg = yggdrasil_address(pubkey).packed

        return cls(
            pubkey=pubkey,
            iid=iid,
            ygg_addr=ygg,
            trust_level=trust_level,
            first_seen=now,
            last_seen=now,
            revoked=False,
            metadata={} if metadata is None else metadata,
        )

    def to_peer_identity(self) -> PeerIdentity:
        """Convert to PeerIdentity for signature verification."""
        return PeerIdentity(pubkey=self.pubkey, iid=self.iid)

    def ipv6_address(self) -> IPv6Address:
        """Return the Yggdrasil 02xx address as IPv6Address."""
        return IPv6Address(self.ygg_addr)


def verify_pubkey_derivation(pubkey: bytes, iid: bytes) -> bool:
    """Verify that pubkey correctly derives to the given IID.

    SECURITY: This is the core binding check. Per spec 8.7, the key
    MUST derive to the observed IID/02xx address. Mismatches indicate
    MITM or key compromise.

    Args:
        pubkey: 32-byte Ed25519 public key.
        iid: 8-byte IID to verify against.

    Returns:
        True if pubkey derives to the given IID.
    """
    if len(pubkey) != 32 or len(iid) != 8:
        return False

    derived_iid = _pubkey_to_iid(pubkey)
    # SECURITY: Constant-time comparison prevents timing attacks
    return hmac.compare_digest(derived_iid, iid)


def verify_pubkey_to_ygg_addr(pubkey: bytes, addr: bytes) -> bool:
    """Verify that pubkey correctly derives to the given 02xx address.

    Args:
        pubkey: 32-byte Ed25519 public key.
        addr: 16-byte Yggdrasil address.

    Returns:
        True if pubkey derives to the given 02xx address.
    """
    if len(pubkey) != 32 or len(addr) != 16:
        return False

    derived_addr = yggdrasil_address(pubkey).packed
    return hmac.compare_digest(derived_addr, addr)


def compute_rotation_transcript(
    old_pubkey: bytes,
    new_pubkey: bytes,
    rotation_sequence: int,
) -> bytes:
    """Compute canonical key rotation transcript for signing.

    The transcript binds the signature to the exact key transition:
    - Old pubkey being rotated from
    - New pubkey being rotated to
    - Monotonic sequence number for replay protection
    - Domain tag for protocol separation

    Args:
        old_pubkey: 32-byte Ed25519 public key being rotated from.
        new_pubkey: 32-byte Ed25519 public key being rotated to.
        rotation_sequence: Monotonic counter, must be > stored rotation_sequence.

    Returns:
        Canonical transcript bytes for Schnorr48 signing.
    """
    if type(old_pubkey) is not bytes or type(new_pubkey) is not bytes:
        raise TypeError("rotation transcript pubkeys must be immutable bytes")
    if len(old_pubkey) != 32:
        raise ValueError(f"old_pubkey must be 32 bytes, got {len(old_pubkey)}")
    if len(new_pubkey) != 32:
        raise ValueError(f"new_pubkey must be 32 bytes, got {len(new_pubkey)}")
    if type(rotation_sequence) is not int or not 0 <= rotation_sequence <= _MAX_ROTATION_SEQUENCE:
        raise ValueError("rotation_sequence must fit in u64")

    return (
        KEY_ROTATION_DOMAIN
        + old_pubkey
        + _pubkey_to_iid(old_pubkey)
        + new_pubkey
        + rotation_sequence.to_bytes(8, "big")
    )


class TrustStore:
    """In-memory trust store for peer public keys.

    Implements TOFU (Trust On First Use) with cryptographic binding
    per spec section 8.7. Supports multiple trust levels for hybrid
    deployments (TOFU + BR-provisioned).

    Thread-safety: Not thread-safe. Callers must synchronize if
    accessed from multiple threads.

    Usage:
        store = TrustStore()

        # On first contact, pin the peer's key (TOFU)
        store.verify_or_pin(peer_pubkey, claimed_iid)

        # On subsequent contacts, verify the key matches
        entry = store.verify_peer(peer_pubkey, claimed_iid)

        # For BR-provisioned trust anchors
        store.add_trust_anchor(peer_pubkey, TrustLevel.BR_PROVISIONED)

        # Revocation
        store.revoke(iid)
    """

    def __init__(
        self,
        auto_pin: bool = True,
        *,
        persistence: TrustPersistence | None = None,
    ) -> None:
        """Initialize an empty trust store.

        Args:
            auto_pin: If True, automatically pin unknown peers on first
                contact (TOFU mode). If False, reject unknown peers.
        """
        if type(auto_pin) is not bool:
            raise TypeError("auto_pin must be bool")
        self.auto_pin = auto_pin
        self._persistence = persistence
        # Persistence backends use compare-and-swap revisions to prevent
        # stale concurrent snapshots from silently replacing newer pins.
        self._persistence_revision = 0
        # Key by IID (8 bytes) for O(1) lookup
        self._entries: dict[bytes, TrustEntry] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, iid: bytes) -> bool:
        return iid in self._entries

    def get(self, iid: bytes) -> TrustEntry | None:
        """Look up a peer by IID.

        Args:
            iid: 8-byte Interface Identifier.

        Returns:
            TrustEntry if found, None otherwise.
        """
        entry = self._entries.get(iid)
        return None if entry is None else replace(entry)

    def verify_or_pin(
        self,
        pubkey: bytes,
        iid: bytes,
    ) -> TrustEntry:
        """Verify a peer's pubkey or pin it if new (TOFU).

        This is the main verification entry point for TOFU mode.

        Per spec 8.7:
        1. If IID unknown and auto_pin enabled: verify derivation, pin key
        2. If IID known: verify key matches pinned value
        3. Key/IID mismatch: reject (MITM or key compromise)

        Args:
            pubkey: 32-byte Ed25519 public key from incoming frame.
            iid: 8-byte IID claimed by the peer (from address or frame).
        Returns:
            TrustEntry for the verified/pinned peer.

        Raises:
            DerivationMismatchError: Pubkey doesn't derive to claimed IID.
            KeyMismatchError: Pubkey doesn't match pinned key for this IID.
            UnknownPeerError: Peer not in store and auto_pin disabled.
            RevokedPeerError: Peer has been revoked.
        """
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
        if len(iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(iid)}")

        # SECURITY: Cryptographic binding verification (spec 8.7)
        # The pubkey MUST derive to the claimed IID
        if not verify_pubkey_derivation(pubkey, iid):
            raise DerivationMismatchError(
                f"pubkey {pubkey.hex()[:16]}... does not derive to IID {iid.hex()}"
            )

        existing = self._entries.get(iid)

        if existing is None:
            # First contact - TOFU pin if enabled
            if not self.auto_pin:
                raise UnknownPeerError(f"unknown peer IID {iid.hex()}")

            entry = TrustEntry.from_pubkey(pubkey, TrustLevel.TOFU)
            self._entries[iid] = entry
            return replace(entry)

        # Existing entry - verify key matches
        if existing.revoked:
            raise RevokedPeerError(f"peer IID {iid.hex()} has been revoked")

        # SECURITY: Constant-time key comparison
        if not hmac.compare_digest(existing.pubkey, pubkey):
            raise KeyMismatchError(
                f"pubkey mismatch for IID {iid.hex()} - "
                f"pinned {existing.pubkey.hex()[:16]}..., "
                f"received {pubkey.hex()[:16]}..."
            )

        # Update last_seen timestamp
        existing = replace(existing, last_seen=time.time())
        self._entries[iid] = existing
        return replace(existing)

    def verify_peer(self, pubkey: bytes, iid: bytes) -> TrustEntry:
        """Verify a known peer's pubkey (no auto-pinning).

        Unlike verify_or_pin, this never pins new peers.

        Args:
            pubkey: 32-byte Ed25519 public key.
            iid: 8-byte IID.

        Returns:
            TrustEntry for the verified peer.

        Raises:
            DerivationMismatchError: Pubkey doesn't derive to claimed IID.
            KeyMismatchError: Pubkey doesn't match pinned key.
            UnknownPeerError: Peer not in trust store.
            RevokedPeerError: Peer has been revoked.
        """
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
        if len(iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(iid)}")

        # Cryptographic binding check
        if not verify_pubkey_derivation(pubkey, iid):
            raise DerivationMismatchError(f"pubkey does not derive to IID {iid.hex()}")

        existing = self._entries.get(iid)
        if existing is None:
            raise UnknownPeerError(f"unknown peer IID {iid.hex()}")

        if existing.revoked:
            raise RevokedPeerError(f"peer IID {iid.hex()} has been revoked")

        if not hmac.compare_digest(existing.pubkey, pubkey):
            raise KeyMismatchError(f"pubkey mismatch for IID {iid.hex()}")

        existing = replace(existing, last_seen=time.time())
        self._entries[iid] = existing
        return replace(existing)

    def add_trust_anchor(
        self,
        pubkey: bytes,
        trust_level: TrustLevel = TrustLevel.BR_PROVISIONED,
        metadata: dict[str, str] | None = None,
    ) -> TrustEntry:
        """Add a trusted anchor (e.g., from BR provisioning).

        Unlike verify_or_pin, this explicitly adds a trust anchor
        without requiring first contact. Used for BR-provisioned
        trust anchor distribution.

        Args:
            pubkey: 32-byte Ed25519 public key.
            trust_level: Trust level (default BR_PROVISIONED).
            metadata: Optional metadata.

        Returns:
            New or updated TrustEntry.

        Raises:
            ValueError: Invalid pubkey length.
        """
        entry = TrustEntry.from_pubkey(pubkey, trust_level, metadata)
        iid = entry.iid

        existing = self._entries.get(iid)
        if existing is not None:
            # Upgrade trust level if higher
            if trust_level > existing.trust_level:
                merged_metadata = dict(existing.metadata)
                if metadata is not None:
                    merged_metadata.update(metadata)
                existing = replace(
                    existing,
                    trust_level=trust_level,
                    last_seen=time.time(),
                    metadata=merged_metadata,
                )
                self._entries[iid] = existing
                return replace(existing)
            # Same or lower level - just update timestamp
            existing = replace(existing, last_seen=time.time())
            self._entries[iid] = existing
            return replace(existing)

        self._entries[iid] = entry
        return replace(entry)

    def rotate_key(
        self,
        old_pubkey: bytes,
        new_pubkey: bytes,
        rotation_sequence: int,
        rotation_signature: bytes,
    ) -> TrustEntry:
        """Durably rotate a key using its canonical signed authorization."""
        return self._rotate_key(
            old_pubkey,
            new_pubkey,
            rotation_sequence,
            rotation_signature,
            require_persistence=True,
        )

    def rotate_key_semantics_for_test(
        self,
        old_pubkey: bytes,
        new_pubkey: bytes,
        rotation_sequence: int,
        rotation_signature: bytes,
    ) -> TrustEntry:
        """Explicitly unsafe in-memory rotation helper for cryptographic tests."""
        return self._rotate_key(
            old_pubkey,
            new_pubkey,
            rotation_sequence,
            rotation_signature,
            require_persistence=False,
        )

    def _rotate_key(
        self,
        old_pubkey: bytes,
        new_pubkey: bytes,
        rotation_sequence: int,
        rotation_signature: bytes,
        *,
        require_persistence: bool,
    ) -> TrustEntry:
        """Handle key rotation with signature from old key.

        Per spec 8.7: Key change with valid signature from old key
        is accepted. Creates fresh replay state for new key.

        SECURITY: The signature must be over a canonical domain-separated
        transcript computed by compute_rotation_transcript(). This binds
        the signature to the exact key transition and prevents replay of
        arbitrary prior signatures.

        Args:
            old_pubkey: Current pinned public key.
            new_pubkey: New public key to rotate to.
            rotation_sequence: Monotonic counter, must be > stored sequence.
            rotation_signature: Schnorr48 signature from old key over the
                canonical transcript from compute_rotation_transcript().

        Returns:
            Updated TrustEntry with new key.

        Raises:
            UnknownPeerError: Old key not in trust store.
            RevokedPeerError: Peer has been revoked.
            TrustError: Signature verification failed or sequence replay.
        """
        if type(old_pubkey) is not bytes or type(new_pubkey) is not bytes:
            raise TypeError("pubkeys must be immutable bytes")
        if type(rotation_signature) is not bytes:
            raise TypeError("rotation_signature must be immutable bytes")
        if len(old_pubkey) != 32 or len(new_pubkey) != 32:
            raise ValueError("pubkeys must be 32 bytes")
        if (
            type(rotation_sequence) is not int
            or not 0 <= rotation_sequence <= _MAX_ROTATION_SEQUENCE
        ):
            raise ValueError("rotation_sequence must fit in u64")

        old_iid = _pubkey_to_iid(old_pubkey)
        existing = self._entries.get(old_iid)

        if existing is None:
            raise UnknownPeerError(f"unknown peer IID {old_iid.hex()}")

        if existing.revoked:
            raise RevokedPeerError(f"peer IID {old_iid.hex()} has been revoked")

        # SECURITY: Anti-replay check - sequence must be strictly greater
        if rotation_sequence <= existing.rotation_sequence:
            raise TrustError(
                f"rotation sequence replay: {rotation_sequence} <= {existing.rotation_sequence}"
            )

        # SECURITY: Compute canonical transcript internally - do not accept
        # arbitrary caller-supplied message (prevents signature replay)
        transcript = compute_rotation_transcript(old_pubkey, new_pubkey, rotation_sequence)

        if not schnorr_verify(old_pubkey, transcript, rotation_signature):
            raise TrustError("key rotation signature verification failed")

        if require_persistence:
            if self._persistence is None:
                raise TrustError("crash-safe trust persistence required for key rotation")
            if not self._persistence.is_crash_safe or not self._persistence.fails_closed:
                raise TrustError("key rotation persistence must be crash-safe and fail closed")

        # Create new entry with new key (new IID)
        new_iid = _pubkey_to_iid(new_pubkey)
        if new_iid != old_iid and new_iid in self._entries:
            raise KeyMismatchError(f"rotation destination IID {new_iid.hex()} is already pinned")
        new_entry = TrustEntry.from_pubkey(
            new_pubkey,
            existing.trust_level,
            dict(existing.metadata),
        )
        # Carry forward rotation sequence to new entry for future rotations
        new_entry = replace(new_entry, rotation_sequence=rotation_sequence)

        # Remove old entry, add new. Public rotation commits this complete
        # snapshot before exposing success so the anti-replay sequence cannot
        # roll back across a crash.
        previous_revision = self._persistence_revision
        del self._entries[old_iid]
        self._entries[new_iid] = new_entry
        if require_persistence:
            assert self._persistence is not None
            try:
                self._persistence.save(self)
            except BaseException:
                del self._entries[new_iid]
                self._entries[old_iid] = existing
                self._persistence_revision = previous_revision
                raise

        return replace(new_entry)

    def revoke(self, iid: bytes) -> bool:
        """Mark a peer as revoked.

        Revoked peers are kept in the store (to reject reconnection
        attempts) but marked as revoked.

        Args:
            iid: 8-byte IID to revoke.

        Returns:
            True if peer was found and revoked, False if not found.
        """
        entry = self._entries.get(iid)
        if entry is None:
            return False
        self._entries[iid] = replace(entry, revoked=True)
        return True

    def remove(self, iid: bytes) -> bool:
        """Remove a peer from the trust store entirely.

        Unlike revoke(), this deletes the entry. Use with caution -
        the peer could be re-pinned via TOFU if auto_pin is enabled.

        Args:
            iid: 8-byte IID to remove.

        Returns:
            True if peer was found and removed, False if not found.
        """
        if iid in self._entries:
            del self._entries[iid]
            return True
        return False

    def list_entries(
        self,
        *,
        include_revoked: bool = False,
        trust_level: TrustLevel | None = None,
    ) -> list[TrustEntry]:
        """List trust store entries.

        Args:
            include_revoked: Include revoked entries.
            trust_level: Filter by trust level (None = all).

        Returns:
            List of matching TrustEntry objects.
        """
        result = []
        for entry in self._entries.values():
            if not include_revoked and entry.revoked:
                continue
            if trust_level is not None and entry.trust_level != trust_level:
                continue
            result.append(replace(entry))
        return result

    def clear(self) -> None:
        """Remove all entries from the trust store."""
        self._entries.clear()


# Oracle functions for test vector generation


def generate_trust_vector(
    seed: bytes,
    trust_level: TrustLevel = TrustLevel.TOFU,
) -> dict[str, object]:
    """Generate a test vector for trust model verification.

    Args:
        seed: 32-byte seed for deterministic key generation.
        trust_level: Trust level to include in vector.

    Returns:
        Dict with pubkey, iid, ygg_addr, trust_level for verification.
    """
    from .identity import Identity

    identity = Identity.from_seed(seed)

    return {
        "seed_hex": seed.hex(),
        "pubkey_hex": identity.pubkey.hex(),
        "iid_hex": identity.iid.hex(),
        "ygg_addr_hex": identity.ygg_addr.hex(),
        "ygg_addr_str": str(yggdrasil_address(identity.pubkey)),
        "trust_level": trust_level.name,
        "derivation_valid": True,
    }


def verify_trust_vector(vector: Mapping[str, object]) -> bool:
    """Verify a trust model test vector.

    Args:
        vector: Dict with pubkey_hex, iid_hex, derivation_valid.

    Returns:
        True if vector is valid.
    """
    pubkey_hex = vector["pubkey_hex"]
    iid_hex = vector["iid_hex"]
    expected_valid = vector.get("derivation_valid", True)
    if type(pubkey_hex) is not str or type(iid_hex) is not str:
        return False
    if type(expected_valid) is not bool:
        return False
    pubkey = bytes.fromhex(pubkey_hex)
    iid = bytes.fromhex(iid_hex)

    actual_valid = verify_pubkey_derivation(pubkey, iid)
    return actual_valid == expected_valid
