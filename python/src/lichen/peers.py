# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Peer database management for LICHEN nodes.

This module provides peer identity storage with bounded capacity, safe eviction
based on live protocol state, and collision detection for IID/pubkey bindings.

The PeerDatabase class manages known peers for signature verification and routing.
Capacity is bounded by MAX_ENTRIES from the gradient table specification.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Iterator, Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from lichen.crypto.identity import PeerIdentity
from lichen.gradient import MAX_ENTRIES

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

PEER_DB_MAX_SIZE = MAX_ENTRIES


class PeerIdentityCollisionError(ValueError):
    """A peer IID is already bound to a different public key."""


class PeerDatabaseFullError(RuntimeError):
    """No peer database entry can be safely evicted."""


class PeerInUseError(RuntimeError):
    """A peer cannot be forgotten while dependent protocol state is live."""


def _canonical_peer(peer: object) -> PeerIdentity:
    """Validate and detach one peer's key-derived identity.

    Args:
        peer: A PeerIdentity instance to validate.

    Returns:
        A canonical PeerIdentity with validated pubkey and IID.

    Raises:
        TypeError: If peer is not an exact PeerIdentity.
        ValueError: If pubkey is not 32 bytes or IID does not match pubkey.
    """
    if type(peer) is not PeerIdentity:
        raise TypeError("peer must be an exact PeerIdentity")
    if type(peer.pubkey) is not bytes or len(peer.pubkey) != 32:
        raise ValueError("peer must expose an exact 32-byte public key")
    canonical = PeerIdentity.from_pubkey(bytes(peer.pubkey))
    if type(peer.iid) is not bytes or peer.iid != canonical.iid:
        raise ValueError("peer IID does not match its public key")
    return canonical


class PeerDatabase:
    """Database of known peers for a LICHEN node.

    Manages peer identities with bounded capacity and safe eviction. The database
    ensures that peers with live protocol state (active sessions, routing entries,
    pinned keys) are not evicted.

    Attributes:
        peers: Read-only view of the peer database (IID -> PeerIdentity).
        max_size: Maximum number of peers that can be stored.
    """

    def __init__(
        self,
        max_size: int = PEER_DB_MAX_SIZE,
        initial_peers: Mapping[bytes, PeerIdentity] | None = None,
        eviction_checker: Callable[[PeerIdentity, int], bool] | None = None,
    ) -> None:
        """Initialize the peer database.

        Args:
            max_size: Maximum number of peers. Defaults to PEER_DB_MAX_SIZE (64).
            initial_peers: Optional mapping of IID -> PeerIdentity to preload.
            eviction_checker: Optional callback(peer, now_ms) -> bool returning
                True if the peer has live state and cannot be evicted.

        Raises:
            ValueError: If initial_peers exceeds max_size or contains invalid peers.
            PeerIdentityCollisionError: If initial_peers has IID/pubkey conflicts.
        """
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self._max_size = max_size
        self._eviction_checker = eviction_checker
        self._peers: dict[bytes, PeerIdentity] = {}

        if initial_peers:
            if len(initial_peers) > max_size:
                raise ValueError(f"peer database cannot exceed {max_size} entries")
            for iid, peer in initial_peers.items():
                canonical = _canonical_peer(peer)
                if type(iid) is not bytes or iid != canonical.iid:
                    raise ValueError("peer database key does not match its peer identity")
                incumbent = self._peers.get(canonical.iid)
                if incumbent is not None and incumbent.pubkey != canonical.pubkey:
                    raise PeerIdentityCollisionError(
                        f"peer IID collision for {canonical.iid.hex()}"
                    )
                self._peers[canonical.iid] = canonical

        self._peers_view: Mapping[bytes, PeerIdentity] = MappingProxyType(self._peers)

    @property
    def peers(self) -> Mapping[bytes, PeerIdentity]:
        """Read-only view of the peer database."""
        return self._peers_view

    @property
    def max_size(self) -> int:
        """Maximum number of peers that can be stored."""
        return self._max_size

    def __len__(self) -> int:
        """Return the number of peers in the database."""
        return len(self._peers)

    def __contains__(self, iid: bytes) -> bool:
        """Check if a peer IID is in the database."""
        return iid in self._peers

    def __iter__(self) -> Iterator[bytes]:
        """Iterate over peer IIDs in the database."""
        return iter(self._peers)

    def get(self, iid: bytes) -> PeerIdentity | None:
        """Get a peer by IID.

        Args:
            iid: 8-byte Interface Identifier.

        Returns:
            The PeerIdentity if found, None otherwise.
        """
        if iid and len(iid) == 8:
            return self._peers.get(iid)
        return None

    def find_by_pubkey(self, pubkey: bytes) -> PeerIdentity | None:
        """Find a peer by their public key.

        Args:
            pubkey: 32-byte Ed25519 public key.

        Returns:
            The PeerIdentity if found, None otherwise.
        """
        return next(
            (peer for peer in self._peers.values() if peer.pubkey == pubkey),
            None,
        )

    def _get_now_ms(self) -> int:
        """Get current time in milliseconds from event loop or monotonic clock."""
        try:
            return int(asyncio.get_running_loop().time() * 1000)
        except RuntimeError:
            return int(time.monotonic() * 1000)

    def _peer_has_live_state(self, peer: PeerIdentity, now_ms: int) -> bool:
        """Check if a peer has live protocol state preventing eviction.

        Uses the eviction_checker callback if provided; otherwise assumes
        no live state (safe to evict).
        """
        if self._eviction_checker is None:
            return False
        return self._eviction_checker(peer, now_ms)

    def _evictable_peer_iid(self, now_ms: int) -> bytes | None:
        """Select the oldest peer whose removal cannot orphan live state.

        Returns:
            The IID of the first evictable peer, or None if all are protected.
        """
        return next(
            (
                iid
                for iid, peer in self._peers.items()
                if not self._peer_has_live_state(peer, now_ms)
            ),
            None,
        )

    def add(self, peer: PeerIdentity) -> None:
        """Add a peer to the database.

        If the database is full, attempts to evict an idle peer. Peers with
        live protocol state are protected from eviction.

        Args:
            peer: The peer identity to add.

        Raises:
            TypeError: If peer is not an exact PeerIdentity.
            ValueError: If peer has invalid pubkey or IID.
            PeerIdentityCollisionError: If IID is bound to a different pubkey.
            PeerDatabaseFullError: If database is full and no peer can be evicted.
        """
        canonical = _canonical_peer(peer)
        incumbent = self._peers.get(canonical.iid)
        if incumbent is not None:
            if incumbent.pubkey != canonical.pubkey:
                logger.error(
                    "peer IID collision: iid=%s incumbent=%s candidate=%s",
                    canonical.iid.hex(),
                    incumbent.pubkey.hex(),
                    canonical.pubkey.hex(),
                )
                raise PeerIdentityCollisionError(
                    f"peer IID collision for {canonical.iid.hex()}"
                )
            return  # Already present with same pubkey

        if len(self._peers) >= self._max_size:
            now_ms = self._get_now_ms()
            evicted_iid = self._evictable_peer_iid(now_ms)
            if evicted_iid is None:
                raise PeerDatabaseFullError(
                    f"peer database is full ({self._max_size} protected entries)"
                )
            self._peers.pop(evicted_iid)
            logger.debug("evicted peer: %s", evicted_iid.hex())

        self._peers[canonical.iid] = canonical
        logger.debug("added peer: %s", canonical.iid.hex())

    def remove(self, iid: bytes) -> bool:
        """Remove a peer from the database.

        Only removes peers that have no live protocol state.

        Args:
            iid: 8-byte Interface Identifier of the peer to remove.

        Returns:
            True if the peer was removed, False if not found.

        Raises:
            ValueError: If iid is not 8 bytes.
            PeerInUseError: If the peer has live protocol state.
        """
        if type(iid) is not bytes or len(iid) != 8:
            raise ValueError("peer IID must be exact 8-byte bytes")

        peer = self._peers.get(iid)
        if peer is None:
            return False

        now_ms = self._get_now_ms()
        if self._peer_has_live_state(peer, now_ms):
            raise PeerInUseError(f"peer {iid.hex()} has live protocol state")

        self._peers.pop(iid)
        logger.debug("removed peer: %s", iid.hex())
        return True

    def values(self) -> list[PeerIdentity]:
        """Return all peers in the database."""
        return list(self._peers.values())

    def items(self) -> list[tuple[bytes, PeerIdentity]]:
        """Return all (IID, peer) pairs in the database."""
        return list(self._peers.items())
