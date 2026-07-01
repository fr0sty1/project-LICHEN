# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Meshtastic node ID to LICHEN IPv6 address mapping.

Meshtastic uses 32-bit node IDs while LICHEN uses 128-bit IPv6 addresses
derived from Ed25519 public keys. This module provides bidirectional
mapping between the two address spaces.

The mapping strategy:
- LICHEN→Meshtastic: Extract low 32 bits of IID as node_num
- Meshtastic→LICHEN: Search peer table for IID ending in node_num
- Unknown nodes get synthetic IIDs with "MESH" marker

This mirrors the Rust implementation in lichen-meshtastic/src/address.rs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Broadcast destination in Meshtastic
BROADCAST_NODE_NUM: int = 0xFFFFFFFF

# Marker for synthetic IIDs: "MESH" in ASCII
_SYNTHETIC_MARKER = bytes([0x4D, 0x45, 0x53, 0x48])


def iid_to_node_num(iid: bytes) -> int:
    """Extract Meshtastic node_num from an IID.

    Returns the low 32 bits of the IID. This is deterministic but may
    collide if two peers happen to have IIDs with the same suffix.

    Args:
        iid: 8-byte Interface Identifier

    Returns:
        32-bit Meshtastic node number
    """
    if len(iid) != 8:
        raise ValueError(f"IID must be 8 bytes, got {len(iid)}")
    return int.from_bytes(iid[4:8], "big")


def iid_to_user_id(iid: bytes) -> str:
    """Convert IID to Meshtastic user ID format (!XXXXXXXX).

    Args:
        iid: 8-byte Interface Identifier

    Returns:
        String like "!deadbeef"
    """
    node_num = iid_to_node_num(iid)
    return f"!{node_num:08x}"


def node_num_to_iid(node_num: int, peers: dict[bytes, bytes] | None = None) -> bytes | None:
    """Look up IID from Meshtastic node_num.

    Searches the peer table for an IID whose low 32 bits match node_num.
    Returns None if no match found (caller should drop the message).

    Args:
        node_num: 32-bit Meshtastic node number
        peers: Dict mapping IID → pubkey (or any value, only keys used)

    Returns:
        8-byte IID if found, None otherwise
    """
    if node_num == BROADCAST_NODE_NUM:
        # Broadcast maps to all-ones IID (will become ff02::1 multicast)
        return bytes([0xFF] * 8)

    if peers is None:
        return None

    # Search for matching IID
    for iid in peers:
        if iid_to_node_num(iid) == node_num:
            return iid

    return None


def is_synthetic_iid(iid: bytes) -> bool:
    """Check if an IID is synthetic (unknown Meshtastic node).

    Synthetic IIDs have the "MESH" marker in bytes 0-3.

    Args:
        iid: 8-byte Interface Identifier

    Returns:
        True if this is a synthetic IID
    """
    return len(iid) == 8 and iid[0:4] == _SYNTHETIC_MARKER


def synthetic_iid(node_num: int) -> bytes:
    """Create a synthetic IID for an unknown Meshtastic node.

    Format: "MESH" (4 bytes) + node_num (4 bytes big-endian)

    Args:
        node_num: 32-bit Meshtastic node number

    Returns:
        8-byte synthetic IID
    """
    return _SYNTHETIC_MARKER + node_num.to_bytes(4, "big")


def extract_synthetic_node_num(iid: bytes) -> int | None:
    """Extract node_num from a synthetic IID.

    Args:
        iid: 8-byte Interface Identifier

    Returns:
        node_num if synthetic, None otherwise
    """
    if is_synthetic_iid(iid):
        return int.from_bytes(iid[4:8], "big")
    return None


@dataclass
class AddressMapper:
    """Maps between Meshtastic node IDs and LICHEN IIDs.

    Maintains a peer table to resolve node_num → IID lookups.
    Unknown nodes get synthetic IIDs until their real identity is learned.
    """

    # IID → pubkey mapping (peer table)
    _peers: dict[bytes, bytes] = field(default_factory=dict)

    # node_num → IID cache for fast reverse lookup
    _by_node_num: dict[int, bytes] = field(default_factory=dict)

    def learn(self, iid: bytes, pubkey: bytes) -> None:
        """Learn a peer's identity.

        Args:
            iid: 8-byte Interface Identifier
            pubkey: 32-byte Ed25519 public key
        """
        if len(iid) != 8:
            raise ValueError(f"IID must be 8 bytes, got {len(iid)}")
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")

        node_num = iid_to_node_num(iid)

        # Check for collision
        if node_num in self._by_node_num and self._by_node_num[node_num] != iid:
            # Log warning but use first match (spec behavior)
            pass

        self._peers[iid] = pubkey
        self._by_node_num[node_num] = iid

    def iid_to_node_num(self, iid: bytes) -> int:
        """Convert IID to Meshtastic node_num."""
        return iid_to_node_num(iid)

    def node_num_to_iid(self, node_num: int) -> bytes:
        """Convert Meshtastic node_num to IID.

        Returns synthetic IID if node is unknown.
        """
        if node_num == BROADCAST_NODE_NUM:
            return bytes([0xFF] * 8)

        iid = self._by_node_num.get(node_num)
        if iid is not None:
            return iid

        # Unknown node: return synthetic IID
        return synthetic_iid(node_num)

    def get_pubkey(self, iid: bytes) -> bytes | None:
        """Get pubkey for an IID, if known."""
        return self._peers.get(iid)

    def is_known(self, node_num: int) -> bool:
        """Check if a node_num maps to a known peer."""
        return node_num in self._by_node_num

    def __len__(self) -> int:
        return len(self._peers)
