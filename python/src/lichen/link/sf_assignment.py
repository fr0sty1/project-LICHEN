# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Spreading Factor assignment oracle (spec 02-physical-link.md §3.4).

Implements the stateless hash-based fallback per CCP-15.8.3:

    assigned_sf = 7 + (hash_32(IID) mod 6)

where hash_32 is FNV-1a32 with basis 0x811c9dc5 (see lichen.link.channel.hash_32,
lichen.sim.tdma.hash_32, lichen.channel_plan.hash_32).  Short-address DAD
uses crc32_ieee, not this hash.  Gateway-assigned ASSIGNED_SF via DIO (preferred)
and SF10 fallback (join / no assignment) are also modelled.

Gateway- and node-side MUST receive on all SF7-SF12.
"""

from __future__ import annotations

from dataclasses import dataclass

from lichen.link.channel import hash_32 as fnv1a32


def assigned_sf_hash_based(iid: bytes) -> int:
    """Stateless hash-based SF assignment.

    Args:
        iid: 8-byte IID / EUI-64.  Any length is accepted; spec IID is 8 bytes.

    Returns:
        SF in 7..12 inclusive.
    """
    if not isinstance(iid, (bytes, bytearray)):
        raise TypeError("iid must be bytes")
    if len(iid) == 0:
        raise ValueError("iid must be non-empty")
    h = fnv1a32(bytes(iid))
    return 7 + (h % 6)


def assigned_sf_hash_based_hex(iid_hex: str) -> int:
    """Helper for vectors: hex string -> SF."""
    return assigned_sf_hash_based(bytes.fromhex(iid_hex))


@dataclass(frozen=True)
class SfAssignmentState:
    """Per-node SF assignment state."""

    iid: bytes
    assigned_sf_dio: int | None = None
    joined: bool = False

    def effective_sf(self) -> int:
        """Resolve effective TX SF per spec §3.4 priority.

        1. Gateway-assigned ASSIGNED_SF via DIO (if present, 7..12) -> MUST use.
        2. Stateless hash-based fallback -> 7+(hash(IID)%6).
        3. No assignment -> SF10 (backwards compat, join-based initial).
        """
        if self.assigned_sf_dio is not None:
            if not 7 <= self.assigned_sf_dio <= 12:
                raise ValueError(f"assigned_sf_dio out of range 7..12: {self.assigned_sf_dio}")
            return self.assigned_sf_dio
        if not self.joined:
            return 10
        # joined but no DIO assignment -> hash fallback
        return assigned_sf_hash_based(self.iid)


def gateway_assigned_sf(load_by_sf: dict[int, int]) -> int:
    """Gateway load-balancing: pick least-loaded SF (7..12, tie -> lowest SF)."""
    if not load_by_sf:
        return 10
    best = min(range(7, 13), key=lambda sf: (load_by_sf.get(sf, 0), sf))
    return best


def must_receive_all_sf(sf: int) -> bool:
    """Nodes and gateways MUST receive on all SF7-SF12 regardless of TX SF."""
    return 7 <= sf <= 12


__all__ = [
    "assigned_sf_hash_based",
    "assigned_sf_hash_based_hex",
    "gateway_assigned_sf",
    "must_receive_all_sf",
    "SfAssignmentState",
]
