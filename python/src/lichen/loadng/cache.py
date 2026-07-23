# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LOADng route cache (spec section 9.6, appendix B2.2).

Holds discovered forward routes (destination -> next hop) with their metric and
freshness, separate from the unified gradient table: this cache is LOADng's own
working set during and after discovery. Timestamps are caller-supplied integers
(milliseconds) so the cache is deterministic; capacity is bounded with LRU
eviction.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from ipaddress import IPv6Address

from lichen.ipv6 import to_ipv6

ROUTE_CACHE_SIZE = 32
ROUTE_TIMEOUT_MS = 300_000  # 300 s route validity with no traffic
ROUTE_REFRESH_MS = 60_000  # refresh if used within 60 s of activity

# Sequence numbers are 16-bit with wrap-around.
_SEQ_MAX = 0xFFFF
_SEQ_HALF = 0x8000


def _is_seq_fresher(old_seq: int, new_seq: int) -> bool:
    """Return True if new_seq is fresher than old_seq (wrap-around aware).

    Uses serial number arithmetic (RFC 1982 style) for 16-bit sequence numbers:
    new_seq is fresher if (new_seq - old_seq) mod 2^16 is in [1, 2^15).
    """
    diff = (new_seq - old_seq) & _SEQ_MAX
    return diff != 0 and diff < _SEQ_HALF


@dataclass
class RouteEntry:
    """A cached LOADng forward route (spec 9.6)."""

    destination: IPv6Address
    next_hop: IPv6Address
    hop_count: int
    metric: int
    seq_num: int
    valid_until: int

    def __post_init__(self) -> None:
        self.destination = to_ipv6(self.destination)
        self.next_hop = to_ipv6(self.next_hop)
        if not 0 <= self.hop_count <= 255:
            raise ValueError(f"hop_count out of range: {self.hop_count}")
        if not 0 <= self.metric <= 0xFFFF:
            raise ValueError(f"metric out of range: {self.metric}")
        if not 0 <= self.seq_num <= 0xFFFF:
            raise ValueError(f"seq_num out of range: {self.seq_num}")


class RouteCache:
    """Bounded, LRU-evicting cache of LOADng routes."""

    def __init__(
        self,
        max_entries: int = ROUTE_CACHE_SIZE,
        route_timeout_ms: int = ROUTE_TIMEOUT_MS,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self.route_timeout_ms = route_timeout_ms
        self._entries: OrderedDict[IPv6Address, RouteEntry] = OrderedDict()

    def add(self, entry: RouteEntry) -> None:
        """Insert or replace the route to ``entry.destination`` (LRU on insert).

        Per LOADng spec, only updates if the new entry is fresher:
        1. If new seq_num is fresher than existing: update
        2. If seq_nums equal and new metric is better: update
        3. Otherwise: ignore (stale or worse route)
        """
        existing = self._entries.get(entry.destination)
        if existing is not None:
            if _is_seq_fresher(entry.seq_num, existing.seq_num):
                return
            if existing.seq_num == entry.seq_num and entry.metric >= existing.metric:
                return
        self._entries[entry.destination] = entry
        self._entries.move_to_end(entry.destination)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def lookup(
        self, destination: IPv6Address | str, now: int | None = None
    ) -> RouteEntry | None:
        """Return the route (None if absent or expired); marks it recently used."""
        dest = to_ipv6(destination)
        entry = self._entries.get(dest)
        if entry is None:
            return None
        if now is not None and entry.valid_until <= now:
            return None
        self._entries.move_to_end(dest)
        return entry

    def remove(self, destination: IPv6Address | str) -> None:
        """Remove the route to ``destination`` if present."""
        self._entries.pop(to_ipv6(destination), None)

    def remove_via(self, next_hop: IPv6Address | str) -> list[IPv6Address]:
        """Remove every route through ``next_hop``; return their destinations."""
        nh = to_ipv6(next_hop)
        dests = [d for d, e in self._entries.items() if e.next_hop == nh]
        for dest in dests:
            del self._entries[dest]
        return dests

    def refresh(self, destination: IPv6Address | str, now: int) -> bool:
        """Extend validity to now+timeout if not expired; True if refreshed."""
        dest = to_ipv6(destination)
        entry = self._entries.get(dest)
        if entry is None:
            return False
        if entry.valid_until <= now:
            del self._entries[dest]
            return False
        entry.valid_until = now + self.route_timeout_ms
        self._entries.move_to_end(dest)
        return True

    def expire_old(self, now: int) -> int:
        """Drop routes whose validity is at or before ``now``; return count."""
        stale = [d for d, e in self._entries.items() if e.valid_until <= now]
        for dest in stale:
            del self._entries[dest]
        return len(stale)

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, destination: IPv6Address | str) -> bool:
        """Check if ``destination`` exists in cache (ignores expiry).

        Note: This only checks key presence; it does NOT verify that the route
        is still valid (project-LICHEN-6xyv). To check validity, use
        ``lookup(dest, now=...)`` which returns None for expired routes.
        """
        return to_ipv6(destination) in self._entries
