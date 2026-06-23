"""Unified gradient (routing) table (spec section 11).

A single table holds next-hop gradients toward destinations, populated by every
routing method: Announce (section 9), LOADng RREP (section 10), RPL, and passive
learning from forwarded data (section 11.2). Entries carry a source priority so
explicitly-advertised routes win over opportunistic ones.

Replacement order for the same destination (best first): higher source priority,
then higher sequence number (fresher), then lower hop count. Timestamps are
caller-supplied integers (milliseconds); the table never reads a wall clock, so
it is deterministic and usable under the simulator. Capacity is bounded with LRU
eviction.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv6Address

MAX_ENTRIES = 64
DATA_GRADIENT_TIMEOUT_MS = 60_000  # opportunistic data gradients expire sooner
GRADIENT_TIMEOUT_MS = 600_000  # announce/rrep gradients (spec section 9)


class GradientSource(Enum):
    """How a gradient entry was learned (spec 11.1/11.3)."""

    ANNOUNCE = "announce"
    RREP = "rrep"
    RPL = "rpl"
    DATA = "data"

    @property
    def priority(self) -> int:
        """Higher wins. Explicitly-advertised routes outrank opportunistic data."""
        return 0 if self is GradientSource.DATA else 1


def _addr(value: IPv6Address | str) -> IPv6Address:
    return value if isinstance(value, IPv6Address) else IPv6Address(value)


@dataclass
class GradientEntry:
    """A next-hop gradient toward ``destination`` (spec 11.1)."""

    destination: IPv6Address
    next_hop: IPv6Address
    hop_count: int
    seq_num: int
    source: GradientSource
    expires: int
    coords: tuple[float, float] | None = None  # (lat, lon) from app_data (spec 9.7)

    def __post_init__(self) -> None:
        self.destination = _addr(self.destination)
        self.next_hop = _addr(self.next_hop)

    def _rank(self) -> tuple[int, int, int]:
        # Larger is better: priority, then freshness, then fewer hops.
        return (self.source.priority, self.seq_num, -self.hop_count)


class GradientTable:
    """Bounded, LRU-evicting table of gradient entries."""

    def __init__(self, max_entries: int = MAX_ENTRIES) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._entries: OrderedDict[IPv6Address, GradientEntry] = OrderedDict()

    def lookup(
        self, destination: IPv6Address | str, now: int | None = None
    ) -> GradientEntry | None:
        """Return the gradient for ``destination`` (None if absent or expired)."""
        dest = _addr(destination)
        entry = self._entries.get(dest)
        if entry is None:
            return None
        if now is not None and entry.expires <= now:
            return None
        self._entries.move_to_end(dest)  # mark recently used
        return entry

    def update(self, entry: GradientEntry, now: int | None = None) -> bool:
        """Insert or replace the gradient for ``entry.destination``.

        Replaces the existing entry if it is missing, expired (when ``now`` is
        given), or strictly worse-or-equal in rank than ``entry``. Returns True
        if the table was changed.
        """
        dest = entry.destination
        existing = self._entries.get(dest)
        expired = now is not None and existing is not None and existing.expires <= now

        if existing is None or expired or entry._rank() >= existing._rank():
            self._entries[dest] = entry
            self._entries.move_to_end(dest)
            self._evict_if_needed()
            return True
        return False

    def remove(self, destination: IPv6Address | str) -> None:
        """Remove the gradient for ``destination`` if present."""
        self._entries.pop(_addr(destination), None)

    def remove_via(self, next_hop: IPv6Address | str) -> list[IPv6Address]:
        """Remove every gradient routing through ``next_hop``; return their dsts."""
        nh = _addr(next_hop)
        dests = [d for d, e in self._entries.items() if e.next_hop == nh]
        for dest in dests:
            del self._entries[dest]
        return dests

    def expire_old(self, now: int) -> int:
        """Drop entries whose ``expires`` is at or before ``now``; return count."""
        stale = [d for d, e in self._entries.items() if e.expires <= now]
        for dest in stale:
            del self._entries[dest]
        return len(stale)

    def _evict_if_needed(self) -> None:
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)  # evict least-recently-used

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, destination: IPv6Address | str) -> bool:
        return _addr(destination) in self._entries
