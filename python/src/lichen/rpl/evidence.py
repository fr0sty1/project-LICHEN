# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Bounded LOADng local-evidence lifetime tracking.

The local-evidence gate permits discovery only for destinations recently seen
through an authenticated routing source. Every refresh has one fixed
1200-second lifetime; callers cannot supply an arbitrary expiry.
"""

from __future__ import annotations

from dataclasses import dataclass

LOCAL_EVIDENCE_LIFETIME_SECONDS = 1200
MAX_LOCAL_EVIDENCE_PEERS = 32
MAX_MONOTONIC_SECONDS = (1 << 64) - 1

AUTHENTICATED_SOURCES = frozenset({"announce", "rrep", "rpl", "data"})


class EvidenceError(ValueError):
    """Base error for rejected local-evidence operations."""


class EvidenceTimeError(EvidenceError):
    """A timestamp regressed or cannot produce a bounded expiry."""


class EvidenceCapacityError(EvidenceError):
    """The bounded peer table has no expired slot for a new destination."""


@dataclass(frozen=True)
class GradientEntry:
    """One authenticated reachability observation owned by the tracker."""

    destination: str
    next_hop: str
    hop_count: int
    seq_num: int
    source: str
    observed_at_s: int
    expires_at_s: int


class EvidenceTable:
    """Track recent authenticated peers using a monotonic ``u64`` clock."""

    def __init__(self, max_peers: int = MAX_LOCAL_EVIDENCE_PEERS) -> None:
        if isinstance(max_peers, bool) or not isinstance(max_peers, int) or max_peers <= 0:
            raise ValueError("max_peers must be a positive integer")
        self._max_peers = max_peers
        self._entries: dict[str, GradientEntry] = {}
        self._last_now_s: int | None = None

    @property
    def max_peers(self) -> int:
        """Maximum number of simultaneously live destinations."""
        return self._max_peers

    def __len__(self) -> int:
        return len(self._entries)

    def _validate_now(self, now_s: int) -> None:
        if isinstance(now_s, bool) or not isinstance(now_s, int):
            raise EvidenceTimeError("now_s must be an integer")
        if not 0 <= now_s <= MAX_MONOTONIC_SECONDS:
            raise EvidenceTimeError("now_s is outside the unsigned 64-bit range")
        if self._last_now_s is not None and now_s < self._last_now_s:
            raise EvidenceTimeError(f"monotonic time regressed from {self._last_now_s} to {now_s}")

    def _advance(self, now_s: int) -> None:
        self._validate_now(now_s)
        self._last_now_s = now_s

    def _purge_expired(self, now_s: int) -> int:
        expired = [
            destination
            for destination, entry in self._entries.items()
            if entry.expires_at_s <= now_s
        ]
        for destination in expired:
            del self._entries[destination]
        return len(expired)

    def refresh(
        self,
        destination: str,
        now_s: int,
        *,
        source: str,
        next_hop: str = "",
        hop_count: int = 0,
        seq_num: int = 0,
    ) -> GradientEntry:
        """Create or refresh one peer for exactly 1200 seconds.

        The operation is atomic on validation, capacity, regression, and
        overflow failures. Expired peers are reclaimed before capacity is
        evaluated; live peers are never silently evicted.
        """
        self._validate_now(now_s)
        if now_s > MAX_MONOTONIC_SECONDS - LOCAL_EVIDENCE_LIFETIME_SECONDS:
            raise EvidenceTimeError("local-evidence expiry would overflow u64")
        if not isinstance(destination, str) or not destination:
            raise EvidenceError("destination must be a non-empty string")
        if source not in AUTHENTICATED_SOURCES:
            raise EvidenceError(f"unauthenticated evidence source: {source!r}")
        if (
            isinstance(hop_count, bool)
            or not isinstance(hop_count, int)
            or not 0 <= hop_count <= 255
        ):
            raise EvidenceError("hop_count must be in 0..255")
        if isinstance(seq_num, bool) or not isinstance(seq_num, int) or not 0 <= seq_num <= 65535:
            raise EvidenceError("seq_num must be in 0..65535")

        is_existing = destination in self._entries
        expired = [peer for peer, entry in self._entries.items() if entry.expires_at_s <= now_s]
        resulting_size = len(self._entries) - len(expired) + (0 if is_existing else 1)
        if resulting_size > self._max_peers:
            raise EvidenceCapacityError(f"local-evidence table is full ({self._max_peers})")

        self._last_now_s = now_s
        for peer in expired:
            del self._entries[peer]
        entry = GradientEntry(
            destination=destination,
            next_hop=next_hop,
            hop_count=hop_count,
            seq_num=seq_num,
            source=source,
            observed_at_s=now_s,
            expires_at_s=now_s + LOCAL_EVIDENCE_LIFETIME_SECONDS,
        )
        self._entries[destination] = entry
        return entry

    def has_evidence(self, destination: str, now_s: int) -> bool:
        """Return whether a destination has evidence strictly after ``now_s``."""
        self._advance(now_s)
        entry = self._entries.get(destination)
        if entry is None:
            return False
        if entry.expires_at_s <= now_s:
            del self._entries[destination]
            return False
        return True

    def prune(self, now_s: int) -> int:
        """Remove all expired peers and return the number reclaimed."""
        self._advance(now_s)
        return self._purge_expired(now_s)

    def get(self, destination: str, now_s: int) -> GradientEntry | None:
        """Return a live immutable entry, or ``None`` after expiry."""
        if not self.has_evidence(destination, now_s):
            return None
        return self._entries[destination]
