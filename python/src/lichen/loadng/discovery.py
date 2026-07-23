# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LOADng reactive route discovery (spec sections 10.3-10.5, B2.6).

Implements RREQ/RREP processing as a deterministic, side-effect-free handler:
each method updates the route cache / gradient table and returns an action
describing what the caller should transmit (rebroadcast an RREQ, unicast an
RREP, or nothing). The caller owns the radio and the clock; ``now`` is an
integer millisecond timestamp.

RREQ handling (spec 10.3): if we are the destination, or hold a gradient to it,
reply with an RREP; if the RREQ is a duplicate (originator/destination/seq seen
within the suppression window), drop it; otherwise record a reverse route and
rebroadcast with the hop limit decremented. RREP handling (spec 10.4-10.5):
install a forward gradient toward the sought node and forward the RREP along the
reverse route until it reaches the original requester.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from ipaddress import IPv6Address

from lichen.gradient import (
    GRADIENT_TIMEOUT_MS,
    GradientEntry,
    GradientSource,
    GradientTable,
)
from lichen.ipv6 import to_ipv6
from lichen.loadng.cache import _SEQ_MAX, RouteCache, RouteEntry, _is_seq_fresher
from lichen.loadng.messages import INITIAL_HOP_LIMIT, RREP, RREQ

SUPPRESS_WINDOW_MS = 10_000


@dataclass
class RreqResult:
    suppressed: bool = False
    reply: RREP | None = None
    reply_next_hop: IPv6Address | None = None
    forward: RREQ | None = None


@dataclass
class RrepResult:
    """Outcome of processing an RREP.

    Note on forward_next_hop (project-LICHEN-f9mx): The next_hop is snapshotted
    from cache.lookup() at processing time. Due to the side-effect-free design,
    between RrepResult return and caller transmission, the route may be removed
    by expire_old(), RERR processing, or replaced by a better route. Caller
    should re-validate (via cache.lookup or neighbor liveness) before tx.
    This is accepted limitation of pull-based architecture prioritizing
    testability/determinism over atomicity.
    """

    delivered: bool = False
    forward: RREP | None = None
    forward_next_hop: IPv6Address | None = None
    dropped: bool = False


class LoadngRouter:
    """Reactive route discovery state machine for one node."""

    # Prune _seen cache every N suppression checks to amortize O(n) cost.
    _PRUNE_INTERVAL = 16
    _MAX_SEEN_ENTRIES = 1024

    def __init__(
        self,
        node_address: IPv6Address | str,
        gradient: GradientTable,
        cache: RouteCache,
        *,
        suppress_window_ms: int = SUPPRESS_WINDOW_MS,
    ) -> None:
        self.node_address = to_ipv6(node_address)
        self.gradient = gradient
        self.cache = cache
        self.suppress_window_ms = suppress_window_ms
        self._own_seq = 0
        self._seen: dict[tuple[IPv6Address, IPv6Address], tuple[int, int]] = {}
        self._prune_countdown = self._PRUNE_INTERVAL

    def originate_rreq(
        self,
        destination: IPv6Address | str,
        now: int,
        hop_limit: int = INITIAL_HOP_LIMIT,
    ) -> RREQ:
        """Create a new RREQ for ``destination`` and record it as seen."""
        self._own_seq = (self._own_seq + 1) & _SEQ_MAX
        rreq = RREQ(
            originator=self.node_address,
            destination=to_ipv6(destination),
            seq_num=self._own_seq,
            hop_limit=hop_limit,
        )
        self._mark_seen(rreq, now)
        return rreq

    def process_rreq(
        self, rreq: RREQ, from_neighbor: IPv6Address | str, now: int
    ) -> RreqResult:
        from_neighbor = to_ipv6(from_neighbor)
        if rreq.originator == self.node_address:
            return RreqResult(suppressed=True)  # echo of our own RREQ
        if self._is_suppressed(rreq, now):
            return RreqResult(suppressed=True)
        self._mark_seen(rreq, now)

        # Reverse route back toward the originator, used to return the RREP.
        actual_hops = INITIAL_HOP_LIMIT - rreq.hop_limit
        self.cache.add(
            RouteEntry(
                destination=rreq.originator,
                next_hop=from_neighbor,
                hop_count=actual_hops,
                metric=actual_hops,
                seq_num=rreq.seq_num,
                valid_until=now + self.cache.route_timeout_ms,
            )
        )

        if rreq.destination == self.node_address:
            # We are the destination; reply with our own sequence number
            # (not the RREQ's seq_num, which belongs to the RREQ originator).
            self._own_seq = (self._own_seq + 1) & _SEQ_MAX
            rrep = RREP(
                originator=self.node_address,
                destination=rreq.originator,
                seq_num=self._own_seq,
                hop_count=0,
            )
            return RreqResult(reply=rrep, reply_next_hop=from_neighbor)

        # Intermediate reply if we already hold a gradient to the destination.
        # Set proxy flag (bit 0) so receivers can distinguish direct/authoritative
        # RREPs (flags=0, from actual destination) from proxied ones (flags=0x01,
        # from intermediate using cached gradient, potentially stale).
        # Addresses bead project-LICHEN-ih8n.
        grad = self.gradient.lookup(rreq.destination, now)
        if grad is not None:
            rrep = RREP(
                originator=rreq.destination,
                destination=rreq.originator,
                seq_num=grad.seq_num,
                hop_count=grad.hop_count,
                flags=0x01,  # proxy/intermediate reply indicator
            )
            return RreqResult(reply=rrep, reply_next_hop=from_neighbor)

        if rreq.hop_limit > 1:
            return RreqResult(forward=replace(rreq, hop_limit=rreq.hop_limit - 1))

        return RreqResult()  # hop limit exhausted -> dropped

    def process_rrep(
        self, rrep: RREP, from_neighbor: IPv6Address | str, now: int
    ) -> RrepResult:
        from_neighbor = to_ipv6(from_neighbor)
        install_hops = rrep.hop_count + 1

        existing = self.gradient.lookup(rrep.originator, now)
        if existing is None or _is_seq_fresher(existing.seq_num, rrep.seq_num):
            self.gradient.update(
                GradientEntry(
                    destination=rrep.originator,
                    next_hop=from_neighbor,
                    hop_count=install_hops,
                    seq_num=rrep.seq_num,
                    source=GradientSource.RREP,
                    expires=now + GRADIENT_TIMEOUT_MS,
                ),
                now=now,
            )
        self.cache.add(
            RouteEntry(
                destination=rrep.originator,
                next_hop=from_neighbor,
                hop_count=install_hops,
                metric=install_hops,
                seq_num=rrep.seq_num,
                valid_until=now + self.cache.route_timeout_ms,
            )
        )

        if rrep.destination == self.node_address:
            return RrepResult(delivered=True)

        # Forward along the reverse route toward the original requester.
        reverse = self.cache.lookup(rrep.destination, now)
        if reverse is None:
            return RrepResult(dropped=True)
        return RrepResult(
            forward=replace(rrep, hop_count=install_hops),
            forward_next_hop=reverse.next_hop,
        )

    def _rreq_key(self, rreq: RREQ) -> tuple[IPv6Address, IPv6Address]:
        return (to_ipv6(rreq.originator), to_ipv6(rreq.destination))

    def _mark_seen(self, rreq: RREQ, now: int) -> None:
        key = self._rreq_key(rreq)
        if len(self._seen) >= self._MAX_SEEN_ENTRIES:
            self._prune_seen(now)
            if len(self._seen) >= self._MAX_SEEN_ENTRIES:
                oldest_key = min(self._seen, key=lambda k: self._seen[k][1])
                del self._seen[oldest_key]
        cached = self._seen.get(key)
        if cached is None or rreq.seq_num == cached[0] or _is_seq_fresher(cached[0], rreq.seq_num):
            self._seen[key] = (rreq.seq_num, now)

    def _is_suppressed(self, rreq: RREQ, now: int) -> bool:
        self._prune_countdown -= 1
        if self._prune_countdown <= 0:
            self._prune_seen(now)
            self._prune_countdown = self._PRUNE_INTERVAL
        cached = self._seen.get(self._rreq_key(rreq))
        if cached is None:
            return False
        cached_seq, cached_ts = cached
        if _is_seq_fresher(cached_seq, rreq.seq_num):
            return False
        elapsed = now - cached_ts
        if elapsed < 0:
            return False
        return elapsed < self.suppress_window_ms

    def _prune_seen(self, now: int) -> None:
        stale = [k for k, (_, ts) in self._seen.items() if now - ts >= self.suppress_window_ms]
        for key in stale:
            del self._seen[key]
