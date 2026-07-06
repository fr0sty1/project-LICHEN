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

from lichen.ipv6 import to_ipv6
from lichen.gradient import (
    GRADIENT_TIMEOUT_MS,
    GradientEntry,
    GradientSource,
    GradientTable,
)
from lichen.loadng.cache import RouteCache, RouteEntry
from lichen.loadng.messages import INITIAL_HOP_LIMIT, RREP, RREQ

SUPPRESS_WINDOW_MS = 10_000  # duplicate-RREQ suppression window (spec B2.6)


@dataclass
class RreqResult:
    """Outcome of processing an RREQ."""

    suppressed: bool = False
    reply: RREP | None = None
    reply_next_hop: IPv6Address | None = None
    forward: RREQ | None = None


@dataclass
class RrepResult:
    """Outcome of processing an RREP."""

    delivered: bool = False
    forward: RREP | None = None
    forward_next_hop: IPv6Address | None = None
    dropped: bool = False


class LoadngRouter:
    """Reactive route discovery state machine for one node."""

    # Prune _seen cache every N suppression checks to amortize O(n) cost.
    _PRUNE_INTERVAL = 16

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
        self._seen: dict[tuple[IPv6Address, IPv6Address, int], int] = {}
        self._prune_countdown = self._PRUNE_INTERVAL

    def originate_rreq(
        self,
        destination: IPv6Address | str,
        now: int,
        hop_limit: int = INITIAL_HOP_LIMIT,
    ) -> RREQ:
        """Create a new RREQ for ``destination`` and record it as seen."""
        self._own_seq = (self._own_seq + 1) & 0xFFFF
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
        self.cache.add(
            RouteEntry(
                destination=rreq.originator,
                next_hop=from_neighbor,
                hop_count=0,
                metric=0,
                seq_num=rreq.seq_num,
                valid_until=now + self.cache.route_timeout_ms,
            )
        )

        if rreq.destination == self.node_address:
            rrep = RREP(
                originator=self.node_address,
                destination=rreq.originator,
                seq_num=rreq.seq_num,
                hop_count=0,
            )
            return RreqResult(reply=rrep, reply_next_hop=from_neighbor)

        # Intermediate reply if we already hold a gradient to the destination.
        grad = self.gradient.lookup(rreq.destination, now)
        if grad is not None:
            rrep = RREP(
                originator=rreq.destination,
                destination=rreq.originator,
                seq_num=rreq.seq_num,
                hop_count=grad.hop_count,
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

        # Forward gradient toward the sought node (the RREP's originator).
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

    def _rreq_key(self, rreq: RREQ) -> tuple[IPv6Address, IPv6Address, int]:
        return (to_ipv6(rreq.originator), to_ipv6(rreq.destination), rreq.seq_num)

    def _mark_seen(self, rreq: RREQ, now: int) -> None:
        self._seen[self._rreq_key(rreq)] = now

    def _is_suppressed(self, rreq: RREQ, now: int) -> bool:
        # Lazy prune: only prune every N checks to amortize O(n) cost.
        # Stale entries don't affect correctness; they only waste memory.
        self._prune_countdown -= 1
        if self._prune_countdown <= 0:
            self._prune_seen(now)
            self._prune_countdown = self._PRUNE_INTERVAL
        ts = self._seen.get(self._rreq_key(rreq))
        return ts is not None and now - ts < self.suppress_window_ms

    def _prune_seen(self, now: int) -> None:
        stale = [k for k, t in self._seen.items() if now - t >= self.suppress_window_ms]
        for key in stale:
            del self._seen[key]
