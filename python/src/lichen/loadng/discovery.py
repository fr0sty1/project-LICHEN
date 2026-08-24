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

Trust and validation posture:

- RREP signatures are opaque bytes at this layer (produced/verified by the
  link/security layer); process_rrep performs NO destination-owned sequence
  verification. Any neighbor can forge an authoritative-looking RREP
  (flags=0), so unflagged replies remain trusted per the freshness gate alone
  -- a residual trust gap until signed/pinned-key verification lands.
  Proxy-flagged replies (RREP_FLAG_PROXY) are treated as non-authoritative
  hints: they may bootstrap a route for a destination with no existing usable
  cache/gradient entry, but they never replace or upgrade existing knowledge
  (project-LICHEN-worker6-bugi).
- RREPs are forwarded only when they carry information at least as fresh as
  the local route cache, and duplicate/stale replays within the suppression
  window are dropped, so injected or delayed replies do not amplify along the
  reverse path (project-LICHEN-worker6-tiw8).
- RREQ hop_limit values above INITIAL_HOP_LIMIT are handler-rejected with no
  state change. They are wire-legal (appendix B2.5 expanding-ring search
  originates floods at 8 and 15, and messages.py accepts up to
  MAX_HOP_LIMIT), but the reverse-route cost derivation
  ``INITIAL_HOP_LIMIT - hop_limit`` is meaningless for larger rings, so until
  messages carry traversed-hop data they are dropped cleanly instead of being
  mis-costed (project-LICHEN-worker6-0tk2).

Known limitation (project-LICHEN-f9mx): RrepResult.forward_next_hop may be
stale by transmission time due to cache mutations.
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
from lichen.loadng.messages import INITIAL_HOP_LIMIT, MAX_HOP_LIMIT, RREP, RREQ

SUPPRESS_WINDOW_MS = 10_000

# RREP flags bit 0 marks an intermediate/proxy reply (set by process_rreq when
# answering from a cached gradient). spec/05-routing.md 10.4 defines the Flags
# field but assigns no bit values; this bit is a LICHEN convention (see the
# rrep_proxied_flag_preserved vector in test/vectors/loadng_discovery.json).
# Receivers treat flagged replies as non-authoritative hints: unverified
# sequence claims that must not displace existing knowledge.
RREP_FLAG_PROXY = 0x01


@dataclass
class RreqResult:
    suppressed: bool = False
    reply: RREP | None = None
    reply_next_hop: IPv6Address | None = None
    forward: RREQ | None = None
    # Handler-reject outcome for inputs this router refuses before any state
    # change (malformed or unsupported, e.g. hop_limit above the base flood
    # size; see module docstring). Distinct from ``suppressed``, which means
    # "duplicate of a recently seen RREQ".
    dropped: bool = False


@dataclass
class RrepResult:
    """Outcome of processing an RREP.

    Note (project-LICHEN-f9mx): forward_next_hop is a snapshot from
    cache.lookup() at the time of process_rrep(). Between return and
    caller transmission, the cache may have been mutated by expire_old(),
    RERR processing, or concurrent updates. This is a known limitation
    of the side-effect-free design (trades atomicity for testability).
    Callers should re-validate routes before use where possible.
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
        # Replay window for forwarded RREPs (project-LICHEN-worker6-tiw8),
        # mirroring the RREQ suppression store: key (originator, destination)
        # -> (seq_num, seen_at_ms).
        self._rrep_seen: dict[tuple[IPv6Address, IPv6Address], tuple[int, int]] = {}
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

    def process_rreq(self, rreq: RREQ, from_neighbor: IPv6Address | str, now: int) -> RreqResult:
        from_neighbor = to_ipv6(from_neighbor)
        # Handler-reject hop limits outside the base flood size before any
        # state changes (project-LICHEN-worker6-0tk2): the reverse-route cost
        # below derives distance as INITIAL_HOP_LIMIT - hop_limit, which goes
        # negative for the wire-legal expanding-ring values 5..15 (appendix
        # B2.5). Not suppressed (this is not a duplicate), not seen-marked,
        # nothing installed.
        if not 0 <= rreq.hop_limit <= INITIAL_HOP_LIMIT:
            return RreqResult(dropped=True)
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

    def process_rrep(self, rrep: RREP, from_neighbor: IPv6Address | str, now: int) -> RrepResult:
        from_neighbor = to_ipv6(from_neighbor)
        # Entry validation for directly-constructed messages
        # (project-LICHEN-worker6-4tbd): RREP.from_bytes() guarantees these
        # ranges on the wire path, but host code can build RREPs that bypass
        # it; reject cleanly instead of raising mid-processing from
        # RouteEntry/GradientEntry construction. Unknown flag bits are also
        # rejected: an unrecognized bit could carry semantics this
        # implementation must not silently ignore.
        if (
            not 0 <= rrep.seq_num <= _SEQ_MAX
            or not 0 <= rrep.hop_count <= MAX_HOP_LIMIT
            or rrep.flags not in (0, RREP_FLAG_PROXY)
        ):
            return RrepResult(dropped=True)

        # Installing or forwarding costs one more hop than the received message.
        # Past MAX_HOP_LIMIT the resulting RREP cannot be serialized (spec B2.1:
        # hop values above 15 are malformed on the wire), so drop cleanly rather
        # than emit a message that raises at to_bytes() time or store a route
        # cost no RREP can ever carry (project-LICHEN-worker6-1leg).
        install_hops = rrep.hop_count + 1
        if install_hops > MAX_HOP_LIMIT:
            return RrepResult(dropped=True)

        is_proxy = bool(rrep.flags & RREP_FLAG_PROXY)
        # Freshness/superiority standard (bead project-LICHEN-worker6-uosr,
        # RFC 3561 section 6.2): act only if no usable route exists, the reply
        # sequence number is fresher (RFC 1982), or the sequence numbers are
        # equal and this reply offers strictly fewer hops.
        #
        # The INSTALL verdict consults every local store (both stores must
        # accept), while FORWARDING keeps the historical cache-only gate:
        # stale-but-harmless traffic (e.g. proxy hints) still relays once, and
        # only writes are unified-verdict gated (project-LICHEN-worker6-3ae7).
        acceptable = self._rrep_beats_local_state(
            rrep.originator, rrep.seq_num, install_hops, now
        )
        # Proxy replies are non-authoritative hints (project-LICHEN-worker6-bugi):
        # their sequence claims are unverified at this layer, so they may only
        # bootstrap a route when we hold no usable knowledge of the destination;
        # they must never displace or upgrade an existing entry.
        known = (
            self.cache.lookup(rrep.originator, now) is not None
            or self.gradient.lookup(rrep.originator, now) is not None
        )
        may_install = acceptable and not (is_proxy and known)

        if rrep.destination == self.node_address:
            if may_install:
                self._install_route(rrep.originator, from_neighbor, install_hops, rrep.seq_num, now)
            return RrepResult(delivered=True)

        # Forwarding path (intermediate). First suppress replays within the
        # window (project-LICHEN-worker6-tiw8): a repeated or stale-seq copy of
        # an already-relayed reply must not burn a transmission per node.
        key = (to_ipv6(rrep.originator), to_ipv6(rrep.destination))
        if self._seen_is_repeat(self._rrep_seen, key, rrep.seq_num, now):
            return RrepResult(dropped=True)
        self._seen_record(self._rrep_seen, key, rrep.seq_num, now)

        # A reply carrying nothing fresher than the local route cache is not
        # forwarded either: each forwarded copy costs one TX per reverse-path
        # node, so stale injections would otherwise amplify along the path
        # (project-LICHEN-worker6-tiw8). Cache-only by design: forwarding
        # relays information, it writes nothing.
        if not self._rrep_beats_cache(rrep.originator, rrep.seq_num, install_hops, now):
            return RrepResult(dropped=True)

        if may_install:
            self._install_route(rrep.originator, from_neighbor, install_hops, rrep.seq_num, now)

        # Forward along the reverse route toward the original requester.
        # See RrepResult docstring for staleness note (project-LICHEN-f9mx).
        reverse = self.cache.lookup(rrep.destination, now)
        if reverse is None:
            return RrepResult(dropped=True)
        return RrepResult(
            forward=replace(rrep, hop_count=install_hops),
            forward_next_hop=reverse.next_hop,
        )

    def _rrep_beats_local_state(
        self, originator: IPv6Address | str, seq_num: int, install_hops: int, now: int
    ) -> bool:
        """Freshness/superiority gate over every local store (RFC 3561 6.2).

        The route cache is LRU(32) with a shorter timeout than the gradient
        table, so a cache miss does not mean "no local knowledge"
        (project-LICHEN-worker6-3ae7): deciding from the cache alone let a
        stale or equal-seq reply install into the cache while gradient.update()
        rejected it, leaving the two stores contradicting each other and
        reopening the uosr class. Each store's own predicate must accept.
        """
        for existing in (
            self.cache.lookup(originator, now),
            self.gradient.lookup(originator, now),
        ):
            if existing is not None and not (
                _is_seq_fresher(existing.seq_num, seq_num)
                or (existing.seq_num == seq_num and install_hops < existing.hop_count)
            ):
                return False
        return True

    def _rrep_beats_cache(
        self, originator: IPv6Address | str, seq_num: int, install_hops: int, now: int
    ) -> bool:
        """Freshness/superiority gate vs the route cache only (RFC 3561 6.2).

        Used for the FORWARDING decision: relaying a reply writes nothing, so
        it keeps the historical cache-only standard instead of the stricter
        two-store install verdict.
        """
        existing_route = self.cache.lookup(originator, now)
        if existing_route is None:
            return True
        return _is_seq_fresher(existing_route.seq_num, seq_num) or (
            existing_route.seq_num == seq_num and install_hops < existing_route.hop_count
        )

    def _install_route(
        self,
        destination: IPv6Address | str,
        next_hop: IPv6Address | str,
        hop_count: int,
        seq_num: int,
        now: int,
    ) -> None:
        """Write a discovered route into the cache and the gradient table."""
        dest = to_ipv6(destination)
        nh = to_ipv6(next_hop)
        self.cache.add(
            RouteEntry(
                destination=dest,
                next_hop=nh,
                hop_count=hop_count,
                metric=hop_count,
                seq_num=seq_num,
                valid_until=now + self.cache.route_timeout_ms,
            )
        )
        self.gradient.update(
            GradientEntry(
                destination=dest,
                next_hop=nh,
                hop_count=hop_count,
                seq_num=seq_num,
                source=GradientSource.RREP,
                expires=now + GRADIENT_TIMEOUT_MS,
            ),
            now=now,
        )

    def _rreq_key(self, rreq: RREQ) -> tuple[IPv6Address, IPv6Address]:
        return (to_ipv6(rreq.originator), to_ipv6(rreq.destination))

    def _mark_seen(self, rreq: RREQ, now: int) -> None:
        self._seen_record(self._seen, self._rreq_key(rreq), rreq.seq_num, now)

    def _is_suppressed(self, rreq: RREQ, now: int) -> bool:
        self._prune_countdown -= 1
        if self._prune_countdown <= 0:
            self._prune_seen(now)
            self._prune_countdown = self._PRUNE_INTERVAL
        return self._seen_is_repeat(self._seen, self._rreq_key(rreq), rreq.seq_num, now)

    def _seen_is_repeat(
        self,
        store: dict[tuple[IPv6Address, IPv6Address], tuple[int, int]],
        key: tuple[IPv6Address, IPv6Address],
        seq_num: int,
        now: int,
    ) -> bool:
        """True if (key, seq_num) was seen within the suppression window.

        A strictly fresher sequence number (RFC 1982) is never a repeat.
        """
        cached = store.get(key)
        if cached is None:
            return False
        cached_seq, cached_ts = cached
        if _is_seq_fresher(cached_seq, seq_num):
            return False
        elapsed = now - cached_ts
        return elapsed >= 0 and elapsed < self.suppress_window_ms

    def _seen_record(
        self,
        store: dict[tuple[IPv6Address, IPv6Address], tuple[int, int]],
        key: tuple[IPv6Address, IPv6Address],
        seq_num: int,
        now: int,
    ) -> None:
        """Record (key, seq_num) as seen, pruning/evicting when oversized."""
        if len(store) >= self._MAX_SEEN_ENTRIES:
            pruned = {k: v for k, v in store.items() if now - v[1] < self.suppress_window_ms}
            store.clear()
            store.update(pruned)
            if len(store) >= self._MAX_SEEN_ENTRIES:
                del store[min(store, key=lambda k: store[k][1])]
        cached = store.get(key)
        if cached is None or seq_num == cached[0] or _is_seq_fresher(cached[0], seq_num):
            store[key] = (seq_num, now)

    def _prune_seen(self, now: int) -> None:
        # Atomic rebind avoids iterate-then-delete race
        self._seen = {k: v for k, v in self._seen.items() if now - v[1] < self.suppress_window_ms}
