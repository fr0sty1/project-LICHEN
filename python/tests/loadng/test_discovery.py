# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LOADng route discovery (spec 10.3-10.5)."""

from __future__ import annotations

from ipaddress import IPv6Address

from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.loadng.cache import RouteCache
from lichen.loadng.discovery import RREP_FLAG_PROXY, SUPPRESS_WINDOW_MS, LoadngRouter
from lichen.loadng.messages import INITIAL_HOP_LIMIT, MAX_HOP_LIMIT, RREP, RREQ

ORIG = IPv6Address("fd00::1")  # originator / requester
M = IPv6Address("fd00::2")  # intermediate
D = IPv6Address("fd00::3")  # destination / sought node


def _router(node: IPv6Address) -> LoadngRouter:
    return LoadngRouter(node, GradientTable(), RouteCache())


def test_originate_rreq() -> None:
    r = _router(ORIG)
    rreq = r.originate_rreq(D, now=0)
    assert rreq.originator == ORIG
    assert rreq.destination == D
    assert rreq.seq_num == 1
    assert r.originate_rreq(D, now=0).seq_num == 2  # increments


def test_destination_replies() -> None:
    dest = _router(D)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    result = dest.process_rreq(rreq, from_neighbor=M, now=100)
    assert result.reply is not None
    assert result.reply.originator == D
    assert result.reply.destination == ORIG
    assert result.reply.hop_count == 0
    assert result.reply_next_hop == M
    # RREP uses the destination's own sequence number, not the RREQ's seq_num.
    # RREQ had seq_num=1, but the RREP should use dest's own seq (1 after first increment).
    assert result.reply.seq_num == 1
    # Verify a second RREQ gets a different (incremented) seq_num in the RREP.
    rreq2 = RREQ(originator=ORIG, destination=D, seq_num=99)
    result2 = dest.process_rreq(rreq2, from_neighbor=M, now=200)
    assert result2.reply is not None
    assert result2.reply.seq_num == 2  # dest's own seq incremented, not RREQ's 99
    # Reverse route to the originator is installed.
    assert dest.cache.lookup(ORIG).next_hop == M


def test_duplicate_rreq_suppressed() -> None:
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    first = r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    assert first.forward is not None  # first time: forwarded
    second = r.process_rreq(rreq, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is True


def test_suppression_expires_after_window() -> None:
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    # Past the 10s window the same RREQ is processed again (not suppressed).
    later = r.process_rreq(rreq, from_neighbor=ORIG, now=10_000)
    assert later.suppressed is False
    assert later.forward is not None


def test_own_rreq_echo_ignored() -> None:
    r = _router(ORIG)
    rreq = r.originate_rreq(D, now=0)
    assert r.process_rreq(rreq, from_neighbor=M, now=1).suppressed is True


def test_intermediate_forward_decrements_hop_limit() -> None:
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1, hop_limit=4)
    result = r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    assert result.forward is not None
    assert result.forward.hop_limit == 3
    assert r.cache.lookup(ORIG).next_hop == ORIG  # reverse route


def test_hop_limit_exhausted_drops() -> None:
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1, hop_limit=1)
    result = r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    assert result.forward is None
    assert result.reply is None


def test_intermediate_reply_from_gradient() -> None:
    r = _router(M)
    r.gradient.update(GradientEntry(D, IPv6Address("fe80::9"), 2, 1, GradientSource.RREP, 10_000))
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    result = r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    assert result.reply is not None
    assert result.reply.originator == D
    assert result.reply.hop_count == 2  # uses the gradient's hop count


def test_rrep_delivered_at_requester() -> None:
    r = _router(ORIG)
    rrep = RREP(originator=D, destination=ORIG, seq_num=1, hop_count=1)
    result = r.process_rrep(rrep, from_neighbor=M, now=0)
    assert result.delivered is True
    grad = r.gradient.lookup(D)
    assert grad.next_hop == M
    assert grad.hop_count == 2  # received hop_count + 1


def test_rrep_forwarded_along_reverse_route() -> None:
    r = _router(M)
    # M previously learned a reverse route to ORIG (via ORIG) from the RREQ.
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    rrep = RREP(originator=D, destination=ORIG, seq_num=1, hop_count=0)
    result = r.process_rrep(rrep, from_neighbor=D, now=1)
    assert result.forward is not None
    assert result.forward.hop_count == 1
    assert result.forward_next_hop == ORIG
    assert r.gradient.lookup(D).next_hop == D  # forward gradient toward D


def test_rrep_without_reverse_route_dropped() -> None:
    r = _router(M)
    rrep = RREP(originator=D, destination=ORIG, seq_num=1, hop_count=0)
    result = r.process_rrep(rrep, from_neighbor=D, now=0)
    assert result.dropped is True


def test_three_node_discovery_round_trip() -> None:
    o, m, d = _router(ORIG), _router(M), _router(D)

    rreq = o.originate_rreq(D, now=0)
    fwd = m.process_rreq(rreq, from_neighbor=ORIG, now=1).forward
    assert fwd is not None
    reply = d.process_rreq(fwd, from_neighbor=M, now=2)
    assert reply.reply is not None and reply.reply_next_hop == M

    at_m = m.process_rrep(reply.reply, from_neighbor=D, now=3)
    assert at_m.forward is not None and at_m.forward_next_hop == ORIG
    at_o = o.process_rrep(at_m.forward, from_neighbor=M, now=4)
    assert at_o.delivered is True

    # The originator now has a 2-hop gradient to D via M.
    grad = o.gradient.lookup(D)
    assert grad.next_hop == M
    assert grad.hop_count == 2


def test_seq_wrap_around_not_suppressed() -> None:
    """After seq wraps from 0xFFFF to 0, new RREQ is not suppressed."""
    r = _router(M)
    # Receive RREQ with seq=0xFFFF (near wrap point).
    rreq_old = RREQ(originator=ORIG, destination=D, seq_num=0xFFFF)
    first = r.process_rreq(rreq_old, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    # New RREQ with seq=0 (wrapped around) should NOT be suppressed,
    # even though it's within the suppression window.
    rreq_new = RREQ(originator=ORIG, destination=D, seq_num=0)
    second = r.process_rreq(rreq_new, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is False
    assert second.forward is not None


def test_older_seq_still_suppressed() -> None:
    """An RREQ with an older seq (even after wrap handling) is suppressed."""
    r = _router(M)
    # Receive RREQ with seq=100.
    rreq_new = RREQ(originator=ORIG, destination=D, seq_num=100)
    first = r.process_rreq(rreq_new, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    # RREQ with seq=50 is older (not newer in wrap-aware sense), so suppressed.
    rreq_old = RREQ(originator=ORIG, destination=D, seq_num=50)
    second = r.process_rreq(rreq_old, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is True


def test_seq_half_range_boundary_0_to_32768_not_suppressed() -> None:
    """seq 0->32768: half-range boundary, 32768 is NOT fresher, so seq=32768 is suppressed."""
    r = _router(M)
    rreq_a = RREQ(originator=ORIG, destination=D, seq_num=0)
    first = r.process_rreq(rreq_a, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    rreq_b = RREQ(originator=ORIG, destination=D, seq_num=0x8000)
    second = r.process_rreq(rreq_b, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is True


def test_seq_half_range_just_below_0_to_32767_not_suppressed() -> None:
    """seq 0->32767: 32767 is fresher (diff < half), so processed again (not suppressed)."""
    r = _router(M)
    rreq_a = RREQ(originator=ORIG, destination=D, seq_num=0)
    first = r.process_rreq(rreq_a, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    rreq_b = RREQ(originator=ORIG, destination=D, seq_num=0x7FFF)
    second = r.process_rreq(rreq_b, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is False
    assert second.forward is not None


def test_seq_wrap_ffff_to_1_not_suppressed() -> None:
    """seq 0xFFFF->1: wrapped forward two steps, processed again."""
    r = _router(M)
    rreq_a = RREQ(originator=ORIG, destination=D, seq_num=0xFFFF)
    first = r.process_rreq(rreq_a, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    rreq_b = RREQ(originator=ORIG, destination=D, seq_num=1)
    second = r.process_rreq(rreq_b, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is False
    assert second.forward is not None


def test_seq_0_to_ffff_suppressed() -> None:
    """seq 0->0xFFFF: 0xFFFF is stale (wrap backward), suppressed."""
    r = _router(M)
    rreq_a = RREQ(originator=ORIG, destination=D, seq_num=0)
    first = r.process_rreq(rreq_a, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    rreq_b = RREQ(originator=ORIG, destination=D, seq_num=0xFFFF)
    second = r.process_rreq(rreq_b, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is True


def test_seq_half_plus_one_to_0_not_suppressed() -> None:
    """seq 0x8001->0: wraps forward with diff=32767 < half, processed again."""
    r = _router(M)
    rreq_a = RREQ(originator=ORIG, destination=D, seq_num=0x8001)
    first = r.process_rreq(rreq_a, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    rreq_b = RREQ(originator=ORIG, destination=D, seq_num=0)
    second = r.process_rreq(rreq_b, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is False
    assert second.forward is not None


def test_seq_32767_to_32768_fresher_not_suppressed() -> None:
    """seq 0x7FFF->0x8000: diff=1, 32768 is fresher, not suppressed."""
    r = _router(M)
    rreq_a = RREQ(originator=ORIG, destination=D, seq_num=0x7FFF)
    first = r.process_rreq(rreq_a, from_neighbor=ORIG, now=0)
    assert first.forward is not None

    rreq_b = RREQ(originator=ORIG, destination=D, seq_num=0x8000)
    second = r.process_rreq(rreq_b, from_neighbor=ORIG, now=5_000)
    assert second.suppressed is False
    assert second.forward is not None


# Regression: RREP hop_count wire boundary (project-LICHEN-worker6-1leg).
# Spec B2.1 / messages._validate_hop: hop values above MAX_HOP_LIMIT (15) are
# malformed on the wire. The router must never emit or store a larger cost.


def test_rrep_at_max_depth_forwards_serializable_reply() -> None:
    """Exactly-at-max is valid: receiving hop_count=14 installs/forwards 15."""
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    rrep = RREP(originator=D, destination=ORIG, seq_num=7, hop_count=MAX_HOP_LIMIT - 1)
    result = r.process_rrep(rrep, from_neighbor=D, now=1)
    assert result.dropped is False
    assert result.forward is not None
    assert result.forward.hop_count == MAX_HOP_LIMIT
    # Serialization round-trip at max depth must succeed (spec B2.1 wire bound).
    parsed = RREP.from_bytes(result.forward.to_bytes())
    assert parsed.hop_count == MAX_HOP_LIMIT
    assert parsed.originator == D
    assert parsed.destination == ORIG
    grad = r.gradient.lookup(D, now=1)
    assert grad is not None and grad.hop_count == MAX_HOP_LIMIT


def test_rrep_at_max_depth_delivered_at_requester() -> None:
    """hop_count=14 arriving at the requester installs a 15-hop route."""
    r = _router(ORIG)
    rrep = RREP(originator=D, destination=ORIG, seq_num=7, hop_count=MAX_HOP_LIMIT - 1)
    result = r.process_rrep(rrep, from_neighbor=M, now=0)
    assert result.delivered is True
    grad = r.gradient.lookup(D)
    assert grad.hop_count == MAX_HOP_LIMIT


def test_rrep_beyond_max_depth_dropped_without_state_change() -> None:
    """hop_count=15 would require a 16-hop install/forward: reject cleanly."""
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    rrep = RREP(originator=D, destination=ORIG, seq_num=7, hop_count=MAX_HOP_LIMIT)
    result = r.process_rrep(rrep, from_neighbor=D, now=1)  # must not raise
    assert result.dropped is True
    assert result.delivered is False
    assert result.forward is None
    assert r.gradient.lookup(D, now=1) is None  # no partial install
    assert r.cache.lookup(D, now=1) is None


def test_rrep_beyond_max_depth_at_requester_dropped() -> None:
    """Even delivery is refused: a 16-hop route cannot exist on the wire."""
    r = _router(ORIG)
    rrep = RREP(originator=D, destination=ORIG, seq_num=7, hop_count=MAX_HOP_LIMIT)
    result = r.process_rrep(rrep, from_neighbor=M, now=0)  # must not raise
    assert result.dropped is True
    assert result.delivered is False


# Regression: freshness/superiority gate shared by cache and gradient
# (project-LICHEN-worker6-uosr). Rule per RFC 3561 section 6.2: install only
# if no usable route exists, the reply sequence number is fresher, or the
# sequence numbers are equal with strictly fewer hops; stale never replaces
# fresh.


def test_stale_rrep_does_not_overwrite_fresh_cache_or_gradient() -> None:
    """A delayed/retransmitted older-seq RREP leaves both stores untouched."""
    r = _router(ORIG)
    fresh = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=1)
    r.process_rrep(fresh, from_neighbor=M, now=0)
    delayed = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=50, hop_count=1),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    assert delayed.delivered is True  # processing continues; only installs are gated
    route = r.cache.lookup(D, now=1)
    assert route.next_hop == M
    assert route.seq_num == 100
    grad = r.gradient.lookup(D, now=1)
    assert grad.next_hop == M
    assert grad.seq_num == 100


def test_stale_rrep_does_not_install_into_empty_gradient() -> None:
    """Cache fresh + gradient pruned: stale reply must not split the stores.

    Previously the gradient gate consulted the (empty) gradient table while
    the cache gate rejected, so a stale sequence number was installed into
    the gradient only, leaving gradient and cache inconsistent.
    """
    r = _router(ORIG)
    fresh = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=1)
    r.process_rrep(fresh, from_neighbor=M, now=0)
    r.gradient.remove(D)  # simulate gradient expiry/prune; cache stays fresh
    r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=50, hop_count=1),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    assert r.gradient.lookup(D, now=1) is None
    route = r.cache.lookup(D, now=1)
    assert route.seq_num == 100
    assert route.next_hop == M


def test_equal_seq_shorter_hops_replaces_route_in_both_stores() -> None:
    """Same seq with strictly fewer hops improves both stores (RFC 3561 6.2)."""
    r = _router(ORIG)
    longer = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=3)
    r.process_rrep(longer, from_neighbor=M, now=0)
    r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=100, hop_count=1),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    route = r.cache.lookup(D, now=1)
    assert route.next_hop == IPv6Address("fe80::a")
    assert route.hop_count == 2
    grad = r.gradient.lookup(D, now=1)
    assert grad.next_hop == IPv6Address("fe80::a")
    assert grad.hop_count == 2


def test_equal_seq_longer_hops_keeps_existing_route() -> None:
    """Same seq with more hops never replaces the shorter known route."""
    r = _router(ORIG)
    shorter = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=3)
    r.process_rrep(shorter, from_neighbor=M, now=0)
    r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=100, hop_count=5),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    route = r.cache.lookup(D, now=1)
    assert route.next_hop == M
    assert route.hop_count == 4
    grad = r.gradient.lookup(D, now=1)
    assert grad.next_hop == M
    assert grad.hop_count == 4


def test_fresher_seq_replaces_route_even_with_longer_hops() -> None:
    """A newer sequence number wins regardless of hop count superiority."""
    r = _router(ORIG)
    older = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=3)
    r.process_rrep(older, from_neighbor=M, now=0)
    r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=101, hop_count=13),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    route = r.cache.lookup(D, now=1)
    assert route.next_hop == IPv6Address("fe80::a")
    assert route.seq_num == 101
    assert route.hop_count == 14
    grad = r.gradient.lookup(D, now=1)
    assert grad.next_hop == IPv6Address("fe80::a")
    assert grad.seq_num == 101


# Regression: RREQ hop_limit above the base flood size is handler-rejected
# (project-LICHEN-worker6-0tk2). Wire values 5..15 are legal (appendix B2.5
# expanding-ring search originates at 8 and 15; messages._validate_hop allows
# 0..MAX_HOP_LIMIT), but the reverse-route cost derivation
# INITIAL_HOP_LIMIT - hop_limit would go negative, so such RREQs are dropped
# cleanly with no state change instead of crashing RouteEntry validation.


def test_rreq_at_initial_hop_limit_boundary_is_valid() -> None:
    """hop_limit == INITIAL_HOP_LIMIT is the largest supported flood input."""
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1, hop_limit=INITIAL_HOP_LIMIT)
    result = r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    assert result.dropped is False
    assert result.suppressed is False
    assert result.forward is not None
    assert result.forward.hop_limit == INITIAL_HOP_LIMIT - 1
    # Wire round-trip at the boundary must serialize (spec B2.1 hop field).
    parsed = RREQ.from_bytes(result.forward.to_bytes())
    assert parsed.hop_limit == INITIAL_HOP_LIMIT - 1
    # Reverse-route cost is zero hops at the boundary.
    route = r.cache.lookup(ORIG, now=0)
    assert route is not None and route.hop_count == 0


def test_rreq_at_initial_hop_limit_boundary_replies_at_destination() -> None:
    dest = _router(D)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1, hop_limit=INITIAL_HOP_LIMIT)
    result = dest.process_rreq(rreq, from_neighbor=M, now=0)
    assert result.dropped is False
    assert result.reply is not None


def test_rreq_above_initial_hop_limit_dropped_at_intermediate() -> None:
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1, hop_limit=INITIAL_HOP_LIMIT + 1)
    result = r.process_rreq(rreq, from_neighbor=ORIG, now=0)  # must not raise
    assert result.dropped is True
    assert result.suppressed is False
    assert result.forward is None
    assert result.reply is None
    assert r.cache.lookup(ORIG, now=0) is None  # no reverse-route install


def test_rreq_above_initial_hop_limit_dropped_at_destination() -> None:
    dest = _router(D)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1, hop_limit=INITIAL_HOP_LIMIT + 1)
    result = dest.process_rreq(rreq, from_neighbor=M, now=0)  # must not raise
    assert result.dropped is True
    assert result.reply is None
    assert dest.cache.lookup(ORIG, now=0) is None


def test_rreq_max_wire_hop_limit_dropped_cleanly_and_repeatable() -> None:
    """hop_limit=MAX_HOP_LIMIT is wire-legal but unsupported: clean rejection.

    Rejection also leaves no suppression state, so an identical retransmission
    gets the same verdict rather than being swallowed as a "duplicate".
    """
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1, hop_limit=MAX_HOP_LIMIT)
    first = r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    second = r.process_rreq(rreq, from_neighbor=ORIG, now=1)
    for result in (first, second):
        assert result.dropped is True
        assert result.suppressed is False
        assert result.forward is None and result.reply is None
    assert r.cache.lookup(ORIG, now=1) is None


# Regression: forged-RREP poisoning via the proxy flag
# (project-LICHEN-worker6-bugi). No destination-owned sequence verification
# exists in this layer (RREP signatures are opaque bytes here), so proxy
# replies are non-authoritative hints: they may bootstrap a route for an
# unknown destination (the committed rrep_proxied_flag_preserved vector), but
# they must never replace or upgrade existing cache/gradient knowledge.


def test_proxy_rrep_does_not_replace_existing_route() -> None:
    """A flagged reply claiming a fresher seq cannot displace known routes."""
    r = _router(ORIG)
    legit = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=1)
    r.process_rrep(legit, from_neighbor=M, now=0)
    forged = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=200, hop_count=1, flags=RREP_FLAG_PROXY),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    assert forged.delivered is True  # processing continues; only installs are gated
    route = r.cache.lookup(D, now=1)
    assert route.next_hop == M
    assert route.seq_num == 100
    grad = r.gradient.lookup(D, now=1)
    assert grad.next_hop == M
    assert grad.seq_num == 100


def test_proxy_rrep_does_not_upgrade_equal_seq_fewer_hops() -> None:
    r = _router(ORIG)
    longer = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=3)
    r.process_rrep(longer, from_neighbor=M, now=0)
    r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=100, hop_count=1, flags=RREP_FLAG_PROXY),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    route = r.cache.lookup(D, now=1)
    assert route.next_hop == M
    assert route.hop_count == 4
    grad = r.gradient.lookup(D, now=1)
    assert grad.next_hop == M
    assert grad.hop_count == 4


def test_unflagged_fresher_rrep_still_replaces_route() -> None:
    """Same input without the proxy flag keeps pre-existing semantics."""
    r = _router(ORIG)
    older = RREP(originator=D, destination=ORIG, seq_num=100, hop_count=1)
    r.process_rrep(older, from_neighbor=M, now=0)
    fresher = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=200, hop_count=1),
        from_neighbor=IPv6Address("fe80::a"),
        now=1,
    )
    assert fresher.delivered is True
    assert r.cache.lookup(D, now=1).seq_num == 200
    assert r.gradient.lookup(D, now=1).seq_num == 200


def test_proxy_rrep_bootstraps_unknown_destination_and_forwards() -> None:
    """A proxied hint may fill in a destination we know nothing about."""
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    result = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=9, hop_count=0, flags=RREP_FLAG_PROXY),
        from_neighbor=D,
        now=1,
    )
    assert result.dropped is False
    assert result.forward is not None
    assert result.forward.flags == RREP_FLAG_PROXY  # flag preserved on forward
    assert result.forward.hop_count == 1
    assert result.forward_next_hop == ORIG
    assert r.cache.lookup(D, now=1).next_hop == D
    assert r.gradient.lookup(D, now=1).next_hop == D


# Regression: non-installing (stale/replayed) RREPs are no longer forwarded
# (project-LICHEN-worker6-tiw8). Two gates protect the forwarding path: a
# replay window mirroring the RREQ suppression store, and the freshness
# verdict itself -- a reply carrying nothing newer than local state stops
# here instead of burning one TX per reverse-path node.


def test_stale_rrep_replay_not_forwarded() -> None:
    r = _router(M)
    rreq = RREQ(originator=ORIG, destination=D, seq_num=1)
    r.process_rreq(rreq, from_neighbor=ORIG, now=0)
    first = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=7, hop_count=0),
        from_neighbor=D,
        now=1,
    )
    assert first.forward is not None
    replay = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=7, hop_count=0),
        from_neighbor=IPv6Address("fe80::b"),
        now=2,
    )
    assert replay.dropped is True
    assert replay.forward is None


def test_distinct_stale_seq_rrep_not_forwarded() -> None:
    """An old-seq reply that fails the freshness gate is not forwarded."""
    r = _router(M)
    r.process_rreq(RREQ(originator=ORIG, destination=D, seq_num=1), from_neighbor=ORIG, now=0)
    fresh = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=99, hop_count=0),
        from_neighbor=D,
        now=1,
    )
    assert fresh.forward is not None
    stale = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=3, hop_count=0),
        from_neighbor=IPv6Address("fe80::b"),
        now=2,
    )
    assert stale.dropped is True
    assert stale.forward is None


def test_fresher_seq_within_window_still_forwarded() -> None:
    """The window never suppresses a strictly fresher sequence number."""
    r = _router(M)
    r.process_rreq(RREQ(originator=ORIG, destination=D, seq_num=1), from_neighbor=ORIG, now=0)
    first = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=7, hop_count=0),
        from_neighbor=D,
        now=1,
    )
    assert first.forward is not None
    second = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=8, hop_count=0),
        from_neighbor=D,
        now=2,
    )
    assert second.dropped is False
    assert second.forward is not None


def test_proxy_rrep_replay_suppressed_even_without_install_state() -> None:
    """Proxy replies never install over known destinations, yet replays of
    them are still suppressed by the window (not just by the freshness gate).
    """
    r = _router(M)
    # M knows D already via a gradient, so a proxy reply installs nothing.
    r.gradient.update(
        GradientEntry(D, IPv6Address("fe80::9"), 2, 500, GradientSource.ANNOUNCE, 100_000)
    )
    r.process_rreq(RREQ(originator=ORIG, destination=D, seq_num=1), from_neighbor=ORIG, now=0)
    hint = RREP(originator=D, destination=ORIG, seq_num=9, hop_count=0, flags=RREP_FLAG_PROXY)
    first = r.process_rrep(hint, from_neighbor=D, now=1)
    assert first.forward is not None  # hints still forward once
    replay = r.process_rrep(hint, from_neighbor=IPv6Address("fe80::b"), now=2)
    assert replay.dropped is True
    assert replay.forward is None
    after_window = r.process_rrep(
        hint, from_neighbor=IPv6Address("fe80::b"), now=1 + SUPPRESS_WINDOW_MS
    )
    assert after_window.forward is not None  # window expiry restores forwarding


def test_rrep_delivery_not_gated_by_forward_window() -> None:
    """Endpoint delivery is informational and unaffected by replay gating."""
    r = _router(ORIG)
    rrep = RREP(originator=D, destination=ORIG, seq_num=5, hop_count=1)
    assert r.process_rrep(rrep, from_neighbor=M, now=0).delivered is True
    assert r.process_rrep(rrep, from_neighbor=M, now=1).delivered is True


# The RREP replay store is pruned on the same cadence as the RREQ suppression
# store: every 16 replay checks (project-LICHEN-worker6-m7fl). Pruning keeps
# only in-window entries -- exactly the set that can still suppress a replay --
# so bounded memory never weakens replay protection.


def test_rrep_seen_pruned_periodically() -> None:
    """RREP-only traffic prunes the replay store on the 16-check cadence."""
    r = _router(M)
    r.process_rreq(RREQ(originator=ORIG, destination=D, seq_num=1), from_neighbor=ORIG, now=0)
    r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=1, hop_count=0),
        from_neighbor=D,
        now=1,
    )
    assert len(r._rrep_seen) == 1
    # 16 forwarded RREPs with no intervening RREQ activity: the countdown
    # fires and drops the entry that aged out of the suppression window.
    for i in range(16):
        orig = IPv6Address(f"fd00:a::{i:04x}")
        result = r.process_rrep(
            RREP(originator=orig, destination=ORIG, seq_num=1, hop_count=0),
            from_neighbor=IPv6Address("fe80::c"),
            now=20_000 + i,
        )
        assert result.forward is not None
    assert len(r._rrep_seen) == 16
    assert (D, ORIG) not in r._rrep_seen
    # The countdown reset after pruning: another 16 checks prune again,
    # dropping the previous batch instead of growing without bound.
    for i in range(16):
        orig = IPv6Address(f"fd00:b::{i:04x}")
        r.process_rrep(
            RREP(originator=orig, destination=ORIG, seq_num=1, hop_count=0),
            from_neighbor=IPv6Address("fe80::c"),
            now=40_000 + i,
        )
    assert len(r._rrep_seen) == 16


def test_rrep_replay_still_suppressed_after_prune() -> None:
    """Pruning retains in-window entries, so replay protection is unchanged."""
    r = _router(M)
    r.process_rreq(RREQ(originator=ORIG, destination=D, seq_num=1), from_neighbor=ORIG, now=0)
    first = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=7, hop_count=0),
        from_neighbor=D,
        now=1,
    )
    assert first.forward is not None
    # 16 distinct replay checks trigger the periodic prune; the fresh
    # (D, ORIG) entry is inside the window and must survive it.
    for i in range(16):
        orig = IPv6Address(f"fd00:c::{i:04x}")
        r.process_rrep(
            RREP(originator=orig, destination=ORIG, seq_num=1, hop_count=0),
            from_neighbor=IPv6Address("fe80::c"),
            now=2 + i,
        )
    assert (D, ORIG) in r._rrep_seen
    replay = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=7, hop_count=0),
        from_neighbor=IPv6Address("fe80::b"),
        now=20,
    )
    assert replay.dropped is True
    assert replay.forward is None


# Regression: directly-constructed RREPs bypassing RREP.from_bytes() are
# validated at process_rrep entry (project-LICHEN-worker6-4tbd); invalid
# fields map to RrepResult(dropped=True) instead of raising ValueError from
# RouteEntry/GradientEntry construction mid-function.


def test_rrep_seq_num_out_of_range_dropped_cleanly() -> None:
    r = _router(ORIG)
    result = r.process_rrep(
        RREP(originator=D, destination=ORIG, seq_num=0x1_0000, hop_count=1),
        from_neighbor=M,
        now=0,
    )  # must not raise
    assert result.dropped is True
    assert result.delivered is False
    assert result.forward is None
    assert r.cache.lookup(D, now=0) is None
    assert r.gradient.lookup(D, now=0) is None


def test_rrep_negative_fields_dropped_cleanly() -> None:
    for kwargs in (
        {"seq_num": -1},
        {"hop_count": -1},
    ):
        r = _router(ORIG)
        base = {"originator": D, "destination": ORIG, "hop_count": 1, "seq_num": 5}
        base.update(kwargs)
        result = r.process_rrep(RREP(**base), from_neighbor=M, now=0)  # must not raise
        assert result.dropped is True, kwargs
        assert r.cache.lookup(D, now=0) is None
        assert r.gradient.lookup(D, now=0) is None


def test_rrep_unknown_flag_bits_dropped_cleanly() -> None:
    for flags in (0x02, 0x81):
        r = _router(ORIG)
        result = r.process_rrep(
            RREP(originator=D, destination=ORIG, seq_num=5, hop_count=1, flags=flags),
            from_neighbor=M,
            now=0,
        )  # must not raise
        assert result.dropped is True, hex(flags)
        assert r.cache.lookup(D, now=0) is None
        assert r.gradient.lookup(D, now=0) is None
