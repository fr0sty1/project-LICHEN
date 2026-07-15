# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LOADng route discovery (spec 10.3-10.5)."""

from __future__ import annotations

from ipaddress import IPv6Address

from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.loadng.cache import RouteCache
from lichen.loadng.discovery import LoadngRouter
from lichen.loadng.messages import RREP, RREQ

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
    r.gradient.update(
        GradientEntry(D, IPv6Address("fe80::9"), 2, 1, GradientSource.RREP, 10_000)
    )
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
