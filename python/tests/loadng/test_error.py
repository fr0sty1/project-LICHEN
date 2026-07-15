# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LOADng route error handling (spec 10.6)."""

from __future__ import annotations

from ipaddress import IPv6Address

from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.loadng.cache import RouteCache, RouteEntry
from lichen.loadng.error import RouteErrorManager
from lichen.loadng.messages import RERR

DEST = IPv6Address("fd00::100")
NEXT = IPv6Address("fe80::a")
OTHER = IPv6Address("fe80::b")
SRC1 = IPv6Address("fd00::1")
SRC2 = IPv6Address("fd00::2")


def _populated() -> tuple[RouteErrorManager, GradientTable, RouteCache]:
    grad = GradientTable()
    cache = RouteCache()
    grad.update(GradientEntry(DEST, NEXT, 3, 1, GradientSource.RREP, 10_000))
    cache.add(RouteEntry(DEST, NEXT, 3, 3, 1, 10_000))
    return RouteErrorManager(grad, cache), grad, cache


def test_link_failure_invalidates_and_notifies_precursors() -> None:
    mgr, grad, cache = _populated()
    mgr.record_flow(DEST, SRC1)
    mgr.record_flow(DEST, SRC2)

    actions = mgr.on_link_failure(NEXT)
    assert len(actions) == 1
    action = actions[0]
    assert action.rerr.unreachable == DEST
    assert action.invalidated == [DEST]
    assert action.notify == sorted([SRC1, SRC2], key=str)
    # Route gone from both tables.
    assert grad.lookup(DEST) is None
    assert DEST not in cache


def test_link_failure_without_precursors() -> None:
    mgr, _, _ = _populated()
    actions = mgr.on_link_failure(NEXT)
    assert len(actions) == 1
    assert actions[0].notify == []
    assert actions[0].invalidated == [DEST]


def test_link_failure_unrelated_next_hop_noop() -> None:
    mgr, grad, cache = _populated()
    actions = mgr.on_link_failure(OTHER)
    assert actions == []
    assert grad.lookup(DEST) is not None  # untouched
    assert DEST in cache


def test_process_rerr_invalidates_and_propagates() -> None:
    mgr, grad, cache = _populated()
    mgr.record_flow(DEST, SRC1)
    rerr = RERR(unreachable=DEST, error_code=2)
    action = mgr.process_rerr(rerr, from_neighbor=NEXT, now=5000)
    assert action is not None
    assert action.invalidated == [DEST]
    assert action.notify == [SRC1]
    assert action.rerr.error_code == 2
    assert grad.lookup(DEST) is None
    assert DEST not in cache


def test_process_rerr_ignored_if_route_via_other_neighbor() -> None:
    mgr, grad, cache = _populated()
    rerr = RERR(unreachable=DEST)
    # The route to DEST is via NEXT, not OTHER; an RERR from OTHER is irrelevant.
    assert mgr.process_rerr(rerr, from_neighbor=OTHER, now=5000) is None
    assert grad.lookup(DEST) is not None
    assert DEST in cache


def test_process_rerr_ignored_if_no_route() -> None:
    mgr = RouteErrorManager(GradientTable(), RouteCache())
    assert mgr.process_rerr(RERR(unreachable=DEST), from_neighbor=NEXT, now=5000) is None


def test_remove_via_only_removes_matching_next_hop() -> None:
    grad = GradientTable()
    grad.update(GradientEntry(DEST, NEXT, 1, 1, GradientSource.RREP, 10_000))
    keep = IPv6Address("fd00::200")
    grad.update(GradientEntry(keep, OTHER, 1, 1, GradientSource.RREP, 10_000))
    removed = grad.remove_via(NEXT)
    assert removed == [DEST]
    assert grad.lookup(keep) is not None
