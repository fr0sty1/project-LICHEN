# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LOADng route error handling (RERR) (spec section 10.6, 9.7).

When a link to a next hop fails, every route through it is invalidated and a
RERR naming each now-unreachable destination is sent toward the upstream nodes
that were using the route (its precursors). A received RERR invalidates the
matching local route and propagates further upstream.

Like the discovery handler this is a deterministic, action-returning class: it
mutates the route cache / gradient table and returns the RERRs to transmit; the
caller owns the radio and clock. Precursors must be recorded via
:meth:`record_flow` as data is forwarded so failures can be attributed. Call
:meth:`clear_precursors` after successful transmission of returned
RerrActions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv6Address

from lichen.gradient import GradientTable
from lichen.ipv6 import to_ipv6
from lichen.loadng.cache import RouteCache
from lichen.loadng.messages import RERR


@dataclass
class RerrAction:
    """A RERR to transmit and the precursors to send it to."""

    rerr: RERR
    notify: list[IPv6Address] = field(default_factory=list)
    invalidated: list[IPv6Address] = field(default_factory=list)


class RouteErrorManager:
    """Tracks route precursors and handles link failures / RERRs for one node.

    Call :meth:`clear_precursors` after successfully transmitting an RerrAction
    (or deciding not to retry) to avoid losing precursor data on transmission
    failure.
    """

    def __init__(self, gradient: GradientTable, cache: RouteCache) -> None:
        self.gradient = gradient
        self.cache = cache
        self._precursors: dict[IPv6Address, set[IPv6Address]] = {}

    def record_flow(self, destination: IPv6Address | str, upstream: IPv6Address | str) -> None:
        """Note that ``upstream`` forwards traffic to ``destination`` through us."""
        self._precursors.setdefault(to_ipv6(destination), set()).add(to_ipv6(upstream))

    def clear_precursors(self, dest: IPv6Address | str) -> None:
        """Clear precursor tracking for ``dest`` after successful RERR transmission."""
        self._precursors.pop(to_ipv6(dest), None)

    def on_link_failure(self, next_hop: IPv6Address | str) -> list[RerrAction]:
        """Invalidate routes through a failed ``next_hop`` and build RERRs."""
        nh = to_ipv6(next_hop)
        dests = set(self.cache.remove_via(nh)) | set(self.gradient.remove_via(nh))
        precursor_groups = {}
        for dest in dests:
            pset = self._precursors.pop(dest, set())
            key = frozenset(pset)
            precursor_groups.setdefault(key, []).append(dest)
        actions = []
        for key, g_dests in precursor_groups.items():
            g_dests = sorted(g_dests, key=str)
            primary = g_dests[0]
            action = self._build_action(primary, precursors=set(key), invalidated=g_dests)
            actions.append(action)
        return sorted(actions, key=lambda a: str(a.rerr.unreachable))

    def process_rerr(
        self, rerr: RERR, from_neighbor: IPv6Address | str, now: int
    ) -> RerrAction | None:
        dest = to_ipv6(rerr.unreachable)
        from_neighbor = to_ipv6(from_neighbor)

        grad = self.gradient.lookup(dest, now)
        route = self.cache.lookup(dest, now)
        affected = (grad is not None and grad.next_hop == from_neighbor) or (
            route is not None and route.next_hop == from_neighbor
        )
        if not affected:
            return None

        if grad is not None and grad.next_hop == from_neighbor:
            self.gradient.remove(dest)
        if route is not None and route.next_hop == from_neighbor:
            self.cache.remove(dest)

        return self._build_action(dest, error_code=rerr.error_code)

    def _build_action(
        self,
        dest: IPv6Address,
        error_code: int = 0,
        precursors: set[IPv6Address] | None = None,
        invalidated: list[IPv6Address] | None = None,
    ) -> RerrAction:
        if precursors is None:
            precursors = self._precursors.get(dest, set()).copy()
        return RerrAction(
            rerr=RERR(unreachable=dest, error_code=error_code),
            notify=sorted(precursors, key=str),
            invalidated=invalidated or [dest],
        )
