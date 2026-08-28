# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Route table abstraction for DAO manager route operations.

This module provides a RouteTable class that wraps the core RoutingTable
and adds higher-level operations used by DAO processing: route merging,
snapshots, and host route extraction.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from ipaddress import IPv6Address

from lichen.rpl.routing import RouteEntry, RouteTarget, RoutingTable


@dataclass
class RouteTable:
    """Extended routing table with DAO manager route utilities.

    Wraps the core RoutingTable and adds methods for route merging,
    snapshots, and host route extraction used by DAO processing.

    This class provides:
    - Delegation to RoutingTable for basic operations (add/remove/lookup)
    - Host route extraction for DAO route building
    - Prefix route merging for combined route tables
    - Snapshot generation for route state inspection
    """

    _routing_table: RoutingTable = field(default_factory=RoutingTable)

    def add_route(
        self, target: IPv6Address | str, path: Sequence[IPv6Address | str]
    ) -> None:
        """Add a host route to the routing table."""
        self._routing_table.add_route(target, path)

    def add_prefix_route(
        self,
        target: RouteTarget,
        egress: IPv6Address | str,
        path: Sequence[IPv6Address | str],
    ) -> None:
        """Add a prefix route to the routing table."""
        self._routing_table.add_prefix_route(target, egress, path)

    def remove_route(self, target: IPv6Address | str) -> None:
        """Remove a host route from the routing table."""
        self._routing_table.remove_route(target)

    def remove_prefix_route(self, target: RouteTarget) -> None:
        """Remove a prefix route from the routing table."""
        self._routing_table.remove_prefix_route(target)

    def get_route(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        """Look up a route by target address using longest-prefix match."""
        return self._routing_table.lookup(target)

    def lookup(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        """Alias for get_route for compatibility with RoutingTable."""
        return self._routing_table.lookup(target)

    def routes(self) -> dict[RouteTarget, list[IPv6Address]]:
        """Return all routes in the table."""
        return self._routing_table.routes()

    def replace_routes(self, routes: dict[RouteTarget, list[IPv6Address]]) -> None:
        """Replace all routes with the provided routes."""
        self._routing_table.replace_routes(routes)

    def clear(self) -> None:
        """Clear all routes from the table."""
        self._routing_table.clear()

    def entry_state(self, target: IPv6Address | str) -> str | None:
        """Return the state of a route entry (fresh/stale/expired)."""
        return self._routing_table.entry_state(target)

    def build_source_route(self, target: IPv6Address | str) -> list[IPv6Address] | None:
        """Build a source route to the target address."""
        return self._routing_table.build_source_route(target)

    def host_routes(self) -> dict[RouteTarget, list[IPv6Address]]:
        """Return only /128 host routes from the table.

        This is equivalent to routes() when no prefix routes are present.
        """
        return self._routing_table.routes()

    def merge_prefix_routes(
        self, host_routes: dict[RouteTarget, list[IPv6Address]]
    ) -> dict[RouteTarget, list[IPv6Address]]:
        """Merge host routes with existing prefix routes.

        Host routes from the input are combined with existing prefix routes
        (prefix_len < 128) from the routing table. This allows DAO-derived
        host routes to coexist with manually configured prefix routes.

        Args:
            host_routes: Dict of /128 host routes to merge.

        Returns:
            Combined dict with input host routes and existing prefix routes.
        """
        merged = dict(host_routes)
        for rt, entry in self._routing_table._routes.items():
            if rt.prefix_len < 128 and entry.is_usable():
                merged[rt] = list(entry.path)
        return merged

    def snapshot(self) -> dict[str, list[str]]:
        """Return exact installed complete paths keyed by target hex.

        This provides a serializable view of the routing table suitable
        for debugging, logging, or external inspection.

        Returns:
            Dict mapping target address hex to list of hop address hex strings.
        """
        return {
            rt.prefix.packed.hex(): [hop.packed.hex() for hop in path]
            for rt, path in sorted(self._routing_table.routes().items())
        }

    @property
    def internal_routes(self) -> dict[RouteTarget, RouteEntry]:
        """Direct access to internal route entries.

        This exposes the underlying _routes dict for operations that need
        to inspect RouteEntry state directly (e.g., prefix route filtering).
        Prefer using the higher-level methods when possible.
        """
        return self._routing_table._routes

    def __len__(self) -> int:
        """Return the number of routes in the table."""
        return len(self._routing_table)

    def __contains__(self, target: IPv6Address | str) -> bool:
        """Check if a host route exists for the target."""
        return target in self._routing_table
