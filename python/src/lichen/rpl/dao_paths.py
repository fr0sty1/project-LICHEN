# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO path computation helpers.

This module provides functions for building routes, assembling paths,
and detecting cycles in the DAO candidate graph.
"""
from __future__ import annotations

from ipaddress import IPv6Address

from lichen.rpl.dao_types import (
    MAX_CHAIN,
    MAX_ROUTE_HOPS_ALIAS,
    Candidate,
    DaoError,
)


def contains_cycle(parents: dict[IPv6Address, tuple[IPv6Address, ...]]) -> bool:
    """Detect cycles in the candidate parent graph."""
    visiting: set[IPv6Address] = set()
    visited: set[IPv6Address] = set()

    def visit(node: IPv6Address) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(parent in parents and visit(parent) for parent in parents.get(node, ())):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(target) for target in parents)


def path_control_rank(control: int, pcs: int) -> int | None:
    """Compute the path control rank for candidate selection.

    Args:
        control: Path control byte from Transit Information.
        pcs: Path Control Size (0-7).

    Returns:
        Rank (0-3) if an active bit is set, None otherwise.
    """
    active_mask = (0xFF << (7 - pcs)) & 0xFF
    masked = control & active_mask
    for rank, shift in enumerate((6, 4, 2, 0)):
        if masked & (0x03 << shift):
            return rank
    return None


def select_path(
    target: IPv6Address,
    node_address: IPv6Address,
    parents: dict[IPv6Address, tuple[IPv6Address, ...]],
    candidates: dict[IPv6Address, tuple[Candidate, ...]],
    pcs: int,
    visiting: set[IPv6Address],
) -> tuple[list[IPv6Address], Candidate, int] | None:
    """Select the best path to a target based on path control ranking.

    Args:
        target: The destination address.
        node_address: The root node address.
        parents: Map of target to active parent addresses.
        candidates: Map of target to candidate tuples.
        pcs: Path Control Size.
        visiting: Set of nodes currently being visited (cycle detection).

    Returns:
        Tuple of (path, candidate, rank) or None if no path found.
    """
    if target == node_address:
        return None
    if target in visiting or len(visiting) >= MAX_CHAIN:
        return None
    visiting = visiting | {target}
    choices: list[tuple[int, tuple[int, ...], list[IPv6Address], Candidate]] = []
    active_parents = set(parents.get(target, ()))
    for candidate in candidates.get(target, ()):
        if candidate.parent not in active_parents:
            continue
        rank = path_control_rank(candidate.path_control, pcs)
        if rank is None:
            continue
        if candidate.parent == node_address:
            parent_path: list[IPv6Address] = []
        else:
            parent_selected = select_path(
                candidate.parent, node_address, parents, candidates, pcs, visiting
            )
            if parent_selected is None:
                continue
            parent_path = parent_selected[0]
        path = [*parent_path, target]
        if len(path) > MAX_ROUTE_HOPS_ALIAS:
            raise DaoError("route exceeds maximum hop count", reason="route_too_long")
        choices.append((rank, tuple(int(hop) for hop in path), path, candidate))
    if not choices:
        return None
    rank, _, path, candidate = min(choices)
    return path, candidate, rank


def assemble_path(
    target: IPv6Address,
    node_address: IPv6Address,
    parents: dict[IPv6Address, tuple[IPv6Address, ...]],
    candidates: dict[IPv6Address, tuple[Candidate, ...]],
    pcs: int,
    visiting: set[IPv6Address],
) -> list[IPv6Address] | None:
    """Assemble a complete path to a target.

    Args:
        target: The destination address.
        node_address: The root node address.
        parents: Map of target to active parent addresses.
        candidates: Map of target to candidate tuples.
        pcs: Path Control Size.
        visiting: Set of nodes currently being visited.

    Returns:
        List of addresses forming the path, or None if no path.
    """
    selected = select_path(target, node_address, parents, candidates, pcs, visiting)
    return None if selected is None else selected[0]


def build_routes(
    node_address: IPv6Address,
    parents: dict[IPv6Address, tuple[IPv6Address, ...]],
    candidates: dict[IPv6Address, tuple[Candidate, ...]],
    pcs: int,
) -> dict[IPv6Address, list[IPv6Address]]:
    """Build complete routes for all targets with active parents.

    Args:
        node_address: The root node address.
        parents: Map of target to active parent addresses.
        candidates: Map of target to candidate tuples.
        pcs: Path Control Size.

    Returns:
        Map of target to complete path.
    """
    routes: dict[IPv6Address, list[IPv6Address]] = {}
    for target in sorted(parents):
        path = assemble_path(target, node_address, parents, candidates, pcs, set())
        if path:
            routes[target] = path
    return routes
