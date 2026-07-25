# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from collections.abc import Mapping
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from lichen.rpl.dodag import DodagState


"""DODAG visualization for the simulation harness (spec section 8).

Renders the routing tree formed by RPL into serializable representations that a
headless simulation can emit and a human (or Graphviz) inspect: a Graphviz
DOT graph and an indented ASCII tree. The input is a topology — a mapping of
node id to its preferred parent (``None`` for a root) — which can be extracted
from a set of :class:`~lichen.rpl.dodag.DodagState` objects.

These are pure functions over a snapshot; the caller decides when to snapshot
the evolving DODAG during a run.
"""

Topology = dict[IPv6Address, Optional[IPv6Address]]


def topology_from_states(states: Mapping[IPv6Address, DodagState]) -> Topology:
    """Extract a node -> preferred-parent topology from DODAG states.

    Both keys and parent values are :class:`IPv6Address` objects from
    ``states``, so parent values can be looked up as keys in the resulting
    topology.
    """
    return {
        node_id: state.preferred_parent
        for node_id, state in states.items()
    }


def ranks_from_states(states: Mapping[IPv6Address, DodagState]) -> dict[IPv6Address, int]:
    """Extract a node -> rank mapping from DODAG states."""
    return {node_id: state.rank for node_id, state in states.items()}


def _children_of(parents: Topology) -> dict[Optional[IPv6Address], list[IPv6Address]]:
    children: dict[Optional[IPv6Address], list[IPv6Address]] = {}
    for node, parent in parents.items():
        children.setdefault(parent, []).append(node)
    return children


def _roots(parents: Topology) -> list[IPv6Address]:
    """Nodes with no parent, or whose parent is outside the topology."""
    return sorted(
        node for node, parent in parents.items() if parent is None or parent not in parents
    )


def _dot_escape(s: str) -> str:
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    return s


def to_dot(
    parents: Topology,
    ranks: Mapping[IPv6Address, int] | None = None,
    name: str = "DODAG",
) -> str:
    """Render the topology as Graphviz DOT (child -> parent edges, root on top)."""
    lines = [f"digraph {name} {{", "  rankdir=BT;"]
    for node in sorted(parents):
        label = _dot_escape(str(node))
        if ranks is not None and node in ranks:
            label = f"{label}\\nrank={ranks[node]}"
        attrs = f'label="{label}"'
        if parents[node] is None:
            attrs += ", shape=doublecircle"
        lines.append(f'  "{_dot_escape(str(node))}" [{attrs}];')
    for node in sorted(parents):
        parent = parents[node]
        if parent is not None:
            lines.append(f'  "{_dot_escape(str(node))}" -> "{_dot_escape(str(parent))}";')
    lines.append("}")
    return "\n".join(lines)


def to_ascii(parents: Topology) -> str:
    """Render the topology as an indented ASCII tree (roots first)."""
    children = _children_of(parents)
    visited: set[IPv6Address] = set()
    lines: list[str] = []

    def render(node: IPv6Address, depth: int) -> None:
        if node in visited:
            lines.append("  " * depth + f"{node} (cycle)")
            return
        visited.add(node)
        lines.append("  " * depth + str(node))
        for child in sorted(children.get(node, [])):
            render(child, depth + 1)

    for root in _roots(parents):
        render(root, 0)
    # Any nodes not reachable from a root (e.g. caught in a cycle).
    for node in sorted(parents):
        if node not in visited:
            render(node, 0)
    return "\n".join(lines)


def format_source_route(path: list[str], root: str = "root") -> str:
    """Render a downward source-route path as ``root -> h1 -> ... -> dest``."""
    return " -> ".join([root] + path)
