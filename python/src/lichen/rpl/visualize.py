# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from typing import Optional

"""DODAG visualization for the simulation harness (spec section 8).

Renders the routing tree formed by RPL into serializable representations that a
headless simulation can emit and a human (or Graphviz) can inspect: a Graphviz
DOT graph and an indented ASCII tree. The input is a topology — a mapping of
node id to its preferred parent (``None`` for a root) — which can be extracted
from a set of :class:`~lichen.rpl.dodag.DodagState` objects.

These are pure functions over a snapshot; the caller decides when to snapshot
the evolving DODAG during a run.
"""

from collections.abc import Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lichen.rpl.dodag import DodagState


Topology = dict[str, Optional[str]]  # noqa: UP045


def topology_from_states(states: Mapping[str, DodagState]) -> Topology:
    """Extract a node -> preferred-parent topology from DODAG states.

    The mapping keys must be IPv6Address strings (e.g., ``"fe80::1"``) that match
    what ``DodagState.preferred_parent`` contains, so that parent values can be
    looked up as keys in the resulting topology. Using arbitrary names will break
    the parent lookup in ``to_ascii()`` and ``to_dot()``.
    """
    return {
        node_id: str(state.preferred_parent) if state.preferred_parent else None
        for node_id, state in states.items()
    }


def ranks_from_states(states: Mapping[str, DodagState]) -> dict[str, int]:
    """Extract a node -> rank mapping from DODAG states."""
    return {node_id: state.rank for node_id, state in states.items()}


def _children_of(parents: Topology) -> dict[str | None, list[str]]:
    children: dict[str | None, list[str]] = {}
    for node, parent in parents.items():
        children.setdefault(parent, []).append(node)
    return children


def _roots(parents: Topology) -> list[str]:
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
    ranks: Mapping[str, int] | None = None,
    name: str = "DODAG",
) -> str:
    """Render the topology as Graphviz DOT (child -> parent edges, root on top)."""
    def _escape_dot(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"')
    lines = [f"digraph {name} {{", "  rankdir=BT;"]
    for node in sorted(parents):
        label = _dot_escape(node)
        if ranks is not None and node in ranks:
            label = f"{label}\\nrank={ranks[node]}"
        attrs = f'label="{label}"'
        if parents[node] is None:
            attrs += ", shape=doublecircle"
        lines.append(f'  "{_dot_escape(node)}" [{attrs}];')
    for node in sorted(parents):
        parent = parents[node]
        if parent is not None:
            lines.append(f'  "{_dot_escape(node)}" -> "{_dot_escape(parent)}";')
    lines.append("}")
    return "\n".join(lines)


def to_ascii(parents: Topology) -> str:
    """Render the topology as an indented ASCII tree (roots first)."""
    children = _children_of(parents)
    visited: set[str] = set()
    lines: list[str] = []

    def render(node: str, depth: int) -> None:
        if node in visited:
            lines.append("  " * depth + f"{node} (cycle)")
            return
        visited.add(node)
        lines.append("  " * depth + node)
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
    return " -> ".join([root, *path])
