# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for DODAG visualization (hrv)."""

from __future__ import annotations

from ipaddress import IPv6Address

from lichen.rpl.dodag import DodagState
from lichen.rpl.visualize import (
    format_source_route,
    ranks_from_states,
    to_ascii,
    to_dot,
    topology_from_states,
)

# Topology: root <- a <- b, root <- c.
ROOT = IPv6Address("fe80::1")
A = IPv6Address("fe80::2")
B = IPv6Address("fe80::3")
C = IPv6Address("fe80::4")
TOPO: dict[IPv6Address, IPv6Address | None] = {ROOT: None, A: ROOT, B: A, C: ROOT}


def test_to_dot_structure() -> None:
    dot = to_dot(TOPO)
    assert dot.startswith("digraph DODAG {")
    assert dot.rstrip().endswith("}")
    assert f'"{A}" -> "{ROOT}";' in dot
    assert f'"{B}" -> "{A}";' in dot
    assert f'"{C}" -> "{ROOT}";' in dot
    # Root is drawn distinctly and has no outgoing edge.
    assert "shape=doublecircle" in dot
    assert f'"{ROOT}" -> ' not in dot


def test_to_dot_with_ranks() -> None:
    dot = to_dot(TOPO, ranks={A: 512})
    assert "rank=512" in dot


def test_to_ascii_tree() -> None:
    ascii_tree = to_ascii(TOPO)
    lines = ascii_tree.splitlines()
    assert lines[0] == str(ROOT)
    # A and C are children of root (indented one level); B is under A.
    assert f"  {A}" in lines
    assert f"  {C}" in lines
    assert f"    {B}" in lines


def test_to_ascii_handles_cycle_without_infinite_loop() -> None:
    # x <-> y cycle with no root; rendering must terminate and flag it.
    x = IPv6Address("fe80::a")
    y = IPv6Address("fe80::b")
    cyclic = {x: y, y: x}
    out = to_ascii(cyclic)
    assert "(cycle)" in out


def test_topology_and_ranks_from_states() -> None:
    # Keys are IPv6Address objects matching preferred_parent values,
    # so parent lookups work correctly in to_ascii() and to_dot().
    root_addr = IPv6Address("fe80::1")
    child_addr = IPv6Address("fe80::2")
    root = DodagState.as_root(0, "fd00::1", 1)
    child = DodagState(rpl_instance_id=0, dodag_id="fd00::1", version=1)
    child.process_dio(_dio(), root_addr, link_etx=1.0)
    states: dict[IPv6Address, DodagState] = {root_addr: root, child_addr: child}
    topo = topology_from_states(states)
    assert topo[root_addr] is None
    assert topo[child_addr] == root_addr
    # Verify parent lookup works (child's parent is in the topology keys)
    assert topo[child_addr] in topo
    ranks = ranks_from_states(states)
    assert ranks[root_addr] == root.rank
    assert ranks[child_addr] == child.rank


def test_format_source_route() -> None:
    assert format_source_route(["a", "b", "dest"]) == "root -> a -> b -> dest"
    assert format_source_route(["dest"], root="R") == "R -> dest"


def _dio():
    from lichen.rpl.messages import DIO

    return DIO(rpl_instance_id=0, version=1, rank=256, dtsn=0, dodag_id="fd00::1")
