"""Tests for RPL DAO handling and route advertisement (non-storing mode)."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.rpl.dao import (
    DaoError,
    DaoManager,
    RplTarget,
    TransitInformation,
)
from lichen.rpl.messages import RplOptionType

ROOT = IPv6Address("fd00::1")
N1 = IPv6Address("fd00::11")
N2 = IPv6Address("fd00::12")
N3 = IPv6Address("fd00::13")
N4 = IPv6Address("fd00::14")


def test_rpl_target_round_trip() -> None:
    opt = RplTarget(N1).to_option()
    assert opt.type == RplOptionType.RPL_TARGET
    parsed = RplTarget.from_option(opt)
    assert parsed.target == N1
    assert parsed.prefix_length == 128


def test_transit_information_round_trip() -> None:
    opt = TransitInformation(ROOT, path_lifetime=30, path_sequence=2).to_option()
    assert opt.type == RplOptionType.TRANSIT_INFORMATION
    parsed = TransitInformation.from_option(opt)
    assert parsed.parent_address == ROOT
    assert parsed.path_lifetime == 30
    assert parsed.path_sequence == 2


def test_build_dao_carries_target_and_transit() -> None:
    mgr = DaoManager(node_address=N2, dodag_id=ROOT)
    dao = mgr.build_dao(N1, ack_requested=True)
    assert dao.ack_requested is True
    assert dao.dodag_id == ROOT
    assert dao.dao_sequence == 1
    target, parent = DaoManager._extract_edge(dao)
    assert target == N2
    assert parent == N1


def test_dao_sequence_increments() -> None:
    mgr = DaoManager(node_address=N2)
    assert mgr.build_dao(N1).dao_sequence == 1
    assert mgr.build_dao(N1).dao_sequence == 2


def test_process_dao_requires_root() -> None:
    mgr = DaoManager(node_address=N2, is_root=False)
    with pytest.raises(DaoError):
        mgr.process_dao(DaoManager(node_address=N2).build_dao(N1))


def test_dao_ack_returned_when_requested() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    dao = DaoManager(node_address=N1, dodag_id=ROOT).build_dao(ROOT, ack_requested=True)
    ack = root.process_dao(dao)
    assert ack is not None
    assert ack.dao_sequence == dao.dao_sequence
    # No ack when not requested.
    dao2 = DaoManager(node_address=N2, dodag_id=ROOT).build_dao(N1)
    assert root.process_dao(dao2) is None


def test_root_installs_route_for_direct_child() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    dao = DaoManager(node_address=N1).build_dao(ROOT)
    root.process_dao(dao)
    assert root.routing_table.lookup(N1) == [N1]


def test_incomplete_chain_yields_no_route_until_filled() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    # N2's DAO arrives before N1's; N1's parent is unknown -> no route yet.
    root.process_dao(DaoManager(node_address=N2).build_dao(N1))
    assert root.routing_table.lookup(N2) is None
    # Once N1 -> ROOT is known, both routes resolve.
    root.process_dao(DaoManager(node_address=N1).build_dao(ROOT))
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) == [N1, N2]


def test_five_node_line_topology() -> None:
    """Issue acceptance test: root learns routes to all nodes in a line."""
    root = DaoManager(node_address=ROOT, is_root=True)
    edges = [(N1, ROOT), (N2, N1), (N3, N2), (N4, N3)]
    for node, parent in edges:
        root.process_dao(DaoManager(node_address=node).build_dao(parent))

    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) == [N1, N2]
    assert root.routing_table.lookup(N3) == [N1, N2, N3]
    assert root.routing_table.lookup(N4) == [N1, N2, N3, N4]


def test_parent_change_updates_route() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(DaoManager(node_address=N1).build_dao(ROOT))
    root.process_dao(DaoManager(node_address=N2).build_dao(ROOT))
    root.process_dao(DaoManager(node_address=N3).build_dao(N1))
    assert root.routing_table.lookup(N3) == [N1, N3]
    # N3 reparents to N2.
    root.process_dao(DaoManager(node_address=N3).build_dao(N2))
    assert root.routing_table.lookup(N3) == [N2, N3]


def test_loop_in_chain_yields_no_route() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    # N1 -> N2 and N2 -> N1 with neither reaching root: a cycle.
    root.process_dao(DaoManager(node_address=N1).build_dao(N2))
    root.process_dao(DaoManager(node_address=N2).build_dao(N1))
    assert root.routing_table.lookup(N1) is None
    assert root.routing_table.lookup(N2) is None
