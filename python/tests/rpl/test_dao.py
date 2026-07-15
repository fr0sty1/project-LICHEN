# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
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


def test_multi_target_dao_rejected() -> None:
    """Multi-target DAOs are rejected rather than silently dropping targets."""
    from lichen.rpl.messages import DAO

    # Build a DAO with two RPL Target options (RFC 6550 allows this but we don't).
    dao = DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        dodag_id=ROOT,
        ack_requested=False,
        options=[
            RplTarget(N1).to_option(),
            RplTarget(N2).to_option(),
            TransitInformation(ROOT).to_option(),
        ],
    )
    with pytest.raises(DaoError, match="multi-target"):
        DaoManager._extract_edge(dao)


def test_dao_with_root_as_target_is_ignored() -> None:
    """A DAO with the root's own address as target yields empty path and is skipped.

    Previously, _assemble_path() would return [] (empty list) instead of None,
    and the check 'if path is not None' passed, then add_route() raised RoutingError.
    This crashed the rebuild loop partway through, corrupting the routing table.
    """
    root = DaoManager(node_address=ROOT, is_root=True)
    # First install a valid route.
    root.process_dao(DaoManager(node_address=N1).build_dao(ROOT))
    assert root.routing_table.lookup(N1) == [N1]

    # Now send a malicious DAO with target=root (attacker scenario).
    malicious_dao = DaoManager(node_address=ROOT).build_dao(N1)
    # Should not raise; the empty path is silently skipped.
    root.process_dao(malicious_dao)

    # The existing route must still be intact.
    assert root.routing_table.lookup(N1) == [N1]
    # No route to root itself (empty path was skipped).
    assert root.routing_table.lookup(ROOT) is None


def test_process_dao_rejects_wrong_rpl_instance_id() -> None:
    """DAOs for a different RPL instance must be rejected (RFC 6550 9.5).

    A malicious or misconfigured node could send a DAO for a different RPL
    instance, and without this check the root would accept it and corrupt
    its routing table with edges from a different routing domain.
    """
    root = DaoManager(node_address=ROOT, is_root=True, rpl_instance_id=0)
    # Build a DAO with a different RPL instance ID.
    sender = DaoManager(node_address=N1, rpl_instance_id=42)
    dao = sender.build_dao(ROOT)
    assert dao.rpl_instance_id == 42  # confirm setup

    with pytest.raises(DaoError, match="instance ID 42 != 0"):
        root.process_dao(dao)

    # Routing table must remain empty.
    assert root.routing_table.lookup(N1) is None


def test_process_dao_accepts_matching_rpl_instance_id() -> None:
    """DAOs with matching RPL instance ID are accepted normally."""
    root = DaoManager(node_address=ROOT, is_root=True, rpl_instance_id=5)
    sender = DaoManager(node_address=N1, rpl_instance_id=5)
    dao = sender.build_dao(ROOT)

    # Should succeed without error.
    root.process_dao(dao)
    assert root.routing_table.lookup(N1) == [N1]


def test_transit_information_e_flag_parsing() -> None:
    """RFC 6550 6.7.8: Parent Address is only present when E flag is set.

    The parser must check the E flag and only require/parse parent address
    when E=1. Options with E=0 (no parent address) must parse successfully.
    """
    from lichen.rpl.messages import RplOption

    # E=1 (0x80): parent address present (standard LICHEN case)
    e1_data = bytes([0x80, 0, 1, 30]) + ROOT.packed  # E=1, path_seq=1, lifetime=30
    opt_e1 = RplOption(RplOptionType.TRANSIT_INFORMATION, e1_data)
    ti_e1 = TransitInformation.from_option(opt_e1)
    assert ti_e1.parent_address == ROOT
    assert ti_e1.path_sequence == 1
    assert ti_e1.path_lifetime == 30

    # E=0: no parent address (RFC-compliant option from other implementations)
    e0_data = bytes([0x00, 0, 2, 60])  # E=0, path_seq=2, lifetime=60
    opt_e0 = RplOption(RplOptionType.TRANSIT_INFORMATION, e0_data)
    ti_e0 = TransitInformation.from_option(opt_e0)
    assert ti_e0.parent_address is None
    assert ti_e0.path_sequence == 2
    assert ti_e0.path_lifetime == 60


def test_transit_information_e_flag_encoding() -> None:
    """Verify E flag is correctly encoded when serializing Transit Information."""
    # With parent address: E flag should be set (0x80)
    ti_with_parent = TransitInformation(parent_address=ROOT, path_lifetime=30)
    opt = ti_with_parent.to_option()
    assert opt.data[0] & 0x80 == 0x80  # E flag is set
    assert len(opt.data) == 4 + 16  # includes parent address

    # Without parent address: E flag should be clear
    ti_no_parent = TransitInformation(parent_address=None, path_lifetime=30)
    opt_no_parent = ti_no_parent.to_option()
    assert opt_no_parent.data[0] & 0x80 == 0x00  # E flag is clear
    assert len(opt_no_parent.data) == 4  # no parent address
