# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for complete, grouped RPL DAO candidate snapshots."""

from __future__ import annotations

from copy import copy
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.rpl.dao import (
    DaoError,
    DaoManager,
    RplTarget,
    TransitInformation,
    run_route_state_vectors,
)
from lichen.rpl.messages import DAO, RplOption, RplOptionType

ROOT = IPv6Address("fd00::1")
N1 = IPv6Address("fd00::11")
N2 = IPv6Address("fd00::12")
N3 = IPv6Address("fd00::13")
N4 = IPv6Address("fd00::14")


def make_dao(
    target: IPv6Address,
    parent: IPv6Address,
    *,
    sequence: int = 1,
    lifetime: int = 255,
    control: int = 0x80,
    dao_sequence: int = 1,
) -> DAO:
    return DAO(
        rpl_instance_id=0,
        dao_sequence=dao_sequence,
        options=[
            RplTarget(target).to_option(),
            TransitInformation(
                parent,
                path_sequence=sequence,
                path_lifetime=lifetime,
                path_control=control,
            ).to_option(),
        ],
    )


def grouped_dao(targets: list[IPv6Address], transits: list[TransitInformation]) -> DAO:
    return DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        options=[
            *(RplTarget(target).to_option() for target in targets),
            *(transit.to_option() for transit in transits),
        ],
    )


def test_option_codecs_are_exact_and_canonicalize_unused_prefix_bits() -> None:
    target = RplTarget.from_option(RplOption(RplOptionType.RPL_TARGET, b"\0\x7f" + N1.packed))
    assert target.target == IPv6Address("fd00::10")
    assert target.prefix_length == 127

    transit = TransitInformation(N1, 30, 2, 0x40)
    assert TransitInformation.from_option(transit.to_option()) == transit
    with pytest.raises(DaoError, match="canonical length"):
        RplTarget.from_option(RplOption(RplOptionType.RPL_TARGET, b"\0\x00\0"))
    with pytest.raises(DaoError, match="must contain|missing parent address"):
        TransitInformation.from_option(
            RplOption(RplOptionType.TRANSIT_INFORMATION, b"\x80\x00\x00\x00")
        )


@pytest.mark.parametrize("flags", [0x01, 0x7f])
def test_transit_information_rejects_nonzero_flags(flags: int) -> None:
    option = RplOption(
        RplOptionType.TRANSIT_INFORMATION,
        bytes([flags, 0x80, 1, 255]) + ROOT.packed,
    )
    with pytest.raises(DaoError, match="flags must be zero"):
        TransitInformation.from_option(option)


def test_transit_information_rejects_external_encoding() -> None:
    with pytest.raises(DaoError, match="external.*not supported"):
        TransitInformation(ROOT, external=True).to_option()


def test_build_dao_advances_sequences_and_compatibility_edge_parser() -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)
    manager_copy = copy(manager)
    first = manager.build_dao(N1, ack_requested=True)
    copied_first = manager_copy.build_dao(N1)
    second = manager.build_dao(ROOT)
    assert first.ack_requested is True
    assert first.dao_sequence == copied_first.dao_sequence == 241
    first_transit = TransitInformation.from_option(first.options[1])
    copied_transit = TransitInformation.from_option(copied_first.options[1])
    assert first_transit.path_sequence == copied_transit.path_sequence == 241
    assert first_transit.path_control == 0x80
    assert second.dao_sequence == 242
    assert TransitInformation.from_option(second.options[1]).path_sequence == 242
    assert DaoManager._extract_edge(first) == (N2, N1)


def test_build_dao_with_lifetime_advances_new_updates_but_not_copies() -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)

    first = manager.build_dao_with_lifetime(N1, 17)
    first_transit = TransitInformation.from_option(first.options[1])
    assert first.dao_sequence == 241
    assert first_transit.path_sequence == 241
    assert first_transit.path_lifetime == 17

    exact_copy = manager.build_dao_copy_with_lifetime(N1, 17)
    copy_transit = TransitInformation.from_option(exact_copy.options[1])
    assert exact_copy.dao_sequence == 242
    assert copy_transit.path_sequence == 241
    assert copy_transit.path_lifetime == 17

    withdrawal = manager.build_dao_with_lifetime(N1, 0)
    withdrawal_transit = TransitInformation.from_option(withdrawal.options[1])
    assert withdrawal.dao_sequence == 243
    assert withdrawal_transit.path_sequence == 242
    assert withdrawal_transit.path_lifetime == 0


def test_build_dao_copy_rejects_before_first_logical_update() -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)

    with pytest.raises(DaoError, match="last logical update"):
        manager.build_dao_copy_with_lifetime(N1, 17)


def test_build_dao_copy_rejects_parent_mismatch() -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)
    manager.build_dao_with_lifetime(N1, 17)

    with pytest.raises(DaoError, match="last logical update"):
        manager.build_dao_copy_with_lifetime(ROOT, 17)


def test_build_dao_copy_rejects_lifetime_mismatch() -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)
    manager.build_dao_with_lifetime(N1, 17)

    with pytest.raises(DaoError, match="last logical update"):
        manager.build_dao_copy_with_lifetime(N1, 18)


def test_rejected_dao_copies_leave_both_counters_unchanged() -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)
    manager.build_dao_with_lifetime(N1, 17)
    counters = (manager._dao_sequence, manager._path_sequence)

    with pytest.raises(DaoError):
        manager.build_dao_copy_with_lifetime(ROOT, 17)

    assert (manager._dao_sequence, manager._path_sequence) == counters


def test_exact_dao_copy_advances_only_dao_sequence_and_copies_with_manager() -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)
    update = manager.build_dao_with_lifetime(N1, 17)
    manager_copy = copy(manager)

    exact_copy = manager_copy.build_dao_copy_with_lifetime(N1, 17)
    transit = TransitInformation.from_option(exact_copy.options[1])

    assert exact_copy.dao_sequence == update.dao_sequence + 1
    assert transit.parent_address == N1
    assert transit.path_lifetime == 17
    assert transit.path_sequence == TransitInformation.from_option(update.options[1]).path_sequence
    assert manager._dao_sequence == update.dao_sequence
    assert manager._path_sequence == transit.path_sequence


@pytest.mark.parametrize(
    ("method_name", "lifetime"),
    [
        ("build_dao_with_lifetime", -1),
        ("build_dao_with_lifetime", 256),
        ("build_dao_copy_with_lifetime", -1),
        ("build_dao_copy_with_lifetime", 256),
    ],
)
def test_build_dao_with_lifetime_rejects_invalid_lifetimes(
    method_name: str,
    lifetime: int,
) -> None:
    manager = DaoManager(node_address=N2, dodag_id=ROOT)

    with pytest.raises(ValueError, match="Path Lifetime must fit one octet"):
        getattr(manager, method_name)(N1, lifetime)

    valid = manager.build_dao_with_lifetime(N1, 1)
    assert valid.dao_sequence == 241
    assert TransitInformation.from_option(valid.options[1]).path_sequence == 241


@pytest.mark.parametrize(
    "current, expected",
    [(126, 127), (127, 0), (254, 255), (255, 0)],
)
def test_lollipop_increment_boundaries(current: int, expected: int) -> None:
    assert DaoManager._increment_sequence(current) == expected


def test_process_requires_root_and_matching_instance() -> None:
    with pytest.raises(DaoError, match="only valid on the root"):
        DaoManager(node_address=N1).process_dao(make_dao(N1, ROOT))

    root = DaoManager(node_address=ROOT, is_root=True, rpl_instance_id=5)
    wrong = make_dao(N1, ROOT)
    with pytest.raises(DaoError, match="instance ID 0 != 5"):
        root.process_dao(wrong)
    assert root.routing_table.lookup(N1) is None


def test_ack_and_line_routes_remain_compatible() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    ack_dao = make_dao(N1, ROOT)
    ack_dao.ack_requested = True
    ack = root.process_dao(ack_dao)
    assert ack is not None
    assert ack.dao_sequence == 1

    root.process_dao(make_dao(N2, N1))
    root.process_dao(make_dao(N3, N2))
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) == [N1, N2]
    assert root.routing_table.lookup(N3) == [N1, N2, N3]


def test_parent_change_updates_route() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(DaoManager(node_address=N1).build_dao(ROOT))
    root.process_dao(DaoManager(node_address=N2).build_dao(ROOT))
    n3 = DaoManager(node_address=N3)
    root.process_dao(n3.build_dao(N1))
    assert root.routing_table.lookup(N3) == [N1, N3]
    # N3 reparents to N2 (seq now increments, satisfying replay check).
    root.process_dao(n3.build_dao(N2))
    assert root.routing_table.lookup(N3) == [N2, N3]
    assert (N3, N1) not in root._edge_expiry
    assert root._edge_expiry[(N3, N2)] is None


@pytest.mark.parametrize(
    ("initial_descriptor", "incoming_descriptor", "retained_descriptor"),
    [
        (b"\x00\x00\x00\x01", b"\x00\x00\x00\x02", 1),
        (b"\x00\x00\x00\x01", None, 1),
        (None, b"\x00\x00\x00\x01", None),
    ],
    ids=["change", "removal", "addition"],
)
def test_equal_path_sequence_descriptor_mutations_reject_atomically(
    initial_descriptor: bytes | None,
    incoming_descriptor: bytes | None,
    retained_descriptor: int | None,
) -> None:
    def dao_with_descriptor(descriptor: bytes | None) -> DAO:
        options = [RplTarget(N1).to_option()]
        if descriptor is not None:
            options.append(RplOption(9, descriptor))
        options.append(
            TransitInformation(
                ROOT,
                path_sequence=10,
                path_lifetime=10,
                path_control=0x80,
            ).to_option()
        )
        return DAO(rpl_instance_id=0, dao_sequence=1, options=options)

    root = DaoManager(node_address=ROOT, is_root=True, lifetime_unit_seconds=1)
    root.process_dao_at(dao_with_descriptor(initial_descriptor), 100)
    candidates = dict(root._candidate_map)

    with pytest.raises(DaoError, match="equal Path Sequence"):
        root.process_dao_at(dao_with_descriptor(incoming_descriptor), 101)

    assert root._path_sequences == {N1: 10}
    assert root._descriptors == {N1: retained_descriptor}
    assert root._candidate_map == candidates
    assert root._edge_expiry == {(N1, ROOT): 110}
    assert root.routing_table.lookup(N1) == [N1]


def test_lollipop_wrap_is_newer_but_large_jump_is_incomparable() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(make_dao(N1, ROOT, sequence=255))
    root.process_dao(make_dao(N1, ROOT, sequence=0))
    with pytest.raises(DaoError, match="stale or incomparable"):
        root.process_dao(make_dao(N1, ROOT, sequence=32))
    assert root._path_sequences[N1] == 0


def test_grouped_targets_and_transits_expand_cartesian_product() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    dao = grouped_dao(
        [N1, N2],
        [
            TransitInformation(ROOT, path_sequence=7, path_control=0x80),
            TransitInformation(N3, path_sequence=7, path_control=0x40),
        ],
    )
    root.process_dao(dao)
    assert root._parent_map[N1] == (ROOT, N3)
    assert root._parent_map[N2] == (ROOT, N3)
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) == [N2]


def test_consecutive_groups_and_target_descriptors_are_accepted() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    dao = DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        options=[
            RplTarget(N1).to_option(),
            RplOption(9, b"\x01\x02\x03\x04"),
            TransitInformation(ROOT, path_sequence=3).to_option(),
            RplTarget(N2).to_option(),
            TransitInformation(N1, path_sequence=8).to_option(),
        ],
    )
    root.process_dao(dao)
    assert root.routing_table.lookup(N2) == [N1, N2]


def test_exact_duplicate_transits_deduplicate_but_conflicts_reject_atomically() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    transit = TransitInformation(ROOT, path_sequence=3, path_control=0x80)
    root.process_dao(grouped_dao([N1], [transit, transit]))
    assert root._parent_map[N1] == (ROOT,)

    conflict = grouped_dao(
        [N2],
        [
            TransitInformation(ROOT, path_sequence=4, path_control=0x80),
            TransitInformation(ROOT, path_sequence=4, path_control=0x40),
        ],
    )
    with pytest.raises(DaoError, match="conflicting duplicate"):
        root.process_dao(conflict)
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) is None


@pytest.mark.parametrize(
    "transits",
    [
        [
            TransitInformation(ROOT, path_sequence=1),
            TransitInformation(N1, path_sequence=2),
        ],
        [
            TransitInformation(ROOT, path_sequence=1, path_lifetime=2),
            TransitInformation(N1, path_sequence=1, path_lifetime=3),
        ],
    ],
)
def test_group_sequence_and_lifetime_must_match(
    transits: list[TransitInformation],
) -> None:
    with pytest.raises(DaoError, match="inconsistent Transit group"):
        DaoManager(node_address=ROOT, is_root=True).process_dao(grouped_dao([N2], transits))


def test_duplicate_target_across_groups_rejects_without_mutation() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    dao = DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        options=[
            RplTarget(N1).to_option(),
            TransitInformation(ROOT).to_option(),
            RplTarget(N1).to_option(),
            TransitInformation(N2).to_option(),
        ],
    )
    with pytest.raises(DaoError, match="duplicate RPL Target"):
        root.process_dao(dao)
    assert len(root.routing_table) == 0
    assert root._path_sequences == {}


def test_candidate_control_preference_then_complete_path_lexical_order() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(make_dao(N1, ROOT))
    root.process_dao(make_dao(N2, ROOT))
    root.process_dao(
        grouped_dao(
            [N3],
            [
                TransitInformation(N1, path_sequence=5, path_control=0x10),
                TransitInformation(N2, path_sequence=5, path_control=0x80),
            ],
        )
    )
    assert root.routing_table.lookup(N3) == [N2, N3]

    root.process_dao(
        grouped_dao(
            [N3],
            [
                TransitInformation(N2, path_sequence=6, path_control=0x80),
                TransitInformation(N1, path_sequence=6, path_control=0x40),
            ],
        )
    )
    assert root.routing_table.lookup(N3) == [N1, N3]


def test_incomplete_preferred_candidate_is_skipped_for_complete_path() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(make_dao(N1, ROOT))
    root.process_dao(
        grouped_dao(
            [N3],
            [
                TransitInformation(N2, path_sequence=1, path_control=0x80),
                TransitInformation(N1, path_sequence=1, path_control=0x10),
            ],
        )
    )
    assert root.routing_table.lookup(N3) == [N1, N3]


def test_child_before_parent_commits_state_then_routes_without_child_resend() -> None:
    authority = IPv6Address("fd00::aa")
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(make_dao(N3, N1))
    assert root._path_sequences == {N3: 1}
    assert root.routing_table.lookup(N3) is None
    child_state = root.route_state_snapshot(authority)["targets"][0]
    assert child_state["disposition"] == "active"
    assert child_state["selected_candidate"] is None
    assert root.routing_table_snapshot() == {}

    root.process_dao(make_dao(N1, ROOT))
    assert root.routing_table.lookup(N3) == [N1, N3]


def test_incomplete_cycle_rejects_atomically_then_parent_can_arrive() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(make_dao(N1, N2))
    assert root.routing_table.lookup(N1) is None

    with pytest.raises(DaoError, match="cycle"):
        root.process_dao(make_dao(N2, N1))
    assert root._path_sequences == {N1: 1}
    assert N2 not in root._candidate_map
    assert root.routing_table.lookup(N1) is None

    root.process_dao(make_dao(N2, ROOT))
    assert root.routing_table.lookup(N1) == [N2, N1]
    assert root.routing_table.lookup(N2) == [N2]


def test_no_active_path_control_bit_rejects_atomically() -> None:
    root = DaoManager(node_address=ROOT, is_root=True, pcs=3)
    root.process_dao(make_dao(N1, ROOT))
    with pytest.raises(DaoError, match="no active Path Control"):
        root.process_dao(make_dao(N2, ROOT, control=0x01))
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) is None


def test_ninth_hop_dao_is_rejected_atomically() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    nodes = [IPv6Address(f"fd00::{index}") for index in range(2, 11)]
    parent = ROOT
    for node in nodes[:8]:
        root.process_dao(make_dao(node, parent))
        parent = node

    before_sequences = dict(root._path_sequences)
    before_routes = root.routing_table_snapshot()
    with pytest.raises(DaoError, match="maximum hop count"):
        root.process_dao(make_dao(nodes[8], nodes[7]))

    assert root._path_sequences == before_sequences
    assert root.routing_table_snapshot() == before_routes
    assert root.routing_table.lookup(nodes[7]) == nodes[:8]
    assert root.routing_table.lookup(nodes[8]) is None


def test_newer_withdrawal_and_expiry_retain_tombstones_and_equal_cannot_revive() -> None:
    root = DaoManager(node_address=ROOT, is_root=True, lifetime_unit_seconds=1)
    active = make_dao(N1, ROOT, sequence=10, lifetime=2)
    root.process_dao_at(active, 100)
    assert root.expire_routes(102) is True
    assert root.routing_table.lookup(N1) is None
    assert root._path_sequences[N1] == 10
    assert N1 in root._candidate_map

    root.process_dao_at(active, 103)
    assert root.routing_table.lookup(N1) is None
    with pytest.raises(DaoError, match="equal Path Sequence"):
        root.process_dao_at(make_dao(N1, ROOT, sequence=10, lifetime=3), 103)

    root.process_dao_at(make_dao(N1, ROOT, sequence=11, lifetime=3), 103)
    assert root.routing_table.lookup(N1) == [N1]
    with pytest.raises(DaoError, match="stale or incomparable"):
        root.process_dao_at(make_dao(N1, ROOT, sequence=10, lifetime=0), 104)
    root.process_dao_at(make_dao(N1, ROOT, sequence=12, lifetime=0), 104)
    assert root.routing_table.lookup(N1) is None
    assert root._path_sequences[N1] == 12


@pytest.mark.parametrize(
    "options, message",
    [
        ([TransitInformation(ROOT).to_option()], "before an RPL Target"),
        ([RplTarget(N1).to_option()], "missing RPL Target or Transit"),
        ([RplOption(9, b"x")], "immediately follow one Target"),
        (
            [RplTarget(N1, 64).to_option(), TransitInformation(ROOT).to_option()],
            "only /128",
        ),
    ],
)
def test_malformed_group_ordering_rejects(options: list[RplOption], message: str) -> None:
    dao = DAO(rpl_instance_id=0, dao_sequence=1, options=options)
    with pytest.raises(DaoError, match=message):
        DaoManager(node_address=ROOT, is_root=True).process_dao(dao)


def test_cycle_failure_is_atomic() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    root.process_dao(make_dao(N1, ROOT))
    root.process_dao(make_dao(N2, N1))
    with pytest.raises(DaoError, match="cycle"):
        root.process_dao(make_dao(N1, N2, sequence=2))
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) == [N1, N2]
    assert root._path_sequences[N1] == 1


def test_target_candidate_and_route_capacity_failures_are_atomic() -> None:
    target_limited = DaoManager(node_address=ROOT, is_root=True, max_targets=1)
    target_limited.process_dao(make_dao(N1, ROOT))
    with pytest.raises(DaoError, match="Path Sequence capacity"):
        target_limited.process_dao(make_dao(N2, ROOT))
    assert target_limited.routing_table.lookup(N1) == [N1]
    assert target_limited.routing_table.lookup(N2) is None

    candidate_limited = DaoManager(node_address=ROOT, is_root=True, max_candidates=1)
    with pytest.raises(DaoError, match="candidate capacity"):
        candidate_limited.process_dao(
            grouped_dao(
                [N3],
                [TransitInformation(N1), TransitInformation(N2)],
            )
        )
    assert candidate_limited._path_sequences == {}

    route_limited = DaoManager(node_address=ROOT, is_root=True, max_routes=1)
    route_limited.process_dao(make_dao(N1, ROOT))
    with pytest.raises(DaoError, match="route capacity"):
        route_limited.process_dao(make_dao(N2, ROOT))
    assert route_limited.routing_table.lookup(N1) == [N1]
    assert route_limited.routing_table.lookup(N2) is None


@pytest.mark.parametrize("capacity", [0, -1])
def test_per_target_candidate_capacity_must_be_positive(capacity: int) -> None:
    with pytest.raises(ValueError, match="DAO capacities must be positive"):
        DaoManager(
            node_address=ROOT,
            is_root=True,
            max_candidates_per_target=capacity,
        )


def test_per_target_candidate_capacity_exact_boundary_is_accepted() -> None:
    root = DaoManager(
        node_address=ROOT,
        is_root=True,
        max_candidates=3,
        max_candidates_per_target=2,
    )
    dao = grouped_dao(
        [N3],
        [
            TransitInformation(N1, path_sequence=7),
            TransitInformation(N2, path_sequence=7),
        ],
    )

    root.process_dao(dao)

    assert root._path_sequences == {N3: 7}
    assert root._parent_map == {N3: (N1, N2)}
    assert len(root._candidate_map[N3]) == 2


def test_per_target_candidate_capacity_over_boundary_rejects_atomically() -> None:
    root = DaoManager(
        node_address=ROOT,
        is_root=True,
        max_candidates=4,
        max_candidates_per_target=2,
    )
    root.process_dao(make_dao(N4, ROOT, sequence=6))
    dao = grouped_dao(
        [N3],
        [
            TransitInformation(ROOT, path_sequence=7),
            TransitInformation(N1, path_sequence=7),
            TransitInformation(N2, path_sequence=7),
        ],
    )

    with pytest.raises(DaoError, match="per-target candidate capacity exceeded"):
        root.process_dao(dao)

    assert root._path_sequences == {N4: 6}
    assert root._parent_map == {N4: (ROOT,)}
    assert root._edge_expiry == {(N4, ROOT): None}
    assert root.routing_table.lookup(N4) == [N4]
    assert len(root._candidate_map) == 1
    assert len(root._candidate_map[N4]) == 1
    assert root._candidate_map[N4][0].parent == ROOT
    assert N3 not in root._candidate_map


def test_target_descriptor_is_optional_once_and_immediately_after_each_target() -> None:
    root = DaoManager(node_address=ROOT, is_root=True)
    accepted = DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        options=[
            RplTarget(N1).to_option(),
            RplOption(9, b"one!"),
            RplTarget(N2).to_option(),
            RplOption(9, b"two!"),
            TransitInformation(ROOT).to_option(),
        ],
    )
    root.process_dao(accepted)
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) == [N2]

    malformed = [
        [RplOption(9, b"nope"), *accepted.options],
        [
            RplTarget(N3).to_option(),
            RplOption(9, b"one!"),
            RplOption(9, b"two!"),
            TransitInformation(ROOT).to_option(),
        ],
        [
            RplTarget(N3).to_option(),
            TransitInformation(ROOT).to_option(),
            RplOption(9, b"late"),
        ],
    ]
    for options in malformed:
        with pytest.raises(DaoError, match="immediately follow one Target"):
            root.process_dao(DAO(rpl_instance_id=0, dao_sequence=2, options=options))
    assert root.routing_table.lookup(N1) == [N1]
    assert root.routing_table.lookup(N2) == [N2]


def test_inactive_snapshot_does_not_consume_active_candidate_capacity() -> None:
    root = DaoManager(
        node_address=ROOT,
        is_root=True,
        max_targets=2,
        max_candidates=1,
    )
    root.process_dao(make_dao(N1, ROOT, sequence=1, lifetime=0))
    root.process_dao(make_dao(N2, ROOT, sequence=1, lifetime=255))
    assert root._path_sequences == {N1: 1, N2: 1}
    assert len(root._candidate_map[N1]) == 1
    assert root.routing_table.lookup(N1) is None
    assert root.routing_table.lookup(N2) == [N2]


def test_exact_deadline_boundary_expires_without_refresh() -> None:
    root = DaoManager(node_address=ROOT, is_root=True, lifetime_unit_seconds=2)
    root.process_dao_at(make_dao(N1, ROOT, sequence=1, lifetime=3), 10)
    assert root._edge_expiry[(N1, ROOT)] == 16
    assert root.expire_routes(15.999) is False
    assert root.routing_table.lookup(N1) == [N1]
    assert root.expire_routes(16) is True
    assert root.routing_table.lookup(N1) is None


def test_expired_tombstone_reclaims_only_after_retention_boundary() -> None:
    root = DaoManager(
        node_address=ROOT,
        is_root=True,
        lifetime_unit_seconds=1,
        freshness_retention_seconds=10,
        max_targets=1,
    )
    root.process_dao_at(make_dao(N1, ROOT, sequence=1, lifetime=2), 100)
    root.expire_routes(102)
    with pytest.raises(DaoError, match="capacity"):
        root.process_dao_at(make_dao(N2, ROOT), 111.999)
    assert root._path_sequences == {N1: 1}

    # Should succeed without error. Retention boundary allows reclaim of tombstone.
    root.process_dao_at(
        make_dao(N1, ROOT, sequence=2, lifetime=255, dao_sequence=2), 112
    )
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
