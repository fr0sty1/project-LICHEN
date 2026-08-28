# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the RPL DODAG state machine and parent selection (MRHOF).

Cost oracle: path_cost = advertised_rank + round(link_etx * 256). A perfect
(ETX=1) hop adds 256.
"""

from __future__ import annotations

import math
from ipaddress import IPv6Address

import pytest

from lichen.rpl.dodag import (
    INFINITE_RANK,
    MAX_PARENTS,
    ROOT_RANK,
    SEQUENCE_WINDOW,
    DodagRole,
    DodagState,
    ParentCandidate,
    lollipop_cmp,
    version_is_newer,
    versions_incomparable,
)
from lichen.rpl.messages import DIO

DODAG_ID = "fd00::1"

P1 = IPv6Address("fe80::1")
P2 = IPv6Address("fe80::2")
P3 = IPv6Address("fe80::3")
P_FAR = IPv6Address("fe80::fa12")


def _dio(rank: int, version: int = 1) -> DIO:
    return DIO(
        rpl_instance_id=0,
        version=version,
        rank=rank,
        dtsn=0,
        dodag_id=DODAG_ID,
    )


def _node(version: int = 1) -> DodagState:
    return DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=version)


def test_root_construction() -> None:
    root = DodagState.as_root(0, DODAG_ID, 1)
    assert root.is_root()
    assert root.get_rank() == ROOT_RANK  # 256
    assert root.is_joined()


def test_root_ignores_dio() -> None:
    root = DodagState.as_root(0, DODAG_ID, 1)
    root.process_dio(_dio(128), P1, link_etx=1.0)
    assert root.is_root()
    assert root.get_rank() == ROOT_RANK
    assert root.preferred_parent is None


def test_unjoined_node_joins_on_first_dio() -> None:
    node = _node()
    assert node.role is DodagRole.UNJOINED
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.role is DodagRole.JOINED
    assert node.preferred_parent == P1
    assert node.get_rank() == 256 + 256  # 512


def test_does_not_switch_without_meaningful_improvement() -> None:
    node = _node()
    node.process_dio(_dio(512), P1, link_etx=1.0)  # cost 768
    # P3 cost 640: better than 768 but improvement (128) < threshold (192).
    node.process_dio(_dio(256), P3, link_etx=1.5)  # cost 256 + 384 = 640
    assert node.preferred_parent == P1
    assert node.get_rank() == 768


def test_switches_on_large_improvement() -> None:
    node = _node()
    node.process_dio(_dio(512), P1, link_etx=1.0)  # cost 768
    node.process_dio(_dio(256), P2, link_etx=1.0)  # cost 512, improvement 256
    assert node.preferred_parent == P2
    assert node.get_rank() == 512


def test_rank_strictly_greater_than_parent() -> None:
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.get_rank() > 256  # always above the parent's advertised rank


def test_higher_etx_raises_cost() -> None:
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=2.0)  # cost 256 + 512 = 768
    assert node.get_rank() == 768


def test_newer_version_triggers_rejoin() -> None:
    node = _node(version=1)
    node.process_dio(_dio(256, version=1), P1, link_etx=1.0)
    assert node.version == 1
    # A newer version clears the old parent set and rejoins.
    node.process_dio(_dio(256, version=2), P2, link_etx=1.0)
    assert node.version == 2
    assert node.preferred_parent == P2
    assert P1 not in node.parents
    assert node.get_rank() == 512


def test_older_version_ignored() -> None:
    node = _node(version=1)
    node.process_dio(_dio(256, version=1), P1, link_etx=1.0)
    node.process_dio(_dio(0, version=0), P2, link_etx=1.0)  # stale
    assert P2 not in node.parents
    assert node.preferred_parent == P1


def test_poisoned_dio_removes_candidate() -> None:
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    node.process_dio(_dio(256), P2, link_etx=2.0)
    assert node.preferred_parent == P1
    # P2 advertises infinite rank (poisoned) -> drop it, fall back to P1.
    node.process_dio(_dio(INFINITE_RANK), P1, link_etx=1.0)
    assert P1 not in node.parents
    assert node.preferred_parent == P2
    assert node.get_rank() == 768


def test_max_rank_increase_rejects_distant_parent() -> None:
    """RFC 6550 6.7.6: MaxRankIncrease rejects a lower-rank but costly parent.

    Join via advertised rank 256 and ETX 1.0:
        path_cost = 256 + round(1.0 * 256) = 512
        ceiling   = 512 + 2048 = 2560

    A later candidate with advertised rank 256 (< node.rank 512, >= MHRI)
    and ETX 10.0 has:
        path_cost = 256 + round(10.0 * 256) = 2816 > 2560
        DAGRank(256) = 1 < DAGRank(512) = 2

    so the dio.rank >= self.rank loop check does not fire; only
    MaxRankIncrease rejects it. Oracle is the arithmetic above, not
    ``_admissible()``.
    """
    mhri = 256
    max_rank_increase = 2048
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    joined_cost = 256 + round(1.0 * mhri)
    assert node.get_rank() == joined_cost == 512

    parent_rank = 256
    link_etx = 10.0
    candidate_cost = parent_rank + round(link_etx * mhri)
    ceiling = joined_cost + max_rank_increase
    assert parent_rank < node.get_rank()
    assert parent_rank >= mhri
    assert parent_rank // mhri < node.get_rank() // mhri
    assert candidate_cost == 2816
    assert candidate_cost > ceiling  # 2816 > 2560

    node.process_dio(_dio(parent_rank), P_FAR, link_etx=link_etx)
    assert P_FAR not in node.parents
    assert node.preferred_parent == P1
    assert node.get_rank() == 512


def test_remove_parent_falls_back_or_unjoins() -> None:
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    node.remove_parent(P1)
    assert node.role is DodagRole.UNJOINED
    assert node.preferred_parent is None
    assert node.get_rank() == INFINITE_RANK


def test_process_dio_accepts_string_neighbor_id() -> None:
    """Verify that process_dio coerces string neighbor_id to IPv6Address."""
    node = _node()
    node.process_dio(_dio(256), "fe80::1", link_etx=1.0)  # string, not IPv6Address
    assert node.role is DodagRole.JOINED
    assert node.preferred_parent == P1  # should match the IPv6Address constant
    assert P1 in node.parents


def test_remove_parent_accepts_string_neighbor_id() -> None:
    """Verify that remove_parent coerces string neighbor_id to IPv6Address."""
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    node.remove_parent("fe80::1")  # string, not IPv6Address
    assert node.role is DodagRole.UNJOINED
    assert P1 not in node.parents


def test_parent_table_unifies_zoned_and_unzoned_neighbors() -> None:
    # Independent oracle: RFC 4291 zone is not in the 128-bit address.
    packed = bytes.fromhex("fe800000000000000000000000000001")
    zoned = IPv6Address("fe80::1%lci0")
    unzoned = IPv6Address("fe80::1")
    assert zoned != unzoned
    assert zoned.packed == unzoned.packed == packed

    node = _node()
    node.process_dio(_dio(256), zoned, link_etx=1.0)
    assert node.preferred_parent == unzoned
    assert unzoned in node.parents
    node.remove_parent(IPv6Address("fe80::1%eth0"))
    assert unzoned not in node.parents
    assert node.preferred_parent is None


def test_process_dio_rejects_self_as_parent_across_zone() -> None:
    own_zoned = IPv6Address("fe80::1234%lci0")
    own_unzoned = IPv6Address("fe80::1234")
    assert own_zoned.packed == own_unzoned.packed
    node = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1, node_address=own_zoned)
    node.process_dio(_dio(256), own_unzoned, link_etx=1.0)
    assert own_unzoned not in node.parents
    assert node.role is DodagRole.UNJOINED


def test_process_dio_rejects_invalid_neighbor_id_type() -> None:
    """Verify that process_dio raises TypeError for invalid neighbor_id types."""
    import pytest

    node = _node()
    dio = _dio(256)

    with pytest.raises(TypeError, match="neighbor_id must be IPv6Address or str"):
        node.process_dio(dio, 12345, link_etx=1.0)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="neighbor_id must be IPv6Address or str"):
        node.process_dio(dio, None, link_etx=1.0)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="neighbor_id must be IPv6Address or str"):
        node.process_dio(dio, ["fe80::1"], link_etx=1.0)  # type: ignore[arg-type]


def test_joined_node_ignores_dio_from_different_instance() -> None:
    """RFC 6550 Section 8.2: filter DIOs by RPL Instance ID."""
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.role is DodagRole.JOINED
    # DIO from a different RPL instance should be ignored
    different_instance_dio = DIO(
        rpl_instance_id=1,  # different from node's rpl_instance_id=0
        version=1,
        rank=10,
        dtsn=0,
        dodag_id=DODAG_ID,
    )
    node.process_dio(different_instance_dio, P2, link_etx=1.0)
    # P2 should not be added as a parent
    assert P2 not in node.parents
    assert node.preferred_parent == P1


def test_parents_dict_defensive_copy() -> None:
    """Verify that passing a shared parents dict does not cause cross-state pollution."""
    shared_dict: dict[IPv6Address, ParentCandidate] = {}
    state1 = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1, parents=shared_dict)
    state2 = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1, parents=shared_dict)

    # Modify state1's parents
    state1.process_dio(_dio(256), P1, link_etx=1.0)

    # state2 should NOT see P1 in its parents (defensive copy prevents pollution)
    assert P1 in state1.parents
    assert P1 not in state2.parents
    assert len(state2.parents) == 0

    # Original shared_dict should be empty (it was copied, not used directly)
    assert len(shared_dict) == 0


def test_process_dio_rejects_self_as_parent() -> None:
    """RFC 6550 Section 8.2.2.5: nodes MUST NOT select themselves as parent."""
    own_addr = IPv6Address("fe80::1234")
    node = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1, node_address=own_addr)
    # DIO appearing to come from the node's own address should be ignored
    node.process_dio(_dio(256), own_addr, link_etx=1.0)
    assert own_addr not in node.parents
    assert node.role is DodagRole.UNJOINED
    assert node.preferred_parent is None


def test_process_dio_rejects_self_as_parent_string_form() -> None:
    """RFC 6550 Section 8.2.2.5: self-rejection works with string neighbor_id."""
    own_addr = IPv6Address("fe80::1234")
    node = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1, node_address=own_addr)
    # String form of the same address should also be rejected
    node.process_dio(_dio(256), "fe80::1234", link_etx=1.0)
    assert own_addr not in node.parents
    assert node.role is DodagRole.UNJOINED


def test_process_dio_allows_others_when_node_address_set() -> None:
    """Verify that setting node_address does not block legitimate neighbors."""
    own_addr = IPv6Address("fe80::1234")
    node = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1, node_address=own_addr)
    # DIO from a different address should still be processed
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.role is DodagRole.JOINED
    assert node.preferred_parent == P1


def test_process_dio_without_node_address_backward_compatible() -> None:
    """Verify backward compatibility: no node_address means no self-rejection check."""
    node = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1)
    # Without node_address, DIOs are processed (caller is responsible for filtering)
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.role is DodagRole.JOINED
    assert node.preferred_parent == P1


# RFC 6550 Section 7.2 lollipop comparison table (independent oracle).
# None means incomparable (same-region absolute difference > SEQUENCE_WINDOW=16).
_RFC_LOLLIPOP_CASES: list[tuple[int, int, int | None]] = [
    (16, 0, 1),
    (17, 0, None),
    (0, 16, -1),
    (0, 17, None),
    (0, 127, None),
    (127, 0, None),
    (120, 5, None),
    (5, 100, None),
    (100, 5, None),
    (255, 239, 1),
    (255, 238, None),
    (5, 250, 1),
    (5, 240, -1),
    (0, 240, 1),
    (0, 239, -1),
    (240, 5, 1),
    (250, 5, -1),
]


def test_lollipop_cmp_matches_rfc_6550_7_2_table() -> None:
    for a, b, expected in _RFC_LOLLIPOP_CASES:
        assert lollipop_cmp(a, b) == expected, f"{a} vs {b}"


def _rfc_lollipop_oracle(a: int, b: int) -> int | None:
    if a == b:
        return 0
    if (a < 128) == (b < 128):
        if abs(a - b) > SEQUENCE_WINDOW:
            return None
        return 1 if a > b else -1
    if a < 128:
        return 1 if 256 - b + a <= SEQUENCE_WINDOW else -1
    return -1 if 256 - a + b <= SEQUENCE_WINDOW else 1


def test_lollipop_cmp_exhaustive_rfc_oracle_and_antisymmetry() -> None:
    for a in range(256):
        for b in range(256):
            actual = lollipop_cmp(a, b)
            assert actual == _rfc_lollipop_oracle(a, b), f"{a} vs {b}"
            reverse = lollipop_cmp(b, a)
            assert (actual is None) == (reverse is None)
            if actual is not None:
                assert actual == -reverse


def test_version_is_newer_preserves_explicit_adjacent_restart_policy() -> None:
    assert lollipop_cmp(0, 127) is None
    assert version_is_newer(0, 127) is True
    assert version_is_newer(127, 0) is False
    assert lollipop_cmp(5, 120) is None
    assert version_is_newer(5, 120) is False
    assert version_is_newer(120, 5) is False
    assert version_is_newer(255, 239) is True
    assert version_is_newer(5, 240) is False
    assert version_is_newer(240, 5) is True
    assert version_is_newer(5, 250) is True
    assert version_is_newer(250, 5) is False
    assert version_is_newer(0, 240) is True
    assert version_is_newer(1, 1) is False


def test_demote_resets_lowest_rank_so_rejoin_is_not_capped() -> None:
    root = DodagState.as_root(0, DODAG_ID, 1)
    assert root._lowest_rank == ROOT_RANK
    root.demote()
    assert root.role is DodagRole.UNJOINED
    assert root._lowest_rank == INFINITE_RANK
    assert root.rank == INFINITE_RANK
    # Parent path cost 2560 would exceed leftover root bound 256+2048=2304.
    root.process_dio(_dio(2304), P1, link_etx=1.0)
    assert root.role is DodagRole.JOINED
    assert root.preferred_parent == P1


def test_root_ignores_newer_version_dio() -> None:
    root = DodagState.as_root(0, DODAG_ID, 1)
    root.process_dio(_dio(128, version=2), P1, link_etx=1.0)
    assert root.is_root()
    assert root.version == 1
    assert root.get_rank() == ROOT_RANK
    assert root.preferred_parent is None


def test_incomparable_version_is_ignored_not_mixed() -> None:
    assert versions_incomparable(17, 0) is True
    node = _node(version=0)
    node.process_dio(_dio(256, version=17), P1, link_etx=1.0)
    assert node.role is DodagRole.UNJOINED
    assert P1 not in node.parents
    assert node.version == 0


def test_joined_node_ignores_incomparable_version_parent() -> None:
    node = _node(version=1)
    node.process_dio(_dio(256, version=1), P1, link_etx=1.0)
    node.process_dio(_dio(10, version=18), P2, link_etx=1.0)
    assert node.version == 1
    assert node.preferred_parent == P1
    assert P2 not in node.parents


def test_unjoined_foreign_dodag_is_not_version_compared() -> None:
    node = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=5)
    foreign = DIO(
        rpl_instance_id=0,
        version=0,
        rank=256,
        dtsn=0,
        dodag_id="fd00::99",
    )
    node.process_dio(foreign, P1, link_etx=1.0)
    assert str(node.dodag_id) == "fd00::99"
    assert node.version == 0
    assert node.preferred_parent == P1


def test_rank_inflation_evicts_stale_parent() -> None:
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.preferred_parent == P1
    own_rank = node.get_rank()
    node.process_dio(_dio(own_rank), P1, link_etx=1.0)
    assert P1 not in node.parents
    assert node.role is DodagRole.UNJOINED


def test_max_rank_increase_zero_is_unlimited() -> None:
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    node.max_rank_increase = 0
    # Parent DAGRank still below ours; path cost 5376 exceeds default MaxRankIncrease.
    far = ParentCandidate(P_FAR, 256, 20.0)
    assert node._admissible(far) is True


def test_string_node_address_rejects_self_parent() -> None:
    own = "fe80::1234"
    node = DodagState(rpl_instance_id=0, dodag_id=DODAG_ID, version=1, node_address=own)
    node.process_dio(_dio(256), own, link_etx=1.0)
    assert node.role is DodagRole.UNJOINED
    assert node.preferred_parent is None


def test_below_root_floor_rank_is_rejected() -> None:
    node = _node()
    node.process_dio(_dio(100), P1, link_etx=1.0)
    assert node.role is DodagRole.UNJOINED
    assert P1 not in node.parents


def test_dagrang_must_increase_through_parent() -> None:
    # RFC 6550 3.5.1: DAGRank(511)=1 == DAGRank(256)=1, so Rank does not increase.
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=255.0 / 256.0)
    assert node.role is DodagRole.UNJOINED
    assert P1 not in node.parents


def test_inadmissible_update_evicts_cached_parent() -> None:
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.5)  # cost 640, DAGRank 2
    assert node.preferred_parent == P1
    # 600 < 640 so the raw rank>=self.rank eviction does not fire;
    # DAGRank(600)==DAGRank(640)==2 so the parent is no longer admissible.
    node.process_dio(_dio(600), P1, link_etx=1.0)
    assert P1 not in node.parents
    assert node.role is DodagRole.UNJOINED


def test_parent_candidate_rejects_nan_and_inf_link_etx() -> None:
    """NaN/+inf fail ``etx < 0`` (IEEE 754); reject before path_cost."""
    for etx in (float("nan"), float("inf"), float("-inf")):
        assert math.isnan(etx) or math.isinf(etx)
        with pytest.raises(ValueError, match="link_etx"):
            ParentCandidate(P1, 256, etx)


def test_process_dio_rejects_nan_and_inf_link_etx() -> None:
    """process_dio must raise on NaN/inf before ParentCandidate.path_cost."""
    node = _node()
    for etx in (float("nan"), float("inf"), float("-inf")):
        assert math.isnan(etx) or math.isinf(etx)
        with pytest.raises(ValueError, match="link_etx"):
            node.process_dio(_dio(256), P1, link_etx=etx)
    assert node.role is DodagRole.UNJOINED
    assert P1 not in node.parents
    assert node.preferred_parent is None


def test_path_cost_saturates_when_finite_etx_product_overflows_to_inf() -> None:
    """IEEE 754: 1e307 is finite; 1e307 * 256 is inf. path_cost must not crash.

    Independent oracle: ``math.isinf(etx * mhri)`` is True, so the 16-bit
    rank (RFC 6550 Section 8.2.2.5) saturates to INFINITE_RANK. Does not use
    path_cost as its own oracle for the expected result.
    """
    etx = 1e307
    mhri = 256
    assert math.isfinite(etx)
    assert math.isinf(etx * mhri)

    candidate = ParentCandidate(P1, 256, etx)
    assert candidate.path_cost(mhri) == INFINITE_RANK


def test_process_dio_finite_overflowing_etx_does_not_crash_or_replace_parent() -> None:
    """process_dio(link_etx=1e307) must not OverflowError or change parent/role.

    Input etx is finite, so the NaN/inf ValueError door does not apply. The
    product with MHRI is inf (independent IEEE 754 oracle), so the candidate
    is unusable: path_cost saturates to INFINITE_RANK and _admissible rejects.
    """
    etx = 1e307
    mhri = 256
    assert math.isfinite(etx)
    assert math.isinf(etx * mhri)

    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.role is DodagRole.JOINED
    assert node.preferred_parent == P1
    joined_rank = 256 + round(1.0 * mhri)
    assert node.get_rank() == joined_rank == 512

    node.process_dio(_dio(256), P2, link_etx=etx)
    assert P2 not in node.parents
    assert node.preferred_parent == P1
    assert node.role is DodagRole.JOINED
    assert node.get_rank() == joined_rank


def test_process_dio_finite_overflowing_etx_does_not_join() -> None:
    """An unjoined node hearing only an overflowing-ETX DIO stays unjoined."""
    etx = 1e307
    assert math.isfinite(etx)
    assert math.isinf(etx * 256)

    node = _node()
    node.process_dio(_dio(256), P1, link_etx=etx)
    assert node.role is DodagRole.UNJOINED
    assert P1 not in node.parents
    assert node.preferred_parent is None
    assert node.get_rank() == INFINITE_RANK


def test_dodag_state_rejects_non_positive_min_hop_rank_increase() -> None:
    """RFC 6550 3.5.1: DAGRank is undefined when MinHopRankIncrease is 0."""
    with pytest.raises(ValueError, match="min_hop_rank_increase must be > 0"):
        DodagState(
            rpl_instance_id=0,
            dodag_id=DODAG_ID,
            version=1,
            min_hop_rank_increase=0,
        )
    with pytest.raises(ValueError, match="min_hop_rank_increase must be > 0"):
        DodagState(
            rpl_instance_id=0,
            dodag_id=DODAG_ID,
            version=1,
            min_hop_rank_increase=-256,
        )
    node = DodagState(
        rpl_instance_id=0,
        dodag_id=DODAG_ID,
        version=1,
        min_hop_rank_increase=256,
    )
    assert node.min_hop_rank_increase == 256


def test_temporary_parent_loss_preserves_lowest_rank() -> None:
    """RFC 6550 8.2.2.5: _lowest_rank must not reset on temporary UNJOINED.

    Attack scenario this test prevents:
    1. Node joins at rank 512 (_lowest_rank = 512)
    2. MaxRankIncrease = 2048, so max admissible rank is 2560
    3. All parents are withdrawn (temporary link failure or attack)
    4. Node becomes UNJOINED, but _lowest_rank must remain 512
    5. Attacker advertises high-rank parent (e.g., 60000)
    6. Node must reject due to MaxRankIncrease (path_cost > 512 + 2048)

    If _lowest_rank were reset to INFINITE_RANK, the attacker's high-rank
    parent would be accepted, defeating the rank cycling protection.
    """
    # SECURITY: RFC 6550 MaxRankIncrease prevents rank cycling attacks
    mhri = 256
    max_rank_increase = 2048

    node = _node()
    # Step 1: Join at rank 512
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.role is DodagRole.JOINED
    assert node.get_rank() == 512
    assert node._lowest_rank == 512

    # Step 2: All parents withdrawn - node becomes UNJOINED
    node.remove_parent(P1)
    assert node.role is DodagRole.UNJOINED
    assert node.get_rank() == INFINITE_RANK
    # CRITICAL: _lowest_rank must remain 512, not reset to INFINITE_RANK
    assert node._lowest_rank == 512

    # Step 3: Attacker advertises high-rank parent
    # path_cost = 60000 + 256 = 60256 > 512 + 2048 = 2560
    attacker_rank = 60000
    attacker_cost = attacker_rank + round(1.0 * mhri)
    ceiling = 512 + max_rank_increase
    assert attacker_cost == 60256
    assert attacker_cost > ceiling  # 60256 > 2560

    # Node must reject this parent due to MaxRankIncrease constraint
    node.process_dio(_dio(attacker_rank), P2, link_etx=1.0)
    assert P2 not in node.parents
    assert node.role is DodagRole.UNJOINED
    assert node.preferred_parent is None


def test_stale_parents_are_pruned_by_max_age() -> None:
    """Parents older than max_parent_age are removed during select_parent.

    Long-running nodes would otherwise accumulate stale entries for neighbors
    that went silent. This test injects a mock time source to verify eviction.
    """
    mock_time = 0.0

    def time_func() -> float:
        return mock_time

    node = DodagState(
        rpl_instance_id=0,
        dodag_id=DODAG_ID,
        version=1,
        max_parent_age=300.0,
        _time_func=time_func,
    )

    # Add two parents at time 0
    node.process_dio(_dio(256), P1, link_etx=1.0)
    node.process_dio(_dio(384), P2, link_etx=1.0)
    assert P1 in node.parents
    assert P2 in node.parents
    assert node.preferred_parent == P1
    assert node.role is DodagRole.JOINED

    # Advance time by 200s - both still fresh
    mock_time = 200.0
    node.select_parent()
    assert P1 in node.parents
    assert P2 in node.parents

    # Update P2 at time 200
    node.process_dio(_dio(384), P2, link_etx=1.0)
    assert node.parents[P2].last_heard == 200.0

    # Advance time to 350s - P1 (heard at 0) is stale, P2 (heard at 200) is fresh
    mock_time = 350.0
    node.select_parent()
    assert P1 not in node.parents  # pruned (350 - 0 > 300)
    assert P2 in node.parents  # still fresh (350 - 200 < 300)
    assert node.preferred_parent == P2
    assert node.role is DodagRole.JOINED

    # Advance time to 600s - P2 is now stale too
    mock_time = 600.0
    node.select_parent()
    assert P2 not in node.parents  # pruned (600 - 200 > 300)
    assert node.role is DodagRole.UNJOINED


def test_max_parent_age_zero_disables_pruning() -> None:
    """max_parent_age=0 disables age-based eviction."""
    mock_time = 0.0

    def time_func() -> float:
        return mock_time

    node = DodagState(
        rpl_instance_id=0,
        dodag_id=DODAG_ID,
        version=1,
        max_parent_age=0.0,
        _time_func=time_func,
    )

    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert P1 in node.parents

    # Advance time far beyond any reasonable max age
    mock_time = 10000.0
    node.select_parent()
    assert P1 in node.parents  # not pruned because max_parent_age=0


def _addr(n: int) -> IPv6Address:
    return IPv6Address(f"fe80::{n:x}")


def _fill_parent_set(node: DodagState, *, filler_rank: int = 384, filler_etx: float = 1.0) -> None:
    """Join via P1 (cost 512) then fill the set to MAX_PARENTS with fillers.

    Fillers advertise filler_rank (< the joined rank of 512) so each is
    admissible; P1 stays preferred (its cost is the lowest).
    """
    node.process_dio(_dio(256), P1, link_etx=1.0)
    assert node.preferred_parent == P1
    for n in range(2, MAX_PARENTS + 1):
        node.process_dio(_dio(filler_rank), _addr(n), link_etx=filler_etx)
    assert len(node.parents) == MAX_PARENTS


def test_parent_set_bounded_under_dio_flood() -> None:
    """DIOs from more than MAX_PARENTS neighbors cannot grow the parent set."""
    node = _node()
    for n in range(1, MAX_PARENTS + 11):
        node.process_dio(_dio(256), _addr(n), link_etx=1.0)
    assert len(node.parents) == MAX_PARENTS
    assert node.role is DodagRole.JOINED
    assert node.preferred_parent == _addr(1)


def test_full_parent_set_evicts_worst_for_better_candidate() -> None:
    """At capacity, a strictly better candidate displaces the worst parent."""
    node = _node()
    node.process_dio(_dio(256), P1, link_etx=1.0)  # cost 512, joins, preferred
    for n in range(2, MAX_PARENTS + 1):
        # Escalating ranks 384..496 give distinct costs 640..752.
        node.process_dio(_dio(384 + (n - 2) * 8), _addr(n), link_etx=1.0)
    assert len(node.parents) == MAX_PARENTS
    worst = _addr(MAX_PARENTS)  # rank 496 -> cost 752, the highest kept cost
    assert worst in node.parents

    intruder = _addr(MAX_PARENTS + 1)
    node.process_dio(_dio(256), intruder, link_etx=1.0)  # cost 512

    assert len(node.parents) == MAX_PARENTS
    assert worst not in node.parents
    assert intruder in node.parents
    assert P1 in node.parents
    assert node.preferred_parent == P1


def test_full_parent_set_rejects_worse_candidates() -> None:
    """At capacity, equal/worse candidates are rejected and nothing is evicted."""
    node = _node()
    _fill_parent_set(node)
    before = dict(node.parents)
    for n in range(MAX_PARENTS + 1, MAX_PARENTS + 51):
        node.process_dio(_dio(384), _addr(n), link_etx=5.0)  # cost 1664 > any kept
    assert len(node.parents) == MAX_PARENTS
    assert node.parents == before
    assert node.preferred_parent == P1


def test_preferred_parent_is_never_evicted() -> None:
    """The preferred parent survives capacity pressure even at the worst cost."""
    node = DodagState(
        rpl_instance_id=0,
        dodag_id=DODAG_ID,
        version=1,
        parent_switch_threshold=0xFFFF,  # hysteresis pins preferred to P1
    )
    node.process_dio(_dio(384), P1, link_etx=3.0)  # cost 1152, joins, preferred
    for n in range(2, MAX_PARENTS + 1):
        node.process_dio(_dio(384), _addr(n), link_etx=2.0)  # cost 896
    assert node.preferred_parent == P1
    assert len(node.parents) == MAX_PARENTS

    intruder = _addr(MAX_PARENTS + 1)
    node.process_dio(_dio(256), intruder, link_etx=1.0)  # cost 512

    assert len(node.parents) == MAX_PARENTS
    assert P1 in node.parents
    assert node.preferred_parent == P1
    assert _addr(MAX_PARENTS) not in node.parents  # worst filler evicted instead
    assert intruder in node.parents


def test_existing_parent_update_at_capacity() -> None:
    """Refreshing an existing parent at capacity updates in place, not evict."""
    mock_time = 0.0

    def time_func() -> float:
        return mock_time

    node = DodagState(
        rpl_instance_id=0,
        dodag_id=DODAG_ID,
        version=1,
        _time_func=time_func,
    )
    _fill_parent_set(node)
    mock_time = 50.0
    node.process_dio(_dio(384), P1, link_etx=1.0)
    assert len(node.parents) == MAX_PARENTS
    assert node.parents[P1].last_heard == 50.0
    assert node.preferred_parent == P1
