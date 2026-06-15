"""Tests for the RPL DODAG state machine and parent selection (MRHOF).

Cost oracle: path_cost = advertised_rank + round(link_etx * 256). A perfect
(ETX=1) hop adds 256.
"""

from __future__ import annotations

from lichen.rpl.dodag import (
    INFINITE_RANK,
    ROOT_RANK,
    DodagRole,
    DodagState,
)
from lichen.rpl.messages import DIO

DODAG_ID = "fd00::1"


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
    root.process_dio(_dio(128), "P1", link_etx=1.0)
    assert root.is_root()
    assert root.get_rank() == ROOT_RANK
    assert root.preferred_parent is None


def test_unjoined_node_joins_on_first_dio() -> None:
    node = _node()
    assert node.role is DodagRole.UNJOINED
    node.process_dio(_dio(256), "P1", link_etx=1.0)
    assert node.role is DodagRole.JOINED
    assert node.preferred_parent == "P1"
    assert node.get_rank() == 256 + 256  # 512


def test_does_not_switch_without_meaningful_improvement() -> None:
    node = _node()
    node.process_dio(_dio(256), "P1", link_etx=1.0)  # cost 512
    # P3 cost 456: better than 512 but improvement (56) < threshold (192).
    node.process_dio(_dio(200), "P3", link_etx=1.0)  # cost 456
    assert node.preferred_parent == "P1"
    assert node.get_rank() == 512


def test_switches_on_large_improvement() -> None:
    node = _node()
    node.process_dio(_dio(256), "P1", link_etx=1.0)  # cost 512
    node.process_dio(_dio(10), "P2", link_etx=1.0)  # cost 266, improvement 246
    assert node.preferred_parent == "P2"
    assert node.get_rank() == 266


def test_rank_strictly_greater_than_parent() -> None:
    node = _node()
    node.process_dio(_dio(256), "P1", link_etx=1.0)
    assert node.get_rank() > 256  # always above the parent's advertised rank


def test_higher_etx_raises_cost() -> None:
    node = _node()
    node.process_dio(_dio(256), "P1", link_etx=2.0)  # cost 256 + 512 = 768
    assert node.get_rank() == 768


def test_newer_version_triggers_rejoin() -> None:
    node = _node(version=1)
    node.process_dio(_dio(256, version=1), "P1", link_etx=1.0)
    assert node.version == 1
    # A newer version clears the old parent set and rejoins.
    node.process_dio(_dio(100, version=2), "P2", link_etx=1.0)
    assert node.version == 2
    assert node.preferred_parent == "P2"
    assert "P1" not in node.parents
    assert node.get_rank() == 356


def test_older_version_ignored() -> None:
    node = _node(version=1)
    node.process_dio(_dio(256, version=1), "P1", link_etx=1.0)
    node.process_dio(_dio(0, version=0), "P2", link_etx=1.0)  # stale
    assert "P2" not in node.parents
    assert node.preferred_parent == "P1"


def test_poisoned_dio_removes_candidate() -> None:
    node = _node()
    node.process_dio(_dio(256), "P1", link_etx=1.0)
    node.process_dio(_dio(10), "P2", link_etx=1.0)
    assert node.preferred_parent == "P2"
    # P2 advertises infinite rank (poisoned) -> drop it, fall back to P1.
    node.process_dio(_dio(INFINITE_RANK), "P2", link_etx=1.0)
    assert "P2" not in node.parents
    assert node.preferred_parent == "P1"
    assert node.get_rank() == 512


def test_max_rank_increase_rejects_distant_parent() -> None:
    node = _node()
    node.process_dio(_dio(256), "P1", link_etx=1.0)  # rank 512, lowest 512
    # Candidate cost 512 + 2049 = 2561 > lowest(512) + MaxRankIncrease(2048).
    node.process_dio(_dio(2305), "P_far", link_etx=1.0)
    assert node.preferred_parent == "P1"
    assert node.get_rank() == 512


def test_remove_parent_falls_back_or_unjoins() -> None:
    node = _node()
    node.process_dio(_dio(256), "P1", link_etx=1.0)
    node.remove_parent("P1")
    assert node.role is DodagRole.UNJOINED
    assert node.preferred_parent is None
    assert node.get_rank() == INFINITE_RANK
