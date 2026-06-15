"""RPL DODAG state machine and parent selection (RFC 6550, spec section 8).

Implements DODAG join/parent selection using MRHOF with ETX (spec B.1). A node
is UNJOINED until it hears a usable DIO, then JOINED with a preferred parent, or
it may be a configured/elected ROOT.

Rank is computed as ``preferred_parent.rank + rank_increase``, where the
increase is ``link_etx * MinHopRankIncrease`` — so a single hop over a perfect
(ETX=1) link adds ``MinHopRankIncrease`` (spec B.1/B.2). Link ETX is supplied by
the caller (estimated from RSSI/SNR/success rate); the DODAG layer does not
measure links itself.

Stability mechanisms:
- Hysteresis: switch preferred parent only if a candidate improves path cost by
  more than ``parent_switch_threshold`` (RFC 6550 MRHOF default 192).
- MaxRankIncrease: reject candidates whose path cost exceeds the lowest rank
  held this version plus ``max_rank_increase`` (spec B.2), bounding rank growth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from lichen.rpl.messages import DIO

INFINITE_RANK = 0xFFFF
MIN_HOP_RANK_INCREASE = 256
MAX_RANK_INCREASE = 2048
PARENT_SWITCH_THRESHOLD = 192
ROOT_RANK = MIN_HOP_RANK_INCREASE


class DodagRole(Enum):
    """A node's role within the DODAG."""

    UNJOINED = "unjoined"
    JOINED = "joined"
    ROOT = "root"


@dataclass
class ParentCandidate:
    """A neighbour advertising membership in the DODAG."""

    neighbor_id: str
    rank: int
    link_etx: float

    def path_cost(self, min_hop_rank_increase: int) -> int:
        """Rank this node would have via this neighbour (MRHOF, spec B.1)."""
        return self.rank + round(self.link_etx * min_hop_rank_increase)


@dataclass
class DodagState:
    """RPL DODAG membership state for a single node.

    ``neighbor_id`` values are opaque identifiers for neighbours (e.g. their
    link-local address as a string).
    """

    rpl_instance_id: int
    dodag_id: str
    version: int
    role: DodagRole = DodagRole.UNJOINED
    rank: int = INFINITE_RANK
    preferred_parent: str | None = None
    parents: dict[str, ParentCandidate] = field(default_factory=dict)
    min_hop_rank_increase: int = MIN_HOP_RANK_INCREASE
    max_rank_increase: int = MAX_RANK_INCREASE
    parent_switch_threshold: int = PARENT_SWITCH_THRESHOLD
    _lowest_rank: int = INFINITE_RANK

    @classmethod
    def as_root(cls, rpl_instance_id: int, dodag_id: str, version: int) -> DodagState:
        """Create a DODAG root (rank = MinHopRankIncrease)."""
        return cls(
            rpl_instance_id=rpl_instance_id,
            dodag_id=dodag_id,
            version=version,
            role=DodagRole.ROOT,
            rank=ROOT_RANK,
            _lowest_rank=ROOT_RANK,
        )

    def is_root(self) -> bool:
        return self.role is DodagRole.ROOT

    def is_joined(self) -> bool:
        return self.role in (DodagRole.JOINED, DodagRole.ROOT)

    def get_rank(self) -> int:
        return self.rank

    def process_dio(self, dio: DIO, neighbor_id: str, link_etx: float = 1.0) -> None:
        """Process a received DIO from ``neighbor_id`` and re-select a parent.

        Newer DODAG versions trigger a rejoin (parents cleared); older versions
        and poisoned (infinite-rank) DIOs are ignored. The root ignores DIOs.
        """
        if self.role is DodagRole.ROOT:
            return
        if str(dio.dodag_id) != self.dodag_id and self.is_joined():
            return  # belongs to a different DODAG

        if dio.version > self.version or not self.is_joined():
            # Adopt this (newer or first-seen) DODAG version and rejoin.
            self._adopt_version(dio)
        elif dio.version < self.version:
            return  # stale advertisement

        if dio.rank >= INFINITE_RANK:
            # Poisoned route; drop this neighbour as a candidate.
            self.parents.pop(neighbor_id, None)
            self.select_parent()
            return

        self.parents[neighbor_id] = ParentCandidate(neighbor_id, dio.rank, link_etx)
        self.select_parent()

    def _adopt_version(self, dio: DIO) -> None:
        self.dodag_id = str(dio.dodag_id)
        self.rpl_instance_id = dio.rpl_instance_id
        self.version = dio.version
        self.parents.clear()
        self.preferred_parent = None
        self.rank = INFINITE_RANK
        self._lowest_rank = INFINITE_RANK
        self.role = DodagRole.UNJOINED

    def _admissible(self, candidate: ParentCandidate) -> bool:
        cost = candidate.path_cost(self.min_hop_rank_increase)
        if self._lowest_rank >= INFINITE_RANK:
            return True
        return cost <= self._lowest_rank + self.max_rank_increase

    def select_parent(self) -> None:
        """Choose the preferred parent via MRHOF with hysteresis."""
        admissible = [c for c in self.parents.values() if self._admissible(c)]
        if not admissible:
            if self.role is not DodagRole.ROOT:
                self.role = DodagRole.UNJOINED
                self.preferred_parent = None
                self.rank = INFINITE_RANK
            return

        best = min(admissible, key=lambda c: c.path_cost(self.min_hop_rank_increase))
        best_cost = best.path_cost(self.min_hop_rank_increase)

        current = self.parents.get(self.preferred_parent or "")
        if current is not None and current.neighbor_id != best.neighbor_id:
            current_cost = current.path_cost(self.min_hop_rank_increase)
            # Hysteresis: only switch on a meaningful improvement.
            if best_cost > current_cost - self.parent_switch_threshold:
                best, best_cost = current, current_cost

        self.preferred_parent = best.neighbor_id
        self.rank = best_cost
        self.role = DodagRole.JOINED
        self._lowest_rank = min(self._lowest_rank, best_cost)

    def remove_parent(self, neighbor_id: str) -> None:
        """Drop a neighbour (e.g. on link failure) and re-select."""
        self.parents.pop(neighbor_id, None)
        self.select_parent()
