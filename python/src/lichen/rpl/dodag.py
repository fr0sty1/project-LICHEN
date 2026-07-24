# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address

from lichen.ipv6 import to_ipv6
from lichen.rpl.messages import DIO

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

INFINITE_RANK = 0xFFFF
MIN_HOP_RANK_INCREASE = 256
MAX_RANK_INCREASE = 2048
PARENT_SWITCH_THRESHOLD = 192
ROOT_RANK = MIN_HOP_RANK_INCREASE

# DODAGVersionNumber is an 8-bit lollipop counter (RFC 6550 Section 7.2)
_VERSION_MODULUS = 256
_VERSION_HALF = 128
_LOLLIPOP_LINEAR_START = 128  # Values below this are in the linear region


def version_is_newer(new_version: int, old_version: int) -> bool:
    """Check if new_version is newer than old_version using lollipop semantics.

    RFC 6550 Section 7.2 defines DODAGVersionNumber as an 8-bit lollipop counter:
    - Linear region (0-127): values increase linearly; always newer than circular
    - Circular region (128-255): window-based modular comparison

    The counter starts at 128, increments through 255, wraps to 0 (entering linear),
    and continues to 127. Linear values represent a "later epoch" than any circular.
    """
    new_in_linear = new_version < _LOLLIPOP_LINEAR_START
    old_in_linear = old_version < _LOLLIPOP_LINEAR_START

    if new_in_linear and old_in_linear:
        # Both in linear region: simple integer comparison
        return new_version > old_version
    elif not new_in_linear and not old_in_linear:
        # Both in circular region: window-based modular comparison
        diff = (new_version - old_version) % _VERSION_MODULUS
        return 0 < diff < _VERSION_HALF
    else:
        # Cross-region: linear values are always newer than circular values
        return new_in_linear


class DodagRole(Enum):
    """A node's role within the DODAG."""

    UNJOINED = "unjoined"
    JOINED = "joined"
    ROOT = "root"


@dataclass
class ParentCandidate:
    """A neighbour advertising membership in the DODAG."""

    neighbor_id: IPv6Address
    rank: int
    link_etx: float

    def __post_init__(self) -> None:
        if self.link_etx < 0:
            raise ValueError("link_etx must be non-negative")

    def path_cost(self, min_hop_rank_increase: int) -> int:
        """Rank this node would have via this neighbour (MRHOF, spec B.1)."""
        return self.rank + round(self.link_etx * min_hop_rank_increase)


@dataclass
class DodagState:
    """RPL DODAG membership state for a single node.

    ``neighbor_id`` values are link-local IPv6 addresses identifying neighbours.
    """

    rpl_instance_id: int
    dodag_id: IPv6Address
    version: int
    node_address: IPv6Address | None = None
    role: DodagRole = DodagRole.UNJOINED
    rank: int = INFINITE_RANK
    preferred_parent: IPv6Address | None = None
    parents: dict[IPv6Address, ParentCandidate] = field(default_factory=dict)
    min_hop_rank_increase: int = MIN_HOP_RANK_INCREASE
    max_rank_increase: int = MAX_RANK_INCREASE
    parent_switch_threshold: int = PARENT_SWITCH_THRESHOLD
    gateway_centric: bool = False
    _lowest_rank: int = INFINITE_RANK

    def __post_init__(self) -> None:
        """Make defensive copies of mutable arguments to prevent cross-state pollution."""
        self.parents = dict(self.parents)
        self.dodag_id = to_ipv6(self.dodag_id)

    @classmethod
    def as_root(
        cls,
        rpl_instance_id: int,
        dodag_id: IPv6Address | str,
        version: int,
        node_address: IPv6Address | str | None = None,
    ) -> DodagState:
        """Create a DODAG root (rank = MinHopRankIncrease)."""
        addr = to_ipv6(node_address) if node_address is not None else None
        return cls(
            rpl_instance_id=rpl_instance_id,
            dodag_id=to_ipv6(dodag_id),
            version=version,
            node_address=addr,
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

    def process_dio(
        self, dio: DIO, neighbor_id: IPv6Address | str, link_etx: float = 1.0
    ) -> None:
        """Process a received DIO from ``neighbor_id`` and re-select a parent.

        Newer DODAG versions trigger a rejoin (parents cleared); older versions
        and poisoned (infinite-rank) DIOs are ignored. The root ignores DIOs.

        ``neighbor_id`` may be an IPv6Address or a string representation; it is
        coerced to IPv6Address internally for consistent dict-key handling.

        Raises:
            TypeError: If ``neighbor_id`` is not an IPv6Address or str.
            ValueError: If ``link_etx`` is negative.
        """
        if link_etx < 0:
            raise ValueError("link_etx must be non-negative")
        if not isinstance(neighbor_id, (IPv6Address, str)):
            raise TypeError(
                f"neighbor_id must be IPv6Address or str, got {type(neighbor_id).__name__}"
            )
        neighbor_id = to_ipv6(neighbor_id)
        if self.role is DodagRole.ROOT:
            return
        if self.node_address is not None and neighbor_id == self.node_address:
            return
        if dio.rpl_instance_id != self.rpl_instance_id and self.is_joined():
            return
        if dio.dodag_id != self.dodag_id and self.is_joined():
            return

        if version_is_newer(dio.version, self.version) or not self.is_joined():
            # Adopt this (newer or first-seen) DODAG version and rejoin.
            self._adopt_version(dio)
        elif version_is_newer(self.version, dio.version):
            return  # stale advertisement

        if dio.rank >= INFINITE_RANK:
            # Poisoned route; drop this neighbour as a candidate.
            self.parents.pop(neighbor_id, None)
            self.select_parent()
            return

        # SECURITY: RFC 6550 Section 8.2.2.5 - reject parents with equal or
        # higher rank to prevent routing loops. Only accept neighbors with
        # strictly lower rank (unless we're unjoined with infinite rank).
        if self.rank != INFINITE_RANK and dio.rank >= self.rank:
            return

        self.parents[neighbor_id] = ParentCandidate(neighbor_id, dio.rank, link_etx)
        self.select_parent()

    def _adopt_version(self, dio: DIO) -> None:
        self.dodag_id = dio.dodag_id
        self.rpl_instance_id = dio.rpl_instance_id
        self.version = dio.version
        self.parents.clear()
        self.preferred_parent = None
        self.rank = INFINITE_RANK
        self._lowest_rank = INFINITE_RANK
        self.role = DodagRole.UNJOINED

    def _admissible(self, candidate: ParentCandidate) -> bool:
        cost = candidate.path_cost(self.min_hop_rank_increase)
        if cost >= INFINITE_RANK:
            return False  # Rank overflow - not admissible
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
                self._lowest_rank = INFINITE_RANK
            return

        best = min(admissible, key=lambda c: c.path_cost(self.min_hop_rank_increase))
        best_cost = best.path_cost(self.min_hop_rank_increase)

        current = self.parents.get(self.preferred_parent) if self.preferred_parent else None
        if current is not None and current.neighbor_id != best.neighbor_id:
            current_cost = current.path_cost(self.min_hop_rank_increase)
            # Hysteresis: stick with current unless improvement reaches threshold (RFC 6550 s3.6).
            improvement = current_cost - best_cost
            if improvement < self.parent_switch_threshold:
                best, best_cost = current, current_cost

        self.preferred_parent = best.neighbor_id
        self.rank = best_cost
        self.role = DodagRole.JOINED
        self._lowest_rank = min(self._lowest_rank, best_cost)

    def remove_parent(self, neighbor_id: IPv6Address | str) -> None:
        """Drop a neighbour (e.g. on link failure) and re-select.

        ``neighbor_id`` may be an IPv6Address or a string representation.
        """
        self.parents.pop(to_ipv6(neighbor_id), None)
        self.select_parent()
