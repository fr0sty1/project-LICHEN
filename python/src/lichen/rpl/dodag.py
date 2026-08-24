# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import math
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Literal

from lichen.ipv6 import to_ipv6
from lichen.ipv6.packet import IPv6Header
from lichen.rpl.messages import DIO
from lichen.rpl.root_signature import verify_dodagid_binding
from lichen.schc.context import versions_compatible
from lichen.schc.rules import RULE_SET_VERSION, SCHC_RULE_VERSION_TYPE, SchcRuleVersionOption

if TYPE_CHECKING:
    from lichen.link.link_layer import LinkLayer, RxFrame
    from lichen.rpl.authenticated_dio import AuthenticatedDio

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
  at least ``parent_switch_threshold`` (RFC 6550 MRHOF default 192).
- MaxRankIncrease: reject candidates whose path cost exceeds the lowest rank
  held this version plus ``max_rank_increase`` (spec B.2), bounding rank growth.
"""

INFINITE_RANK = 0xFFFF
MIN_HOP_RANK_INCREASE = 256
MAX_RANK_INCREASE = 2048
PARENT_SWITCH_THRESHOLD = 192
ROOT_RANK = MIN_HOP_RANK_INCREASE


def _require_finite_non_negative_etx(link_etx: float) -> None:
    """Reject NaN/inf before ``round(link_etx * MHRI)`` can crash path_cost.

    ``link_etx < 0`` is False for both NaN and +inf (IEEE 754), so those
    values must be checked with ``math.isnan`` / ``math.isinf``.
    """
    if math.isnan(link_etx) or math.isinf(link_etx):
        raise ValueError("link_etx must be finite")
    if link_etx < 0:
        raise ValueError("link_etx must be non-negative")


# DODAGVersionNumber is an 8-bit lollipop counter (RFC 6550 Section 7.2)
SEQUENCE_WINDOW = 16
_LOLLIPOP_LINEAR_START = 128  # Values below this are in the linear region


def lollipop_cmp(a: int, b: int) -> int | None:
    """Compare two 8-bit lollipop counters (RFC 6550 Section 7.2).

    Returns 1 if ``a`` is newer, -1 if older, 0 if equal, or None when both
    counters are in the same region and ``|a-b| > SEQUENCE_WINDOW`` (16).
    Cross-region values are always comparable: a wrap distance of at most
    SEQUENCE_WINDOW makes the wrapped counter newer; a larger distance makes
    the unwrapped counter newer.
    """
    a &= 0xFF
    b &= 0xFF
    if a == b:
        return 0
    a_linear = a < _LOLLIPOP_LINEAR_START
    b_linear = b < _LOLLIPOP_LINEAR_START
    if a_linear == b_linear:
        if abs(a - b) <= SEQUENCE_WINDOW:
            return 1 if a > b else -1
        return None
    if a_linear:
        wrap_distance = 256 - b + a
        return 1 if wrap_distance <= SEQUENCE_WINDOW else -1
    wrap_distance = 256 - a + b
    return -1 if wrap_distance <= SEQUENCE_WINDOW else 1


def version_is_newer(new_version: int, old_version: int) -> bool:
    """True if ``new_version`` is strictly newer than ``old_version``.

    Matches rust/lichen-rpl ``version_is_newer``: RFC 6550 Section 7.2
    lollipop comparison, plus the observed adjacent wrap ``0`` is newer
    than ``127`` (linear-region restart after 127).
    """
    new_version &= 0xFF
    old_version &= 0xFF
    if (new_version, old_version) == (0, 127):
        return True
    return lollipop_cmp(new_version, old_version) == 1


def versions_incomparable(a: int, b: int) -> bool:
    """True when neither counter is newer (RFC 6550 desynchronization)."""
    a &= 0xFF
    b &= 0xFF
    if a == b:
        return False
    return not version_is_newer(a, b) and not version_is_newer(b, a)


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
        _require_finite_non_negative_etx(self.link_etx)

    def path_cost(self, min_hop_rank_increase: int) -> int:
        """Rank this node would have via this neighbour (MRHOF, spec B.1).

        Returns INFINITE_RANK on overflow to keep rank in the 16-bit range
        (RFC 6550 Section 8.2.2.5: rank is a 16-bit unsigned integer).

        A finite ``link_etx`` can still overflow IEEE 754: ``1e307 * 256`` is
        inf, and ``round(inf)`` raises OverflowError. Treat a non-finite
        product as unusable (same saturation as rust/lichen-rpl).
        """
        try:
            increase = self.link_etx * min_hop_rank_increase
        except OverflowError:
            # mhri too large to convert to float (e.g. 2**1024)
            return INFINITE_RANK
        if not math.isfinite(increase):
            return INFINITE_RANK
        cost = self.rank + round(increase)
        return INFINITE_RANK if cost >= INFINITE_RANK else cost


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
    _lock: threading.RLock = field(
        default_factory=threading.RLock, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Make defensive copies of mutable arguments to prevent cross-state pollution."""
        self.parents = dict(self.parents)
        self.dodag_id = to_ipv6(self.dodag_id)
        if self.node_address is not None:
            self.node_address = to_ipv6(self.node_address)
        # RFC 6550 3.5.1: DAGRank(R) = floor(R / MinHopRankIncrease); MHRI of
        # 0 is undefined, and a negative MHRI inverts rank increase.
        if self.min_hop_rank_increase <= 0:
            raise ValueError("min_hop_rank_increase must be > 0")

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

    def demote(self) -> None:
        """Demote a root to UNJOINED, clearing parent state and rank.

        No-op if the node is not currently a root.
        """
        if self.role is DodagRole.ROOT:
            self.role = DodagRole.UNJOINED
            self.preferred_parent = None
            self.rank = INFINITE_RANK
            self.parents.clear()
            self._lowest_rank = INFINITE_RANK

    def get_rank(self) -> int:
        return self.rank

    def process_dio(self, dio: DIO, neighbor_id: IPv6Address | str, link_etx: float = 1.0) -> None:
        """Process a received DIO from ``neighbor_id`` and re-select a parent.

        Newer DODAG versions trigger a rejoin (parents cleared); older versions
        and poisoned (infinite-rank) DIOs are ignored. The root ignores DIOs.

        ``neighbor_id`` may be an IPv6Address or a string representation; it is
        coerced to IPv6Address internally for consistent dict-key handling.

        Raises:
            TypeError: If ``neighbor_id`` is not an IPv6Address or str.
            ValueError: If ``link_etx`` is NaN, infinite, or negative.
        """
        with self._lock:
            self._process_dio_unlocked(dio, neighbor_id, link_etx)

    def _process_dio_unlocked(
        self,
        dio: DIO,
        neighbor_id: IPv6Address | str,
        link_etx: float,
    ) -> None:
        _require_finite_non_negative_etx(link_etx)
        if not isinstance(neighbor_id, (IPv6Address, str)):
            raise TypeError(
                f"neighbor_id must be IPv6Address or str, got {type(neighbor_id).__name__}"
            )
        neighbor_id = to_ipv6(neighbor_id)
        if self.role is DodagRole.ROOT:
            return
        if self.node_address is not None and neighbor_id == self.node_address:
            return

        foreign = dio.rpl_instance_id != self.rpl_instance_id or dio.dodag_id != self.dodag_id
        if self.is_joined():
            if foreign:
                return
            if version_is_newer(dio.version, self.version):
                self._adopt_version(dio)
            elif version_is_newer(self.version, dio.version) or versions_incomparable(
                dio.version, self.version
            ):
                return
        elif foreign:
            # Unjoined: a different (instance, DODAGID) is a first join, not a
            # DODAGVersionNumber comparison (RFC 6550 3.1.2 / 7.2).
            self._adopt_version(dio)
        elif version_is_newer(dio.version, self.version):
            self._adopt_version(dio)
        elif version_is_newer(self.version, dio.version) or versions_incomparable(
            dio.version, self.version
        ):
            return

        if dio.rank >= INFINITE_RANK:
            # Poisoned route; drop this neighbour as a candidate.
            self.parents.pop(neighbor_id, None)
            self.select_parent()
            return

        # SECURITY: RFC 6550 Section 8.2.2.5 - reject parents with equal or
        # higher rank to prevent routing loops. Only accept neighbors with
        # strictly lower rank (unless we're unjoined with infinite rank).
        if self.rank != INFINITE_RANK and dio.rank >= self.rank:
            if neighbor_id in self.parents:
                self.parents.pop(neighbor_id, None)
                self.select_parent()
            return

        candidate = ParentCandidate(neighbor_id, dio.rank, link_etx)
        if not self._admissible(candidate):
            if neighbor_id in self.parents:
                self.parents.pop(neighbor_id, None)
                self.select_parent()
            return
        self.parents[neighbor_id] = candidate
        self.gateway_centric = dio.gateway_centric
        self.select_parent()

    def _would_accept_dio_unlocked(
        self,
        dio: DIO,
        neighbor_id: IPv6Address,
        link_etx: float,
    ) -> bool:
        """Return whether ``process_dio`` would install this exact candidate."""
        _require_finite_non_negative_etx(link_etx)
        if self.role is DodagRole.ROOT:
            return False
        if self.node_address is not None and neighbor_id == self.node_address:
            return False
        foreign = dio.rpl_instance_id != self.rpl_instance_id or dio.dodag_id != self.dodag_id
        adopts = False
        if self.is_joined():
            if foreign:
                return False
            if version_is_newer(dio.version, self.version):
                adopts = True
            elif version_is_newer(self.version, dio.version) or versions_incomparable(
                dio.version, self.version
            ):
                return False
        elif foreign or version_is_newer(dio.version, self.version):
            adopts = True
        elif version_is_newer(self.version, dio.version) or versions_incomparable(
            dio.version, self.version
        ):
            return False
        if dio.rank >= INFINITE_RANK:
            return False
        effective_rank = INFINITE_RANK if adopts else self.rank
        effective_lowest = INFINITE_RANK if adopts else self._lowest_rank
        if effective_rank != INFINITE_RANK and dio.rank >= effective_rank:
            return False
        candidate = ParentCandidate(neighbor_id, dio.rank, link_etx)
        if adopts:
            mhri = self.min_hop_rank_increase
            cost = candidate.path_cost(mhri)
            return (
                mhri > 0
                and cost < INFINITE_RANK
                and candidate.rank >= mhri
                and cost // mhri > candidate.rank // mhri
            )
        mhri = self.min_hop_rank_increase
        cost = candidate.path_cost(mhri)
        if (
            mhri == 0
            or cost >= INFINITE_RANK
            or candidate.rank < mhri
            or cost // mhri <= candidate.rank // mhri
        ):
            return False
        if effective_rank != INFINITE_RANK and candidate.rank // mhri >= effective_rank // mhri:
            return False
        return (
            self.max_rank_increase == 0
            or effective_lowest >= INFINITE_RANK
            or cost <= effective_lowest + self.max_rank_increase
        )

    def process_authenticated_dio(
        self,
        link_layer: LinkLayer,
        received: RxFrame,
        *,
        expected_role: Literal["root", "peer"],
        link_etx: float = 1.0,
    ) -> None:
        """Admit a DIO only through its link-owned authenticated receipt.

        Version mismatch, reserved/unsupported values, and malformed option
        cardinality fail before any DODAG state is changed.
        """
        with self._lock:
            expected_instance = self.rpl_instance_id
            expected_dodag = self.dodag_id
        authenticated = link_layer.accept_authenticated_dio(
            received,
            expected_rpl_instance_id=expected_instance,
            expected_dodag_id=expected_dodag,
            expected_mop=1,
            expected_role=expected_role,
        )
        self._process_authenticated_dio_evidence_unlocked(
            link_layer,
            authenticated,
            expected_role=expected_role,
            link_etx=link_etx,
        )

    def process_authenticated_dio_evidence(
        self,
        link_layer: LinkLayer,
        authenticated: AuthenticatedDio,
        *,
        expected_role: Literal["root", "peer"],
        link_etx: float = 1.0,
    ) -> None:
        """Admit sealed DIO evidence issued during authenticated reassembly."""
        from lichen.rpl.authenticated_dio import AuthenticatedDio

        if type(authenticated) is not AuthenticatedDio:
            raise TypeError("authenticated must be an exact AuthenticatedDio")
        self._process_authenticated_dio_evidence_unlocked(
            link_layer,
            authenticated,
            expected_role=expected_role,
            link_etx=link_etx,
        )

    def _process_authenticated_dio_evidence_unlocked(
        self,
        link_layer: LinkLayer,
        authenticated: AuthenticatedDio,
        *,
        expected_role: Literal["root", "peer"],
        link_etx: float,
    ) -> None:
        """Validate and commit one LinkLayer-owned DIO issuance."""

        def prepare_candidate(
            detached: object,
        ) -> Callable[[object], None] | None:
            from lichen.rpl.authenticated_dio import DetachedAuthenticatedDio

            if type(detached) is not DetachedAuthenticatedDio:
                raise TypeError("invalid detached authenticated DIO")
            source = IPv6Header.from_bytes(detached.ipv6).src_addr.packed
            expected_source = b"\xfe\x80" + bytes(6) + detached.sender_iid
            if source != expected_source:
                raise ValueError("authenticated DIO source IID does not match signer")
            parsed = DIO.from_bytes(detached.dio_bytes)
            if (
                parsed.rpl_instance_id != self.rpl_instance_id
                or parsed.dodag_id != self.dodag_id
            ):
                raise ValueError(
                    "DODAG scope changed during authenticated DIO admission"
                )
            if expected_role == "root" and not verify_dodagid_binding(
                detached.sender_pubkey, parsed.dodag_id
            ):
                raise ValueError("authenticated root DODAGID does not match signer key")
            version_options = [
                option for option in detached.options if option.type == SCHC_RULE_VERSION_TYPE
            ]
            if len(version_options) != 1:
                raise ValueError(
                    "authenticated DIO must contain exactly one SCHC Rule Version option"
                )
            version_data = version_options[0].data
            version = SchcRuleVersionOption.from_bytes(
                bytes((SCHC_RULE_VERSION_TYPE, len(version_data))) + version_data
            ).version
            if not versions_compatible(RULE_SET_VERSION, version):
                raise ValueError(
                    f"incompatible SCHC rule version {version}; DODAG admission denied"
                )
            neighbor_id = IPv6Address(b"\xfe\x80" + bytes(6) + detached.sender_iid)
            if not self._would_accept_dio_unlocked(parsed, neighbor_id, link_etx):
                return None

            def commit_candidate(peer: object) -> None:
                from lichen.schc.context import AuthenticatedPeerSchcContext

                if type(peer) is not AuthenticatedPeerSchcContext or not peer.allows_dodag_join:
                    raise ValueError("DODAG transaction received an incompatible SCHC policy")
                self._process_dio_unlocked(parsed, neighbor_id, link_etx)

            return commit_candidate

        link_layer.transact_authenticated_schc_dio(
            authenticated,
            prepare=prepare_candidate,
            consumer_lock=self._lock,
        )

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
        mhri = self.min_hop_rank_increase
        if mhri == 0:
            return False
        cost = candidate.path_cost(mhri)
        if cost >= INFINITE_RANK:
            return False
        # RFC 6550 3.5.1 / 8.2.2.4: DAGRank(R) = floor(R / MinHopRankIncrease).
        # Root floor is MinHopRankIncrease; Rank MUST increase through the parent.
        if candidate.rank < mhri or cost // mhri <= candidate.rank // mhri:
            return False
        if self.rank != INFINITE_RANK and candidate.rank // mhri >= self.rank // mhri:
            return False
        # RFC 6550 Section 6.7.6: MaxRankIncrease of 0 means no limit.
        if self.max_rank_increase == 0 or self._lowest_rank >= INFINITE_RANK:
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

        current = self.parents.get(self.preferred_parent) if self.preferred_parent else None
        if (
            current is not None
            and self._admissible(current)
            and current.neighbor_id != best.neighbor_id
        ):
            current_cost = current.path_cost(self.min_hop_rank_increase)
            # Hysteresis: stick with current unless improvement reaches threshold (RFC 6550 s3.6).
            improvement = current_cost - best_cost
            if improvement < self.parent_switch_threshold:
                best, best_cost = current, current_cost

        self.preferred_parent = best.neighbor_id
        self.rank = best_cost if best_cost < INFINITE_RANK else INFINITE_RANK - 1
        self.role = DodagRole.JOINED
        self._lowest_rank = min(self._lowest_rank, self.rank)

    def remove_parent(self, neighbor_id: IPv6Address | str) -> None:
        """Drop a neighbour (e.g. on link failure) and re-select.

        ``neighbor_id`` may be an IPv6Address or a string representation.
        """
        self.parents.pop(to_ipv6(neighbor_id), None)
        self.select_parent()
