# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO state tracking helpers.

This module provides functions for managing DAO freshness state,
active parent tracking, and edge expiry.
"""
from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv6Address

from lichen.rpl.dao_types import Candidate, DaoError, Freshness


def compute_active_parents(
    edge_expiry: dict[tuple[IPv6Address, IPv6Address], float | None],
    now: float,
) -> dict[IPv6Address, tuple[IPv6Address, ...]]:
    """Compute currently active parents from edge expiry data.

    Args:
        edge_expiry: Map of (target, parent) to expiry deadline.
        now: Current monotonic time.

    Returns:
        Map of target to tuple of active parent addresses.
    """
    active: dict[IPv6Address, list[IPv6Address]] = {}
    for (target, parent), deadline in edge_expiry.items():
        if deadline is None or deadline > now:
            active.setdefault(target, []).append(parent)
    return {target: tuple(sorted(parents)) for target, parents in active.items()}


def compute_deadline(
    lifetime: int,
    now: float,
    lifetime_unit_seconds: float,
) -> float | None:
    """Compute the expiry deadline for a path lifetime.

    Args:
        lifetime: Path lifetime value (0-255).
        now: Current monotonic time.
        lifetime_unit_seconds: Duration of one lifetime unit.

    Returns:
        Expiry deadline, or None for infinite lifetime (255).
    """
    if lifetime == 255:
        return None
    if lifetime_unit_seconds <= 0:
        raise DaoError("finite Path Lifetime requires a positive lifetime unit")
    return now + lifetime * lifetime_unit_seconds


def make_freshness_room(
    freshness: dict[IPv6Address, Freshness],
    path_sequences: dict[IPv6Address, int],
    candidates: dict[IPv6Address, tuple[Candidate, ...]],
    candidate_timing: dict[tuple[IPv6Address, IPv6Address], tuple[float, float | None]],
    descriptors: dict[IPv6Address, int | None],
    parents: dict[IPv6Address, tuple[IPv6Address, ...]],
    expiry: dict[tuple[IPv6Address, IPv6Address], float | None],
    now: float,
    max_targets: int,
    protected: Iterable[IPv6Address],
) -> None:
    """Reclaim space in freshness tracking if at capacity.

    Modifies the provided dictionaries in place to remove reclaimable entries.

    Args:
        freshness: Freshness state map (modified in place).
        path_sequences: Path sequence map (modified in place).
        candidates: Candidate map (modified in place).
        candidate_timing: Candidate timing map (modified in place).
        descriptors: Descriptor map (modified in place).
        parents: Parent map (modified in place).
        expiry: Edge expiry map (modified in place).
        now: Current monotonic time.
        max_targets: Maximum number of targets to track.
        protected: Targets that cannot be reclaimed.
    """
    if len(freshness) < max_targets:
        return
    reclaimable = [
        (record.updated_at, int(target), target)
        for target, record in freshness.items()
        if target not in protected and record.reclaimable(now)
    ]
    if not reclaimable:
        raise DaoError("Path Sequence capacity exceeded", reason="capacity")
    target = min(reclaimable)[2]
    freshness.pop(target)
    path_sequences.pop(target, None)
    candidates.pop(target, None)
    descriptors.pop(target, None)
    parents.pop(target, None)
    for edge in [edge for edge in candidate_timing if edge[0] == target]:
        candidate_timing.pop(edge)
    for edge in [edge for edge in expiry if edge[0] == target]:
        expiry.pop(edge)
