# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO manager for non-storing mode (RFC 6550, spec section 8.5).

In non-storing mode every node sends a DAO directly to the root advertising
itself as an RPL Target and its preferred parent as Transit Information. The
root chains these (target -> parent) edges into a full source route for each
node and installs it in the routing table.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from typing import Any

from lichen.ipv6 import to_ipv6
from lichen.rpl.dao_paths import build_routes, contains_cycle, path_control_rank, select_path
from lichen.rpl.dao_state import compute_active_parents, compute_deadline, make_freshness_room
from lichen.rpl.dao_types import (
    DEFAULT_FRESHNESS_RETENTION_SECONDS,
    TARGET_DESCRIPTOR,
    Candidate,
    DaoError,
    DaoOutcome,
    Freshness,
    RplTarget,
    TransitInformation,
    Update,
    sequence_relation,
)
from lichen.rpl.messages import DAO, DAOAck, RplOptionType
from lichen.rpl.routing import RoutingTable


@dataclass
class DaoManager:
    """Build DAOs and atomically maintain complete root-side candidate snapshots."""

    node_address: IPv6Address
    is_root: bool = False
    rpl_instance_id: int = 0
    dodag_id: IPv6Address | None = None
    routing_table: RoutingTable = field(default_factory=RoutingTable)
    lifetime_unit_seconds: float = 60.0
    pcs: int = 7
    max_targets: int = 256
    max_candidates: int = 256
    max_routes: int = 256
    max_candidates_per_target: int | None = None
    freshness_retention_seconds: float = DEFAULT_FRESHNESS_RETENTION_SECONDS
    clock: Callable[[], float] = time.monotonic
    _dao_sequence: int = 240
    _path_sequence: int = 240
    _last_logical_update: tuple[IPv6Address, int] | None = field(
        default=None, init=False, repr=False
    )
    _parent_map: dict[IPv6Address, tuple[IPv6Address, ...]] = field(default_factory=dict)
    _candidate_map: dict[IPv6Address, tuple[Candidate, ...]] = field(default_factory=dict)
    _descriptors: dict[IPv6Address, int | None] = field(default_factory=dict)
    _path_sequences: dict[IPv6Address, int] = field(default_factory=dict)
    _freshness: dict[IPv6Address, Freshness] = field(default_factory=dict)
    _candidate_timing: dict[tuple[IPv6Address, IPv6Address], tuple[float, float | None]] = field(
        default_factory=dict
    )
    _edge_expiry: dict[tuple[IPv6Address, IPv6Address], float | None] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.node_address = to_ipv6(self.node_address)
        if self.dodag_id is not None:
            self.dodag_id = to_ipv6(self.dodag_id)
        if not 0 <= self.pcs <= 7:
            raise ValueError("PCS must be between 0 and 7")
        if self.max_candidates_per_target is None:
            self.max_candidates_per_target = self.max_candidates
        if (
            min(
                self.max_targets,
                self.max_candidates,
                self.max_routes,
                self.max_candidates_per_target,
            )
            < 1
        ):
            raise ValueError("DAO capacities must be positive")
        if self.freshness_retention_seconds < 0:
            raise ValueError("freshness retention must not be negative")

    def build_dao(self, parent_address: IPv6Address | str, *, ack_requested: bool = False) -> DAO:
        """Build a new logical DAO and advance both lollipop counters."""
        return self._build_dao(parent_address, 255, True, ack_requested)

    def build_dao_with_lifetime(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        *,
        ack_requested: bool = False,
    ) -> DAO:
        """Build a new logical DAO update with an explicit Path Lifetime."""
        return self._build_dao(parent_address, path_lifetime, True, ack_requested)

    def build_dao_copy_with_lifetime(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        *,
        ack_requested: bool = False,
    ) -> DAO:
        """Build a logical copy while retaining the current Path Sequence."""
        return self._build_dao(parent_address, path_lifetime, False, ack_requested)

    def _build_dao(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        advance_path_sequence: bool,
        ack_requested: bool,
    ) -> DAO:
        if not 0 <= path_lifetime <= 255:
            raise ValueError("Path Lifetime must fit one octet")
        parent = to_ipv6(parent_address)
        logical_update = (parent, path_lifetime)
        if not advance_path_sequence and logical_update != self._last_logical_update:
            raise DaoError("DAO copy does not match the last logical update")

        dao_sequence = self._increment_sequence(self._dao_sequence)
        path_sequence = self._path_sequence
        if advance_path_sequence:
            path_sequence = self._increment_sequence(path_sequence)
        dao = DAO(
            rpl_instance_id=self.rpl_instance_id,
            dao_sequence=dao_sequence,
            dodag_id=self.dodag_id,
            ack_requested=ack_requested,
            options=[
                RplTarget(self.node_address).to_option(),
                TransitInformation(
                    parent,
                    path_sequence=path_sequence,
                    path_lifetime=path_lifetime,
                ).to_option(),
            ],
        )
        self._dao_sequence = dao_sequence
        self._path_sequence = path_sequence
        if advance_path_sequence:
            self._last_logical_update = logical_update
        return dao

    def process_dao(self, dao: DAO) -> DAOAck | None:
        """Root-side: record the target/parent edge and rebuild routes.

        Returns a DAO-ACK when the DAO requested one (K flag), else ``None``.
        """
        if not self.is_root:
            raise DaoError("process_dao is only valid on the root")
        now = self.clock()
        return self.process_dao_at(dao, now)

    def process_dao_at(self, dao: DAO, now_seconds: float) -> DAOAck | None:
        """Validate and atomically apply a DAO at a deterministic monotonic time."""
        self._apply_dao_at(dao, now_seconds)
        if dao.ack_requested:
            return self.build_dao_ack(dao)
        return None

    def evaluate_dao_at(self, dao: DAO, now_seconds: float) -> DaoOutcome:
        """Apply a DAO and return a structured rejection instead of raising."""
        try:
            return self._apply_dao_at(dao, now_seconds)
        except DaoError as exc:
            return DaoOutcome(False, False, False, exc.reason)

    def _apply_dao_at(self, dao: DAO, now_seconds: float) -> DaoOutcome:
        if not self.is_root:
            raise DaoError("process_dao is only valid on the root")
        # SECURITY: RFC 6550 Section 9.5 requires filtering DAOs by RPL Instance ID.
        # Accepting DAOs from a different instance could corrupt the routing table.
        if dao.rpl_instance_id != self.rpl_instance_id:
            raise DaoError(
                f"DAO instance ID {dao.rpl_instance_id} != {self.rpl_instance_id}",
                reason="instance_mismatch",
            )
        if dao.flags != 0 or dao.reserved != 0:
            raise DaoError("DAO reserved base fields must be zero", reason="malformed_group")
        if self.dodag_id is not None and dao.dodag_id is not None and dao.dodag_id != self.dodag_id:
            raise DaoError(
                f"DAO DODAGID {dao.dodag_id} != {self.dodag_id}",
                reason="dodag_mismatch",
            )

        updates = self._extract_updates(dao)
        incoming: dict[IPv6Address, tuple[Candidate, ...]] = {}
        sequences: dict[IPv6Address, int] = {}
        descriptors: dict[IPv6Address, int | None] = {}
        for update in updates:
            sequences.setdefault(update.target, update.path_sequence)
            descriptors.setdefault(update.target, update.descriptor)
            incoming.setdefault(update.target, ())
            incoming[update.target] += (update.candidate,)
        incoming = {
            target: tuple(sorted(set(candidates))) for target, candidates in incoming.items()
        }
        assert self.max_candidates_per_target is not None
        for snapshot in incoming.values():
            if len(snapshot) > self.max_candidates_per_target:
                raise DaoError("per-target candidate capacity exceeded", reason="capacity")

        parents = compute_active_parents(self._edge_expiry, now_seconds)
        expiry = {
            edge: deadline
            for edge, deadline in self._edge_expiry.items()
            if deadline is None or deadline > now_seconds
        }
        candidates = dict(self._candidate_map)
        retained_descriptors = dict(self._descriptors)
        candidate_timing = dict(self._candidate_timing)
        path_sequences = dict(self._path_sequences)
        freshness = dict(self._freshness)
        changed: set[IPv6Address] = set()
        reason = "semantic_replay"

        for target, snapshot in incoming.items():
            sequence = sequences[target]
            previous = path_sequences.get(target)
            if previous is not None:
                if sequence == previous:
                    if (
                        candidates.get(target) != snapshot
                        or retained_descriptors.get(target) != descriptors[target]
                    ):
                        raise DaoError(
                            "equal Path Sequence changed candidate snapshot",
                            reason="equal_sequence_mutation",
                        )
                    if (
                        not changed
                        and target not in parents
                        and any(candidate.path_lifetime != 0 for candidate in snapshot)
                    ):
                        reason = "equal_expired_no_revival"
                    continue
                relation = sequence_relation(sequence, previous)
                if relation != "newer":
                    rejection = (
                        "stale_withdrawal"
                        if relation == "stale"
                        and all(candidate.path_lifetime == 0 for candidate in snapshot)
                        else f"{relation}_sequence"
                    )
                    raise DaoError("stale or incomparable Path Sequence", reason=rejection)

            if all(candidate.path_lifetime == 0 for candidate in snapshot):
                reason = "withdrawn"
            elif previous is None:
                reason = "installed"
            elif target not in parents and any(
                candidate.path_lifetime != 0 for candidate in candidates.get(target, ())
            ):
                reason = "reinstalled"
            else:
                reason = "replaced"

            if previous is None:
                make_freshness_room(
                    freshness,
                    path_sequences,
                    candidates,
                    candidate_timing,
                    retained_descriptors,
                    parents,
                    expiry,
                    now_seconds,
                    self.max_targets,
                    incoming.keys(),
                )
                freshness[target] = Freshness(
                    sequence,
                    None,
                    now_seconds + self.freshness_retention_seconds,
                    now_seconds,
                )
            candidates[target] = snapshot
            retained_descriptors[target] = descriptors[target]
            path_sequences[target] = sequence
            parents.pop(target, None)
            expiry = {edge: deadline for edge, deadline in expiry.items() if edge[0] != target}
            candidate_timing = {
                edge: timing for edge, timing in candidate_timing.items() if edge[0] != target
            }
            changed.add(target)

        for target in changed:
            active: list[IPv6Address] = []
            active_until: float | None = now_seconds
            for candidate in incoming[target]:
                if path_control_rank(candidate.path_control, self.pcs) is None:
                    raise DaoError(
                        "candidate has no active Path Control bit",
                        reason="path_control",
                    )
                if candidate.path_lifetime == 0:
                    candidate_timing[(target, candidate.parent)] = (now_seconds, None)
                    continue
                deadline = compute_deadline(
                    candidate.path_lifetime, now_seconds, self.lifetime_unit_seconds
                )
                active.append(candidate.parent)
                expiry[(target, candidate.parent)] = deadline
                candidate_timing[(target, candidate.parent)] = (now_seconds, deadline)
                if deadline is None:
                    active_until = None
                elif active_until is not None:
                    active_until = max(active_until, deadline)
            if active:
                parents[target] = tuple(sorted(active))
            retain_base = now_seconds if active_until is None else max(now_seconds, active_until)
            freshness[target] = Freshness(
                sequences[target],
                active_until,
                retain_base + self.freshness_retention_seconds,
                now_seconds,
            )

        if len(path_sequences) > self.max_targets:
            raise DaoError("Path Sequence capacity exceeded", reason="capacity")
        if len(expiry) > self.max_candidates:
            raise DaoError("active candidate capacity exceeded", reason="capacity")
        if contains_cycle(parents):
            raise DaoError("candidate graph contains a cycle", reason="cycle")

        host_routes = build_routes(self.node_address, parents, candidates, self.pcs)
        routes = self._merge_prefix_routes(host_routes)
        if len(routes) > self.max_routes:
            raise DaoError("route capacity exceeded", reason="capacity")

        state_changed = (
            bool(changed)
            or parents != self._parent_map
            or expiry != self._edge_expiry
            or host_routes != self._existing_host_routes()
        )

        self._parent_map = parents
        self._candidate_map = candidates
        self._descriptors = retained_descriptors
        self._candidate_timing = candidate_timing
        self._path_sequences = path_sequences
        self._freshness = freshness
        self._edge_expiry = expiry
        self.routing_table.replace_routes(routes)
        return DaoOutcome(True, state_changed, False, reason)

    def _existing_host_routes(self) -> dict[IPv6Address, list[IPv6Address]]:
        return self.routing_table.routes()

    def _merge_prefix_routes(
        self, host_routes: dict[IPv6Address, list[IPv6Address]]
    ) -> dict[IPv6Address, list[IPv6Address]]:
        merged = dict(host_routes)
        for rt, entry in self.routing_table._routes.items():
            if rt.prefix_len < 128 and entry.is_usable():
                merged[rt.prefix] = list(entry.path)
        return merged

    def expire_routes(self, now_seconds: float | None = None) -> bool:
        """Remove expired active edges and routes while retaining snapshot tombstones."""
        now = self.clock() if now_seconds is None else now_seconds
        parents = compute_active_parents(self._edge_expiry, now)
        expiry = {
            edge: deadline
            for edge, deadline in self._edge_expiry.items()
            if deadline is None or deadline > now
        }
        host_routes = build_routes(self.node_address, parents, self._candidate_map, self.pcs)
        routes = self._merge_prefix_routes(host_routes)
        changed = (
            parents != self._parent_map
            or expiry != self._edge_expiry
            or routes != self.routing_table.routes()
        )
        self._parent_map = parents
        self._edge_expiry = expiry
        self.routing_table.replace_routes(routes)
        return changed

    def remove_edge(self, target: IPv6Address | str) -> bool:
        """Remove a target's active candidates while retaining freshness state."""
        target = to_ipv6(target)
        if target not in self._parent_map:
            return False
        now = self.clock()
        self._parent_map.pop(target)
        self._edge_expiry = {
            edge: deadline for edge, deadline in self._edge_expiry.items() if edge[0] != target
        }
        host_routes = build_routes(
            self.node_address, self._parent_map, self._candidate_map, self.pcs
        )
        routes = self._merge_prefix_routes(host_routes)
        self.routing_table.replace_routes(routes)
        current = self._freshness.get(target)
        if current is not None:
            self._freshness[target] = Freshness(
                current.sequence,
                now,
                now + self.freshness_retention_seconds,
                now,
            )
        return True

    def route_state_snapshot(self, sequence_authority: IPv6Address | str) -> dict[str, Any]:
        """Return canonical retained route state in route-vector form."""
        authority = to_ipv6(sequence_authority).packed.hex()
        targets: list[dict[str, Any]] = []
        for target in sorted(self._freshness):
            snapshot = self._candidate_map[target]
            if snapshot and all(candidate.path_lifetime == 0 for candidate in snapshot):
                disposition = "withdrawn"
            elif target in self._parent_map:
                disposition = "active"
            else:
                disposition = "expired"
            candidate_records: list[dict[str, Any]] = []
            for candidate in snapshot:
                installed_at, expires_at = self._candidate_timing[(target, candidate.parent)]
                candidate_records.append(
                    {
                        "parent": candidate.parent.packed.hex(),
                        "external": candidate.external,
                        "path_control": candidate.path_control,
                        "path_lifetime": candidate.path_lifetime,
                        "installed_at": installed_at,
                        "expires_at": expires_at,
                    }
                )
            targets.append(
                {
                    "prefix_length": 128,
                    "prefix": target.packed.hex(),
                    "descriptor": self._descriptors[target],
                    "sequence_authority": authority,
                    "path_sequence": self._freshness[target].sequence,
                    "disposition": disposition,
                    "candidates": candidate_records,
                    "selected_candidate": self._snapshot_selected_candidate(target, disposition),
                }
            )
        route_records: list[dict[str, Any]] = []
        for target in sorted(self.routing_table.routes()):
            selected = select_path(
                target, self.node_address, self._parent_map, self._candidate_map, self.pcs, set()
            )
            if selected is None:
                raise AssertionError("installed route has no selected candidate")
            path, candidate, _ = selected
            installed_at, expires_at = self._candidate_timing[(target, candidate.parent)]
            route_records.append(
                {
                    "prefix_length": 128,
                    "prefix": target.packed.hex(),
                    "path": [hop.packed.hex() for hop in path],
                    "path_lifetime": candidate.path_lifetime,
                    "installed_at": installed_at,
                    "expires_at": expires_at,
                }
            )
        return {
            "targets": targets,
            "routing_table": {"routes": route_records},
        }

    def routing_table_snapshot(self) -> dict[str, list[str]]:
        """Return exact installed complete paths keyed by target hex."""
        return {
            target.packed.hex(): [hop.packed.hex() for hop in path]
            for target, path in sorted(self.routing_table.routes().items())
        }

    def build_dao_ack(self, dao: DAO, status: int = 0) -> DAOAck:
        return DAOAck(
            rpl_instance_id=dao.rpl_instance_id,
            dao_sequence=dao.dao_sequence,
            status=status,
            dodag_id=dao.dodag_id,
        )

    @staticmethod
    def _extract_edge(dao: DAO) -> tuple[IPv6Address, IPv6Address]:
        """Compatibility helper for callers expecting one target/parent pair."""
        updates = DaoManager._extract_updates(dao)
        if len(updates) != 1:
            raise DaoError("DAO does not contain exactly one target/parent edge")
        return updates[0].target, updates[0].candidate.parent

    @staticmethod
    def _extract_updates(dao: DAO) -> list[Update]:
        """Parse Target/Transit groups and expand their Cartesian products."""
        updates: list[Update] = []
        seen_targets: set[IPv6Address] = set()
        targets: list[tuple[IPv6Address, int | None]] = []
        transits: dict[IPv6Address, TransitInformation] = {}
        in_transits = False
        descriptor_allowed = False

        def finish_group() -> None:
            nonlocal targets, transits, in_transits, descriptor_allowed
            if not targets or not transits:
                raise DaoError(
                    "DAO group missing RPL Target or Transit Information",
                    reason="malformed_group",
                )
            first = next(iter(transits.values()))
            for transit in transits.values():
                if (
                    transit.path_sequence != first.path_sequence
                    or transit.path_lifetime != first.path_lifetime
                    or transit.external != first.external
                ):
                    raise DaoError(
                        "inconsistent Transit group semantics",
                        reason="inconsistent_group",
                    )
            for target, descriptor in targets:
                for transit in transits.values():
                    parent = transit.parent_address
                    if parent is None:
                        if dao.dodag_id is None:
                            raise DaoError(
                                "Transit without parent address and no DODAG ID",
                                reason="malformed_group",
                            )
                        parent = dao.dodag_id
                    updates.append(
                        Update(
                            target,
                            Candidate(
                                parent,
                                transit.path_control,
                                transit.path_lifetime,
                                transit.external,
                            ),
                            transit.path_sequence,
                            descriptor,
                        )
                    )
            targets = []
            transits = {}
            in_transits = False
            descriptor_allowed = False

        for opt in dao.options:
            if opt.type == RplOptionType.RPL_TARGET:
                if in_transits:
                    finish_group()
                parsed_target = RplTarget.from_option(opt)
                if parsed_target.prefix_length != 128:
                    raise DaoError("only /128 RPL Targets are routable by this table")
                if parsed_target.target in seen_targets:
                    raise DaoError("duplicate RPL Target", reason="duplicate_target")
                seen_targets.add(parsed_target.target)
                targets.append((parsed_target.target, None))
                descriptor_allowed = True
            elif opt.type == TARGET_DESCRIPTOR:
                if not descriptor_allowed or in_transits:
                    raise DaoError(
                        "RPL Target Descriptor must immediately follow one Target",
                        reason="malformed_descriptor",
                    )
                if len(opt.data) != 4:
                    raise DaoError(
                        "RPL Target Descriptor must contain four octets",
                        reason="malformed_descriptor",
                    )
                targets[-1] = (targets[-1][0], int.from_bytes(opt.data, "big"))
                descriptor_allowed = False
            elif opt.type == RplOptionType.TRANSIT_INFORMATION:
                if not targets:
                    raise DaoError(
                        "Transit Information before an RPL Target",
                        reason="malformed_group",
                    )
                in_transits = True
                descriptor_allowed = False
                parsed_transit = TransitInformation.from_option(opt)
                transit_parent = parsed_transit.parent_address
                if transit_parent is None:
                    if dao.dodag_id is None:
                        raise DaoError(
                            "Transit without parent address and no DODAG ID",
                            reason="malformed_group",
                        )
                    transit_parent = dao.dodag_id
                existing = transits.get(transit_parent)
                if existing is not None and existing != parsed_transit:
                    raise DaoError(
                        "conflicting duplicate Transit candidate",
                        reason="inconsistent_group",
                    )
                transits[transit_parent] = parsed_transit
            else:
                raise DaoError("unsupported DAO option", reason="malformed_group")
        if targets or transits:
            finish_group()
        if not updates:
            raise DaoError(
                "DAO missing RPL Target or Transit Information",
                reason="malformed_group",
            )
        return updates

    def _snapshot_selected_candidate(
        self,
        target: IPv6Address,
        disposition: str,
    ) -> dict[str, Any] | None:
        if disposition != "active":
            return None
        selected = select_path(
            target, self.node_address, self._parent_map, self._candidate_map, self.pcs, set()
        )
        if selected is None:
            return None
        path, candidate, rank = selected
        return {
            "parent": candidate.parent.packed.hex(),
            "preference_subfield": rank + 1,
            "path": [hop.packed.hex() for hop in path],
        }

    @staticmethod
    def _increment_sequence(sequence: int) -> int:
        return 0 if sequence in (127, 255) else sequence + 1
