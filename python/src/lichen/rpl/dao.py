# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any

from lichen.ipv6 import to_ipv6
from lichen.rpl.messages import DAO, DAOAck, RplOption, RplOptionType
from lichen.rpl.routing import MAX_ROUTE_HOPS, RoutingError, RoutingTable

_TARGET_DESCRIPTOR = 9  # RPL Target Descriptor option type (RFC 6550 §6.7.9)

"""RPL DAO handling for non-storing mode (RFC 6550, spec section 8.5).

In non-storing mode every node sends a DAO directly to the root advertising
itself as an RPL Target and its preferred parent as Transit Information. The
root chains these (target -> parent) edges into a full source route for each
node and installs it in the routing table.

This module provides the RPL Target (type 5) and Transit Information (type 6)
option codecs and a :class:`DaoManager` for both sending (non-root) and
receiving (root) sides.
"""

_MAX_CHAIN = 64  # loop / runaway guard when assembling source routes

_DEFAULT_FRESHNESS_RETENTION_SECONDS = 3600.0
_MAX_ROUTE_HOPS = MAX_ROUTE_HOPS  # alias for vector oracle compatibility


class DaoError(Exception):
    """Raised on malformed, stale, or unrouteable DAO state."""

    def __init__(self, message: str, *, reason: str = "rejected") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass
class RplTarget:
    """RPL Target option (RFC 6550 6.7.7); a full /128 target by default."""

    target: IPv6Address
    prefix_length: int = 128

    def __post_init__(self) -> None:
        if not (0 <= self.prefix_length <= 128):
            raise DaoError(f"prefix_length must be between 0 and 128, got {self.prefix_length}")

    def to_option(self) -> RplOption:
        if not (0 <= self.prefix_length <= 128):
            raise DaoError(f"prefix_length must be between 0 and 128, got {self.prefix_length}")
        nbytes = (self.prefix_length + 7) // 8
        data = bytes([0, self.prefix_length]) + self.target.packed[:nbytes]
        return RplOption(RplOptionType.RPL_TARGET, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> RplTarget:
        if opt.type != RplOptionType.RPL_TARGET:
            raise DaoError(f"not an RPL Target option: type {opt.type}")
        if len(opt.data) < 2:
            raise DaoError("RPL Target option too short")
        prefix_length = opt.data[1]
        if not (0 <= prefix_length <= 128):
            raise DaoError(f"prefix_length must be between 0 and 128, got {prefix_length}")
        nbytes = (prefix_length + 7) // 8
        if len(opt.data) != 2 + nbytes:
            raise DaoError("RPL Target option has non-canonical length")
        prefix = bytearray(opt.data[2:])
        if prefix_length % 8 and prefix:
            prefix[-1] &= 0xFF << (8 - prefix_length % 8)
        return cls(IPv6Address(bytes(prefix).ljust(16, b"\x00")), prefix_length)


@dataclass
class TransitInformation:
    """Transit Information option (RFC 6550 6.7.8) carrying the parent address.

    Per RFC 6550, the Parent Address field is only present when the E (External)
    flag is set in the first byte.
    """

    parent_address: IPv6Address | None = None
    path_lifetime: int = 255
    path_sequence: int = 0
    path_control: int = 0x80
    external: bool = False

    def to_option(self) -> RplOption:
        if self.external:
            raise DaoError("external encoding not supported")
        e_flag = 0x80 if self.parent_address is not None else 0x00
        data = bytes([e_flag, self.path_control, self.path_sequence, self.path_lifetime])
        if self.parent_address is not None:
            data += self.parent_address.packed
        return RplOption(RplOptionType.TRANSIT_INFORMATION, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> TransitInformation:
        if opt.type != RplOptionType.TRANSIT_INFORMATION:
            raise DaoError(f"not a Transit Information option: type {opt.type}")
        if len(opt.data) < 4:
            raise DaoError("Transit Information option too short")
        if (opt.data[0] & 0x7F) != 0:
            raise DaoError("flags must be zero")
        e_flag = opt.data[0] & 0x80
        if e_flag:
            if len(opt.data) < 4 + 16:
                raise DaoError("Transit Information option must contain parent address")
            parent = IPv6Address(opt.data[4:20])
        else:
            parent = None
        return cls(
            parent_address=parent,
            path_control=opt.data[1],
            path_sequence=opt.data[2],
            path_lifetime=opt.data[3],
            external=False,
        )


@dataclass(frozen=True, order=True)
class _Candidate:
    parent: IPv6Address
    path_control: int
    path_lifetime: int
    external: bool


@dataclass(frozen=True)
class _Update:
    target: IPv6Address
    candidate: _Candidate
    path_sequence: int
    descriptor: int | None


@dataclass(frozen=True)
class _Freshness:
    sequence: int
    active_until: float | None
    retain_until: float
    updated_at: float

    def reclaimable(self, now: float) -> bool:
        return (
            self.active_until is not None and self.active_until <= now and self.retain_until <= now
        )


@dataclass(frozen=True)
class DaoOutcome:
    """Non-throwing result for post-provenance route-state processing."""

    accepted: bool
    state_changed: bool
    refreshed: bool
    reason: str


def _sequence_is_newer(new: int, old: int) -> bool:
    """Compare RFC 6550 eight-bit lollipop counters."""
    if new < 128 and old < 128:
        return 1 <= ((new - old) & 0x7F) <= 16
    if new < 128 <= old:
        return 256 + new - old <= 16
    if old < 128 <= new:
        return 256 + old - new > 16
    return 1 <= ((new - old) & 0xFF) <= 16


def _sequence_relation(new: int, old: int) -> str:
    if new == old:
        return "equal"
    if _sequence_is_newer(new, old):
        return "newer"
    if _sequence_is_newer(old, new):
        return "stale"
    return "incomparable"


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
    freshness_retention_seconds: float = _DEFAULT_FRESHNESS_RETENTION_SECONDS
    clock: Callable[[], float] = time.monotonic
    _dao_sequence: int = 240
    _path_sequence: int = 240
    _last_logical_update: tuple[IPv6Address, int] | None = field(
        default=None, init=False, repr=False
    )
    _parent_map: dict[IPv6Address, tuple[IPv6Address, ...]] = field(default_factory=dict)
    _candidate_map: dict[IPv6Address, tuple[_Candidate, ...]] = field(default_factory=dict)
    _descriptors: dict[IPv6Address, int | None] = field(default_factory=dict)
    _path_sequences: dict[IPv6Address, int] = field(default_factory=dict)
    _freshness: dict[IPv6Address, _Freshness] = field(default_factory=dict)
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
        incoming: dict[IPv6Address, tuple[_Candidate, ...]] = {}
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

        parents = self._active_parents(now_seconds)
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
                    if not changed and target not in parents and any(
                        candidate.path_lifetime != 0 for candidate in snapshot
                    ):
                        reason = "equal_expired_no_revival"
                    continue
                relation = _sequence_relation(sequence, previous)
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
                self._make_freshness_room(
                    freshness,
                    path_sequences,
                    candidates,
                    candidate_timing,
                    retained_descriptors,
                    parents,
                    expiry,
                    now_seconds,
                    incoming.keys(),
                )
                freshness[target] = _Freshness(
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
                if self._path_control_rank(candidate.path_control) is None:
                    raise DaoError(
                        "candidate has no active Path Control bit",
                        reason="path_control",
                    )
                if candidate.path_lifetime == 0:
                    candidate_timing[(target, candidate.parent)] = (now_seconds, None)
                    continue
                deadline = self._deadline(candidate.path_lifetime, now_seconds)
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
            freshness[target] = _Freshness(
                sequences[target],
                active_until,
                retain_base + self.freshness_retention_seconds,
                now_seconds,
            )

        if len(path_sequences) > self.max_targets:
            raise DaoError("Path Sequence capacity exceeded", reason="capacity")
        if len(expiry) > self.max_candidates:
            raise DaoError("active candidate capacity exceeded", reason="capacity")
        if self._contains_cycle(parents):
            raise DaoError("candidate graph contains a cycle", reason="cycle")

        routes = self._build_routes(parents, candidates)
        if len(routes) > self.max_routes:
            raise DaoError("route capacity exceeded", reason="capacity")

        state_changed = (
            bool(changed)
            or parents != self._parent_map
            or expiry != self._edge_expiry
            or routes != self.routing_table.routes()
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

    def expire_routes(self, now_seconds: float | None = None) -> bool:
        """Remove expired active edges and routes while retaining snapshot tombstones."""
        now = self.clock() if now_seconds is None else now_seconds
        parents = self._active_parents(now)
        expiry = {
            edge: deadline
            for edge, deadline in self._edge_expiry.items()
            if deadline is None or deadline > now
        }
        routes = self._build_routes(parents, self._candidate_map)
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
        routes = self._build_routes(self._parent_map, self._candidate_map)
        self.routing_table.replace_routes(routes)
        current = self._freshness.get(target)
        if current is not None:
            self._freshness[target] = _Freshness(
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
            selected = self._select_path(target, self._parent_map, self._candidate_map, set())
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
    def _extract_updates(dao: DAO) -> list[_Update]:
        """Parse Target/Transit groups and expand their Cartesian products."""
        updates: list[_Update] = []
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
                        _Update(
                            target,
                            _Candidate(
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
            elif opt.type == _TARGET_DESCRIPTOR:
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

    def _make_freshness_room(
        self,
        freshness: dict[IPv6Address, _Freshness],
        path_sequences: dict[IPv6Address, int],
        candidates: dict[IPv6Address, tuple[_Candidate, ...]],
        candidate_timing: dict[tuple[IPv6Address, IPv6Address], tuple[float, float | None]],
        descriptors: dict[IPv6Address, int | None],
        parents: dict[IPv6Address, tuple[IPv6Address, ...]],
        expiry: dict[tuple[IPv6Address, IPv6Address], float | None],
        now: float,
        protected: Iterable[IPv6Address],
    ) -> None:
        if len(freshness) < self.max_targets:
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

    def _deadline(self, lifetime: int, now: float) -> float | None:
        if lifetime == 255:
            return None
        if self.lifetime_unit_seconds <= 0:
            raise DaoError("finite Path Lifetime requires a positive lifetime unit")
        return now + lifetime * self.lifetime_unit_seconds

    def _active_parents(self, now: float) -> dict[IPv6Address, tuple[IPv6Address, ...]]:
        active: dict[IPv6Address, list[IPv6Address]] = {}
        for (target, parent), deadline in self._edge_expiry.items():
            if deadline is None or deadline > now:
                active.setdefault(target, []).append(parent)
        return {target: tuple(sorted(parents)) for target, parents in active.items()}

    def _path_control_rank(self, control: int) -> int | None:
        active_mask = (0xFF << (7 - self.pcs)) & 0xFF
        masked = control & active_mask
        for rank, shift in enumerate((6, 4, 2, 0)):
            if masked & (0x03 << shift):
                return rank
        return None

    def _snapshot_selected_candidate(
        self,
        target: IPv6Address,
        disposition: str,
    ) -> dict[str, Any] | None:
        if disposition != "active":
            return None
        selected = self._select_path(target, self._parent_map, self._candidate_map, set())
        if selected is None:
            return None
        path, candidate, rank = selected
        return {
            "parent": candidate.parent.packed.hex(),
            "preference_subfield": rank + 1,
            "path": [hop.packed.hex() for hop in path],
        }

    @staticmethod
    def _contains_cycle(parents: dict[IPv6Address, tuple[IPv6Address, ...]]) -> bool:
        visiting: set[IPv6Address] = set()
        visited: set[IPv6Address] = set()

        def visit(node: IPv6Address) -> bool:
            if node in visiting:
                return True
            if node in visited:
                return False
            visiting.add(node)
            if any(parent in parents and visit(parent) for parent in parents.get(node, ())):
                return True
            visiting.remove(node)
            visited.add(node)
            return False

        return any(visit(target) for target in parents)

    def _build_routes(
        self,
        parents: dict[IPv6Address, tuple[IPv6Address, ...]],
        candidates: dict[IPv6Address, tuple[_Candidate, ...]],
    ) -> dict[IPv6Address, list[IPv6Address]]:
        routes: dict[IPv6Address, list[IPv6Address]] = {}
        for target in sorted(parents):
            path = self._assemble_path(target, parents, candidates, set())
            if path:
                routes[target] = path
        return routes

    def _assemble_path(
        self,
        target: IPv6Address,
        parents: dict[IPv6Address, tuple[IPv6Address, ...]],
        candidates: dict[IPv6Address, tuple[_Candidate, ...]],
        visiting: set[IPv6Address],
    ) -> list[IPv6Address] | None:
        selected = self._select_path(target, parents, candidates, visiting)
        return None if selected is None else selected[0]

    def _select_path(
        self,
        target: IPv6Address,
        parents: dict[IPv6Address, tuple[IPv6Address, ...]],
        candidates: dict[IPv6Address, tuple[_Candidate, ...]],
        visiting: set[IPv6Address],
    ) -> tuple[list[IPv6Address], _Candidate, int] | None:
        if target == self.node_address:
            return None
        if target in visiting or len(visiting) >= _MAX_CHAIN:
            return None
        visiting = visiting | {target}
        choices: list[tuple[int, tuple[int, ...], list[IPv6Address], _Candidate]] = []
        active_parents = set(parents.get(target, ()))
        for candidate in candidates.get(target, ()):
            if candidate.parent not in active_parents:
                continue
            rank = self._path_control_rank(candidate.path_control)
            if rank is None:
                continue
            if candidate.parent == self.node_address:
                parent_path: list[IPv6Address] = []
            else:
                parent_selected = self._select_path(candidate.parent, parents, candidates, visiting)
                if parent_selected is None:
                    continue
                parent_path = parent_selected[0]
            path = [*parent_path, target]
            if len(path) > _MAX_ROUTE_HOPS:
                raise DaoError("route exceeds maximum hop count", reason="route_too_long")
            choices.append((rank, tuple(int(hop) for hop in path), path, candidate))
        if not choices:
            return None
        rank, _, path, candidate = min(choices)
        return path, candidate, rank

    @staticmethod
    def _increment_sequence(sequence: int) -> int:
        return 0 if sequence in (127, 255) else sequence + 1


def run_route_state_vectors(path: str | Path) -> DaoManager:
    """Apply canonical literal DAO bytes and verify production route-state outcomes."""
    document: dict[str, Any] = json.loads(Path(path).read_text())
    if document.get("vector_type") != "rpl_route_state":
        raise ValueError("not an RPL route-state vector document")
    oracle: dict[str, Any] = document["oracle"]
    limits: dict[str, int] = oracle["limits"]
    authority = IPv6Address(bytes.fromhex(oracle["sequence_authority"]))
    manager = DaoManager(
        node_address=IPv6Address(bytes.fromhex(oracle["dodag_id"])),
        is_root=True,
        rpl_instance_id=oracle["rpl_instance_id"],
        dodag_id=IPv6Address(bytes.fromhex(oracle["dodag_id"])),
        lifetime_unit_seconds=oracle["lifetime_unit_seconds"],
        pcs=oracle["path_control_size"],
        max_targets=limits["max_targets"],
        max_candidates=limits["max_candidates"],
        max_candidates_per_target=limits.get("max_candidates_per_target", limits["max_candidates"]),
        freshness_retention_seconds=oracle["freshness_retention_seconds"],
    )
    tx_manager = DaoManager(
        node_address=authority,
        rpl_instance_id=oracle["rpl_instance_id"],
        dodag_id=IPv6Address(bytes.fromhex(oracle["dodag_id"])),
    )
    for transition in document["tx_sequence_transitions"]:
        expected_lifetime = transition["path_lifetime"]
        if transition["advance_path_sequence"]:
            tx_dao = tx_manager.build_dao_with_lifetime(
                manager.node_address, transition["path_lifetime"]
            )
        else:
            cached_update = tx_manager._last_logical_update
            if cached_update != (manager.node_address, transition["path_lifetime"]):
                counters = (tx_manager._dao_sequence, tx_manager._path_sequence)
                try:
                    tx_manager.build_dao_copy_with_lifetime(
                        manager.node_address, transition["path_lifetime"]
                    )
                except DaoError:
                    pass
                else:
                    raise AssertionError(f"{transition['name']}: non-exact DAO copy accepted")
                if (tx_manager._dao_sequence, tx_manager._path_sequence) != counters:
                    raise AssertionError(f"{transition['name']}: rejected copy advanced counters")
                if cached_update is None:
                    raise AssertionError(f"{transition['name']}: no logical update to copy")
                expected_lifetime = cached_update[1]
                tx_dao = tx_manager.build_dao_copy_with_lifetime(*cached_update)
            else:
                tx_dao = tx_manager.build_dao_copy_with_lifetime(
                    manager.node_address, transition["path_lifetime"]
                )
        tx_transit = TransitInformation.from_option(tx_dao.options[1])
        if tx_dao.dao_sequence != transition["expected_dao_sequence"]:
            raise AssertionError(f"{transition['name']}: DAOSequence")
        if tx_transit.path_sequence != transition["expected_path_sequence"]:
            raise AssertionError(f"{transition['name']}: Path Sequence")
        if tx_transit.path_lifetime != expected_lifetime:
            raise AssertionError(f"{transition['name']}: Path Lifetime")
    if oracle["max_route_hops"] != _MAX_ROUTE_HOPS:
        raise AssertionError("production route-hop limit differs from vector oracle")
    for boundary in document["route_hop_boundaries"]:
        route_table = RoutingTable()
        path_addresses: list[IPv6Address | str] = [
            IPv6Address(bytes.fromhex(hop)) for hop in boundary["path"]
        ]
        try:
            route_table.add_route(path_addresses[-1], path_addresses)
            accepted = True
        except RoutingError:
            accepted = False
        if accepted != boundary["accepted"]:
            raise AssertionError(f"{boundary['name']}: route-hop boundary")
    for relation in document.get("sequence_relations", []):
        actual = _sequence_relation(relation["incoming"], relation["current"])
        if actual != relation["expected"]:
            raise AssertionError(
                f"{relation['name']}: sequence relation {actual} != {relation['expected']}"
            )
    for vector in document["vectors"]:
        name = vector["name"]
        expected = vector["expected"]
        has_route_oracle = any(
            key in container
            for container in (
                vector,
                expected,
                vector["before"],
                expected["state"],
            )
            for key in ("routes", "routing_table")
        )
        before = manager.route_state_snapshot(authority)
        comparable_before = before if has_route_oracle else _without_selected_candidates(before)
        expected_before = (
            vector["before"] if has_route_oracle else _without_selected_candidates(vector["before"])
        )
        if comparable_before != expected_before:
            raise AssertionError(f"{name}: production pre-state differs from vector")
        if vector["event"] == "expire":
            outcome = DaoOutcome(
                True,
                manager.expire_routes(vector["now_seconds"]),
                False,
                "expired",
            )
        else:
            dao = DAO.from_bytes(bytes.fromhex(vector["dao_hex"]))
            outcome = manager.evaluate_dao_at(dao, vector["now_seconds"])
        actual_outcome = {
            "accepted": outcome.accepted,
            "state_changed": outcome.state_changed,
            "refreshed": outcome.refreshed,
            "reason": outcome.reason,
        }
        expected_outcome = {key: expected[key] for key in actual_outcome}
        if actual_outcome != expected_outcome:
            raise AssertionError(
                f"{name}: production outcome {actual_outcome} != {expected_outcome}"
            )
        snapshot = manager.route_state_snapshot(authority)
        expected_routes = expected.get(
            "routes",
            expected.get(
                "routing_table",
                expected["state"].get(
                    "routes",
                    expected["state"].get(
                        "routing_table",
                        vector.get("routes", vector.get("routing_table")),
                    ),
                ),
            ),
        )
        if expected_routes is None:
            # Version-1 legacy vectors selected from parent addresses without
            # providing parent-to-root state. Their retained candidate state is
            # still valid, but synthetic selected paths are not production routes.
            comparable_actual = _without_selected_candidates(snapshot)
            comparable_expected = _without_selected_candidates(expected["state"])
        else:
            comparable_actual = snapshot
            comparable_expected = expected["state"]
            actual_routes = manager.routing_table_snapshot()
            normalized_routes = _normalize_expected_routes(expected_routes)
            if actual_routes != normalized_routes:
                raise AssertionError(
                    f"{name}: production routes {actual_routes} != {normalized_routes}"
                )
        if comparable_actual != comparable_expected:
            raise AssertionError(f"{name}: production post-state differs from vector")
        if "selected_path" in expected:
            target = IPv6Address(bytes.fromhex(expected["selected_target"]))
            selected = manager.routing_table.lookup(target)
            encoded = None if selected is None else [hop.packed.hex() for hop in selected]
            if encoded != expected["selected_path"]:
                raise AssertionError(f"{name}: selected path differs from vector")
    return manager


def _without_selected_candidates(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "targets": [
            {key: value for key, value in target.items() if key != "selected_candidate"}
            for target in snapshot["targets"]
        ]
    }


def _normalize_expected_routes(routes: Any) -> dict[str, list[str]]:
    if isinstance(routes, dict):
        if "routes" in routes:
            return _normalize_expected_routes(routes["routes"])
        return {str(target): list(path) for target, path in routes.items()}
    if isinstance(routes, list):
        return {str(route.get("target", route["prefix"])): list(route["path"]) for route in routes}
    raise ValueError("route-state vector routes must be an object or array")
