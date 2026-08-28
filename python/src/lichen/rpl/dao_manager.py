# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO manager for non-storing mode (RFC 6550, spec section 8.5).

In non-storing mode every node sends a DAO directly to the root advertising
itself as an RPL Target and its preferred parent as Transit Information. The
root chains these (target -> parent) edges into a full source route for each
node and installs it in the routing table.

Per spec section 8.6, DAO state requires crash-safe persistence:
- TX side: sequence and DAO bytes must be committed before transmission
- RX side: replay floor (sequence, digest) per origin must be committed
  before accepting the DAO

When a DaoPersistence backend is configured, the manager enforces crash-safe
semantics. Missing or corrupt state fails closed per spec.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from typing import Any, cast

from lichen.crypto.identity import Identity, yggdrasil_address
from lichen.crypto.schnorr48 import sign as schnorr_sign
from lichen.crypto.schnorr48 import verify as schnorr_verify
from lichen.ipv6 import routing_key
from lichen.rpl.dao_origin import (
    DAO_ORIGIN_SIGNATURE_TYPE,
    DaoOriginRejectReason,
    DaoOriginResult,
    DaoOriginSignature,
    DaoOriginValidator,
    compute_dao_digest,
    compute_signature_transcript,
)
from lichen.rpl.dao_paths import build_routes, contains_cycle, path_control_rank, select_path
from lichen.rpl.dao_persistence import DaoPersistence
from lichen.rpl.dao_refresh import DaoRefreshScheduler
from lichen.rpl.dao_state import compute_active_parents, make_freshness_room
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
from lichen.rpl.messages import DAO, DAOAck, RplError, RplOptionType, _exact_received_dao_wire
from lichen.rpl.route_table import RouteTable
from lichen.rpl.routing import RouteTarget, RoutingTable

# Map DaoOriginRejectReason to DaoError reason strings for consistency
_ORIGIN_REJECT_TO_REASON: dict[DaoOriginRejectReason, str] = {
    DaoOriginRejectReason.ORIGIN_NOT_PINNED: "origin_not_pinned",
    DaoOriginRejectReason.IID_MISMATCH: "iid_mismatch",
    DaoOriginRejectReason.SIGNATURE_MISSING: "signature_missing",
    DaoOriginRejectReason.SIGNATURE_DUPLICATE: "signature_duplicate",
    DaoOriginRejectReason.SIGNATURE_NOT_FINAL: "signature_not_final",
    DaoOriginRejectReason.SIGNATURE_INVALID_LENGTH: "signature_invalid_length",
    DaoOriginRejectReason.SIGNATURE_INVALID: "signature_invalid",
    DaoOriginRejectReason.ZERO_SEQUENCE: "zero_sequence",
    DaoOriginRejectReason.MALFORMED_OPTIONS: "malformed_option",
    DaoOriginRejectReason.SEQUENCE_REPLAY: "origin_sequence_replay",
    DaoOriginRejectReason.SEQUENCE_EQUAL_DIFFERENT_BYTES: "origin_sequence_mutation",
}
_MAX_RESOURCE_CAPACITY = 65535


@dataclass
class DaoManager:
    """Build DAOs and atomically maintain complete root-side candidate snapshots.

    When `persistence` is set, the manager enforces crash-safe semantics per
    spec section 8.6:
    - TX: persists sequence + DAO bytes before returning from build_dao()
    - RX: persists replay floor before accepting DAOs in process_dao()

    Missing or corrupt persistent state fails closed; the manager will not
    transmit or accept DAOs until valid state is restored.

    When `require_crash_safety` is True, the manager enforces spec section 8.6
    compliance by raising DaoError if persistence is not configured. This
    should be True for production deployments and False only for testing.
    """

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
    persistence: DaoPersistence | None = None
    require_crash_safety: bool = False
    origin_validator: DaoOriginValidator | None = None
    origin_identity: Identity | None = None
    allow_tx_bootstrap: bool = False
    _dao_sequence: int = 240
    _path_sequence: int = 240
    _origin_sequence: int = 0
    _last_logical_update: tuple[IPv6Address, int] | None = field(
        default=None, init=False, repr=False
    )
    _last_dao_bytes: bytes | None = field(default=None, init=False, repr=False)
    _parent_map: dict[IPv6Address, tuple[IPv6Address, ...]] = field(default_factory=dict)
    _candidate_map: dict[IPv6Address, tuple[Candidate, ...]] = field(default_factory=dict)
    _descriptors: dict[IPv6Address, int | None] = field(default_factory=dict)
    _path_sequences: dict[IPv6Address, int] = field(default_factory=dict)
    _freshness: dict[IPv6Address, Freshness] = field(default_factory=dict)
    _candidate_timing: dict[tuple[IPv6Address, IPv6Address], tuple[float, float | None]] = field(
        default_factory=dict
    )
    _edge_expiry: dict[tuple[IPv6Address, IPv6Address], float | None] = field(default_factory=dict)
    _rx_floors: dict[bytes, tuple[int, bytes]] = field(default_factory=dict)
    _tx_recovery_error: DaoError | None = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _scheduler: DaoRefreshScheduler = field(init=False, repr=False)
    _route_table: RouteTable = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.node_address = routing_key(self.node_address)
        if type(self.is_root) is not bool:
            raise ValueError("is_root must be an exact boolean")
        if type(self.require_crash_safety) is not bool:
            raise ValueError("require_crash_safety must be an exact boolean")
        if type(self.allow_tx_bootstrap) is not bool:
            raise ValueError("allow_tx_bootstrap must be an exact boolean")
        if self.dodag_id is not None:
            self.dodag_id = routing_key(self.dodag_id)
        if type(self.rpl_instance_id) is not int or not 0 <= self.rpl_instance_id <= 0xFF:
            raise ValueError("RPL instance ID must fit in u8")
        if type(self.pcs) is not int or not 0 <= self.pcs <= 7:
            raise ValueError("PCS must be between 0 and 7")
        for name, value in (
            ("max_targets", self.max_targets),
            ("max_candidates", self.max_candidates),
            ("max_routes", self.max_routes),
        ):
            if type(value) is not int or not 1 <= value <= _MAX_RESOURCE_CAPACITY:
                raise ValueError(f"{name} must be an exact bounded positive integer")
        if self.max_candidates_per_target is None:
            self.max_candidates_per_target = self.max_candidates
        if (
            type(self.max_candidates_per_target) is not int
            or not 1 <= self.max_candidates_per_target <= _MAX_RESOURCE_CAPACITY
        ):
            raise ValueError("max_candidates_per_target must be an exact bounded positive integer")
        for duration_name, duration_value, zero_allowed in (
            ("lifetime_unit_seconds", self.lifetime_unit_seconds, False),
            ("freshness_retention_seconds", self.freshness_retention_seconds, True),
        ):
            if type(duration_value) not in (int, float):
                raise ValueError(f"{duration_name} must be a finite valid duration")
            numeric_duration = cast(int | float, duration_value)
            try:
                normalized_duration = float(numeric_duration)
            except OverflowError:
                raise ValueError(f"{duration_name} must be a finite valid duration") from None
            if (
                not math.isfinite(normalized_duration)
                or normalized_duration < 0
                or (not zero_allowed and normalized_duration == 0)
            ):
                raise ValueError(f"{duration_name} must be a finite valid duration")
            setattr(self, duration_name, normalized_duration)
        if not callable(self.clock):
            raise ValueError("clock must be callable")
        for name, value, maximum in (
            ("_dao_sequence", self._dao_sequence, 0xFF),
            ("_path_sequence", self._path_sequence, 0xFF),
            ("_origin_sequence", self._origin_sequence, 0xFFFFFFFFFFFFFFFF),
        ):
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError(f"{name} must be an exact bounded integer")
        if (
            self.origin_identity is not None
            and yggdrasil_address(self.origin_identity.pubkey) != self.node_address
        ):
            raise DaoError(
                "origin identity does not derive to node_address",
                reason="origin_identity_mismatch",
            )
        # SECURITY: Per spec section 8.6, crash-safe persistence is required.
        # When require_crash_safety is True, verify persistence is configured,
        # crash-safe, AND fails closed on missing/corrupt state.
        if self.require_crash_safety:
            if self.persistence is None:
                raise DaoError(
                    "crash-safe persistence required but not configured (spec 8.6)",
                    reason="persistence_required",
                )
            if not self.persistence.is_crash_safe:
                raise DaoError(
                    "persistence backend is not crash-safe (spec 8.6)",
                    reason="persistence_not_crash_safe",
                )
            # SECURITY: Per spec section 8.6: "Missing, corrupt, or unavailable
            # receive state MUST fail closed." A backend that returns None on
            # corrupt state does not satisfy this requirement.
            if not self.persistence.fails_closed:
                raise DaoError(
                    "persistence backend does not fail closed (spec 8.6)",
                    reason="persistence_not_fail_closed",
                )
        # SECURITY: Validate replay floor store consistency (ALWAYS, not just crash-safe mode).
        # Per spec section 8.6, the origin validator's replay_store and the
        # manager's persistence must be the same object to prevent split-brain:
        # - Validation checks against replay_store
        # - Commits write to persistence
        # If these are different objects, replay protection is broken because
        # the store used for checking is never updated by commits.
        if self.origin_validator is not None:
            if self.origin_validator.replay_store is None:
                raise DaoError(
                    "origin_validator requires a replay_store",
                    reason="replay_store_mismatch",
                )
            if self.persistence is None:
                raise DaoError(
                    "origin_validator has replay_store but persistence is not configured; "
                    "these must be the same object (spec 8.6 replay floor consistency)",
                    reason="replay_store_mismatch",
                )
            replay_store_identity: object = self.origin_validator.replay_store
            if replay_store_identity is not self.persistence:
                raise DaoError(
                    "origin_validator.replay_store and persistence are different objects; "
                    "these must be the same object (spec 8.6 replay floor consistency)",
                    reason="replay_store_mismatch",
                )
        # Initialize helper instances for delegation
        self._scheduler = DaoRefreshScheduler(
            lifetime_unit_seconds=self.lifetime_unit_seconds,
            freshness_retention_seconds=self.freshness_retention_seconds,
            clock=self.clock,
        )
        self._route_table = RouteTable(_routing_table=self.routing_table)
        # SECURITY: Restore TX state from persistence if available.
        # Per spec section 8.6, missing/corrupt state is a hard failure;
        # the node must not transmit until valid state is restored.
        if self.persistence is not None:
            self._restore_tx_state()

    def _validate_now(self, value: object) -> float:
        """Validate a time sample is finite, non-negative, and non-regressing."""
        return self._scheduler.validate_now(value)

    @staticmethod
    def _checked_time_sum(base: float, delta: float) -> float:
        """Add two time values with overflow checking."""
        return DaoRefreshScheduler.checked_time_sum(base, delta)

    def _candidate_deadline(self, lifetime: int, now: float) -> float | None:
        """Calculate when a candidate expires based on its lifetime."""
        return self._scheduler.candidate_deadline(lifetime, now)

    def _clock_now(self) -> float:
        """Get the current time from the configured clock."""
        return self._scheduler.clock_now()

    def _restore_tx_state(self) -> None:
        """Restore TX state from persistence after reboot.

        Per spec section 8.6, the TX API must expose the exact retained bytes
        after reboot for retransmission. Missing or corrupt state is a hard
        failure when require_crash_safety is True.
        """
        if self.persistence is None:
            return
        from lichen.rpl.dao_persistence import DaoPersistenceError

        try:
            tx_state = self.persistence.load_tx_state()
        except DaoPersistenceError as exc:
            # SECURITY: Per spec section 8.6, "Missing, corrupt, or unavailable
            # state is a hard failure: the origin MUST NOT transmit until valid
            # state is restored or provisioned above every value previously used."
            failure = DaoError(
                f"TX state corrupt or unavailable (spec 8.6): {exc}",
                reason="persistence_corrupt",
            )
            if self.origin_identity is not None:
                self._tx_recovery_error = failure
            if self.require_crash_safety:
                raise failure from exc
            # When crash safety is not required, fall back to defaults.
            # The next build_dao will start fresh from initial sequence.
            return
        if tx_state is None and self.origin_identity is not None:
            if not self.allow_tx_bootstrap:
                self._tx_recovery_error = DaoError(
                    "authenticated DAO TX state is missing and bootstrap was not authorized",
                    reason="persistence_missing",
                )
            return
        if tx_state is not None:
            # Restore sequence to at least the persisted value.
            # The next build_dao will increment before use.
            try:
                if (
                    type(tx_state.sequence) is not int
                    or not 1 <= tx_state.sequence <= 0xFFFFFFFFFFFFFFFF
                    or type(tx_state.dao_bytes) is not bytes
                ):
                    raise ValueError("invalid retained TX state fields")
                restored = DAO.from_bytes(tx_state.dao_bytes)
                if restored.to_bytes() != tx_state.dao_bytes:
                    raise ValueError("retained DAO encoding is not canonical")
                self._dao_sequence = restored.dao_sequence
                for option in restored.options:
                    if option.type == RplOptionType.TRANSIT_INFORMATION:
                        self._path_sequence = TransitInformation.from_option(option).path_sequence
                        break
                if self.origin_identity is not None:
                    if self.dodag_id is None or not restored.options:
                        raise ValueError("authenticated retained DAO lacks DODAG context")
                    origin = DaoOriginSignature.from_option(restored.options[-1])
                    if origin.origin_sequence != tx_state.sequence:
                        raise ValueError("retained DAO Origin Sequence mismatch")
                    unsigned = tx_state.dao_bytes[: -(2 + len(restored.options[-1].data))]
                    transcript = compute_signature_transcript(
                        self.node_address,
                        self.dodag_id,
                        origin.origin_sequence,
                        unsigned,
                    )
                    if not schnorr_verify(
                        self.origin_identity.pubkey,
                        transcript,
                        origin.signature,
                    ):
                        raise ValueError("retained DAO signature is invalid")
            except (ValueError, DaoError) as exc:
                failure = DaoError(
                    "persisted signed DAO is malformed",
                    reason="persistence_corrupt",
                )
                if self.origin_identity is not None:
                    self._tx_recovery_error = failure
                if self.require_crash_safety:
                    raise failure from exc
                return
            self._origin_sequence = tx_state.sequence
            self._last_dao_bytes = tx_state.dao_bytes

    def get_last_dao_bytes(self) -> bytes | None:
        """Return the last persisted DAO bytes for retransmission after reboot.

        Per spec section 8.6, the TX API must expose the exact retained bytes
        after reboot for retransmission.
        """
        return self._last_dao_bytes

    def build_dao(self, parent_address: IPv6Address | str, *, ack_requested: bool = False) -> DAO:
        """Build and durably reserve an authenticated logical DAO."""
        self._require_authenticated_origination()
        return self._build_dao(parent_address, 255, True, ack_requested)

    def build_dao_with_lifetime(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        *,
        ack_requested: bool = False,
    ) -> DAO:
        """Build an authenticated logical DAO with an explicit lifetime."""
        self._require_authenticated_origination()
        return self._build_dao(parent_address, path_lifetime, True, ack_requested)

    def build_dao_copy_with_lifetime(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        *,
        ack_requested: bool = False,
    ) -> DAO:
        """Build an authenticated logical copy retaining the Path Sequence."""
        self._require_authenticated_origination()
        return self._build_dao(parent_address, path_lifetime, False, ack_requested)

    def build_dao_semantics_for_test(
        self, parent_address: IPv6Address | str, *, ack_requested: bool = False
    ) -> DAO:
        """Explicitly unsafe unsigned DAO builder for semantic-only tests."""
        return self._build_dao(parent_address, 255, True, ack_requested)

    def build_dao_with_lifetime_semantics_for_test(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        *,
        ack_requested: bool = False,
    ) -> DAO:
        """Explicitly unsafe unsigned lifetime builder for semantic tests."""
        return self._build_dao(parent_address, path_lifetime, True, ack_requested)

    def build_dao_copy_with_lifetime_semantics_for_test(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        *,
        ack_requested: bool = False,
    ) -> DAO:
        """Explicitly unsafe unsigned copy builder for semantic tests."""
        return self._build_dao(parent_address, path_lifetime, False, ack_requested)

    def _require_authenticated_origination(self) -> None:
        if self._tx_recovery_error is not None:
            raise self._tx_recovery_error
        if self.persistence is None:
            raise DaoError(
                "crash-safe persistence required for authenticated DAO origination",
                reason="persistence_required",
            )
        if not self.persistence.is_crash_safe:
            raise DaoError(
                "authenticated DAO origination persistence backend is not crash-safe",
                reason="persistence_not_crash_safe",
            )
        if not self.persistence.fails_closed:
            raise DaoError(
                "authenticated DAO origination persistence backend does not fail closed",
                reason="persistence_not_fail_closed",
            )
        if self.origin_identity is None:
            raise DaoError(
                "authenticated DAO origination requires origin_identity",
                reason="origin_identity_required",
            )

    def _build_dao(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        advance_path_sequence: bool,
        ack_requested: bool,
    ) -> DAO:
        with self._lock:
            return self._build_dao_unlocked(
                parent_address, path_lifetime, advance_path_sequence, ack_requested
            )

    def _build_dao_unlocked(
        self,
        parent_address: IPv6Address | str,
        path_lifetime: int,
        advance_path_sequence: bool,
        ack_requested: bool,
    ) -> DAO:
        if type(path_lifetime) is not int or not 0 <= path_lifetime <= 255:
            raise ValueError("Path Lifetime must fit one octet; value must be an exact u8")
        if type(advance_path_sequence) is not bool:
            raise ValueError("advance_path_sequence must be an exact boolean")
        if type(ack_requested) is not bool:
            raise ValueError("ack_requested must be an exact boolean")
        # SECURITY: Per spec section 8.6, crash-safe persistence is required for TX.
        # Defense in depth: check again in case require_crash_safety was set after init.
        if self.require_crash_safety:
            if self.persistence is None:
                raise DaoError(
                    "cannot build DAO: crash-safe persistence required (spec 8.6)",
                    reason="persistence_required",
                )
            if not self.persistence.is_crash_safe:
                raise DaoError(
                    "cannot build DAO: persistence backend is not crash-safe (spec 8.6)",
                    reason="persistence_not_crash_safe",
                )
            if not self.persistence.fails_closed:
                raise DaoError(
                    "cannot build DAO: persistence backend does not fail closed (spec 8.6)",
                    reason="persistence_not_fail_closed",
                )
            if self.origin_identity is None:
                raise DaoError(
                    "authenticated DAO origination requires origin_identity",
                    reason="origin_identity_required",
                )
        parent = routing_key(parent_address)
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
        if self.origin_identity is not None:
            if self._origin_sequence == 0xFFFFFFFFFFFFFFFF:
                raise DaoError("DAO Origin Sequence exhausted", reason="origin_sequence_exhausted")
            if self.dodag_id is None:
                raise DaoError("authenticated DAO requires DODAG ID", reason="dodag_required")
            origin_sequence = self._origin_sequence + 1
            transcript = compute_signature_transcript(
                self.node_address,
                self.dodag_id,
                origin_sequence,
                dao.to_bytes(),
            )
            signature = schnorr_sign(
                self.origin_identity.privkey,
                self.origin_identity.pubkey,
                transcript,
            )
            dao.options.append(DaoOriginSignature(origin_sequence, signature).to_option())
        else:
            origin_sequence = 0
        # SECURITY: Per spec section 8.6, crash-safely commit the sequence and
        # complete DAO bytes BEFORE updating in-memory state or returning.
        # This ensures that on crash recovery, the node can retransmit or
        # continue with a sequence above all previously used values.
        if self.persistence is not None and (
            advance_path_sequence or self.origin_identity is not None
        ):
            dao_bytes = dao.to_bytes()
            persisted_sequence = (
                origin_sequence if self.origin_identity is not None else path_sequence
            )
            self.persistence.store_tx_state(persisted_sequence, dao_bytes)
            self._last_dao_bytes = dao_bytes
        self._dao_sequence = dao_sequence
        self._path_sequence = path_sequence
        if self.origin_identity is not None:
            self._origin_sequence = origin_sequence
        if advance_path_sequence:
            self._last_logical_update = logical_update
        return dao

    def process_dao(self, dao: DAO) -> DAOAck | None:
        """Root-side: record the target/parent edge and rebuild routes.

        Returns a DAO-ACK when the DAO requested one (K flag), else ``None``.
        """
        raise DaoError(
            "unauthenticated DAO receive is test-only; use validate_and_process_dao",
            reason="origin_authentication_required",
        )

    def process_dao_at(self, dao: DAO, now_seconds: float) -> DAOAck | None:
        """Validate and atomically apply a DAO at a deterministic monotonic time."""
        raise DaoError(
            "unauthenticated DAO receive is test-only; use validate_and_process_dao_at",
            reason="origin_authentication_required",
        )

    def process_dao_semantics_for_test(self, dao: DAO) -> DAOAck | None:
        """Explicitly unsafe semantic-only helper for unit tests."""
        return self.process_dao_semantics_for_test_at(dao, self._clock_now())

    def process_dao_semantics_for_test_at(self, dao: DAO, now_seconds: float) -> DAOAck | None:
        """Apply unsigned DAO semantics only when test mode was opted into."""
        self._apply_dao_at(dao, now_seconds, allow_unauthenticated_test=True)
        if dao.ack_requested:
            return self.build_dao_ack(dao)
        return None

    def validate_and_process_dao(
        self,
        dao: DAO,
        source_address: IPv6Address | str,
    ) -> DAOAck | None:
        """Consolidated DAO validation and processing per spec section 8.6.

        This method enforces the spec-required validation order:
        1. link framing and link signature (done at link layer, not here)
        2. bounds-safe DAO structure and active instance/DODAG context
        3. pre-pinned key lookup, source-IID binding, exact transcript, and Schnorr48
        4. per-key replay classification
        5. DAO semantic parsing
        6. exact self /128 Target validation
        7. replay-floor persistence for a fresh DAO
        8. atomic in-memory route mutation

        Args:
            dao: The DAO message to validate and process.
            source_address: The preserved IPv6 source address (origin's 02xx).

        Returns:
            DAO-ACK when the DAO requested one (K flag), else None.

        Raises:
            DaoError: If validation fails at any step.
        """
        if not self.is_root:
            raise DaoError("process_dao is only valid on the root")
        now = self._clock_now()
        return self.validate_and_process_dao_at(dao, source_address, now)

    def validate_and_process_dao_at(
        self,
        dao: DAO,
        source_address: IPv6Address | str,
        now_seconds: float,
    ) -> DAOAck | None:
        """Consolidated DAO validation and processing at a deterministic time.

        See validate_and_process_dao for the full validation order.
        """
        source_addr = routing_key(source_address)
        provenance = _exact_received_dao_wire(dao)
        if provenance is None:
            raise DaoError(
                "DAO exact received wire is unavailable",
                reason="raw_wire_unavailable",
            )
        # Detach exactly once. Validation, semantic mutation, replay digest,
        # and ACK fields all consume this same immutable-wire snapshot even if
        # another thread still owns and mutates the caller's DAO object.
        snapshot = DAO.from_bytes(provenance[0])
        self._apply_dao_at(snapshot, now_seconds, source_addr)
        if snapshot.ack_requested:
            return self.build_dao_ack(snapshot)
        return None

    def validate_and_process_dao_wire_at(
        self,
        wire: bytes,
        source_address: IPv6Address | str,
        now_seconds: float,
    ) -> DAOAck | None:
        """Validate raw DAO context before parsing its option sequence.

        This is the production ingress for an untrusted DAO wire image.  The
        fixed base and active scope are classified before option parsing, as
        required by the canonical decision order.
        """
        if type(wire) is not bytes or len(wire) < 4:
            raise DaoError("DAO base is malformed", reason="malformed_dao")
        if wire[1] & 0x3F:
            raise DaoError("DAO flags are unsupported", reason="unsupported_flags")
        if wire[2] != 0:
            raise DaoError("DAO reserved field must be zero", reason="nonzero_reserved")
        has_dodag = bool(wire[1] & 0x40)
        if has_dodag and len(wire) < 20:
            raise DaoError("DAO DODAGID is truncated", reason="malformed_dao")
        if wire[0] != self.rpl_instance_id:
            raise DaoError("DAO instance does not match active scope", reason="instance_mismatch")
        if has_dodag and self.dodag_id is not None:
            wire_dodag = IPv6Address(wire[4:20])
            if wire_dodag != self.dodag_id:
                raise DaoError("DAO DODAGID does not match active scope", reason="dodag_mismatch")
        offset = 20 if has_dodag else 4
        signature_seen = False
        while offset < len(wire):
            if wire[offset] == int(RplOptionType.PAD1):
                if signature_seen:
                    raise DaoError(
                        "DAO Origin Signature is not final",
                        reason="signature_not_final",
                    )
                offset += 1
                continue
            if offset + 2 > len(wire):
                raise DaoError("DAO option header is truncated", reason="truncated")
            option_type = wire[offset]
            option_length = wire[offset + 1]
            option_end = offset + 2 + option_length
            if option_end > len(wire):
                raise DaoError("DAO option is truncated", reason="truncated")
            if option_type == DAO_ORIGIN_SIGNATURE_TYPE:
                if option_length != 56:
                    raise DaoError(
                        "DAO Origin Signature has invalid length",
                        reason="signature_invalid_length",
                    )
                if signature_seen:
                    raise DaoError(
                        "DAO Origin Signature is duplicated",
                        reason="signature_duplicate",
                    )
                signature_seen = True
            elif signature_seen:
                raise DaoError(
                    "DAO Origin Signature is not final",
                    reason="signature_not_final",
                )
            offset = option_end
        try:
            dao = DAO.from_bytes(wire)
        except RplError as exc:
            reason = "truncated" if "truncated" in str(exc).lower() else "malformed_dao"
            raise DaoError(f"DAO option framing is invalid: {exc}", reason=reason) from exc
        return self.validate_and_process_dao_at(dao, source_address, now_seconds)

    def evaluate_dao_at(
        self,
        dao: DAO,
        now_seconds: float,
        source_address: IPv6Address | None = None,
    ) -> DaoOutcome:
        """Apply a DAO and return a structured rejection instead of raising.

        When source_address is provided and origin_validator is configured,
        full spec 8.6 validation is enforced.
        """
        try:
            return self._apply_dao_at(dao, now_seconds, source_address)
        except DaoError as exc:
            return DaoOutcome(False, False, False, exc.reason)

    def evaluate_dao_semantics_for_test_at(self, dao: DAO, now_seconds: float) -> DaoOutcome:
        """Explicitly unsafe structured semantic oracle for unit tests."""
        try:
            return self._apply_dao_at(dao, now_seconds, allow_unauthenticated_test=True)
        except DaoError as exc:
            return DaoOutcome(False, False, False, exc.reason)

    def _apply_dao_at(
        self,
        dao: DAO,
        now_seconds: float,
        source_address: IPv6Address | None = None,
        *,
        allow_unauthenticated_test: bool = False,
    ) -> DaoOutcome:
        """Apply a DAO with optional consolidated origin validation.

        When source_address is provided, the validation order per spec 8.6 is:
        1. bounds-safe DAO structure and active instance/DODAG context
        2. pre-pinned key lookup, source-IID binding, and Schnorr48 (if origin_validator)
        3. per-key replay classification (handled by origin_validator)
        4. DAO semantic parsing
        5. exact self /128 Target validation
        6. replay-floor persistence for a fresh DAO
        7. atomic in-memory route mutation

        Thread-safe: acquires _lock before mutating state.
        """
        with self._lock:
            return self._apply_dao_at_unlocked(
                dao,
                now_seconds,
                source_address,
                allow_unauthenticated_test=allow_unauthenticated_test,
            )

    def _apply_dao_at_unlocked(
        self,
        dao: DAO,
        now_seconds: float,
        source_address: IPv6Address | None = None,
        *,
        allow_unauthenticated_test: bool = False,
    ) -> DaoOutcome:
        """Internal implementation of _apply_dao_at. Caller must hold _lock."""
        now_seconds = self._validate_now(now_seconds)
        if not self.is_root:
            raise DaoError("process_dao is only valid on the root")

        # SECURITY: Per spec section 8.6, crash-safe persistence is required for RX.
        # "Missing, corrupt, or unavailable receive state MUST fail closed."
        if self.require_crash_safety:
            if self.persistence is None:
                raise DaoError(
                    "cannot process DAO: crash-safe persistence required (spec 8.6)",
                    reason="persistence_required",
                )
            if not self.persistence.is_crash_safe:
                raise DaoError(
                    "cannot process DAO: persistence backend is not crash-safe (spec 8.6)",
                    reason="persistence_not_crash_safe",
                )
            if not self.persistence.fails_closed:
                raise DaoError(
                    "cannot process DAO: persistence backend does not fail closed (spec 8.6)",
                    reason="persistence_not_fail_closed",
                )

        # Step 1: Bounds-safe DAO structure and active instance/DODAG context
        # SECURITY: RFC 6550 Section 9.5 requires filtering DAOs by RPL Instance ID.
        # Accepting DAOs from a different instance could corrupt the routing table.
        if dao.rpl_instance_id != self.rpl_instance_id:
            raise DaoError(
                f"DAO instance ID {dao.rpl_instance_id} != {self.rpl_instance_id}",
                reason="instance_mismatch",
            )
        if dao.flags != 0 or dao.reserved != 0:
            raise DaoError("DAO reserved base fields must be zero", reason="malformed_group")
        effective_dodag_id = dao.dodag_id if dao.dodag_id is not None else self.dodag_id
        if self.dodag_id is not None and dao.dodag_id is not None and dao.dodag_id != self.dodag_id:
            raise DaoError(
                f"DAO DODAGID {dao.dodag_id} != {self.dodag_id}",
                reason="dodag_mismatch",
            )

        # Step 2: Origin validation (pre-pinned key lookup, source-IID binding, Schnorr48)
        # SECURITY: Per spec 8.6, origin validation MUST happen before semantic parsing.
        # This prevents route state mutation from unauthenticated DAOs.
        # SECURITY: When origin_validator is None or source_address is None, origin
        # validation is bypassed and the DAO proceeds without cryptographic authentication.
        # Per spec 8.6: "A DAO that does not satisfy that profile MUST NOT create,
        # refresh, withdraw, or otherwise mutate downward route state." Production
        # deployments MUST configure origin_validator and callers MUST provide
        # source_address via validate_and_process_dao() to enforce this requirement.
        # The legacy process_dao() path without source_address is for testing only.
        origin_result: DaoOriginResult | None = None
        if (
            self.origin_validator is None or source_address is None
        ) and not allow_unauthenticated_test:
            raise DaoError(
                "DAO origin authentication is required",
                reason="origin_authentication_required",
            )
        if self.origin_validator is not None and source_address is not None:
            if effective_dodag_id is None:
                raise DaoError(
                    "origin validation requires DODAG ID",
                    reason="dodag_required",
                )
            origin_result = self.origin_validator.validate(dao, source_address, effective_dodag_id)
            if not origin_result.valid:
                assert origin_result.reject_reason is not None
                reason = _ORIGIN_REJECT_TO_REASON.get(
                    origin_result.reject_reason, "origin_validation_failed"
                )
                raise DaoError(
                    f"DAO origin validation failed: {origin_result.reject_reason.name}",
                    reason=reason,
                )
            if origin_result.signed_dao_bytes is None:
                raise DaoError(
                    "origin validator omitted exact DAO snapshot",
                    reason="origin_invariant_violation",
                )
            dao = DAO.from_bytes(origin_result.signed_dao_bytes)

        # Step 3: DAO semantic parsing (extract Target/Transit groups)
        try:
            updates = self._extract_updates(dao)
        except DaoError as exc:
            if source_address is not None and exc.reason == "inconsistent_group":
                raise DaoError(str(exc), reason="inconsistent_transit") from exc
            raise

        # Step 4: Exact self /128 Target validation
        # SECURITY: Per spec 8.7, the /128 Target MUST equal the preserved DAO source address.
        # This prevents a node from advertising routes for addresses it doesn't own.
        if source_address is not None:
            if len({update.target for update in updates}) != 1:
                raise DaoError(
                    "authenticated DAO profile requires one distinct Target",
                    reason="multiple_target",
                )
            for update in updates:
                if update.target != source_address:
                    raise DaoError(
                        f"Target {update.target} != source address {source_address}",
                        reason="target_mismatch",
                    )
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
                freshness[target] = self._scheduler.create_initial_freshness(
                    sequence, now_seconds
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
                deadline = self._candidate_deadline(candidate.path_lifetime, now_seconds)
                active.append(candidate.parent)
                expiry[(target, candidate.parent)] = deadline
                candidate_timing[(target, candidate.parent)] = (now_seconds, deadline)
                if deadline is None:
                    active_until = None
                elif active_until is not None:
                    active_until = max(active_until, deadline)
            if active:
                parents[target] = tuple(sorted(active))
            freshness[target] = self._scheduler.create_active_freshness(
                sequences[target], active_until, now_seconds
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

        # SECURITY: Per spec section 8.6, durably commit the new replay floor
        # BEFORE using the route or sending a success DAO-ACK.
        # CRITICAL: Per spec 8.6: "On a byte-identical retransmission, the receiver
        # MUST NOT rewrite the replay floor." Only commit for fresh DAOs.
        #
        # When origin_validator was used, the floor is keyed by pubkey (per spec).
        # A fresh DAO (origin_result.is_fresh=True) MUST have its floor committed
        # regardless of whether there are semantic-level changes, because the
        # floor tracks origin_sequence, not path_sequence.
        #
        # Otherwise, fall back to address-based keying for backward compatibility
        # with the legacy path (no origin validation).
        if self.persistence is not None:
            self._scheduler.record_time(now_seconds)
            dao_bytes = dao.to_bytes()
            dao_digest = compute_dao_digest(dao_bytes)

            if origin_result is not None:
                # Origin-validated path: commit floor once per fresh DAO
                # SECURITY: Per spec 8.6, floor is keyed by pubkey and uses
                # origin_sequence (crypto-layer freshness), not path_sequence.
                if origin_result.is_fresh:
                    # SECURITY: Per spec 8.6, a fresh DAO MUST have pubkey and
                    # origin_sequence set by the validator. This is a structural
                    # invariant; violation indicates a bug in origin validation.
                    if origin_result.pubkey is None or origin_result.origin_sequence is None:
                        raise DaoError(
                            "fresh DAO origin_result missing pubkey or origin_sequence",
                            reason="origin_invariant_violation",
                        )
                    origin_key = origin_result.pubkey
                    seq = origin_result.origin_sequence
                    if origin_result.dao_digest is None or origin_result.dao_digest != dao_digest:
                        raise DaoError(
                            "validated DAO digest does not match exact snapshot",
                            reason="origin_invariant_violation",
                        )
                    self.persistence.store_rx_floor(origin_key, seq, origin_result.dao_digest)
                    self._rx_floors[origin_key] = (seq, origin_result.dao_digest)
            elif changed:
                # Legacy path (no origin validation): commit floors per-target
                # using address-based keying and path_sequence.
                # SECURITY: Use batch method to commit atomically. Per spec 8.6,
                # partial commits violate atomicity requirements for crash-safe
                # semantics. If the second store_rx_floor fails after the first
                # succeeds, replay floor state would be inconsistent across targets.
                floors_to_commit: list[tuple[bytes, int, bytes]] = []
                for target in changed:
                    origin_key = target.packed
                    seq = sequences[target]
                    floors_to_commit.append((origin_key, seq, dao_digest))
                self.persistence.store_rx_floors_batch(floors_to_commit)
                # Update in-memory state only after successful persistence
                for origin_key, seq, digest in floors_to_commit:
                    self._rx_floors[origin_key] = (seq, digest)

        self._scheduler.record_time(now_seconds)
        self._parent_map = parents
        self._candidate_map = candidates
        self._descriptors = retained_descriptors
        self._candidate_timing = candidate_timing
        self._path_sequences = path_sequences
        self._freshness = freshness
        self._edge_expiry = expiry
        self.routing_table.replace_routes(routes)
        return DaoOutcome(True, state_changed, False, reason)

    def _existing_host_routes(self) -> dict[RouteTarget, list[IPv6Address]]:
        return self.routing_table.routes()

    def _merge_prefix_routes(
        self, host_routes: dict[RouteTarget, list[IPv6Address]]
    ) -> dict[RouteTarget, list[IPv6Address]]:
        """Merge host routes with existing prefix routes."""
        return self._route_table.merge_prefix_routes(host_routes)

    def expire_routes(self, now_seconds: float | None = None) -> bool:
        """Remove expired active edges and routes while retaining snapshot tombstones.

        Thread-safe: acquires _lock before mutating state.
        """
        with self._lock:
            return self._expire_routes_unlocked(now_seconds)

    def _expire_routes_unlocked(self, now_seconds: float | None = None) -> bool:
        """Internal implementation of expire_routes. Caller must hold _lock."""
        now = self._clock_now() if now_seconds is None else self._validate_now(now_seconds)
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
        self._scheduler.record_time(now)
        self._edge_expiry = expiry
        self.routing_table.replace_routes(routes)
        return changed

    def remove_edge(self, target: IPv6Address | str) -> bool:
        """Remove a target's active candidates while retaining freshness state.

        Thread-safe: acquires _lock before mutating state.
        """
        with self._lock:
            return self._remove_edge_unlocked(target)

    def _remove_edge_unlocked(self, target: IPv6Address | str) -> bool:
        """Internal implementation of remove_edge. Caller must hold _lock."""
        target = routing_key(target)
        if target not in self._parent_map:
            return False
        now = self._clock_now()
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
            self._freshness[target] = self._scheduler.update_freshness_on_withdrawal(current, now)
        self._scheduler.record_time(now)
        return True

    def route_state_snapshot(self, sequence_authority: IPv6Address | str) -> dict[str, Any]:
        """Return canonical retained route state in route-vector form."""
        with self._lock:
            return self._route_state_snapshot_unlocked(sequence_authority)

    def _route_state_snapshot_unlocked(
        self, sequence_authority: IPv6Address | str
    ) -> dict[str, Any]:
        """Internal implementation of route_state_snapshot. Caller must hold _lock."""
        authority = routing_key(sequence_authority).packed.hex()
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
        for rt in sorted(self.routing_table.routes()):
            if rt.prefix_len < 128:
                # Skip prefix routes in target-focused snapshot
                continue
            target = rt.prefix
            selected = select_path(
                target, self.node_address, self._parent_map, self._candidate_map, self.pcs, set()
            )
            if selected is None:
                raise AssertionError("installed route has no selected candidate")
            path, candidate, _ = selected
            installed_at, expires_at = self._candidate_timing[(target, candidate.parent)]
            route_records.append(
                {
                    "prefix_length": rt.prefix_len,
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
        with self._lock:
            return self._route_table.snapshot()

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
                reason = "missing_target" if not targets else "missing_transit"
                raise DaoError(
                    "DAO group missing RPL Target or Transit Information",
                    reason=reason,
                )
            first = next(iter(transits.values()))
            for transit in transits.values():
                if transit.external:
                    raise DaoError(
                        "external Transit is unsupported by the node-owned /128 profile",
                        reason="unsupported_transit_e",
                    )
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
                    assert parent is not None  # enforced by the profile codec
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

        for opt_index, opt in enumerate(dao.options):
            if opt.type == RplOptionType.RPL_TARGET:
                if in_transits:
                    finish_group()
                parsed_target = RplTarget.from_option(opt)
                if parsed_target.prefix_length != 128:
                    raise DaoError(
                        "only /128 RPL Targets are routable by this table",
                        reason="non128_target",
                    )
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
                        reason="missing_target",
                    )
                in_transits = True
                descriptor_allowed = False
                parsed_transit = TransitInformation.from_option(opt)
                transit_parent = parsed_transit.parent_address
                assert transit_parent is not None  # enforced before any state mutation
                existing = transits.get(transit_parent)
                if existing is not None and existing != parsed_transit:
                    raise DaoError(
                        "conflicting duplicate Transit candidate",
                        reason="inconsistent_group",
                    )
                transits[transit_parent] = parsed_transit
            elif opt.type == DAO_ORIGIN_SIGNATURE_TYPE:
                # SECURITY: Per spec 8.6, the DAO Origin Signature Option MUST be
                # the final DAO option. A non-final signature option MUST reject
                # the entire DAO without semantic parsing or state mutation.
                # This check enforces the spec requirement even when origin_validator
                # is not configured.
                if opt_index != len(dao.options) - 1:
                    raise DaoError(
                        "DAO Origin Signature Option must be the final option",
                        reason="signature_not_final",
                    )
                # Signature option is final and valid; it's processed separately
                # by the origin_validator. Stop processing options here.
                break
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
