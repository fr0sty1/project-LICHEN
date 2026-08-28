# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Stratum tracking and wall-clock synchronization status.

This module provides the Stratum enum for time source quality levels,
StratumTracker for managing wall-clock synchronization state, and
related helper functions for sample validation and adoption decisions.
"""

from __future__ import annotations

import math
import threading
import warnings
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING

# Import from provisioning.py (already handles its own deferred imports)
from .provisioning import (
    EpochFloorAuthority,
    EpochFloorResult,
    EpochFloorSnapshot,
    ProvisionEpochStatus,
)

# Import from samples.py - these are defined before stratum.py is imported by time_sync.py
from .samples import (
    DioTimeOption,
    TimeEvidence,
    TimeSample,
    _detach_sample,
    _gpsd_quality_rejection,
    _SampleAuthority,
)

# Import from source.py (no circular deps)
from .source import (
    DEFAULT_SOURCE_PRECEDENCE_POLICY,
    SOURCE_CAN_ESTABLISH_WALL_CLOCK,
    SourceClass,
    SourceClassLike,
    SourcePrecedencePolicy,
    _epoch,
    _mono,
    _source,
)

# Import early-defined items from time_sync.py
# NOTE: These must be defined BEFORE the "from .stratum import" line in time_sync.py
from .time_sync import (
    MAX_NETWORK_REPLAY_GENERATIONS,
    STRATUM_SOURCE_CLASSES,
    SYSTEM_MONOTONIC_CLOCK,
    MonotonicClock,
    Stratum,
    _project,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from .time_sync import (
        TimeAdmin,
    )

# Type alias for runtime use
SampleAuthority = _SampleAuthority


def _get_late_types() -> tuple[type, type, type]:
    """Deferred import for types defined late in time_sync.py."""
    from .time_sync import DioTimeVerifier, TimeAdmin, TimeProvider
    return TimeProvider, DioTimeVerifier, TimeAdmin

_UINT32_MAX = (1 << 32) - 1


def _bound(
    sample: TimeSample,
    authorities: tuple[SampleAuthority, ...],
    snapshots: tuple[tuple[object, ...], ...],
) -> bool:
    return any(
        authority is sample._issuer
        and authority._binding_snapshot() == snapshot
        and authority.accepts(sample)
        for authority, snapshot in zip(authorities, snapshots, strict=True)
    )


def _bound_authority(
    sample: TimeSample,
    authorities: tuple[SampleAuthority, ...],
    snapshots: tuple[tuple[object, ...], ...],
) -> SampleAuthority | None:
    for authority, snapshot in zip(authorities, snapshots, strict=True):
        if (
            authority is sample._issuer
            and authority._binding_snapshot() == snapshot
            and authority.accepts(sample)
        ):
            return authority
    return None


def _rtc_state_stale(sample: TimeSample, now: float, maximum_age: int) -> bool:
    rtc_age = sample.evidence.rtc_age_seconds
    assert rtc_age is not None
    return rtc_age > maximum_age or now - sample.observed_monotonic > maximum_age - rtc_age


def _rejection(
    sample: TimeSample,
    floor: int,
    now: float,
    policy: SourcePrecedencePolicy,
    authorities: tuple[SampleAuthority, ...],
    snapshots: tuple[tuple[object, ...], ...],
    claimed_authority: SampleAuthority | None = None,
) -> str | None:
    if type(sample) is not TimeSample or (
        claimed_authority is None and not _bound(sample, authorities, snapshots)
    ):
        return "sample-authority-not-bound"
    TimeProvider, DioTimeVerifier, TimeAdmin = _get_late_types()  # noqa: N806
    if type(claimed_authority) is DioTimeVerifier and not claimed_authority._generation_live(
        sample
    ):
        return "network-signer-generation-retired"
    if sample.stratum is Stratum.NO_SYNC or sample.source_class is SourceClass.MONOTONIC:
        return "source-cannot-establish-wall-clock"
    if sample.source_class not in STRATUM_SOURCE_CLASSES[sample.stratum]:
        return "source-class-does-not-match-stratum"
    evidence = sample.evidence
    if not evidence.source_valid:
        return "source-evidence-not-valid"
    if not evidence.policy_accepted:
        return "provider-policy-rejected"
    if sample.source_class not in policy.accepted_wall_clock_sources:
        return "source-class-not-accepted"
    if sample.accuracy_seconds > policy.max_accuracy_seconds[sample.source_class]:
        return "source-accuracy-exceeds-policy"
    if sample.unix_time < floor:
        return "below-epoch-floor"
    if now < sample.observed_monotonic:
        return "observation-is-in-the-future"
    if now - sample.observed_monotonic > policy.max_sample_age_s:
        return "sample-stale"
    if sample.source_class is SourceClass.GNSS and evidence.gnss_time_valid is not True:
        return "gnss-time-not-valid"
    if sample.source_class is SourceClass.LOCAL_CLIENT:
        if sample.stratum is Stratum.GNSS_GPSD:
            if evidence.source_subtype != "gpsd" or evidence.source_subtype_verified is not True:
                return "local-client-gpsd-not-verified"
            if evidence.transport_class is None:
                quality_rejection = _gpsd_quality_rejection(
                    evidence.quality, sample.accuracy_seconds
                )
                if quality_rejection is not None:
                    return quality_rejection
        elif sample.stratum is not Stratum.MESH_DERIVED or evidence.source_subtype == "gpsd":
            return "local-client-subtype-stratum-mismatch"
    if sample.source_class is SourceClass.INTERNAL_RTC:
        if evidence.rtc_initialized is not True or evidence.rtc_age_seconds is None:
            return "rtc-validity-metadata-missing"
        if _rtc_state_stale(sample, now, policy.max_sample_age_s):
            return "rtc-state-stale"
    if evidence.transport_class is SourceClass.NETWORK:
        signer, payload, span = (
            evidence.signer_public_key,
            evidence.authenticated_payload,
            evidence.option_span,
        )
        if (
            evidence.network_authenticated is not True
            or signer is None
            or evidence.signer_key_generation is None
            or evidence.replay_counter is None
            or payload is None
            or span is None
            or evidence.clock_domain_identity is None
        ):
            return "network-verifier-evidence-missing"
        if SourceClass.NETWORK not in policy.accepted_wall_clock_sources:
            return "network-transport-not-authorized"
        if signer not in policy.authorized_network_peers:
            return "network-peer-not-authorized-for-time"
        start, end = span
        # Import DioTimeOption from time_sync for option encoding comparison
        from .time_sync import DioTimeOption as DioTimeOptionCls

        if (
            not 0 <= start < end <= len(payload)
            or payload[start:end] != DioTimeOptionCls(sample.stratum, sample.unix_time).encode()
        ):
            return "network-option-evidence-mismatch"
    elif sample.source_class is SourceClass.NETWORK:
        protocol = evidence.network_protocol
        # Import _PROTOCOL_STRATUM from time_sync for protocol validation
        from .time_sync import _PROTOCOL_STRATUM

        if evidence.network_authenticated is not True or protocol not in _PROTOCOL_STRATUM:
            return "direct-network-evidence-missing"
        assert protocol is not None
        if _PROTOCOL_STRATUM[protocol] is not sample.stratum:
            return "network-protocol-stratum-mismatch"
    return None


def _replacement_policy_rejection(
    sample: TimeSample, policy: SourcePrecedencePolicy, now: float
) -> str | None:
    """Re-evaluate the policy-controlled properties of tracker-owned state."""
    if sample.source_class not in policy.accepted_wall_clock_sources:
        return "source-class-not-accepted"
    if sample.accuracy_seconds > policy.max_accuracy_seconds[sample.source_class]:
        return "source-accuracy-exceeds-policy"
    if now < sample.observed_monotonic:
        return "observation-is-in-the-future"
    if now - sample.observed_monotonic > policy.max_sample_age_s:
        return "sample-stale"
    evidence = sample.evidence
    if sample.source_class is SourceClass.INTERNAL_RTC:
        if evidence.rtc_initialized is not True or evidence.rtc_age_seconds is None:
            return "rtc-validity-metadata-missing"
        if _rtc_state_stale(sample, now, policy.max_sample_age_s):
            return "rtc-state-stale"
    if (
        sample.source_class is SourceClass.LOCAL_CLIENT
        and sample.stratum is Stratum.GNSS_GPSD
        and evidence.transport_class is None
    ):
        quality_rejection = _gpsd_quality_rejection(
            evidence.quality, sample.accuracy_seconds
        )
        if quality_rejection is not None:
            return quality_rejection
    if evidence.transport_class is SourceClass.NETWORK:
        signer = evidence.signer_public_key
        if SourceClass.NETWORK not in policy.accepted_wall_clock_sources:
            return "network-transport-not-authorized"
        if signer not in policy.authorized_network_peers:
            return "network-peer-not-authorized-for-time"
    return None


def _correction_rate_allowance(elapsed: float, ppm: int) -> int:
    """Compute floor(elapsed * ppm / 1e6) without float multiplication overflow."""
    whole = math.floor(elapsed)
    fraction = elapsed - whole
    quotient, remainder = divmod(whole * ppm, 1_000_000)
    return quotient + math.floor((remainder + fraction * ppm) / 1_000_000)


def can_establish_sample(
    sample: TimeSample,
    epoch_floor: int,
    current_monotonic: float,
    *,
    authorities: tuple[SampleAuthority, ...] = (),
    policy: SourcePrecedencePolicy = DEFAULT_SOURCE_PRECEDENCE_POLICY,
) -> bool:
    """Non-authoritative diagnostic prefilter; it never changes state."""
    if type(sample) is not TimeSample:
        raise TypeError("sample must be TimeSample")
    now = _mono(current_monotonic)
    floor = _epoch(epoch_floor, "epoch_floor")
    snapshots = tuple(authority._binding_snapshot() for authority in authorities)
    projected = _project(sample.unix_time, sample.observed_monotonic, now)
    return (
        _rejection(sample, floor, now, policy, authorities, snapshots) is None
        and projected <= _UINT32_MAX
        and projected - floor <= policy.max_initial_epoch_lead_s
    )


def can_establish_wall_clock(
    source_class: SourceClassLike,
    timestamp: int,
    epoch_floor: int,
    *,
    policy: SourcePrecedencePolicy = DEFAULT_SOURCE_PRECEDENCE_POLICY,
) -> bool:
    warnings.warn(
        "can_establish_wall_clock is non-authoritative; use a bound TimeProvider",
        DeprecationWarning,
        stacklevel=2,
    )
    source = _source(source_class, "source_class")
    try:
        sample_time = _epoch(timestamp, "timestamp")
        floor = _epoch(epoch_floor, "epoch_floor")
    except (TypeError, ValueError):
        return False
    return (
        sample_time >= floor
        and SOURCE_CAN_ESTABLISH_WALL_CLOCK[source]
        and source in policy.accepted_wall_clock_sources
    )


def should_adopt_time(
    local_stratum: Stratum,
    received_stratum: Stratum,
    received_timestamp: int,
    epoch_floor: int,
) -> bool:
    warnings.warn(
        "should_adopt_time is non-authoritative; use StratumTracker",
        DeprecationWarning,
        stacklevel=2,
    )
    if not isinstance(local_stratum, Stratum) or not isinstance(received_stratum, Stratum):
        raise TypeError("strata must be Stratum values")
    try:
        timestamp = _epoch(received_timestamp, "received_timestamp")
        floor = _epoch(epoch_floor, "epoch_floor")
    except (TypeError, ValueError):
        return False
    return (
        received_stratum is not Stratum.NO_SYNC
        and timestamp >= floor
        and received_stratum > local_stratum
    )


@dataclass(frozen=True)
class TimeStatus:
    wall_clock_valid: bool
    unix_time: int | None
    source_class: SourceClass | None
    source_name: str | None
    stratum: Stratum
    sample_age_seconds: float | None
    accuracy_seconds: float | None
    evidence: TimeEvidence | None
    last_reason: str | None
    epoch_floor: int
    provision_status: ProvisionEpochStatus


class StratumTracker:
    """Locked transition-only state with immutable policy/floor bindings."""

    def __init__(
        self,
        *,
        authorities: tuple[SampleAuthority, ...],
        policy: SourcePrecedencePolicy,
        floor_authority: EpochFloorAuthority,
        clock: MonotonicClock = SYSTEM_MONOTONIC_CLOCK,
        admin: TimeAdmin | None = None,
    ) -> None:
        TimeProvider, DioTimeVerifier, TimeAdmin = _get_late_types()  # noqa: N806
        if not isinstance(authorities, tuple) or not all(
            type(value) in (TimeProvider, DioTimeVerifier) for value in authorities
        ):
            raise TypeError("authorities must contain exact time authority types")
        if len({id(v) for v in authorities}) != len(authorities):
            raise ValueError("authorities must not contain duplicates")
        if type(policy) is not SourcePrecedencePolicy:
            raise TypeError("policy must be exact SourcePrecedencePolicy")
        if type(floor_authority) is not EpochFloorAuthority:
            raise TypeError("floor_authority must be exact EpochFloorAuthority")
        if type(clock) is not MonotonicClock:
            raise TypeError("clock must be an exact MonotonicClock")
        if any(authority.clock is not clock for authority in authorities):
            raise ValueError("all time authorities and tracker must share one MonotonicClock")
        if admin is not None and type(admin) is not TimeAdmin:
            raise TypeError("admin must be exact TimeAdmin or None")
        self.__authorities = authorities
        self.__authority_snapshots = tuple(v._binding_snapshot() for v in authorities)
        self.__policy = self._copy_policy(policy)
        self.__floor_authority = floor_authority
        self.__clock = clock
        self.__clock_snapshot = clock._binding_snapshot()
        self.__floor_snapshot = floor_authority._binding_snapshot()
        self.__admin = admin
        self.__sample: TimeSample | None = None
        self.__last_sample: TimeSample | None = None
        self.__reference_timestamp: int | None = None
        self.__reference_monotonic: float | None = None
        self.__anchor_timestamp: int | None = None
        self.__anchor_monotonic: float | None = None
        self.__last_reason: str | None = None
        self.__network_high_water: OrderedDict[tuple[bytes, object], int] = OrderedDict()
        self.__issuance_high_water: dict[SampleAuthority, int] = {}
        self.__lock = threading.RLock()

    @staticmethod
    def _copy_policy(policy: SourcePrecedencePolicy) -> SourcePrecedencePolicy:
        return SourcePrecedencePolicy(
            precedence=policy.precedence,
            accepted_wall_clock_sources=policy.accepted_wall_clock_sources,
            max_sample_age_s=policy.max_sample_age_s,
            max_initial_epoch_lead_s=policy.max_initial_epoch_lead_s,
            max_forward_step_s=policy.max_forward_step_s,
            max_backward_step_s=policy.max_backward_step_s,
            max_cumulative_forward_correction_s=policy.max_cumulative_forward_correction_s,
            max_correction_rate_ppm=policy.max_correction_rate_ppm,
            authorized_network_peers=policy.authorized_network_peers,
            max_accuracy_seconds=policy.max_accuracy_seconds,
        )

    def _now(self) -> float:
        if self.__clock._binding_snapshot() != self.__clock_snapshot:
            raise RuntimeError("monotonic clock binding changed")
        return _mono(self.__clock(), "tracker clock")

    def _floor_transition(self, transition: Callable[[EpochFloorSnapshot], object]) -> object:
        if self.__floor_authority._binding_snapshot() != self.__floor_snapshot:
            self._clear_locked("epoch-floor-authority-binding-changed")
            raise RuntimeError("epoch floor authority binding changed")
        return self.__floor_authority._with_snapshot(transition)

    @property
    def last_rejection_reason(self) -> str | None:
        with self.__lock:
            return self.__last_reason

    def raw_sample_diagnostic(self) -> TimeSample | None:
        with self.__lock:
            return _detach_sample(self.__sample) if self.__sample is not None else None

    def last_sample_diagnostic(self) -> TimeSample | None:
        with self.__lock:
            return _detach_sample(self.__last_sample) if self.__last_sample is not None else None

    def _reject(self, reason: str) -> bool:
        self.__last_reason = reason
        return False

    def _clear_locked(self, reason: str, *, reset_reference: bool = False) -> None:
        if self.__sample is not None:
            self.__last_sample = self.__sample
        self.__sample = None
        for authority in self.__authorities:
            self.__issuance_high_water[authority] = authority._latest_issuance_sequence()
        if reset_reference:
            self.__reference_timestamp = None
            self.__reference_monotonic = None
        self.__last_reason = reason

    def clear(self, reason: str = "source-invalidated") -> None:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reason must be non-empty")
        with self.__lock:
            self._clear_locked(reason)

    def reset_correction_anchor(self, admin: TimeAdmin, *, reason: str) -> None:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("recovery reason must be non-empty")
        with self.__lock:
            if self.__admin is None or admin is not self.__admin:
                raise PermissionError("anchor recovery requires bound admin")
            self._clear_locked(f"admin-recovery:{reason}", reset_reference=True)
            self.__anchor_timestamp = None
            self.__anchor_monotonic = None

    def replace_policy(self, admin: TimeAdmin, policy: SourcePrecedencePolicy) -> None:
        if type(policy) is not SourcePrecedencePolicy:
            raise TypeError("policy must be exact SourcePrecedencePolicy")
        with self.__lock:
            if self.__admin is None or admin is not self.__admin:
                raise PermissionError("policy replacement requires bound admin")
            now = self._now()

            def replace(snapshot: EpochFloorSnapshot) -> object:
                # Begin with live-floor validation under the old policy, then
                # preserve anchors/replay/reference while replacing policy.
                self._validate_active_locked(now, snapshot.result)
                self.__policy = self._copy_policy(policy)
                if self.__sample is not None:
                    rejection = _replacement_policy_rejection(
                        self.__sample, self.__policy, now
                    )
                    if rejection is not None:
                        self._clear_locked(f"policy-replaced:{rejection}")
                return None

            self._floor_transition(replace)

    def _expire_locked(self, now: float) -> None:
        if self.__sample is None:
            return
        if now < self.__sample.observed_monotonic:
            self._clear_locked("current-monotonic-regressed")
        elif (
            self.__sample.source_class is SourceClass.INTERNAL_RTC
            and self.__sample.evidence.rtc_age_seconds is not None
            and _rtc_state_stale(self.__sample, now, self.__policy.max_sample_age_s)
        ):
            self._clear_locked("current-rtc-state-stale")
        elif now - self.__sample.observed_monotonic > self.__policy.max_sample_age_s:
            self._clear_locked("current-source-expired")

    def _validate_active_locked(self, now: float, live_floor: EpochFloorResult) -> int | None:
        sample = self.__sample
        _, DioTimeVerifier, _ = _get_late_types()  # noqa: N806
        if sample is not None and type(sample._issuer) is DioTimeVerifier:
            try:
                result = sample._issuer._with_live_generation(
                    sample,
                    lambda: self._validate_active_at_live_generation_locked(
                        now, live_floor
                    ),
                )
            except (RuntimeError, ValueError):
                self._clear_locked("current-network-signer-generation-retired")
                return None
            assert result is None or isinstance(result, int)
            return result
        return self._validate_active_at_live_generation_locked(now, live_floor)

    def _validate_active_at_live_generation_locked(
        self, now: float, live_floor: EpochFloorResult
    ) -> int | None:
        if live_floor.provision_status is ProvisionEpochStatus.PERSISTENCE_FAILED:
            self._clear_locked("provision-persistence-failed")
            return None
        self._expire_locked(now)
        if (
            self.__sample is None
            or self.__reference_timestamp is None
            or self.__reference_monotonic is None
        ):
            return None
        value = _project(self.__reference_timestamp, self.__reference_monotonic, now)
        if value > _UINT32_MAX:
            self._clear_locked("projected-time-out-of-wire-range")
            return None
        if value < live_floor.floor:
            self._clear_locked(f"below-live-epoch-floor:{live_floor.provision_status.value}")
            return None
        return value

    def _current_time_locked(self, now: float, live_floor: EpochFloorResult) -> int | None:
        return self._validate_active_locked(now, live_floor)

    def current_time(self) -> int | None:
        with self.__lock:
            now = self._now()
            result = self._floor_transition(
                lambda snapshot: self._current_time_locked(now, snapshot.result)
            )
            assert result is None or isinstance(result, int)
            return result

    def status(self) -> TimeStatus:
        with self.__lock:
            now = self._now()

            def build_status(snapshot: EpochFloorSnapshot) -> object:
                floor = snapshot.result
                unix_time = self._current_time_locked(now, floor)
                sample = self.__sample
                last = sample or self.__last_sample
                return TimeStatus(
                    sample is not None and unix_time is not None,
                    unix_time,
                    sample.source_class if sample is not None else None,
                    sample.source_name if sample is not None else None,
                    sample.stratum if sample is not None else Stratum.NO_SYNC,
                    now - sample.observed_monotonic if sample is not None else None,
                    sample.accuracy_seconds if sample is not None else None,
                    _detach_sample(last).evidence if last is not None else None,
                    self.__last_reason,
                    floor.floor,
                    floor.provision_status,
                )

            result = self._floor_transition(build_status)
            assert isinstance(result, TimeStatus)
            return result

    def _anchor_rejection(self, projected: int, now: float) -> str | None:
        if self.__anchor_timestamp is None or self.__anchor_monotonic is None:
            return None
        if now < self.__anchor_monotonic:
            return "current-monotonic-regressed"
        expected = _project(self.__anchor_timestamp, self.__anchor_monotonic, now)
        cumulative = projected - expected
        elapsed = now - self.__anchor_monotonic
        rate = _correction_rate_allowance(
            elapsed, self.__policy.max_correction_rate_ppm
        )
        if cumulative > self.__policy.max_cumulative_forward_correction_s + rate:
            return "cumulative-forward-correction-exceeds-policy"
        if cumulative < -self.__policy.max_backward_step_s:
            return "cumulative-backward-correction-exceeds-policy"
        return None

    def _adopt_locked(
        self,
        sample: TimeSample,
        now: float,
        floor: int,
        option: DioTimeOption | None = None,
    ) -> bool:
        _, DioTimeVerifier, _ = _get_late_types()  # noqa: N806
        authority = _bound_authority(sample, self.__authorities, self.__authority_snapshots)
        if authority is None:
            return self._reject("sample-authority-not-bound")
        claimed = authority._claim(sample)
        if claimed is None:
            return self._reject("sample-already-considered")
        sample, issuance_sequence = claimed
        if issuance_sequence <= self.__issuance_high_water.get(authority, 0):
            return self._reject("sample-invalidated-or-replayed")
        # Consideration, including rejection, advances the per-authority barrier.
        self.__issuance_high_water[authority] = issuance_sequence
        evidence = sample.evidence
        if evidence.transport_class is SourceClass.NETWORK:
            signer, generation, counter = (
                evidence.signer_public_key,
                evidence.signer_key_generation,
                evidence.replay_counter,
            )
            if signer is None or generation is None or counter is None:
                return self._reject("network-verifier-evidence-missing")
            replay_key = (signer, generation)
            if counter <= self.__network_high_water.get(replay_key, -1):
                return self._reject("network-replay-counter-not-new")
            # Consideration, including rejection, advances the replay barrier.
            for old_key in tuple(self.__network_high_water):
                if old_key[0] == signer and old_key[1] is not generation:
                    self.__network_high_water.pop(old_key, None)
            self.__network_high_water[replay_key] = counter
            self.__network_high_water.move_to_end(replay_key)
            while len(self.__network_high_water) > MAX_NETWORK_REPLAY_GENERATIONS:
                self.__network_high_water.popitem(last=False)
        if option is not None and (
            option.stratum is not sample.stratum or option.timestamp != sample.unix_time
        ):
            return self._reject("sample-does-not-match-option")
        if type(authority) is DioTimeVerifier:
            try:
                result = authority._with_live_generation(
                    sample,
                    lambda: self._adopt_claimed_locked(sample, authority, now, floor),
                )
            except (RuntimeError, ValueError):
                return self._reject("network-signer-generation-retired")
            assert isinstance(result, bool)
            return result
        return self._adopt_claimed_locked(sample, authority, now, floor)

    def _adopt_claimed_locked(
        self,
        sample: TimeSample,
        authority: SampleAuthority,
        now: float,
        floor: int,
    ) -> bool:
        rejection = _rejection(
            sample,
            floor,
            now,
            self.__policy,
            self.__authorities,
            self.__authority_snapshots,
            authority,
        )
        if rejection is not None:
            return self._reject(rejection)
        projected = _project(sample.unix_time, sample.observed_monotonic, now)
        if projected > _UINT32_MAX:
            return self._reject("projected-time-out-of-wire-range")
        if (
            self.__sample is None
            and self.__anchor_timestamp is None
            and projected - floor > self.__policy.max_initial_epoch_lead_s
        ):
            return self._reject("initial-time-too-far-above-epoch-floor")
        if self.__sample is not None:
            current = self.__sample
            if sample.observed_monotonic <= current.observed_monotonic:
                return self._reject("stale-or-duplicate-sample")
            if sample.stratum < current.stratum:
                return self._reject("lower-stratum")
            if sample.stratum is current.stratum and self.__policy.rank(
                sample.source_class
            ) > self.__policy.rank(current.source_class):
                return self._reject("equal-stratum-lower-precedence-source")
        if self.__reference_timestamp is not None and self.__reference_monotonic is not None:
            correction = projected - _project(
                self.__reference_timestamp, self.__reference_monotonic, now
            )
            if correction < -self.__policy.max_backward_step_s:
                return self._reject("backward-step-exceeds-policy")
            if correction > self.__policy.max_forward_step_s:
                return self._reject("forward-step-exceeds-policy")
        anchor_rejection = self._anchor_rejection(projected, now)
        if anchor_rejection is not None:
            return self._reject(anchor_rejection)
        adopted = _detach_sample(sample)
        self.__sample = adopted
        self.__last_sample = adopted
        self.__reference_timestamp = projected
        self.__reference_monotonic = now
        if self.__anchor_timestamp is None:
            self.__anchor_timestamp = projected
            self.__anchor_monotonic = now
        self.__last_reason = None
        return True

    def adopt(self, sample: TimeSample) -> bool:
        if type(sample) is not TimeSample:
            raise TypeError("sample must be TimeSample")
        with self.__lock:
            now = self._now()

            def adopt_at_floor(snapshot: EpochFloorSnapshot) -> object:
                self._validate_active_locked(now, snapshot.result)
                return self._adopt_locked(sample, now, snapshot.result.floor)

            result = self._floor_transition(adopt_at_floor)
            assert isinstance(result, bool)
            return result

    def consider(self, option: DioTimeOption, *, sample: TimeSample | None = None) -> bool:
        if type(option) is not DioTimeOption:
            raise TypeError("option must be exact DioTimeOption")
        with self.__lock:
            now = self._now()
            if sample is None:
                return self._reject("structured-sample-required")

            def consider_at_floor(snapshot: EpochFloorSnapshot) -> object:
                self._validate_active_locked(now, snapshot.result)
                return self._adopt_locked(sample, now, snapshot.result.floor, option)

            result = self._floor_transition(consider_at_floor)
            assert isinstance(result, bool)
            return result
