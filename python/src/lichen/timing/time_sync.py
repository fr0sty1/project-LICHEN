# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Capability-bound wall-clock synchronization (spec 09 section 14.6).

This module provides the core time synchronization capabilities:
- MonotonicClock: Immutable clock capability for monotonic time
- TimeProvider: Trusted direct-source integration for wall-clock samples
- DioTimeVerifier: Derives time evidence from authenticated DIOs
- TimeAdmin: Administrative operations for provisioning and recovery

All other time sync components are re-exported from sibling modules for
backwards compatibility.
"""

from __future__ import annotations

import hashlib
import math
import threading
import time
import weakref
from collections.abc import Callable, Mapping
from enum import IntEnum
from types import MappingProxyType
from typing import Final, TypeAlias

# Import from source.py - base types and utilities
from .source import (
    _UINT64_MAX,
    DEFAULT_MAX_BACKWARD_STEP_S,
    DEFAULT_MAX_CORRECTION_RATE_PPM,
    DEFAULT_MAX_CUMULATIVE_FORWARD_CORRECTION_S,
    DEFAULT_MAX_FORWARD_STEP_S,
    DEFAULT_MAX_INITIAL_EPOCH_LEAD_S,
    DEFAULT_MAX_PROVISION_LEAD_S,
    DEFAULT_MAX_SAMPLE_AGE_S,
    DEFAULT_SOURCE_PRECEDENCE_POLICY,
    MAX_CORRECTION_RATE_PPM,
    PROVISION_VIRGIN_MARKER,
    SOURCE_CAN_ESTABLISH_WALL_CLOCK,
    SOURCE_CLASSES,
    SourceClass,
    SourceClassLike,
    SourcePrecedencePolicy,
    _accuracy,
    _call_sync,
    _epoch,
    _mono,
    _reject_awaitable,
    _require_sync_callable,
    _source,
    _uint,
)

# Constants needed by this module and siblings
_UINT32_MAX = (1 << 32) - 1
_PUBKEY_LEN = 32
MAX_NETWORK_REPLAY_GENERATIONS: Final[int] = 256
DIO_TIME_OPTION_TYPE: Final[int] = 0x15
DIO_TIME_OPTION_LEN: Final[int] = 6
DIO_TIME_OPTION_TOTAL: Final[int] = 8


class MonotonicClock:
    """Structurally immutable clock capability shared by every trust boundary."""

    __slots__ = ("__weakref__",)

    def __init__(self, callback: Callable[[], float] = time.monotonic) -> None:
        _require_sync_callable(callback, "callback")
        with _MONOTONIC_BINDINGS_LOCK:
            if self in _MONOTONIC_BINDINGS:
                raise RuntimeError("MonotonicClock capability is already initialized")
            _MONOTONIC_BINDINGS[self] = (callback, object())

    def __call__(self) -> float:
        return _mono(_call_sync(self.callback, "monotonic clock callback"), "monotonic clock")

    @property
    def callback(self) -> Callable[[], float]:
        """The construction-time callback; the binding cannot be replaced."""
        with _MONOTONIC_BINDINGS_LOCK:
            return _MONOTONIC_BINDINGS[self][0]

    @property
    def domain_identity(self) -> object:
        """Opaque domain token; consumers MUST compare it only by identity."""
        with _MONOTONIC_BINDINGS_LOCK:
            return _MONOTONIC_BINDINGS[self][1]

    def _binding_snapshot(self) -> tuple[object, ...]:
        with _MONOTONIC_BINDINGS_LOCK:
            callback, domain = _MONOTONIC_BINDINGS[self]
            return (id(self), id(callback), id(domain))


_MONOTONIC_BINDINGS_LOCK = threading.RLock()
_MONOTONIC_BINDINGS: weakref.WeakKeyDictionary[
    MonotonicClock, tuple[Callable[[], float], object]
] = weakref.WeakKeyDictionary()


SYSTEM_MONOTONIC_CLOCK: Final[MonotonicClock] = MonotonicClock()


# Stratum enum must be defined here since it's needed by sibling modules
class Stratum(IntEnum):
    NO_SYNC = 0
    MESH_DERIVED = 1
    ROUGHTIME = 2
    NTS = 3
    GNSS_GPSD = 4


STRATUM_SOURCE_CLASSES: Final[Mapping[Stratum, frozenset[SourceClass]]] = MappingProxyType(
    {
        Stratum.NO_SYNC: frozenset({SourceClass.MONOTONIC}),
        Stratum.MESH_DERIVED: frozenset(
            {
                SourceClass.NETWORK,
                SourceClass.LOCAL_CLIENT,
                SourceClass.MANUAL,
                SourceClass.INTERNAL_RTC,
            }
        ),
        Stratum.ROUGHTIME: frozenset({SourceClass.NETWORK}),
        Stratum.NTS: frozenset({SourceClass.NETWORK}),
        Stratum.GNSS_GPSD: frozenset({SourceClass.GNSS, SourceClass.LOCAL_CLIENT}),
    }
)
STRATUM_SOURCE_CLASS = STRATUM_SOURCE_CLASSES
_DIO_ORIGIN_CLASSES: Final[Mapping[Stratum, frozenset[SourceClass]]] = MappingProxyType(
    {
        Stratum.MESH_DERIVED: frozenset({SourceClass.NETWORK}),
        Stratum.ROUGHTIME: frozenset({SourceClass.NETWORK}),
        Stratum.NTS: frozenset({SourceClass.NETWORK}),
        Stratum.GNSS_GPSD: frozenset({SourceClass.GNSS, SourceClass.LOCAL_CLIENT}),
    }
)
_PROTOCOL_STRATUM = MappingProxyType(
    {"NTS": Stratum.NTS, "Roughtime": Stratum.ROUGHTIME, "SNTP-authenticated": Stratum.NTS}
)


def _project(timestamp: int, observed: float, now: float) -> int:
    return timestamp + math.floor(now - observed)


# Import from samples.py - sample data structures
# Import from provisioning.py - epoch floor and provisioning
from .provisioning import (  # noqa: E402
    EpochFloorAuthority,
    EpochFloorResult,
    EpochFloorSnapshot,
    ProvisionClearedState,
    ProvisionEpochMetadata,
    ProvisionEpochStatus,
    ProvisionRecord,
    ProvisionRollbackState,
    ProvisionVerifier,
    ProvisionVirginState,
    effective_epoch_floor,
    evaluate_epoch_floor,
)
from .samples import (  # noqa: E402
    DioTimeOption,
    QualityValue,
    TimeEvidence,
    TimeSample,
    _detach_sample,
    _evidence_snapshot,
    _freeze,
    _frozen_snapshot,
    _gpsd_quality_rejection,
    _sample_snapshot,
    _SampleAuthority,
)


class TimeAdmin:
    def __init__(self, name: str) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("admin name must be non-empty")
        self.__name = name
        self.__virgin_states: weakref.WeakValueDictionary[int, ProvisionVirginState] = (
            weakref.WeakValueDictionary()
        )
        self.__virgin_bootstrap_started = False
        self.__virgin_lock = threading.Lock()

    @property
    def name(self) -> str:
        return self.__name

    def initialize_virgin_provision_state(
        self, persist_marker: Callable[[bytes], object]
    ) -> ProvisionVirginState:
        """Persist and issue the only valid empty rollback-store state."""
        callback = _require_sync_callable(persist_marker, "persist_marker")
        with self.__virgin_lock:
            if self.__virgin_bootstrap_started:
                raise RuntimeError("virgin provision bootstrap is single-use")
            self.__virgin_bootstrap_started = True
        try:
            persisted = _call_sync(callback, "persist_marker", PROVISION_VIRGIN_MARKER)
            if type(persisted) is not bytes or persisted != PROVISION_VIRGIN_MARKER:
                raise RuntimeError("virgin marker persistence was not acknowledged")
            state = object.__new__(ProvisionVirginState)
            object.__setattr__(state, "_admin", self)
            object.__setattr__(
                state, "marker_digest", hashlib.sha256(PROVISION_VIRGIN_MARKER).digest()
            )
            with self.__virgin_lock:
                self.__virgin_states[id(state)] = state
            return state
        except BaseException:
            with self.__virgin_lock:
                self.__virgin_bootstrap_started = False
            raise

    def _consume_virgin_state(self, state: ProvisionVirginState) -> bool:
        with self.__virgin_lock:
            if self.__virgin_states.get(id(state)) is not state:
                return False
            self.__virgin_states.pop(id(state), None)
            return True


class TimeProvider(_SampleAuthority):
    """Immutable capability held by a trusted direct-source integration."""

    def __init__(
        self,
        name: str,
        allowed_sources: frozenset[SourceClass],
        *,
        clock: MonotonicClock = SYSTEM_MONOTONIC_CLOCK,
    ) -> None:
        super().__init__(name, clock)
        if not isinstance(allowed_sources, frozenset) or not allowed_sources:
            raise ValueError("allowed_sources must be a non-empty frozenset")
        if not all(type(value) is SourceClass for value in allowed_sources):
            raise TypeError("allowed_sources must contain exact SourceClass values")
        if SourceClass.MONOTONIC in allowed_sources:
            raise ValueError("Monotonic cannot issue wall-clock samples")
        self.__allowed_sources = frozenset(allowed_sources)

    @property
    def allowed_sources(self) -> frozenset[SourceClass]:
        return self.__allowed_sources

    def _binding_snapshot(self) -> tuple[object, ...]:
        return super()._binding_snapshot() + (self.__allowed_sources,)

    def sample(
        self,
        *,
        source_class: SourceClass,
        source_name: str,
        unix_time: int,
        stratum: Stratum,
        accuracy_seconds: float,
        source_valid: bool,
        policy_accepted: bool,
        gnss_time_valid: bool | None = None,
        gnss_position_valid: bool | None = None,
        rtc_initialized: bool | None = None,
        rtc_age_seconds: int | None = None,
        network_protocol: str | None = None,
        network_authenticated: bool | None = None,
        source_subtype: str | None = None,
        source_subtype_verified: bool | None = None,
        quality: Mapping[str, object] | None = None,
    ) -> TimeSample:
        if type(source_class) is not SourceClass or source_class not in self.__allowed_sources:
            raise ValueError("source_class is not authorized for this provider")
        if not isinstance(source_name, str) or not source_name.strip():
            raise ValueError("source_name must be non-empty")
        if type(stratum) is not Stratum or stratum is Stratum.NO_SYNC:
            raise ValueError("authoritative samples require a non-NO_SYNC stratum")
        if source_class not in STRATUM_SOURCE_CLASSES[stratum]:
            raise ValueError("source class does not match selected time quality")
        if not isinstance(source_valid, bool) or not isinstance(policy_accepted, bool):
            raise TypeError("validity and policy decisions must be bools")
        if source_class is SourceClass.NETWORK:
            protocol = network_protocol
            if network_authenticated is not True or protocol not in _PROTOCOL_STRATUM:
                raise ValueError("direct network time requires an authenticated supported protocol")
            assert protocol is not None
            if _PROTOCOL_STRATUM[protocol] is not stratum:
                raise ValueError("network protocol does not match stratum")
        frozen_quality = _freeze(dict(quality or {}))
        assert isinstance(frozen_quality, Mapping)
        if source_class is SourceClass.LOCAL_CLIENT:
            if not isinstance(source_subtype, str) or not source_subtype.strip():
                raise ValueError("local-client time requires a source_subtype")
            if stratum is Stratum.GNSS_GPSD:
                if source_subtype != "gpsd" or source_subtype_verified is not True:
                    raise ValueError("stratum 4 local-client time requires verified gpsd")
                quality_rejection = _gpsd_quality_rejection(
                    frozen_quality, _accuracy(accuracy_seconds)
                )
                if quality_rejection is not None:
                    raise ValueError(quality_rejection)
            elif stratum is not Stratum.MESH_DERIVED or source_subtype == "gpsd":
                raise ValueError("non-gpsd local-client time must use stratum 1")
        if rtc_age_seconds is not None:
            rtc_age_seconds = _uint(rtc_age_seconds, "rtc_age_seconds")
        evidence = TimeEvidence(
            issuer_name=self.name,
            transport_class=None,
            source_valid=source_valid,
            policy_accepted=policy_accepted,
            gnss_time_valid=gnss_time_valid,
            gnss_position_valid=gnss_position_valid,
            rtc_initialized=rtc_initialized,
            rtc_age_seconds=rtc_age_seconds,
            network_protocol=network_protocol,
            network_authenticated=network_authenticated,
            source_subtype=source_subtype,
            source_subtype_verified=source_subtype_verified,
            clock_domain_identity=self.clock.domain_identity,
            quality=frozen_quality,
        )
        sample = object.__new__(TimeSample)
        for key, value in (
            ("source_class", source_class),
            ("source_name", source_name),
            ("unix_time", _epoch(unix_time, "unix_time")),
            ("observed_monotonic", self._now()),
            ("stratum", stratum),
            ("accuracy_seconds", _accuracy(accuracy_seconds)),
            ("evidence", evidence),
            ("_issuer", self),
        ):
            object.__setattr__(sample, key, value)
        self._SampleAuthority__remember(sample)  # type: ignore[attr-defined]
        return sample


class DioTimeVerifier(_SampleAuthority):
    """Derives time evidence from one sealed, canonical authenticated DIO."""

    def __init__(
        self,
        name: str,
        receiving_link: object,
        *,
        peer_origins: Mapping[bytes, Mapping[Stratum, SourceClass]],
        peer_accuracy_seconds: Mapping[bytes, float],
        clock: MonotonicClock = SYSTEM_MONOTONIC_CLOCK,
    ) -> None:
        from lichen.link.link_layer import LinkLayer

        if type(receiving_link) is not LinkLayer:
            raise TypeError("receiving_link must be an exact LinkLayer")
        if type(clock) is not MonotonicClock:
            raise TypeError("clock must be an exact MonotonicClock")
        if receiving_link.clock_domain_identity is not clock.domain_identity:
            raise ValueError("receiving LinkLayer uses a different monotonic clock domain")
        super().__init__(name, clock)
        origins: dict[bytes, Mapping[Stratum, SourceClass]] = {}
        for peer, entries in peer_origins.items():
            if type(peer) is not bytes or len(peer) != _PUBKEY_LEN:
                raise ValueError("peer keys must be 32 bytes")
            mapping = dict(entries)
            for stratum, source in mapping.items():
                if type(stratum) is not Stratum or type(source) is not SourceClass:
                    raise TypeError("peer origins require exact Stratum -> SourceClass values")
                if stratum is Stratum.NO_SYNC or source not in _DIO_ORIGIN_CLASSES[stratum]:
                    raise ValueError("peer origin does not match stratum")
            origins[bytes(peer)] = MappingProxyType(mapping)
        accuracy = {bytes(peer): _accuracy(value) for peer, value in peer_accuracy_seconds.items()}
        if set(origins) != set(accuracy):
            raise ValueError("every configured peer requires accuracy")
        self.__link = receiving_link
        self.__origins = MappingProxyType(origins)
        self.__accuracy = MappingProxyType(accuracy)

    def _binding_snapshot(self) -> tuple[object, ...]:
        origins = tuple(
            sorted(
                (peer, tuple(sorted(mapping.items()))) for peer, mapping in self.__origins.items()
            )
        )
        return super()._binding_snapshot() + (
            id(self.__link),
            origins,
            tuple(sorted(self.__accuracy.items())),
        )

    def verify(self, authenticated_dio: object) -> TimeSample:
        from lichen.rpl.authenticated_dio import AuthenticatedDio, DetachedAuthenticatedDio

        if type(authenticated_dio) is not AuthenticatedDio:
            raise TypeError("authenticated_dio must be an exact AuthenticatedDio")

        def issue(detached: DetachedAuthenticatedDio) -> TimeSample:
            if detached.receiving_link_identity is not self.__link.receiving_link_identity:
                raise ValueError("authenticated DIO was issued by a different receiving LinkLayer")
            if detached.clock_domain_identity is not self.clock.domain_identity:
                raise ValueError("authenticated DIO uses a different monotonic clock domain")
            matches = [
                option for option in detached.options if option.type == DIO_TIME_OPTION_TYPE
            ]
            if len(matches) != 1:
                raise ValueError("dio-time-option-count")
            match = matches[0]
            option = DioTimeOption.decode(bytes((match.type, len(match.data))) + match.data)
            if option.stratum is Stratum.NO_SYNC:
                raise ValueError("dio-no-sync")
            signer = detached.sender_pubkey
            origins = self.__origins.get(signer)
            if origins is None or option.stratum not in origins:
                raise ValueError("peer-stratum-not-authorized")
            source = origins[option.stratum]
            quality = _freeze(
                {"rssi_dbm": detached.rssi_dbm, "snr_db": detached.snr_db}
            )
            assert isinstance(quality, Mapping)
            evidence = TimeEvidence(
                issuer_name=self.name,
                transport_class=SourceClass.NETWORK,
                source_valid=True,
                policy_accepted=True,
                gnss_time_valid=True if source is SourceClass.GNSS else None,
                network_protocol="peer-dio",
                network_authenticated=True,
                source_subtype="gpsd" if source is SourceClass.LOCAL_CLIENT else None,
                source_subtype_verified=True if source is SourceClass.LOCAL_CLIENT else None,
                signer_public_key=signer,
                signer_key_generation=detached.key_generation,
                replay_counter=(detached.epoch << 16) | detached.seqnum,
                authenticated_payload=detached.ipv6,
                option_span=match.ipv6_span,
                clock_domain_identity=detached.clock_domain_identity,
                quality=quality,
            )
            sample = object.__new__(TimeSample)
            for key, value in (
                ("source_class", source),
                ("source_name", f"peer-dio:{signer.hex()}"),
                ("unix_time", option.timestamp),
                ("observed_monotonic", _mono(detached.received_monotonic, "receipt time")),
                ("stratum", option.stratum),
                ("accuracy_seconds", self.__accuracy[signer]),
                ("evidence", evidence),
                ("_issuer", self),
            ):
                object.__setattr__(sample, key, value)
            self._SampleAuthority__remember(sample)  # type: ignore[attr-defined]
            return sample

        return self.__link.elevate_authenticated_dio(authenticated_dio, elevate=issue)

    def _generation_live(self, sample: TimeSample) -> bool:
        evidence = sample.evidence
        signer, generation = evidence.signer_public_key, evidence.signer_key_generation
        return (
            signer is not None
            and generation is not None
            and self.__link.accepts_time_generation(signer, generation)
        )

    def _with_live_generation(
        self, sample: TimeSample, transition: Callable[[], object]
    ) -> object:
        evidence = sample.evidence
        signer, generation = evidence.signer_public_key, evidence.signer_key_generation
        if signer is None or generation is None:
            raise ValueError("network verifier evidence is missing generation data")
        return self.__link.elevate_time_generation(
            signer, generation, elevate=transition
        )


# Type alias for sample authorities
SampleAuthority: TypeAlias = TimeProvider | DioTimeVerifier


# Import from stratum.py - stratum tracking and status
# NOTE: This import must be AFTER TimeAdmin, TimeProvider, DioTimeVerifier are defined
# to avoid circular import issues.
from .stratum import (  # noqa: E402
    StratumTracker,
    TimeStatus,
    can_establish_sample,
    can_establish_wall_clock,
    should_adopt_time,
)

# Re-export all public names for backwards compatibility
__all__ = [
    # Constants
    "DEFAULT_MAX_SAMPLE_AGE_S",
    "DEFAULT_MAX_INITIAL_EPOCH_LEAD_S",
    "DEFAULT_MAX_FORWARD_STEP_S",
    "DEFAULT_MAX_BACKWARD_STEP_S",
    "DEFAULT_MAX_PROVISION_LEAD_S",
    "DEFAULT_MAX_CUMULATIVE_FORWARD_CORRECTION_S",
    "DEFAULT_MAX_CORRECTION_RATE_PPM",
    "MAX_CORRECTION_RATE_PPM",
    "MAX_NETWORK_REPLAY_GENERATIONS",
    "DIO_TIME_OPTION_TYPE",
    "DIO_TIME_OPTION_LEN",
    "DIO_TIME_OPTION_TOTAL",
    "PROVISION_VIRGIN_MARKER",
    "SOURCE_CLASSES",
    "SOURCE_CAN_ESTABLISH_WALL_CLOCK",
    "STRATUM_SOURCE_CLASSES",
    "STRATUM_SOURCE_CLASS",
    "SYSTEM_MONOTONIC_CLOCK",
    "DEFAULT_SOURCE_PRECEDENCE_POLICY",
    # Types
    "SourceClass",
    "SourceClassLike",
    "Stratum",
    "QualityValue",
    "SampleAuthority",
    # Core classes (defined here)
    "MonotonicClock",
    "TimeProvider",
    "DioTimeVerifier",
    "TimeAdmin",
    # Sample classes (from samples.py)
    "TimeSample",
    "TimeEvidence",
    "DioTimeOption",
    # Policy (from source.py)
    "SourcePrecedencePolicy",
    # Provisioning (from provisioning.py)
    "ProvisionEpochStatus",
    "ProvisionVirginState",
    "ProvisionRecord",
    "ProvisionRollbackState",
    "ProvisionClearedState",
    "ProvisionEpochMetadata",
    "ProvisionVerifier",
    "EpochFloorResult",
    "EpochFloorSnapshot",
    "EpochFloorAuthority",
    "evaluate_epoch_floor",
    "effective_epoch_floor",
    # Stratum tracking (from stratum.py)
    "StratumTracker",
    "TimeStatus",
    "can_establish_sample",
    "can_establish_wall_clock",
    "should_adopt_time",
    # Private helpers needed by sibling modules
    "_project",
    "_epoch",
    "_mono",
    "_uint",
    "_source",
    "_accuracy",
    "_call_sync",
    "_require_sync_callable",
    "_reject_awaitable",
    "_freeze",
    "_frozen_snapshot",
    "_gpsd_quality_rejection",
    "_detach_sample",
    "_evidence_snapshot",
    "_sample_snapshot",
    "_UINT64_MAX",
]
