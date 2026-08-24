# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Capability-bound wall-clock synchronization (spec 09 section 14.6)."""

from __future__ import annotations

import hashlib
import math
import threading
import time
import warnings
import weakref
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Final, TypeAlias

from .._sync_callbacks import reject_awaitable_result


class SourceClass(StrEnum):
    GNSS = "GNSS"
    NETWORK = "Network"
    LOCAL_CLIENT = "Local-client"
    MANUAL = "Manual/static"
    INTERNAL_RTC = "Internal RTC"
    MONOTONIC = "Monotonic"


SourceClassLike: TypeAlias = SourceClass | str
SOURCE_CLASSES: Final[tuple[SourceClass, ...]] = tuple(SourceClass)
SOURCE_CAN_ESTABLISH_WALL_CLOCK: Final[Mapping[SourceClass, bool]] = MappingProxyType(
    {s: s is not SourceClass.MONOTONIC for s in SourceClass}
)
DEFAULT_MAX_SAMPLE_AGE_S: Final[int] = 300
DEFAULT_MAX_INITIAL_EPOCH_LEAD_S: Final[int] = 10 * 366 * 86400
DEFAULT_MAX_FORWARD_STEP_S: Final[int] = 3600
DEFAULT_MAX_BACKWARD_STEP_S: Final[int] = 0
DEFAULT_MAX_PROVISION_LEAD_S: Final[int] = 10 * 366 * 86400
DEFAULT_MAX_CUMULATIVE_FORWARD_CORRECTION_S: Final[int] = 3600
DEFAULT_MAX_CORRECTION_RATE_PPM: Final[int] = 1000
MAX_CORRECTION_RATE_PPM: Final[int] = 1_000_000
MAX_NETWORK_REPLAY_GENERATIONS: Final[int] = 256
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1
_PUBKEY_LEN = 32
_DEFAULT_ACCEPTED = frozenset({SourceClass.GNSS, SourceClass.INTERNAL_RTC})
_DEFAULT_ACCURACY: Final[Mapping[SourceClass, float]] = MappingProxyType(
    {
        SourceClass.GNSS: 5.0,
        SourceClass.NETWORK: 10.0,
        SourceClass.LOCAL_CLIENT: 10.0,
        SourceClass.MANUAL: 1.0,
        SourceClass.INTERNAL_RTC: 3600.0,
    }
)


def _default_accuracy() -> Mapping[SourceClassLike, float]:
    result: dict[SourceClassLike, float] = {}
    for source, limit in _DEFAULT_ACCURACY.items():
        result[source] = limit
    return result


def _source(value: SourceClassLike, name: str) -> SourceClass:
    if isinstance(value, SourceClass):
        return value
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a SourceClass or canonical string")
    try:
        result = SourceClass(value)
    except ValueError as exc:
        raise ValueError(f"unknown {name}: {value!r}") from exc
    warnings.warn(
        f"string {name} is deprecated; pass SourceClass.{result.name}",
        DeprecationWarning,
        stacklevel=3,
    )
    return result


def _uint(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _epoch(value: object, name: str, *, nonzero: bool = False) -> int:
    result = _uint(value, name)
    if result > _UINT32_MAX or (nonzero and result == 0):
        raise ValueError(f"{name} must be {'non-zero and ' if nonzero else ''}uint32")
    return result


def _mono(value: object, name: str = "monotonic time") -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{name} must be finite and non-negative")
    return float(value)


def _reject_awaitable(value: object, name: str) -> object:
    return reject_awaitable_result(value, name)


def _require_sync_callable(callback: object, name: str) -> Callable[..., object]:
    if not callable(callback):
        raise TypeError(f"{name} must be callable")
    import inspect

    if inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
        type(callback).__call__
    ):
        raise TypeError(f"{name} must be synchronous")
    return callback


def _call_sync(callback: Callable[..., object], name: str, *args: object) -> object:
    return _reject_awaitable(callback(*args), name)


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


def _accuracy(value: object) -> float:
    result = _mono(value, "accuracy_seconds")
    return result


QualityValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | bytes
    | tuple["QualityValue", ...]
    | Mapping[str, "QualityValue"]
)


def _freeze(value: object, path: str = "quality") -> QualityValue:
    if value is None or type(value) in (bool, int, str, bytes):
        return value  # type: ignore[return-value]
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{path} floats must be finite")
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item, f"{path}[]") for item in value)
    if isinstance(value, Mapping):
        result: dict[str, QualityValue] = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise ValueError(f"{path} keys must be non-empty strings")
            result[key] = _freeze(item, f"{path}.{key}")
        return MappingProxyType(result)
    raise TypeError(f"{path} contains unsupported {type(value).__name__}")


def _frozen_snapshot(value: QualityValue) -> object:
    if isinstance(value, Mapping):
        return tuple(sorted((k, _frozen_snapshot(v)) for k, v in value.items()))
    if isinstance(value, tuple):
        return tuple(_frozen_snapshot(v) for v in value)
    return value


def _gpsd_quality_rejection(
    quality: Mapping[str, QualityValue], accuracy_seconds: float
) -> str | None:
    """Validate the canonical direct-gpsd time-quality evidence."""
    mode = quality.get("gpsd_mode")
    time_valid = quality.get("gpsd_time_valid")
    measured_accuracy = quality.get("gpsd_time_accuracy_seconds")
    if type(mode) is not int or mode not in (2, 3):
        return "gpsd-fix-mode-not-valid"
    if time_valid is not True:
        return "gpsd-time-not-valid"
    if (
        isinstance(measured_accuracy, bool)
        or not isinstance(measured_accuracy, (int, float))
        or not math.isfinite(measured_accuracy)
        or measured_accuracy < 0
    ):
        return "gpsd-time-accuracy-not-valid"
    if float(measured_accuracy) > accuracy_seconds:
        return "gpsd-accuracy-exceeds-sample-claim"
    return None


@dataclass(frozen=True)
class SourcePrecedencePolicy:
    precedence: tuple[SourceClassLike, ...] = SOURCE_CLASSES
    accepted_wall_clock_sources: frozenset[SourceClassLike] = field(
        default_factory=lambda: _DEFAULT_ACCEPTED
    )
    max_sample_age_s: int = DEFAULT_MAX_SAMPLE_AGE_S
    max_initial_epoch_lead_s: int = DEFAULT_MAX_INITIAL_EPOCH_LEAD_S
    max_forward_step_s: int = DEFAULT_MAX_FORWARD_STEP_S
    max_backward_step_s: int = DEFAULT_MAX_BACKWARD_STEP_S
    max_cumulative_forward_correction_s: int = DEFAULT_MAX_CUMULATIVE_FORWARD_CORRECTION_S
    max_correction_rate_ppm: int = DEFAULT_MAX_CORRECTION_RATE_PPM
    authorized_network_peers: frozenset[bytes] = field(default_factory=frozenset)
    max_accuracy_seconds: Mapping[SourceClassLike, float] = field(default_factory=_default_accuracy)

    def __post_init__(self) -> None:
        precedence = tuple(_source(v, "precedence source") for v in self.precedence)
        accepted = frozenset(
            _source(v, "accepted source") for v in self.accepted_wall_clock_sources
        )
        if len(precedence) != len(SourceClass) or set(precedence) != set(SourceClass):
            raise ValueError("precedence must contain every SourceClass exactly once")
        if SourceClass.MONOTONIC in accepted:
            raise ValueError("Monotonic cannot establish wall clock")
        for name in (
            "max_sample_age_s",
            "max_initial_epoch_lead_s",
            "max_forward_step_s",
            "max_backward_step_s",
            "max_cumulative_forward_correction_s",
            "max_correction_rate_ppm",
        ):
            _uint(getattr(self, name), name)
        if self.max_correction_rate_ppm > MAX_CORRECTION_RATE_PPM:
            raise ValueError(
                f"max_correction_rate_ppm must be <= {MAX_CORRECTION_RATE_PPM}"
            )
        peers = frozenset(bytes(peer) for peer in self.authorized_network_peers)
        if any(len(peer) != _PUBKEY_LEN for peer in peers):
            raise ValueError("authorized peers must be 32 bytes")
        accuracy = {
            _source(k, "accuracy source"): _accuracy(v)
            for k, v in self.max_accuracy_seconds.items()
        }
        if set(accuracy) != set(SourceClass) - {SourceClass.MONOTONIC}:
            raise ValueError("accuracy policy must define every wall-clock source")
        object.__setattr__(self, "precedence", precedence)
        object.__setattr__(self, "accepted_wall_clock_sources", accepted)
        object.__setattr__(self, "authorized_network_peers", peers)
        object.__setattr__(self, "max_accuracy_seconds", MappingProxyType(accuracy))

    def rank(self, source: SourceClassLike) -> int:
        return self.precedence.index(_source(source, "source"))


DEFAULT_SOURCE_PRECEDENCE_POLICY = SourcePrecedencePolicy()


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

DIO_TIME_OPTION_TYPE: Final[int] = 0x15
DIO_TIME_OPTION_LEN: Final[int] = 6
DIO_TIME_OPTION_TOTAL: Final[int] = 8


@dataclass(frozen=True)
class DioTimeOption:
    stratum: Stratum
    timestamp: int
    reserved: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.stratum, Stratum):
            raise TypeError("stratum must be Stratum")
        timestamp = _epoch(self.timestamp, "timestamp")
        if _uint(self.reserved, "reserved") != 0:
            raise ValueError("reserved must be zero")
        if self.stratum is Stratum.NO_SYNC and timestamp != 0:
            raise ValueError("NO_SYNC timestamp must be zero")

    def encode(self) -> bytes:
        return bytes((DIO_TIME_OPTION_TYPE, 6, int(self.stratum), 0)) + self.timestamp.to_bytes(
            4, "big"
        )

    @classmethod
    def decode(cls, data: bytes) -> DioTimeOption:
        if type(data) is not bytes or len(data) != 8:
            raise ValueError("DIO Time Option must be exactly 8 bytes")
        if data[:2] != bytes((DIO_TIME_OPTION_TYPE, DIO_TIME_OPTION_LEN)):
            raise ValueError("invalid DIO Time Option type or length")
        if data[3] != 0:
            raise ValueError("DIO Time Option reserved field must be zero")
        try:
            stratum = Stratum(data[2])
        except ValueError as exc:
            raise ValueError(f"invalid time stratum: {data[2]}") from exc
        return cls(stratum, int.from_bytes(data[4:], "big"))


@dataclass(frozen=True)
class TimeEvidence:
    issuer_name: str
    transport_class: SourceClass | None
    source_valid: bool
    policy_accepted: bool
    gnss_time_valid: bool | None = None
    gnss_position_valid: bool | None = None
    rtc_initialized: bool | None = None
    rtc_age_seconds: int | None = None
    network_protocol: str | None = None
    network_authenticated: bool | None = None
    source_subtype: str | None = None
    source_subtype_verified: bool | None = None
    signer_public_key: bytes | None = None
    signer_key_generation: object | None = field(default=None, repr=False, compare=False)
    replay_counter: int | None = None
    authenticated_payload: bytes | None = None
    option_span: tuple[int, int] | None = None
    clock_domain_identity: object | None = field(default=None, repr=False, compare=False)
    quality: Mapping[str, QualityValue] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        if not isinstance(self.issuer_name, str) or not self.issuer_name.strip():
            raise ValueError("issuer_name must be non-empty")
        if self.source_subtype is not None and (
            not isinstance(self.source_subtype, str) or not self.source_subtype.strip()
        ):
            raise ValueError("source_subtype must be non-empty when present")
        quality = _freeze(self.quality)
        if not isinstance(quality, Mapping):
            raise TypeError("quality must be a mapping")
        object.__setattr__(self, "quality", quality)


@dataclass(frozen=True, init=False)
class TimeSample:
    source_class: SourceClass
    source_name: str
    unix_time: int
    observed_monotonic: float
    stratum: Stratum
    accuracy_seconds: float
    evidence: TimeEvidence
    _issuer: object = field(repr=False, compare=False)

    def __new__(cls) -> TimeSample:
        raise TypeError("TimeSample values are issued only by a bound time authority")


def _evidence_snapshot(e: TimeEvidence) -> tuple[object, ...]:
    return (
        e.issuer_name,
        e.transport_class,
        e.source_valid,
        e.policy_accepted,
        e.gnss_time_valid,
        e.gnss_position_valid,
        e.rtc_initialized,
        e.rtc_age_seconds,
        e.network_protocol,
        e.network_authenticated,
        e.source_subtype,
        e.source_subtype_verified,
        e.signer_public_key,
        e.signer_key_generation,
        e.replay_counter,
        e.authenticated_payload,
        e.option_span,
        e.clock_domain_identity,
        _frozen_snapshot(e.quality),
    )


def _sample_snapshot(s: TimeSample) -> tuple[object, ...]:
    return (
        s.source_class,
        s.source_name,
        s.unix_time,
        s.observed_monotonic,
        s.stratum,
        s.accuracy_seconds,
        _evidence_snapshot(s.evidence),
    )


def _detach_sample(source: TimeSample) -> TimeSample:
    """Copy issued evidence into tracker-owned state with no caller alias."""
    e = source.evidence
    evidence = TimeEvidence(
        issuer_name=e.issuer_name,
        transport_class=e.transport_class,
        source_valid=e.source_valid,
        policy_accepted=e.policy_accepted,
        gnss_time_valid=e.gnss_time_valid,
        gnss_position_valid=e.gnss_position_valid,
        rtc_initialized=e.rtc_initialized,
        rtc_age_seconds=e.rtc_age_seconds,
        network_protocol=e.network_protocol,
        network_authenticated=e.network_authenticated,
        source_subtype=e.source_subtype,
        source_subtype_verified=e.source_subtype_verified,
        signer_public_key=e.signer_public_key,
        signer_key_generation=e.signer_key_generation,
        replay_counter=e.replay_counter,
        authenticated_payload=e.authenticated_payload,
        option_span=e.option_span,
        clock_domain_identity=e.clock_domain_identity,
        quality=e.quality,
    )
    sample = object.__new__(TimeSample)
    for key, value in (
        ("source_class", source.source_class),
        ("source_name", source.source_name),
        ("unix_time", source.unix_time),
        ("observed_monotonic", source.observed_monotonic),
        ("stratum", source.stratum),
        ("accuracy_seconds", source.accuracy_seconds),
        ("evidence", evidence),
        ("_issuer", source._issuer),
    ):
        object.__setattr__(sample, key, value)
    return sample


class _SampleAuthority:
    def __init__(self, name: str, clock: MonotonicClock) -> None:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("authority name must be non-empty")
        if type(clock) is not MonotonicClock:
            raise TypeError("clock must be an exact MonotonicClock")
        self.__name = name
        self.__clock = clock
        self.__issued: weakref.WeakValueDictionary[int, TimeSample] = weakref.WeakValueDictionary()
        self.__snapshots: dict[int, tuple[object, ...]] = {}
        self.__considered: set[int] = set()
        self.__issuance_sequences: dict[int, int] = {}
        self.__next_issuance_sequence = 1
        self.__lock = threading.RLock()

    @property
    def name(self) -> str:
        return self.__name

    def _now(self) -> float:
        return _mono(self.__clock(), "authority clock")

    def accepts(self, sample: TimeSample) -> bool:
        with self.__lock:
            key = id(sample)
            return (
                type(sample) is TimeSample
                and self.__issued.get(key) is sample
                and self.__snapshots.get(key) == _sample_snapshot(sample)
            )

    def _claim(self, sample: TimeSample) -> tuple[TimeSample, int] | None:
        """Atomically consume and detach one exact authoritative issuance."""
        with self.__lock:
            key = id(sample)
            if not self.accepts(sample) or key in self.__considered:
                return None
            expected = self.__snapshots[key]
            detached = _detach_sample(sample)
            if (
                _sample_snapshot(sample) != expected
                or _sample_snapshot(detached) != expected
            ):
                return None
            sequence = self.__issuance_sequences[key]
            self.__considered.add(key)
            return detached, sequence

    def __remember(self, sample: TimeSample) -> None:
        with self.__lock:
            sample_id = id(sample)
            self.__issued[sample_id] = sample
            self.__snapshots[sample_id] = _sample_snapshot(sample)
            self.__issuance_sequences[sample_id] = self.__next_issuance_sequence
            self.__next_issuance_sequence += 1
            weakref.finalize(sample, self.__forget, sample_id)

    def __forget(self, sample_id: int) -> None:
        with self.__lock:
            self.__snapshots.pop(sample_id, None)
            self.__considered.discard(sample_id)
            self.__issuance_sequences.pop(sample_id, None)

    def _latest_issuance_sequence(self) -> int:
        with self.__lock:
            return self.__next_issuance_sequence - 1

    def _binding_snapshot(self) -> tuple[object, ...]:
        return (self.__name, self.__clock._binding_snapshot())

    @property
    def clock(self) -> MonotonicClock:
        return self.__clock


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


class ProvisionEpochStatus(StrEnum):
    MISSING = "missing"
    CLEARED = "cleared"
    ACCEPTED = "accepted"
    ZERO = "zero"
    MALFORMED = "malformed"
    UNAUTHENTICATED = "unauthenticated"
    IDENTITY_MISMATCH = "identity-mismatch"
    ROLLBACK = "rollback"
    BEFORE_BUILD = "before-build"
    BEYOND_LEAD = "beyond-lead"
    PERSISTENCE_FAILED = "persistence-failed"


PROVISION_VIRGIN_MARKER: Final[bytes] = b"LICHEN-PROVISION-VIRGIN-V1"


@dataclass(frozen=True, init=False, eq=False)
class ProvisionVirginState:
    """Admin-issued proof that persistent storage was initialized empty."""

    marker_digest: bytes
    _admin: TimeAdmin = field(repr=False, compare=False)

    def __new__(cls) -> ProvisionVirginState:
        raise TypeError("ProvisionVirginState is issued only by TimeAdmin")


@dataclass(frozen=True)
class ProvisionRecord:
    """Untrusted canonical identity/version/epoch record."""

    board_identity: bytes
    record_version: int
    epoch: int

    def __post_init__(self) -> None:
        if type(self.board_identity) is not bytes or len(self.board_identity) != 32:
            raise ValueError("board_identity must be 32 bytes")
        version = _uint(self.record_version, "record_version")
        if version == 0 or version > _UINT64_MAX:
            raise ValueError("record_version must be non-zero uint64")
        _epoch(self.epoch, "epoch", nonzero=True)

    def encode(self) -> bytes:
        return (
            self.board_identity
            + self.record_version.to_bytes(8, "big")
            + self.epoch.to_bytes(4, "big")
        )

    @classmethod
    def decode(cls, encoded: bytes) -> ProvisionRecord:
        if type(encoded) is not bytes or len(encoded) != 44:
            raise ValueError("provision record must be exactly 44 bytes")
        return cls(
            encoded[:32], int.from_bytes(encoded[32:40], "big"), int.from_bytes(encoded[40:], "big")
        )


@dataclass(frozen=True)
class ProvisionRollbackState:
    record_version: int
    epoch: int
    record_digest: bytes
    encoded_record: bytes

    def __post_init__(self) -> None:
        version = _uint(self.record_version, "record_version")
        if version > _UINT64_MAX:
            raise ValueError("record_version must be uint64")
        _epoch(self.epoch, "epoch", nonzero=True)
        if type(self.record_digest) is not bytes or len(self.record_digest) != 32:
            raise ValueError("record_digest must be 32 bytes")
        if type(self.encoded_record) is not bytes or len(self.encoded_record) != 44:
            raise ValueError("encoded_record must be a canonical provision record")
        record = ProvisionRecord.decode(self.encoded_record)
        if (
            record.record_version != self.record_version
            or record.epoch != self.epoch
            or hashlib.sha256(self.encoded_record).digest() != self.record_digest
        ):
            raise ValueError("persisted provision state does not match encoded_record")


def _detach_rollback_state(value: ProvisionRollbackState) -> ProvisionRollbackState:
    """Copy untrusted/hook-visible state into verifier-owned immutable primitives."""
    return ProvisionRollbackState(
        value.record_version,
        value.epoch,
        bytes(value.record_digest),
        bytes(value.encoded_record),
    )


def _rollback_state_snapshot(value: ProvisionRollbackState) -> tuple[object, ...]:
    return (
        value.record_version,
        value.epoch,
        value.record_digest,
        value.encoded_record,
    )


_PROVISION_CLEAR_DOMAIN: Final[bytes] = b"LICHEN-PROVISION-CLEARED-V1\x00"


def _provision_clear_digest(
    record_version: int,
    epoch: int,
    record_digest: bytes,
    encoded_record: bytes,
    reason: str,
) -> bytes:
    reason_wire = reason.encode("utf-8")
    return hashlib.sha256(
        _PROVISION_CLEAR_DOMAIN
        + record_version.to_bytes(8, "big")
        + epoch.to_bytes(4, "big")
        + record_digest
        + len(encoded_record).to_bytes(2, "big")
        + encoded_record
        + len(reason_wire).to_bytes(4, "big")
        + reason_wire
    ).digest()


@dataclass(frozen=True)
class ProvisionClearedState:
    """Canonical persisted inactive state retaining the rollback floor."""

    record_version: int
    epoch: int
    record_digest: bytes
    encoded_record: bytes
    reason: str
    state_digest: bytes

    def __post_init__(self) -> None:
        version = _uint(self.record_version, "record_version")
        if version > _UINT64_MAX:
            raise ValueError("record_version must be uint64")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("clear reason must be non-empty")
        if type(self.record_digest) is not bytes or len(self.record_digest) != 32:
            raise ValueError("record_digest must be 32 bytes")
        if type(self.encoded_record) is not bytes:
            raise TypeError("encoded_record must be bytes")
        if version == 0:
            if (
                self.epoch != 0
                or self.encoded_record
                or self.record_digest != hashlib.sha256(PROVISION_VIRGIN_MARKER).digest()
            ):
                raise ValueError("empty cleared state must bind the virgin-store marker")
        else:
            _detach_rollback_state(
                ProvisionRollbackState(
                    version, self.epoch, self.record_digest, self.encoded_record
                )
            )
        if (
            type(self.state_digest) is not bytes
            or self.state_digest
            != _provision_clear_digest(
                version,
                self.epoch,
                self.record_digest,
                self.encoded_record,
                self.reason,
            )
        ):
            raise ValueError("cleared provision state digest mismatch")

    def encode(self) -> bytes:
        """Return the exact canonical bytes authenticated by persistent storage."""
        reason_wire = self.reason.encode("utf-8")
        return (
            _PROVISION_CLEAR_DOMAIN
            + self.record_version.to_bytes(8, "big")
            + self.epoch.to_bytes(4, "big")
            + self.record_digest
            + len(self.encoded_record).to_bytes(2, "big")
            + self.encoded_record
            + len(reason_wire).to_bytes(4, "big")
            + reason_wire
            + self.state_digest
        )


def _new_cleared_state(
    rollback: ProvisionRollbackState | None, reason: str
) -> ProvisionClearedState:
    if rollback is None:
        version, epoch = 0, 0
        record_digest = hashlib.sha256(PROVISION_VIRGIN_MARKER).digest()
        encoded_record = b""
    else:
        version, epoch = rollback.record_version, rollback.epoch
        record_digest = bytes(rollback.record_digest)
        encoded_record = bytes(rollback.encoded_record)
    return ProvisionClearedState(
        version,
        epoch,
        record_digest,
        encoded_record,
        reason,
        _provision_clear_digest(version, epoch, record_digest, encoded_record, reason),
    )


@dataclass(frozen=True, init=False)
class ProvisionEpochMetadata:
    epoch: int
    board_identity: bytes
    record_version: int
    record_digest: bytes
    generation: int
    _verifier: object = field(repr=False, compare=False)

    def __new__(cls) -> ProvisionEpochMetadata:
        raise TypeError("ProvisionEpochMetadata is issued only by ProvisionVerifier")

    @property
    def integrity_valid(self) -> bool:
        return True


def _metadata_snapshot(value: ProvisionEpochMetadata) -> tuple[object, ...]:
    return (
        value.epoch,
        value.board_identity,
        value.record_version,
        value.record_digest,
        value.generation,
    )


class ProvisionVerifier:
    """Admin/integrity-gated install with atomic persistent rollback binding."""

    def __init__(
        self,
        *,
        expected_board_identity: bytes,
        rollback_state: ProvisionRollbackState | ProvisionClearedState | ProvisionVirginState,
        verify_integrity: Callable[[bytes], bool],
        persist_rollback_state: Callable[[ProvisionRollbackState], None],
        persist_clear: Callable[[ProvisionClearedState], None],
        admin: TimeAdmin,
    ) -> None:
        if type(expected_board_identity) is not bytes or len(expected_board_identity) != 32:
            raise ValueError("expected_board_identity must be 32 bytes")
        if type(rollback_state) not in (
            ProvisionRollbackState,
            ProvisionClearedState,
            ProvisionVirginState,
        ):
            raise TypeError("rollback_state must be an explicit persisted provision state")
        _require_sync_callable(verify_integrity, "verify_integrity")
        _require_sync_callable(persist_rollback_state, "persist_rollback_state")
        _require_sync_callable(persist_clear, "persist_clear")
        if type(admin) is not TimeAdmin:
            raise TypeError("admin must be exact TimeAdmin")
        if type(rollback_state) is ProvisionVirginState and (
            rollback_state._admin is not admin
            or rollback_state.marker_digest != hashlib.sha256(PROVISION_VIRGIN_MARKER).digest()
            or not admin._consume_virgin_state(rollback_state)
        ):
            raise ValueError("virgin provision state is not bound to the configured admin")
        if type(rollback_state) is ProvisionClearedState:
            try:
                rollback_state = ProvisionClearedState(
                    rollback_state.record_version,
                    rollback_state.epoch,
                    bytes(rollback_state.record_digest),
                    bytes(rollback_state.encoded_record),
                    rollback_state.reason,
                    bytes(rollback_state.state_digest),
                )
                if _call_sync(
                    verify_integrity,
                    "verify_integrity",
                    rollback_state.encode(),
                ) is not True:
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid-persisted-cleared-state") from exc
        self.__expected_identity = bytes(expected_board_identity)
        if type(rollback_state) is ProvisionRollbackState:
            initial_rollback: ProvisionRollbackState | None = _detach_rollback_state(
                rollback_state
            )
        elif type(rollback_state) is ProvisionClearedState and rollback_state.record_version:
            initial_rollback = ProvisionRollbackState(
                rollback_state.record_version,
                rollback_state.epoch,
                bytes(rollback_state.record_digest),
                bytes(rollback_state.encoded_record),
            )
        else:
            initial_rollback = None
        self.__rollback = initial_rollback
        self.__verify_integrity = verify_integrity
        self.__persist_rollback = persist_rollback_state
        self.__persist_clear = persist_clear
        self.__admin = admin
        self.__generation = 0
        self.__cleared = type(rollback_state) is ProvisionClearedState
        self.__current: ProvisionEpochMetadata | None = None
        self.__active_floor_primitives: tuple[int, bytes, int, bytes] | None = None
        self.__issued: weakref.WeakValueDictionary[int, ProvisionEpochMetadata] = (
            weakref.WeakValueDictionary()
        )
        self.__snapshots: dict[int, tuple[object, ...]] = {}
        self.__lock = threading.RLock()
        self.__transition_guard = threading.Lock()
        self.__transition_meta_lock = threading.Lock()
        self.__external_hook_active = False
        self.__transition_violation = False
        self.__persistence_failed = False
        if initial_rollback is not None:
            try:
                record = ProvisionRecord.decode(initial_rollback.encoded_record)
                if (
                    record.board_identity != self.__expected_identity
                    or record.record_version != initial_rollback.record_version
                    or record.epoch != initial_rollback.epoch
                    or hashlib.sha256(initial_rollback.encoded_record).digest()
                    != initial_rollback.record_digest
                    or _call_sync(
                        self.__verify_integrity,
                        "verify_integrity",
                        initial_rollback.encoded_record,
                    )
                    is not True
                ):
                    raise ValueError
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid-persisted-provision-state") from exc
            self.__generation = 1
            if not self.__cleared:
                self.__current = self._issue_locked(record, initial_rollback.record_digest)
                self.__active_floor_primitives = (
                    record.epoch,
                    bytes(record.board_identity),
                    record.record_version,
                    bytes(initial_rollback.record_digest),
                )

    @property
    def expected_board_identity(self) -> bytes:
        return self.__expected_identity

    @property
    def minimum_record_version(self) -> int:
        with self.__lock:
            return self.__rollback.record_version if self.__rollback is not None else 0

    @property
    def cleared(self) -> bool:
        with self.__lock:
            return self.__cleared

    def _poison_after_persistence_failure(self) -> None:
        """Irreversibly revoke all live authority after an ambiguous write."""
        with self.__lock:
            self.__persistence_failed = True
            self.__generation += 1
            self.__current = None
            self.__active_floor_primitives = None
            self.__cleared = True

    def _ensure_persistence_healthy_locked(self) -> None:
        if self.__persistence_failed:
            raise RuntimeError("provision verifier is poisoned after persistence failure")

    def _begin_transition(self) -> None:
        if self.__transition_guard.acquire(blocking=False):
            with self.__transition_meta_lock:
                self.__transition_violation = False
            return
        with self.__transition_meta_lock:
            if self.__external_hook_active:
                self.__transition_violation = True
                raise RuntimeError("provision transition reentry")
        raise RuntimeError("provision transition already in progress")

    def _end_transition(self) -> None:
        self.__transition_guard.release()

    def _call_transition_hook(
        self, callback: Callable[..., object], name: str, *args: object
    ) -> object:
        with self.__transition_meta_lock:
            self.__external_hook_active = True
        try:
            result = _call_sync(callback, name, *args)
        finally:
            with self.__transition_meta_lock:
                self.__external_hook_active = False
        with self.__transition_meta_lock:
            if self.__transition_violation:
                raise RuntimeError("provision transition reentry")
        return result

    def _assert_transition_clean(self) -> None:
        with self.__transition_meta_lock:
            if self.__transition_violation:
                raise RuntimeError("provision transition reentry")

    def _issue_locked(self, record: ProvisionRecord, digest: bytes) -> ProvisionEpochMetadata:
        metadata = object.__new__(ProvisionEpochMetadata)
        for key, value in (
            ("epoch", record.epoch),
            ("board_identity", record.board_identity),
            ("record_version", record.record_version),
            ("record_digest", digest),
            ("generation", self.__generation),
            ("_verifier", self),
        ):
            object.__setattr__(metadata, key, value)
        item_id = id(metadata)
        self.__issued[item_id] = metadata
        self.__snapshots[item_id] = _metadata_snapshot(metadata)
        weakref.finalize(metadata, self.__snapshots.pop, item_id, None)
        return metadata

    def install(self, admin: TimeAdmin, encoded_record: bytes) -> ProvisionEpochMetadata:
        if admin is not self.__admin:
            raise PermissionError("provision install requires bound admin")
        if type(encoded_record) is not bytes:
            raise TypeError("encoded_record must be bytes")
        self._begin_transition()
        persistence_invoked = False
        try:
            record = ProvisionRecord.decode(encoded_record)
            if record.board_identity != self.__expected_identity:
                raise ValueError("identity-mismatch")
            if (
                self._call_transition_hook(
                    self.__verify_integrity,
                    "verify_integrity",
                    encoded_record,
                )
                is not True
            ):
                raise ValueError("unauthenticated")
            digest = hashlib.sha256(encoded_record).digest()
            candidate = ProvisionRollbackState(
                record.record_version, record.epoch, digest, encoded_record
            )
            with self.__lock:
                self._ensure_persistence_healthy_locked()
                current = self.__rollback
                was_cleared = self.__cleared
                if current is None and candidate.record_version == 0:
                    raise ValueError("record-version-must-advance")
                if current is not None:
                    if candidate.record_version < current.record_version:
                        raise ValueError("rollback")
                    if candidate.record_version == current.record_version:
                        if candidate != current:
                            raise ValueError("same-version-content-mismatch")
                        if self.__current is not None and self.accepts(self.__current):
                            return self.__current
            # Reactivation after clear is itself durable state and MUST be
            # persisted even when the canonical record is unchanged.
            if candidate != current or was_cleared:
                persisted_candidate = _detach_rollback_state(candidate)
                persisted_snapshot = _rollback_state_snapshot(persisted_candidate)
                persistence_invoked = True
                self._call_transition_hook(
                    self.__persist_rollback,
                    "persist_rollback_state",
                    persisted_candidate,
                )
                if _rollback_state_snapshot(persisted_candidate) != persisted_snapshot:
                    raise RuntimeError("persistence hook mutated rollback state")
            self._assert_transition_clean()
            with self.__lock:
                self.__rollback = _detach_rollback_state(candidate)
                self.__generation += 1
                metadata = self._issue_locked(record, digest)
                self.__current = metadata
                self.__active_floor_primitives = (
                    record.epoch,
                    bytes(record.board_identity),
                    record.record_version,
                    bytes(digest),
                )
                self.__cleared = False
                return metadata
        except BaseException:
            if persistence_invoked:
                self._poison_after_persistence_failure()
            raise
        finally:
            self._end_transition()

    def accepts(self, metadata: ProvisionEpochMetadata) -> bool:
        with self.__lock:
            item_id = id(metadata)
            return (
                type(metadata) is ProvisionEpochMetadata
                and metadata._verifier is self
                and metadata.generation == self.__generation
                and self.__issued.get(item_id) is metadata
                and self.__snapshots.get(item_id) == _metadata_snapshot(metadata)
                and self.__current is metadata
                and not self.__cleared
                and not self.__persistence_failed
            )

    def current(self) -> ProvisionEpochMetadata | None:
        with self.__lock:
            return (
                self.__current
                if self.__current is not None and self.accepts(self.__current)
                else None
            )

    def _with_floor_snapshot(
        self,
        build: int,
        lead: int,
        transition: Callable[[EpochFloorSnapshot], object],
    ) -> object:
        """Run one synchronous floor-dependent operation under the verifier lock."""
        with self.__lock:
            result = self._floor_result_locked(build, lead)
            return transition(EpochFloorSnapshot(result, self.__generation))

    def _floor_result_locked(self, build: int, lead: int) -> EpochFloorResult:
        if self.__persistence_failed:
            return EpochFloorResult(build, ProvisionEpochStatus.PERSISTENCE_FAILED)
        primitives = self.__active_floor_primitives
        if primitives is None or self.__cleared:
            return EpochFloorResult(
                build,
                ProvisionEpochStatus.CLEARED
                if self.__cleared
                else ProvisionEpochStatus.MISSING,
            )
        epoch, board_identity, _version, _digest = primitives
        if board_identity != self.__expected_identity:
            return EpochFloorResult(build, ProvisionEpochStatus.IDENTITY_MISMATCH)
        if epoch < build:
            return EpochFloorResult(build, ProvisionEpochStatus.BEFORE_BUILD)
        if epoch - build > lead:
            return EpochFloorResult(build, ProvisionEpochStatus.BEYOND_LEAD)
        return EpochFloorResult(epoch, ProvisionEpochStatus.ACCEPTED)

    def _evaluate_metadata_floor(
        self,
        metadata: ProvisionEpochMetadata,
        build: int,
        lead: int,
    ) -> EpochFloorResult:
        """Evaluate one exact live facade solely from verifier-owned primitives."""
        with self.__lock:
            if not self.accepts(metadata):
                return EpochFloorResult(build, ProvisionEpochStatus.UNAUTHENTICATED)
            return self._floor_result_locked(build, lead)

    def _missing_metadata_floor(self, build: int) -> EpochFloorResult:
        with self.__lock:
            if self.__persistence_failed:
                return EpochFloorResult(build, ProvisionEpochStatus.PERSISTENCE_FAILED)
            return EpochFloorResult(
                build,
                ProvisionEpochStatus.CLEARED
                if self.__cleared
                else ProvisionEpochStatus.MISSING,
            )

    def clear(self, admin: TimeAdmin, *, reason: str) -> None:
        if admin is not self.__admin:
            raise PermissionError("provision clear requires bound admin")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("clear reason must be non-empty")
        self._begin_transition()
        persistence_invoked = False
        try:
            with self.__lock:
                self._ensure_persistence_healthy_locked()
                cleared = _new_cleared_state(self.__rollback, reason)
            persisted_clear = ProvisionClearedState(
                cleared.record_version,
                cleared.epoch,
                bytes(cleared.record_digest),
                bytes(cleared.encoded_record),
                cleared.reason,
                bytes(cleared.state_digest),
            )
            clear_snapshot = (
                persisted_clear.record_version,
                persisted_clear.epoch,
                persisted_clear.record_digest,
                persisted_clear.encoded_record,
                persisted_clear.reason,
                persisted_clear.state_digest,
            )
            persistence_invoked = True
            self._call_transition_hook(
                self.__persist_clear, "persist_clear", persisted_clear
            )
            if (
                persisted_clear.record_version,
                persisted_clear.epoch,
                persisted_clear.record_digest,
                persisted_clear.encoded_record,
                persisted_clear.reason,
                persisted_clear.state_digest,
            ) != clear_snapshot:
                raise RuntimeError("persistence hook mutated cleared state")
            self._assert_transition_clean()
            with self.__lock:
                self.__generation += 1
                self.__current = None
                self.__active_floor_primitives = None
                self.__cleared = True
        except BaseException:
            if persistence_invoked:
                self._poison_after_persistence_failure()
            raise
        finally:
            self._end_transition()


@dataclass(frozen=True)
class EpochFloorResult:
    floor: int
    provision_status: ProvisionEpochStatus

    @property
    def provision_accepted(self) -> bool:
        return self.provision_status is ProvisionEpochStatus.ACCEPTED


@dataclass(frozen=True)
class EpochFloorSnapshot:
    """One floor and verifier generation held stable for a complete transition."""

    result: EpochFloorResult
    generation: int


def evaluate_epoch_floor(
    firmware_build_epoch: int,
    board_provision: ProvisionEpochMetadata | None,
    *,
    verifier: ProvisionVerifier | None = None,
    max_provision_lead_s: int = DEFAULT_MAX_PROVISION_LEAD_S,
) -> EpochFloorResult:
    build = _epoch(firmware_build_epoch, "firmware_build_epoch", nonzero=True)
    lead = _uint(max_provision_lead_s, "max_provision_lead_s")
    if verifier is not None and type(verifier) is not ProvisionVerifier:
        raise TypeError("verifier must be an exact ProvisionVerifier or None")
    if board_provision is None:
        return (
            verifier._missing_metadata_floor(build)
            if verifier is not None
            else EpochFloorResult(build, ProvisionEpochStatus.MISSING)
        )
    if type(board_provision) is not ProvisionEpochMetadata:
        raise TypeError("board_provision must be ProvisionEpochMetadata or None")
    if verifier is None:
        return EpochFloorResult(build, ProvisionEpochStatus.UNAUTHENTICATED)
    return verifier._evaluate_metadata_floor(board_provision, build, lead)


def effective_epoch_floor(
    firmware_build_epoch: int,
    board_provision_epoch: int | ProvisionEpochMetadata | None,
    *,
    verifier: ProvisionVerifier | None = None,
    max_provision_lead_s: int = DEFAULT_MAX_PROVISION_LEAD_S,
) -> int:
    if verifier is not None and type(verifier) is not ProvisionVerifier:
        raise TypeError("verifier must be an exact ProvisionVerifier or None")
    if isinstance(board_provision_epoch, int) and not isinstance(board_provision_epoch, bool):
        warnings.warn(
            "raw board provision is unauthenticated and ignored", DeprecationWarning, stacklevel=2
        )
        return _epoch(firmware_build_epoch, "firmware_build_epoch", nonzero=True)
    if isinstance(board_provision_epoch, bool):
        raise TypeError("board_provision_epoch must be metadata, int, or None")
    return evaluate_epoch_floor(
        firmware_build_epoch,
        board_provision_epoch,
        verifier=verifier,
        max_provision_lead_s=max_provision_lead_s,
    ).floor


class EpochFloorAuthority:
    """Immutable build epoch plus current verifier-issued provision state."""

    __slots__ = ("__weakref__",)

    def __init__(
        self,
        firmware_build_epoch: int,
        *,
        verifier: ProvisionVerifier | None = None,
        max_provision_lead_s: int = DEFAULT_MAX_PROVISION_LEAD_S,
    ) -> None:
        build = _epoch(firmware_build_epoch, "firmware_build_epoch", nonzero=True)
        if verifier is not None and type(verifier) is not ProvisionVerifier:
            raise TypeError("verifier must be exact ProvisionVerifier or None")
        lead = _uint(max_provision_lead_s, "max_provision_lead_s")
        with _FLOOR_AUTHORITY_BINDINGS_LOCK:
            if self in _FLOOR_AUTHORITY_BINDINGS:
                raise RuntimeError("EpochFloorAuthority is already initialized")
            _FLOOR_AUTHORITY_BINDINGS[self] = (build, verifier, lead)

    def _binding_snapshot(self) -> tuple[object, ...]:
        with _FLOOR_AUTHORITY_BINDINGS_LOCK:
            build, verifier, lead = _FLOOR_AUTHORITY_BINDINGS[self]
            return (build, id(verifier), lead)

    def _with_snapshot(
        self, transition: Callable[[EpochFloorSnapshot], object]
    ) -> object:
        with _FLOOR_AUTHORITY_BINDINGS_LOCK:
            build, verifier, lead = _FLOOR_AUTHORITY_BINDINGS[self]
        if verifier is None:
            return transition(
                EpochFloorSnapshot(
                    evaluate_epoch_floor(build, None, max_provision_lead_s=lead), 0
                )
            )
        return verifier._with_floor_snapshot(build, lead, transition)

    def current(self) -> EpochFloorResult:
        result = self._with_snapshot(lambda snapshot: snapshot.result)
        assert isinstance(result, EpochFloorResult)
        return result


_FLOOR_AUTHORITY_BINDINGS_LOCK = threading.RLock()
_FLOOR_AUTHORITY_BINDINGS: weakref.WeakKeyDictionary[
    EpochFloorAuthority, tuple[int, ProvisionVerifier | None, int]
] = weakref.WeakKeyDictionary()


SampleAuthority: TypeAlias = TimeProvider | DioTimeVerifier


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


def _project(timestamp: int, observed: float, now: float) -> int:
    return timestamp + math.floor(now - observed)


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
        if (
            not 0 <= start < end <= len(payload)
            or payload[start:end] != DioTimeOption(sample.stratum, sample.unix_time).encode()
        ):
            return "network-option-evidence-mismatch"
    elif sample.source_class is SourceClass.NETWORK:
        protocol = evidence.network_protocol
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
