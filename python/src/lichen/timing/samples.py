# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Time sample data structures and authority for time synchronization.

This module contains the core data structures for representing time samples,
evidence, and the authority that issues them:

- TimeSample: An issued time observation from a trusted source
- TimeEvidence: Provenance metadata attached to a TimeSample
- DioTimeOption: RPL DIO time synchronization option encoding
- _SampleAuthority: Base class for time sample issuers

Also includes helper functions for freezing quality metadata and
creating snapshot tuples for integrity verification.
"""

from __future__ import annotations

import math
import threading
import weakref
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeAlias

if TYPE_CHECKING:
    from .time_sync import MonotonicClock, SourceClass, Stratum

# Runtime imports from sibling module
from .time_sync import (
    DIO_TIME_OPTION_LEN,
    DIO_TIME_OPTION_TYPE,
    MonotonicClock,
    SourceClass,
    Stratum,
    _epoch,
    _mono,
    _uint,
)

__all__ = [
    "QualityValue",
    "TimeSample",
    "TimeEvidence",
    "DioTimeOption",
    "_SampleAuthority",
    "_evidence_snapshot",
    "_sample_snapshot",
    "_detach_sample",
    "_accuracy",
    "_freeze",
    "_frozen_snapshot",
    "_gpsd_quality_rejection",
]


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


def _accuracy(value: object) -> float:
    result = _mono(value, "accuracy_seconds")
    return result


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
        if self.stratum.value == 0 and timestamp != 0:
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
        # Import Stratum at runtime to get the enum value
        from .time_sync import Stratum

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
        if type(clock).__name__ != "MonotonicClock":
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
