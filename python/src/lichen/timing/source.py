# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Source classes, precedence policy, and validation helpers for time sync."""

from __future__ import annotations

import inspect
import math
import warnings
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
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
_UINT32_MAX = (1 << 32) - 1
_UINT64_MAX = (1 << 64) - 1
_PUBKEY_LEN = 32
PROVISION_VIRGIN_MARKER: Final[bytes] = b"LICHEN-PROVISION-VIRGIN-V1"
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
    if inspect.iscoroutinefunction(callback) or inspect.iscoroutinefunction(
        type(callback).__call__
    ):
        raise TypeError(f"{name} must be synchronous")
    return callback


def _call_sync(callback: Callable[..., object], name: str, *args: object) -> object:
    return _reject_awaitable(callback(*args), name)


def _accuracy(value: object) -> float:
    result = _mono(value, "accuracy_seconds")
    return result


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
