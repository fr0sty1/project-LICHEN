# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Presence and status domain types with CBOR codecs (spec 18.5).

Wire contract (spec/12-apps.md 18.5.1)::

    {
      "status": "available",
      "activity": "moving",
      "msg": "On patrol",
      "battery": 87,
      "ts": 1716742800
    }

Optional fields are omitted when unset. Map key order is status, activity,
msg, battery, low_battery, ts so encoding matches
``test/vectors/presence_cbor.json``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import cbor2

PRESENCE_STATUSES: frozenset[str] = frozenset({"available", "busy", "away", "offline", "emergency"})
PRESENCE_ACTIVITIES: frozenset[str] = frozenset({"stationary", "moving", "resting", "working"})

# Spec 18.5.3 automatic-status thresholds.
STATIONARY_AFTER_S = 5 * 60
AWAY_AFTER_S = 30 * 60
LOW_BATTERY_PCT = 10
MAX_MSG_LEN = 256  # bytes; spec convention for presence status messages

_PRESENCE_KEYS = frozenset({"status", "activity", "msg", "battery", "ts", "low_battery"})
_CACHE_KEYS = frozenset({"nodes"})
_CACHE_ENTRY_KEYS = frozenset({"addr", "status", "battery", "age_s"})
_UINT64_MAX = (1 << 64) - 1

MAX_CACHE_ENTRIES = 256


class PresenceError(ValueError):
    """Malformed presence or presence-cache document."""


def _require_map(document: object, what: str) -> dict[str, Any]:
    if type(document) is not dict:
        raise PresenceError(f"{what} must be a map")
    return document


def _require_status(value: object) -> str:
    if type(value) is not str or value not in PRESENCE_STATUSES:
        raise PresenceError("status must be a known presence status")
    return value


def _optional_activity(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str or value not in PRESENCE_ACTIVITIES:
        raise PresenceError("activity must be a known activity hint")
    return value


def _optional_msg(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is not str:
        raise PresenceError("msg must be a text string")
    if len(value.encode("utf-8")) > MAX_MSG_LEN:
        raise PresenceError(f"msg exceeds {MAX_MSG_LEN} bytes")
    return value


def _optional_battery(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or type(value) is not int or value < 0 or value > 100:
        raise PresenceError("battery must be an integer 0..100")
    return value


def _require_ts(value: object) -> int:
    if type(value) is not int or value < 0 or value > _UINT64_MAX:
        raise PresenceError("ts must be an integer in 0..2**64-1")
    return value


def _require_age_s(value: object) -> int:
    if type(value) is not int or value < 0 or value > _UINT64_MAX:
        raise PresenceError("age_s must be an integer in 0..2**64-1")
    return value


def _optional_low_battery(value: object) -> bool | None:
    if value is None:
        return None
    if type(value) is not bool:
        raise PresenceError("low_battery must be a boolean")
    return value


def _require_addr(value: object) -> str:
    if type(value) is not str or value == "":
        raise PresenceError("addr must be a non-empty string")
    return value


def _finite_non_negative(value: object, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or (isinstance(value, float) and not math.isfinite(value))
        or value < 0
    ):
        raise PresenceError(f"{name} must be a non-negative finite number")
    return float(value)


def age_s_at(now: float, ts: float) -> int:
    """Seconds since ``ts``, clamped to 0 when the clock went backwards."""
    # Validate integer bounds before float conversion to avoid precision loss
    if isinstance(now, int) and not isinstance(now, bool) and (now < 0 or now > _UINT64_MAX):
        raise PresenceError("now must be in 0..2**64-1")
    if isinstance(ts, int) and not isinstance(ts, bool) and (ts < 0 or ts > _UINT64_MAX):
        raise PresenceError("ts must be in 0..2**64-1")
    now_f = _finite_non_negative(now, "now")
    ts_f = _finite_non_negative(ts, "ts")
    return max(0, int(now_f - ts_f))


def _validate_low_battery_consistency(battery: int | None, low_battery: bool | None) -> None:
    """Enforce spec 18.5.3: low_battery == True iff battery < LOW_BATTERY_PCT."""
    if battery is None:
        if low_battery is not None:
            raise PresenceError("low_battery requires battery to be present")
    elif battery < LOW_BATTERY_PCT:
        if low_battery is not True:
            raise PresenceError("low_battery must be true when battery < 10")
    else:
        if low_battery is not None:
            raise PresenceError("low_battery must be omitted when battery >= 10")


@dataclass(frozen=True)
class Presence:
    """A node's own presence state from GET/PUT ``/presence`` (spec 18.5.1)."""

    status: str
    ts: int
    activity: str | None = None
    msg: str | None = None
    battery: int | None = None
    low_battery: bool | None = None

    def __post_init__(self) -> None:
        _validate_low_battery_consistency(self.battery, self.low_battery)

    def to_map(self) -> dict[str, Any]:
        """Return the spec field map in vector key order."""
        document: dict[str, Any] = {"status": self.status}
        if self.activity is not None:
            document["activity"] = self.activity
        if self.msg is not None:
            document["msg"] = self.msg
        if self.battery is not None:
            document["battery"] = self.battery
        if self.low_battery is not None:
            document["low_battery"] = self.low_battery
        document["ts"] = self.ts
        return document

    def to_cbor(self) -> bytes:
        return cbor2.dumps(self.to_map())

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> Presence:
        data = _require_map(document if type(document) is dict else dict(document), "presence")
        unknown = set(data) - _PRESENCE_KEYS
        if unknown:
            raise PresenceError("unexpected presence field(s)")
        if "status" not in data:
            raise PresenceError("status is required")
        if "ts" not in data:
            raise PresenceError("ts is required")
        low_battery = _optional_low_battery(data["low_battery"]) if "low_battery" in data else None
        return cls(
            status=_require_status(data.get("status")),
            ts=_require_ts(data.get("ts")),
            activity=_optional_activity(data.get("activity")),
            msg=_optional_msg(data.get("msg")),
            battery=_optional_battery(data.get("battery")),
            low_battery=low_battery,
        )

    @classmethod
    def from_cbor(cls, payload: bytes) -> Presence:
        if type(payload) is not bytes:
            raise PresenceError("payload must be bytes")
        # Lazy import to avoid circular dependency
        from lichen.coap.resources.cbor_validation import _decode_single_cbor

        try:
            document = _decode_single_cbor(payload)
        except ValueError as exc:
            raise PresenceError(f"invalid CBOR: {exc}") from exc
        except Exception as exc:
            raise PresenceError("invalid CBOR") from exc
        return cls.from_mapping(document)


@dataclass(frozen=True)
class PresenceCacheEntry:
    """One ``/presence/cache`` node record (spec 18.5.2)."""

    addr: str
    status: str
    age_s: int
    battery: int | None = None

    def to_map(self) -> dict[str, Any]:
        document: dict[str, Any] = {"addr": self.addr, "status": self.status}
        if self.battery is not None:
            document["battery"] = self.battery
        document["age_s"] = self.age_s
        return document

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> PresenceCacheEntry:
        raw = document if type(document) is dict else dict(document)
        data = _require_map(raw, "presence cache entry")
        unknown = set(data) - _CACHE_ENTRY_KEYS
        if unknown:
            raise PresenceError("unexpected cache entry field(s)")
        if "addr" not in data or "status" not in data or "age_s" not in data:
            raise PresenceError("cache entry requires addr, status, and age_s")
        return cls(
            addr=_require_addr(data.get("addr")),
            status=_require_status(data.get("status")),
            age_s=_require_age_s(data.get("age_s")),
            battery=_optional_battery(data.get("battery")) if "battery" in data else None,
        )


@dataclass(frozen=True)
class PresenceCache:
    """The ``GET /presence/cache`` envelope (spec 18.5.2)."""

    nodes: tuple[PresenceCacheEntry, ...] = ()

    def to_map(self) -> dict[str, Any]:
        return {"nodes": [entry.to_map() for entry in self.nodes]}

    def to_cbor(self) -> bytes:
        return cbor2.dumps(self.to_map())

    @classmethod
    def from_mapping(cls, document: Mapping[str, Any]) -> PresenceCache:
        raw = document if type(document) is dict else dict(document)
        data = _require_map(raw, "presence cache")
        unknown = set(data) - _CACHE_KEYS
        if unknown:
            raise PresenceError("unexpected cache field(s)")
        nodes = data.get("nodes")
        if type(nodes) is not list:
            raise PresenceError("nodes must be an array")
        if len(nodes) > MAX_CACHE_ENTRIES:
            raise PresenceError(f"nodes array exceeds maximum of {MAX_CACHE_ENTRIES} entries")
        return cls(nodes=tuple(PresenceCacheEntry.from_mapping(item) for item in nodes))

    @classmethod
    def from_cbor(cls, payload: bytes) -> PresenceCache:
        if type(payload) is not bytes:
            raise PresenceError("payload must be bytes")
        # Lazy import to avoid circular dependency
        from lichen.coap.resources.cbor_validation import _decode_single_cbor

        try:
            document = _decode_single_cbor(payload)
        except ValueError as exc:
            raise PresenceError(f"invalid CBOR: {exc}") from exc
        except Exception as exc:
            raise PresenceError("invalid CBOR") from exc
        return cls.from_mapping(document)


def apply_automatic_status(
    current: Presence,
    now: float,
    *,
    moving: bool | None = None,
    last_motion_at: float | None = None,
    last_interaction_at: float | None = None,
    sos_active: bool = False,
) -> Presence:
    """Return presence updated from spec 18.5.3 conditions.

    Priority: SOS, GPS motion, inactivity, GPS stationary. ``low_battery`` is
    added when ``battery < 10`` and omitted otherwise. ``ts`` is refreshed only
    when the resulting document differs from ``current``.
    """
    if not isinstance(current, Presence):
        raise PresenceError("current must be a Presence")
    # Validate integer bounds before float conversion to avoid precision loss.
    # Store original integer for ts assignment to preserve full precision.
    now_int: int | None = None
    if isinstance(now, int) and not isinstance(now, bool):
        if now < 0 or now > _UINT64_MAX:
            raise PresenceError("now must be in 0..2**64-1")
        now_int = now
    now_f = _finite_non_negative(now, "now")
    if last_motion_at is not None:
        last_motion_at = _finite_non_negative(last_motion_at, "last_motion_at")
    if last_interaction_at is not None:
        last_interaction_at = _finite_non_negative(last_interaction_at, "last_interaction_at")
    if moving is not None and type(moving) is not bool:
        raise PresenceError("moving must be a boolean or None")
    if type(sos_active) is not bool:
        raise PresenceError("sos_active must be a boolean")

    status = current.status
    activity = current.activity

    if sos_active:
        status = "emergency"
    elif moving is True:
        status = "available"
        activity = "moving"
    elif last_interaction_at is not None and (now_f - last_interaction_at) > AWAY_AFTER_S:
        status = "away"
    elif (
        moving is False
        and last_motion_at is not None
        and (now_f - last_motion_at) > STATIONARY_AFTER_S
    ):
        status = "available"
        activity = "stationary"

    low_battery = (
        True if current.battery is not None and current.battery < LOW_BATTERY_PCT else None
    )
    candidate = Presence(
        status=status,
        ts=current.ts,
        activity=activity,
        msg=current.msg,
        battery=current.battery,
        low_battery=low_battery,
    )
    if candidate == current:
        return current
    # Use original integer for ts to preserve precision for values > 2^53
    ts = now_int if now_int is not None else int(now_f)
    return Presence(
        status=status,
        ts=ts,
        activity=activity,
        msg=current.msg,
        battery=current.battery,
        low_battery=low_battery,
    )
