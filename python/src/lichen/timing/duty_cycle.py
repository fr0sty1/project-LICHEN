# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Duty cycle oracle (spec 09-packets-timing.md §14.4)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from lora_medium import DutyCycleTracker

# §14.4 EU 868 MHz (10% duty cycle) example from spec
# At SF9/125kHz, airtime per 60-byte packet ~200ms
EU868_DUTY_CYCLE_PERCENT: float = 10.0
EU868_SF9_AIRTIME_60B_MS: float = 200.0
EU868_MAX_PACKETS_PER_HOUR: int = int(
    3600 * (EU868_DUTY_CYCLE_PERCENT / 100) / (EU868_SF9_AIRTIME_60B_MS / 1000)
)
# 3600*0.1/0.2 = 1800 packets (spec table)

# Comfortable per-node accounting for routing
EU868_COMFORTABLE_PACKETS_PER_HOUR: tuple[int, int] = (100, 300)

# Regulatory defaults used by the simulator (lora_medium default)
SIM_DUTY_CYCLE_LIMIT_PERCENT: float = 1.0
SIM_WINDOW_S: int = 3600

# Common regional limits
REGIONAL_LIMITS: dict[str, float] = {
    "EU868": 1.0,  # 1% per sub-band (simulator default)
    "EU868_10pct_example": 10.0,  # spec example (§14.4)
    "US915": 100.0,  # FCC no duty cycle (dwell-time limited)
}

US915_FCC_DWELL_TIME_MS: int = 400


@dataclass(frozen=True, slots=True)
class RegionalDutyCycleLimit:
    """Transmit-airtime limits for one regional channel plan.

    ``duty_cycle_percent`` is enforced over ``window_s``.  Regions without a
    regulatory duty-cycle cap use 100%, while ``max_dwell_time_ms`` captures
    their per-transmission dwell-time rule.
    """

    name: str
    duty_cycle_percent: float
    window_s: int = SIM_WINDOW_S
    max_dwell_time_ms: int | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name must not be empty")
        if not 0 < self.duty_cycle_percent <= 100:
            raise ValueError("duty_cycle_percent must be 0 < pct <= 100")
        if self.window_s <= 0:
            raise ValueError("window_s must be positive")
        if self.max_dwell_time_ms is not None and self.max_dwell_time_ms <= 0:
            raise ValueError("max_dwell_time_ms must be positive")


REGIONAL_CONFIGS: Mapping[str, RegionalDutyCycleLimit] = MappingProxyType(
    {
        "EU868": RegionalDutyCycleLimit("EU868", duty_cycle_percent=1.0),
        "US915": RegionalDutyCycleLimit(
            "US915",
            duty_cycle_percent=100.0,
            max_dwell_time_ms=US915_FCC_DWELL_TIME_MS,
        ),
    }
)


def get_regional_limit(region: str) -> RegionalDutyCycleLimit:
    """Return the configured limit for ``region``, failing closed if unknown."""
    try:
        return REGIONAL_CONFIGS[region]
    except KeyError as exc:
        raise ValueError(f"unknown duty-cycle region: {region!r}") from exc


class RegionalDutyCycleEnforcer:
    """Apply a region's rolling duty-cycle and dwell-time limits.

    :meth:`try_transmit` is the enforcement entry point: rejected
    transmissions are not added to accounting state.
    """

    def __init__(
        self,
        region: str,
        *,
        duty_cycle_percent: float | None = None,
        window_s: int | None = None,
        max_dwell_time_ms: int | None = None,
    ) -> None:
        default = get_regional_limit(region)
        self.limit = RegionalDutyCycleLimit(
            name=default.name,
            duty_cycle_percent=(
                default.duty_cycle_percent
                if duty_cycle_percent is None
                else duty_cycle_percent
            ),
            window_s=default.window_s if window_s is None else window_s,
            max_dwell_time_ms=(
                default.max_dwell_time_ms
                if max_dwell_time_ms is None
                else max_dwell_time_ms
            ),
        )
        self._tracker = DutyCycleTracker(
            limit_percent=self.limit.duty_cycle_percent,
            window_seconds=self.limit.window_s,
        )

    def can_transmit(self, airtime_us: int, time_us: int) -> bool:
        """Return whether a proposed transmission satisfies regional limits."""
        if airtime_us <= 0:
            raise ValueError("airtime_us must be positive")
        if time_us < 0:
            raise ValueError("time_us must be non-negative")
        dwell_ms = self.limit.max_dwell_time_ms
        if dwell_ms is not None and airtime_us > dwell_ms * 1000:
            return False
        return self._tracker.can_transmit(airtime_us=airtime_us, time_us=time_us)

    def try_transmit(self, airtime_us: int, time_us: int) -> bool:
        """Record an allowed transmission and reject one over either limit."""
        if not self.can_transmit(airtime_us, time_us):
            return False
        self._tracker.record_tx(airtime_us=airtime_us, time_us=time_us)
        return True

    def usage(self, time_us: int) -> float:
        """Return consumed rolling-window budget as a ratio of the limit."""
        if time_us < 0:
            raise ValueError("time_us must be non-negative")
        return self._tracker.get_usage(time_us=time_us)


def max_packets_per_hour(airtime_ms: float, duty_cycle_percent: float, window_s: int = 3600) -> int:
    """Compute max packets/hour given airtime and duty cycle.

    Formula: ``3600s * (duty_cycle/100) / (airtime_s)``
    Matches spec §14.4: ``3600s * 0.1 / 0.2s = 1800``.
    """
    if airtime_ms <= 0:
        raise ValueError("airtime_ms must be positive")
    if not 0 < duty_cycle_percent <= 100:
        raise ValueError("duty_cycle_percent must be 0 < pct <= 100")
    airtime_s = airtime_ms / 1000
    return int(window_s * (duty_cycle_percent / 100) / airtime_s)


def duty_cycle_usage_percent(used_airtime_ms: float, window_s: int = 3600) -> float:
    """Return duty cycle usage as percent (0-100+) for a given airtime sum."""
    if window_s <= 0:
        raise ValueError("window_s must be positive")
    return (used_airtime_ms / (window_s * 1000)) * 100


__all__ = [
    "EU868_COMFORTABLE_PACKETS_PER_HOUR",
    "EU868_DUTY_CYCLE_PERCENT",
    "EU868_MAX_PACKETS_PER_HOUR",
    "EU868_SF9_AIRTIME_60B_MS",
    "REGIONAL_LIMITS",
    "REGIONAL_CONFIGS",
    "RegionalDutyCycleEnforcer",
    "RegionalDutyCycleLimit",
    "SIM_DUTY_CYCLE_LIMIT_PERCENT",
    "SIM_WINDOW_S",
    "US915_FCC_DWELL_TIME_MS",
    "duty_cycle_usage_percent",
    "get_regional_limit",
    "max_packets_per_hour",
]
