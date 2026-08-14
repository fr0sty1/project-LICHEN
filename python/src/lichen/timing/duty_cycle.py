# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Duty cycle oracle (spec 09-packets-timing.md §14.4)."""

from __future__ import annotations

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
    "SIM_DUTY_CYCLE_LIMIT_PERCENT",
    "SIM_WINDOW_S",
    "duty_cycle_usage_percent",
    "max_packets_per_hour",
]
