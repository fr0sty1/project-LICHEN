# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Timing oracles (spec 09-packets-timing.md §14).

Aggregates trickle, DAO timing, duty cycle, airtime, CSMA, time sync,
SFN/TDMA and data-traffic oracles for ergonomic import.
"""

from lichen.timing.airtime import airtime_ms, airtime_us, airtime_us_with_params  # noqa: F401
from lichen.timing.csma import (  # noqa: F401
    CSMA_BACKOFF_MAX,
    CSMA_BACKOFF_UNIT_MS,
    CSMA_CAD_TIMEOUT_SYMBOLS,
    CSMA_RETRY_LIMIT,
    CsmaState,
    cw_for_exponent,
)
from lichen.timing.dao import (  # noqa: F401
    DAO_INITIAL_DELAY_MAX_MS,
    DAO_INITIAL_DELAY_MIN_MS,
    DAO_REFRESH_S,
    DAO_RETRY_DELAYS_MS,
    dao_retry_delay,
)
from lichen.timing.data_traffic import (  # noqa: F401
    HEARTBEAT_INTERVAL_S,
    TELEMETRY_INTERVAL_MAX_S,
    TELEMETRY_INTERVAL_MIN_S,
)
from lichen.timing.duty_cycle import (  # noqa: F401
    EU868_DUTY_CYCLE_PERCENT,
    EU868_MAX_PACKETS_PER_HOUR,
    duty_cycle_usage_percent,
    max_packets_per_hour,
)
from lichen.timing.sfn import DesyncFSM, DesyncState, hash_32, sfn_delta, slot_for  # noqa: F401
from lichen.timing.time_sync import (  # noqa: F401
    DioTimeOption,
    Stratum,
    effective_epoch_floor,
    should_adopt_time,
)
from lichen.timing.trickle import (  # noqa: F401
    TRICKLE_IMAX_EXACT_MS,
    TRICKLE_IMIN_MS,
    TRICKLE_K,
    TrickleTimer,
)

__all__ = [
    "CSMA_BACKOFF_MAX",
    "CSMA_BACKOFF_UNIT_MS",
    "CSMA_CAD_TIMEOUT_SYMBOLS",
    "CSMA_RETRY_LIMIT",
    "CsmaState",
    "DAO_INITIAL_DELAY_MAX_MS",
    "DAO_INITIAL_DELAY_MIN_MS",
    "DAO_REFRESH_S",
    "DAO_RETRY_DELAYS_MS",
    "DioTimeOption",
    "DesyncFSM",
    "DesyncState",
    "HEARTBEAT_INTERVAL_S",
    "Stratum",
    "TELEMETRY_INTERVAL_MAX_S",
    "TELEMETRY_INTERVAL_MIN_S",
    "TRICKLE_IMAX_EXACT_MS",
    "TRICKLE_IMIN_MS",
    "TRICKLE_K",
    "TrickleTimer",
    "airtime_ms",
    "airtime_us",
    "airtime_us_with_params",
    "cw_for_exponent",
    "dao_retry_delay",
    "duty_cycle_usage_percent",
    "effective_epoch_floor",
    "hash_32",
    "max_packets_per_hour",
    "sfn_delta",
    "should_adopt_time",
    "slot_for",
]
