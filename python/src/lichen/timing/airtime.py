# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LoRa airtime oracle (spec 09-packets-timing.md §14.4).

Wraps :func:`lora_medium.airtime_us` when available; otherwise provides a
pure-Python fallback using the Semtech formula with LICHEN defaults
SF10/125kHz/CR4/5/preamble 8.  All vectors use the simulator default
(SF10) except the spec SF9 example which is computed via fallback.
"""

from __future__ import annotations

import math

LORA_SF_DEFAULT: int = 10
LORA_BW_DEFAULT_HZ: int = 125_000
LORA_CR_DEFAULT: int = 5  # 4/5
LORA_PREAMBLE_DEFAULT: int = 8

# Spec example: SF9/125kHz airtime for 60-byte packet ~200ms (approx)
SPEC_SF9_125KHZ_60B_AIRTIME_MS: float = 200.0


def _airtime_us_fallback(
    payload_len: int,
    *,
    sf: int = LORA_SF_DEFAULT,
    bw_hz: int = LORA_BW_DEFAULT_HZ,
    cr: int = LORA_CR_DEFAULT,
    preamble_symbols: int = LORA_PREAMBLE_DEFAULT,
) -> int:
    """Pure-Python LoRa airtime (Semtech formula) in microseconds.

    T_symbol = 2^SF / BW
    N_payload = max(ceil((8*PL - 4*SF + 28 + 16) / (4*SF)) * CR, 0)
    T = T_symbol * (preamble + 4.25 + 8 + N_payload)  -- in seconds
    """
    if payload_len < 0:
        raise ValueError("payload_len must be non-negative")
    if sf not in range(7, 13):
        raise ValueError("sf must be 7..12")
    tsym = (2**sf) / bw_hz  # seconds per symbol
    # Payload symbol count (simplified, LICHEN uses CRC=1, IH=0, DE=0)
    numerator = 8 * payload_len - 4 * sf + 28 + 16
    denom = 4 * sf
    n_payload = 0 if numerator <= 0 else math.ceil(numerator / denom) * cr
    total_symbols = preamble_symbols + 4.25 + 8 + n_payload
    return int(total_symbols * tsym * 1_000_000)


def airtime_us(payload_len: int) -> int:
    """Return LoRa airtime in microseconds (SF10 fallback oracle).

    Tries ``lora_medium.airtime_us`` (simulator default SF10/125kHz);
    falls back to pure-Python formula if not installed.
    """
    try:
        from lora_medium import airtime_us as _lm_airtime  # type: ignore[import-not-found]

        return int(_lm_airtime(payload_len))
    except Exception:
        return _airtime_us_fallback(payload_len)


def airtime_ms(payload_len: int) -> float:
    """Return airtime in milliseconds."""
    return airtime_us(payload_len) / 1000.0


def airtime_us_with_params(
    payload_len: int,
    *,
    sf: int = LORA_SF_DEFAULT,
    bw_hz: int = LORA_BW_DEFAULT_HZ,
    cr: int = LORA_CR_DEFAULT,
    preamble_symbols: int = LORA_PREAMBLE_DEFAULT,
) -> int:
    """Return airtime in microseconds with explicit LoRa params."""
    return _airtime_us_fallback(
        payload_len,
        sf=sf,
        bw_hz=bw_hz,
        cr=cr,
        preamble_symbols=preamble_symbols,
    )


__all__ = [
    "LORA_BW_DEFAULT_HZ",
    "LORA_CR_DEFAULT",
    "LORA_PREAMBLE_DEFAULT",
    "LORA_SF_DEFAULT",
    "SPEC_SF9_125KHZ_60B_AIRTIME_MS",
    "airtime_ms",
    "airtime_us",
    "airtime_us_with_params",
]
