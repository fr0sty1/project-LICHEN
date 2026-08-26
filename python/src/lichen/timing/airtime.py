# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""SX127x LoRa airtime calculation (spec 09-packets-timing.md §14.4).

The public calculation uses the Semtech packet-airtime formula and defaults to
LICHEN's SF10/125 kHz/CR4/5, eight-symbol preamble, explicit-header, CRC-on
profile.  Parameterized calls cover every SX127x spreading factor, bandwidth,
and coding-rate combination, including automatic low-data-rate optimization.
"""

from __future__ import annotations

LORA_SF_DEFAULT: int = 10
LORA_BW_DEFAULT_HZ: int = 125_000
LORA_CR_DEFAULT: int = 5  # 4/5
LORA_PREAMBLE_DEFAULT: int = 8
LORA_BANDWIDTHS_HZ: tuple[int, ...] = (
    7_800,
    10_400,
    15_600,
    20_800,
    31_250,
    41_700,
    62_500,
    125_000,
    250_000,
    500_000,
)

# Normative spec example: SF9/125 kHz, CR4/5, explicit header, CRC on.
SPEC_SF9_125KHZ_60B_AIRTIME_MS: float = 369.664

_MIN_PREAMBLE_SYMBOLS = 6
_MAX_PREAMBLE_SYMBOLS = 65_535


def _validate_parameters(
    payload_len: int,
    sf: int,
    bw_hz: int,
    cr: int,
    preamble_symbols: int,
    implicit_header: bool,
) -> None:
    """Reject values that cannot be programmed into an SX127x LoRa modem."""
    integer_parameters = {
        "payload_len": payload_len,
        "sf": sf,
        "bw_hz": bw_hz,
        "cr": cr,
        "preamble_symbols": preamble_symbols,
    }
    for name, value in integer_parameters.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must be an integer")

    if not 0 <= payload_len <= 255:
        raise ValueError("payload_len must be 0..255")
    if not 6 <= sf <= 12:
        raise ValueError("sf must be 6..12")
    if sf == 6 and not implicit_header:
        raise ValueError("sf=6 requires implicit_header=True")
    if bw_hz not in LORA_BANDWIDTHS_HZ:
        raise ValueError(f"bw_hz must be one of {LORA_BANDWIDTHS_HZ}")
    if not 5 <= cr <= 8:
        raise ValueError("cr must be 5..8 (for coding rates 4/5 through 4/8)")
    if not _MIN_PREAMBLE_SYMBOLS <= preamble_symbols <= _MAX_PREAMBLE_SYMBOLS:
        raise ValueError(
            f"preamble_symbols must be {_MIN_PREAMBLE_SYMBOLS}..{_MAX_PREAMBLE_SYMBOLS}"
        )


def _airtime_us_fallback(
    payload_len: int,
    *,
    sf: int = LORA_SF_DEFAULT,
    bw_hz: int = LORA_BW_DEFAULT_HZ,
    cr: int = LORA_CR_DEFAULT,
    preamble_symbols: int = LORA_PREAMBLE_DEFAULT,
    crc_enabled: bool = True,
    implicit_header: bool = False,
    low_data_rate_optimization: bool | None = None,
) -> int:
    """Return SX127x LoRa packet airtime in microseconds.

    T_symbol = 2^SF / BW
    N_payload = 8 + max(
        ceil((8*PL - 4*SF + 28 + 16*CRC - 20*IH) / (4*(SF - 2*DE))) * CR,
        0,
    )
    T = T_symbol * (preamble + 4.25 + N_payload)

    ``cr`` is the coding-rate denominator (5 means 4/5, through 8 meaning
    4/8).  When ``low_data_rate_optimization`` is omitted, DE is enabled for
    symbol durations of at least 16 ms, as required by the SX127x.
    """
    if not isinstance(crc_enabled, bool):
        raise TypeError("crc_enabled must be a bool")
    if not isinstance(implicit_header, bool):
        raise TypeError("implicit_header must be a bool")
    if low_data_rate_optimization is not None and not isinstance(low_data_rate_optimization, bool):
        raise TypeError("low_data_rate_optimization must be a bool or None")
    _validate_parameters(payload_len, sf, bw_hz, cr, preamble_symbols, implicit_header)

    symbol_numerator = 1 << sf
    if low_data_rate_optimization is None:
        # T_symbol >= 16 ms, expressed without floating-point comparisons.
        low_data_rate_optimization = symbol_numerator * 1_000 >= 16 * bw_hz
    de = int(low_data_rate_optimization)
    ih = int(implicit_header)
    crc = int(crc_enabled)

    numerator = 8 * payload_len - 4 * sf + 28 + 16 * crc - 20 * ih
    denominator = 4 * (sf - 2 * de)
    coded_blocks = 0 if numerator <= 0 else (numerator + denominator - 1) // denominator
    payload_symbols = 8 + coded_blocks * cr

    total_symbols = preamble_symbols + 4.25 + payload_symbols
    symbol_duration_s = symbol_numerator / bw_hz
    # Truncation matches the canonical simulator/vector representation.
    return int(total_symbols * symbol_duration_s * 1_000_000)


def airtime_us(payload_len: int) -> int:
    """Return LoRa airtime in microseconds for the LICHEN default profile."""
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
    crc_enabled: bool = True,
    implicit_header: bool = False,
    low_data_rate_optimization: bool | None = None,
) -> int:
    """Return airtime in microseconds with explicit LoRa params."""
    return _airtime_us_fallback(
        payload_len,
        sf=sf,
        bw_hz=bw_hz,
        cr=cr,
        preamble_symbols=preamble_symbols,
        crc_enabled=crc_enabled,
        implicit_header=implicit_header,
        low_data_rate_optimization=low_data_rate_optimization,
    )


__all__ = [
    "LORA_BW_DEFAULT_HZ",
    "LORA_BANDWIDTHS_HZ",
    "LORA_CR_DEFAULT",
    "LORA_PREAMBLE_DEFAULT",
    "LORA_SF_DEFAULT",
    "SPEC_SF9_125KHZ_60B_AIRTIME_MS",
    "airtime_ms",
    "airtime_us",
    "airtime_us_with_params",
]
