# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""
Synthesize APRS packets from LICHEN payload data.

Detects common data patterns (position, weather, telemetry) and emits
proper APRS packet types so APRSDroid shows icons/graphs instead of
plain messages.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

try:
    import cbor2
    HAS_CBOR = True
except ImportError:
    HAS_CBOR = False


class AprsDataType(Enum):
    """Detected APRS-compatible data type."""
    POSITION = "position"
    WEATHER = "weather"
    TELEMETRY = "telemetry"
    MESSAGE = "message"  # fallback


@dataclass
class SynthResult:
    """Result of APRS synthesis."""
    data_type: AprsDataType
    aprs_payload: bytes  # Raw APRS info field (without AX.25 wrapper)


# ponytail: one symbol, expand if users complain
DEFAULT_SYMBOL = ">"  # Car symbol for generic LICHEN node


def synthesize_aprs(payload: bytes) -> SynthResult | None:
    """Try to synthesize APRS packet from LICHEN payload.

    Returns SynthResult with proper APRS format, or None if no pattern matched.
    """
    obj = _decode_payload(payload)
    if obj is None:
        return None

    # Try each pattern in order of specificity
    result = _try_weather(obj)
    if result:
        return result

    result = _try_position(obj)
    if result:
        return result

    result = _try_telemetry(obj)
    if result:
        return result

    return None


def _decode_payload(payload: bytes) -> Any:
    """Decode payload as CBOR or JSON."""
    # Try CBOR first (more common for constrained devices)
    if HAS_CBOR:
        try:
            return cbor2.loads(payload)
        except Exception:
            pass

    # Try JSON
    try:
        if payload[0:1] in (b"{", b"["):
            return json.loads(payload)
    except Exception:
        pass

    return None


# --- Position ---

_LAT_KEYS = ("lat", "latitude")
_LON_KEYS = ("lon", "lng", "longitude")
_ALT_KEYS = ("alt", "altitude", "elev", "elevation")


def _try_position(obj: Any) -> SynthResult | None:
    """Detect position data and format as APRS position."""
    if not isinstance(obj, dict):
        return None

    lat = _get_key(obj, _LAT_KEYS)
    lon = _get_key(obj, _LON_KEYS)

    if lat is None or lon is None:
        return None

    try:
        lat = float(lat)
        lon = float(lon)
    except (TypeError, ValueError):
        return None

    alt = _get_key(obj, _ALT_KEYS)

    aprs = _format_position(lat, lon, alt)
    return SynthResult(AprsDataType.POSITION, aprs.encode("ascii"))


def _format_position(lat: float, lon: float, alt: float | None = None) -> str:
    """Format lat/lon as APRS uncompressed position.

    Format: !DDMM.mmN/DDDMM.mmWS
    """
    # Latitude: DDMM.mm
    lat_dir = "N" if lat >= 0 else "S"
    lat = abs(lat)
    lat_deg = int(lat)
    lat_min = (lat - lat_deg) * 60

    # Longitude: DDDMM.mm
    lon_dir = "E" if lon >= 0 else "W"
    lon = abs(lon)
    lon_deg = int(lon)
    lon_min = (lon - lon_deg) * 60

    pos = (
        f"!{lat_deg:02d}{lat_min:05.2f}{lat_dir}/"
        f"{lon_deg:03d}{lon_min:05.2f}{lon_dir}{DEFAULT_SYMBOL}"
    )

    # Altitude extension: /A=NNNNNN (feet)
    if alt is not None:
        try:
            alt_ft = int(float(alt) * 3.28084)  # meters to feet
            pos += f"/A={alt_ft:06d}"
        except (TypeError, ValueError):
            pass

    return pos


# --- Weather ---

_TEMP_KEYS = ("temp", "temperature", "t")
_HUMIDITY_KEYS = ("humidity", "rh", "h")
_PRESSURE_KEYS = ("pressure", "baro", "barometer", "p")
_WIND_SPEED_KEYS = ("wind_speed", "windspeed", "ws")
_WIND_DIR_KEYS = ("wind_dir", "winddir", "wd", "wind_direction")
_WIND_GUST_KEYS = ("wind_gust", "windgust", "wg", "gust")


def _try_weather(obj: Any) -> SynthResult | None:
    """Detect weather data and format as APRS weather report."""
    if not isinstance(obj, dict):
        return None

    # Need at least temp or pressure to call it weather
    temp = _get_key(obj, _TEMP_KEYS)
    pressure = _get_key(obj, _PRESSURE_KEYS)

    if temp is None and pressure is None:
        return None

    humidity = _get_key(obj, _HUMIDITY_KEYS)
    wind_speed = _get_key(obj, _WIND_SPEED_KEYS)
    wind_dir = _get_key(obj, _WIND_DIR_KEYS)
    wind_gust = _get_key(obj, _WIND_GUST_KEYS)

    # Also check for position (weather stations usually have location)
    lat = _get_key(obj, _LAT_KEYS)
    lon = _get_key(obj, _LON_KEYS)

    aprs = _format_weather(
        temp_c=temp,
        humidity=humidity,
        pressure_hpa=pressure,
        wind_speed_mps=wind_speed,
        wind_dir=wind_dir,
        wind_gust_mps=wind_gust,
        lat=lat,
        lon=lon,
    )
    return SynthResult(AprsDataType.WEATHER, aprs.encode("ascii"))


def _format_weather(
    temp_c: float | None = None,
    humidity: float | None = None,
    pressure_hpa: float | None = None,
    wind_speed_mps: float | None = None,
    wind_dir: float | None = None,
    wind_gust_mps: float | None = None,
    lat: float | None = None,
    lon: float | None = None,
) -> str:
    """Format weather data as APRS weather report.

    APRS weather format uses:
    - Temperature in Fahrenheit
    - Wind speed in mph
    - Pressure in tenths of mbar (= tenths of hPa)
    """
    parts = []

    # Position header if available, else use @ with timestamp placeholder
    if lat is not None and lon is not None:
        try:
            lat_f = float(lat)
            lon_f = float(lon)
            lat_dir = "N" if lat_f >= 0 else "S"
            lat_f = abs(lat_f)
            lat_deg = int(lat_f)
            lat_min = (lat_f - lat_deg) * 60

            lon_dir = "E" if lon_f >= 0 else "W"
            lon_f = abs(lon_f)
            lon_deg = int(lon_f)
            lon_min = (lon_f - lon_deg) * 60

            parts.append(f"!{lat_deg:02d}{lat_min:05.2f}{lat_dir}/{lon_deg:03d}{lon_min:05.2f}{lon_dir}_")
        except (TypeError, ValueError):
            parts.append("_")
    else:
        parts.append("_")  # Positionless weather

    # Wind direction (degrees, ... = no data)
    if wind_dir is not None:
        try:
            parts.append(f"{int(float(wind_dir)):03d}")
        except (TypeError, ValueError):
            parts.append("...")
    else:
        parts.append("...")

    # Wind speed (mph, /... = no data)
    parts.append("/")
    if wind_speed_mps is not None:
        try:
            mph = float(wind_speed_mps) * 2.237  # m/s to mph
            parts.append(f"{int(mph):03d}")
        except (TypeError, ValueError):
            parts.append("...")
    else:
        parts.append("...")

    # Wind gust
    if wind_gust_mps is not None:
        try:
            mph = float(wind_gust_mps) * 2.237
            parts.append(f"g{int(mph):03d}")
        except (TypeError, ValueError):
            pass

    if temp_c is not None:
        try:
            temp_f = float(temp_c) * 9 / 5 + 32
            temp_f_int = int(temp_f)
            if -99 <= temp_f_int <= 999:
                if temp_f_int >= 0:
                    parts.append(f"t{temp_f_int:03d}")
                else:
                    parts.append(f"t{temp_f_int:02d}")
            else:
                parts.append("t...")
        except (TypeError, ValueError):
            pass

    # Humidity (00 = 100%)
    if humidity is not None:
        try:
            h = int(float(humidity))
            if h == 100:
                h = 0
            parts.append(f"h{h:02d}")
        except (TypeError, ValueError):
            pass

    # Barometric pressure (tenths of hPa/mbar)
    if pressure_hpa is not None:
        try:
            tenths = int(float(pressure_hpa) * 10)
            parts.append(f"b{tenths:05d}")
        except (TypeError, ValueError):
            pass

    return "".join(parts)


# --- Telemetry ---

_SEQ_KEYS = ("seq", "sequence", "n", "id")


def _try_telemetry(obj: Any) -> SynthResult | None:
    """Detect telemetry data and format as APRS telemetry."""
    values: list[float] = []
    bits: int = 0
    seq: int = 0

    if isinstance(obj, list):
        # Array of numbers
        for v in obj[:5]:  # APRS supports 5 analog channels
            try:
                values.append(float(v))
            except (TypeError, ValueError):
                break
    elif isinstance(obj, dict):
        # Look for channel keys or SenML-style
        seq_val = _get_key(obj, _SEQ_KEYS)
        if seq_val is not None:
            try:  # noqa: SIM105
                seq = int(seq_val) % 1000
            except (TypeError, ValueError):
                pass

        # Try channel keys: ch0, ch1, ... or sensor_0, sensor_1, ...
        for i in range(5):
            for prefix in ("ch", "channel", "sensor_", "v", "a"):
                key = f"{prefix}{i}"
                if key in obj:
                    try:
                        values.append(float(obj[key]))
                        break
                    except (TypeError, ValueError):
                        pass

        # Try digital bits
        digital = obj.get("digital") or obj.get("bits") or obj.get("d")
        if digital is not None:
            try:  # noqa: SIM105
                bits = int(digital) & 0xFF
            except (TypeError, ValueError):
                pass
    else:
        return None

    if not values:
        return None

    aprs = _format_telemetry(seq, values, bits)
    return SynthResult(AprsDataType.TELEMETRY, aprs.encode("ascii"))


def _format_telemetry(seq: int, values: list[float], bits: int = 0) -> str:
    """Format telemetry as APRS T# format.

    Format: T#seq,v1,v2,v3,v4,v5,bbbbbbbb
    """
    # Pad values to 5 channels
    while len(values) < 5:
        values.append(0)

    # Scale values to 0-255 range (APRS analog telemetry)
    # ponytail: just clamp, proper scaling needs per-channel config
    scaled = []
    for v in values[:5]:
        clamped = max(0, min(255, int(v)))
        scaled.append(f"{clamped:03d}")

    # Digital bits as binary string
    bit_str = f"{bits:08b}"

    return f"T#{seq:03d},{','.join(scaled)},{bit_str}"


# --- Helpers ---

def _get_key(obj: dict, keys: tuple[str, ...]) -> Any:
    """Get value from dict trying multiple key names."""
    for k in keys:
        if k in obj:
            return obj[k]
        # Try lowercase
        if k.lower() in obj:
            return obj[k.lower()]
    return None
