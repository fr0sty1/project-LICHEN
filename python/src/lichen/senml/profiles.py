# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Standard SenML sensor profiles for LICHEN nodes.

Each helper returns one or more :class:`~lichen.senml.codec.SenmlRecord`
objects using standard IANA SenML unit names (RFC 8428 Table 12 / IANA
SenML Units registry).

Usage::

    from lichen.senml.profiles import location, battery, temperature
    from lichen.senml.codec import pack

    records = [*location(48.2, 16.4), *battery(percent=72.0), temperature(23.4)]
    payload = pack(records)
"""

from __future__ import annotations

from lichen.constants import (
    SENML_BATTERY_CHARGING,
    SENML_BATTERY_MV,
    SENML_BATTERY_PCT,
    SENML_BATTERY_UNIT_MV,
    SENML_BATTERY_UNIT_PCT,
    SENML_LOCATION_ALT,
    SENML_LOCATION_HEADING,
    SENML_LOCATION_LAT,
    SENML_LOCATION_LON,
    SENML_LOCATION_SPEED,
    SENML_LOCATION_UNIT_DEG,
    SENML_LOCATION_UNIT_M,
    SENML_LOCATION_UNIT_MS,
    SENML_TELEMETRY_TEMP,
    SENML_TELEMETRY_UNIT_CEL,
)
from lichen.senml.codec import SenmlRecord

# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------


def location(lat: float, lon: float, alt: float | None = None) -> list[SenmlRecord]:
    records = [
        SenmlRecord(n=SENML_LOCATION_LAT, u=SENML_LOCATION_UNIT_DEG, v=lat),
        SenmlRecord(n=SENML_LOCATION_LON, u=SENML_LOCATION_UNIT_DEG, v=lon),
    ]
    if alt is not None:
        records.append(SenmlRecord(n=SENML_LOCATION_ALT, u=SENML_LOCATION_UNIT_M, v=alt))
    return records


# ---------------------------------------------------------------------------
# Power / battery
# ---------------------------------------------------------------------------


def battery(percent: float | None = None, mv: float | None = None) -> list[SenmlRecord]:
    records = []
    if percent is not None:
        records.append(SenmlRecord(n=SENML_BATTERY_PCT, u=SENML_BATTERY_UNIT_PCT, v=percent))
    if mv is not None:
        records.append(SenmlRecord(n=SENML_BATTERY_MV, u=SENML_BATTERY_UNIT_MV, v=mv))
    return records


# ---------------------------------------------------------------------------
# Environmental
# ---------------------------------------------------------------------------


def temperature(celsius: float) -> SenmlRecord:
    return SenmlRecord(n=SENML_TELEMETRY_TEMP, u=SENML_TELEMETRY_UNIT_CEL, v=celsius)


def humidity(percent_rh: float) -> SenmlRecord:
    """Relative humidity (unit "%RH").

    Args:
        percent_rh: Relative humidity 0-100 %.

    Returns:
        A single SenML record.
    """
    return SenmlRecord(n="rel-humidity", u="%RH", v=percent_rh)


def pressure(pascal: float) -> SenmlRecord:
    """Barometric pressure (unit "Pa").

    Args:
        pascal: Pressure in Pascals.

    Returns:
        A single SenML record.
    """
    return SenmlRecord(n="pressure", u="Pa", v=pascal)


# ---------------------------------------------------------------------------
# IMU
# ---------------------------------------------------------------------------


def accelerometer(x: float, y: float, z: float) -> list[SenmlRecord]:
    """3-axis accelerometer (unit "m/s2").

    Args:
        x, y, z: Acceleration in m/s² for each axis.

    Returns:
        Three SenML records named "accel-x", "accel-y", "accel-z".
    """
    return [
        SenmlRecord(n="accel-x", u="m/s2", v=x),
        SenmlRecord(n="accel-y", u="m/s2", v=y),
        SenmlRecord(n="accel-z", u="m/s2", v=z),
    ]


def gyroscope(x: float, y: float, z: float) -> list[SenmlRecord]:
    """3-axis gyroscope (unit "rad/s").

    Args:
        x, y, z: Angular velocity in rad/s for each axis.

    Returns:
        Three SenML records named "gyro-x", "gyro-y", "gyro-z".
    """
    return [
        SenmlRecord(n="gyro-x", u="rad/s", v=x),
        SenmlRecord(n="gyro-y", u="rad/s", v=y),
        SenmlRecord(n="gyro-z", u="rad/s", v=z),
    ]


# ---------------------------------------------------------------------------
# Air quality
# ---------------------------------------------------------------------------


def co2_ppm(ppm: float) -> SenmlRecord:
    """CO₂ concentration (unit "ppm").

    Args:
        ppm: CO₂ in parts per million.

    Returns:
        A single SenML record named "CO2".
    """
    return SenmlRecord(n="CO2", u="ppm", v=ppm)


def voc_index(index: float) -> SenmlRecord:
    """Volatile organic compounds index (dimensionless, 1-500 scale).

    Args:
        index: VOC index (Sensirion scale, 1-500).

    Returns:
        A single SenML record named "voc-index".
    """
    return SenmlRecord(n="voc-index", v=index)
