# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Standard SenML sensor profiles for LICHEN nodes.

Each helper returns one or more :class:`~lichen.senml.codec.SenmlRecord`
objects using standard IANA SenML unit names (RFC 8428 Table 12 / IANA
SenML Units registry).

Usage::

    from lichen.senml.profiles import location, battery, temperature
    from lichen.senml.codec import pack

    records = [
        *location(lat=48.2049, lon=16.3710, alt=158.0),
        *battery(voltage_v=3.85, percent=72.0),
        temperature(23.4),
    ]
    payload = pack(records)
"""

from __future__ import annotations

from lichen.senml.codec import SenmlRecord

# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------


def location(lat: float, lon: float, alt: float | None = None) -> list[SenmlRecord]:
    """Geographic position as SenML records.

    Uses IANA-registered SenML names "lat", "lon", "alt" with unit "deg" or
    "m" (RFC 8428, IANA SenML Units).

    Args:
        lat: Latitude in decimal degrees (WGS-84).
        lon: Longitude in decimal degrees (WGS-84).
        alt: Altitude in metres above WGS-84 ellipsoid, or None to omit.

    Returns:
        List of SenML records: lat, lon, and optionally alt.
    """
    records = [
        SenmlRecord(n="lat", u="deg", v=lat),
        SenmlRecord(n="lon", u="deg", v=lon),
    ]
    if alt is not None:
        records.append(SenmlRecord(n="alt", u="m", v=alt))
    return records


# ---------------------------------------------------------------------------
# Power / battery
# ---------------------------------------------------------------------------


def battery(voltage_v: float | None = None, percent: float | None = None) -> list[SenmlRecord]:
    """Battery state as SenML records.

    Args:
        voltage_v: Terminal voltage in volts (unit "V"), or None to omit.
        percent:   State of charge 0-100 % (unit "%EL"), or None to omit.

    Returns:
        List of 0-2 SenML records.  Pass at least one of the arguments.
    """
    records = []
    if voltage_v is not None:
        records.append(SenmlRecord(n="voltage", u="V", v=voltage_v))
    if percent is not None:
        records.append(SenmlRecord(n="battery", u="%EL", v=percent))
    return records


# ---------------------------------------------------------------------------
# Environmental
# ---------------------------------------------------------------------------


def temperature(celsius: float) -> SenmlRecord:
    """Ambient temperature (unit "Cel" per RFC 8428 Table 12).

    Args:
        celsius: Temperature in degrees Celsius.

    Returns:
        A single SenML record.
    """
    return SenmlRecord(n="temperature", u="Cel", v=celsius)


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
