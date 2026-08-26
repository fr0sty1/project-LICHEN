# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""IPSO Smart Object names for SenML records.

IPSO/LwM2M identifies a resource with the numeric path
``object-id/object-instance-id/resource-id``.  SenML names are relative, so
LICHEN carries the same path without a leading slash.  The two-component
``object-id/object-instance-id`` form is also supported for composite profiles
where the resource is implied by the profile.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import IntEnum
from types import MappingProxyType

from lichen.senml.codec import SenmlRecord

_MAX_ID = 0xFFFF


class IpsoObjectId(IntEnum):
    """IPSO Smart Object identifiers used by the LICHEN sensor profiles."""

    TEMPERATURE = 3303
    HUMIDITY = 3304
    ACCELEROMETER = 3313
    BAROMETER = 3315
    PRESSURE = 3323
    GYROMETER = 3334
    LOCATION = 3336


class IpsoResourceId(IntEnum):
    """Reusable IPSO resource identifiers used by supported objects."""

    TIMESTAMP = 5518
    SENSOR_VALUE = 5700
    SENSOR_UNITS = 5701
    X_VALUE = 5702
    Y_VALUE = 5703
    Z_VALUE = 5704
    COMPASS_DIRECTION = 5705
    NUMERIC_LATITUDE = 6051
    NUMERIC_LONGITUDE = 6052
    NUMERIC_UNCERTAINTY = 6053


@dataclass(frozen=True, slots=True)
class IpsoObjectDefinition:
    """Known object metadata needed to create its primary sensor record."""

    object_id: IpsoObjectId
    name: str
    value_resource_id: IpsoResourceId
    default_unit: str


_OBJECT_DEFINITIONS: dict[IpsoObjectId, IpsoObjectDefinition] = {
    IpsoObjectId.TEMPERATURE: IpsoObjectDefinition(
        IpsoObjectId.TEMPERATURE, "Temperature", IpsoResourceId.SENSOR_VALUE, "Cel"
    ),
    IpsoObjectId.HUMIDITY: IpsoObjectDefinition(
        IpsoObjectId.HUMIDITY, "Humidity", IpsoResourceId.SENSOR_VALUE, "%RH"
    ),
    IpsoObjectId.ACCELEROMETER: IpsoObjectDefinition(
        IpsoObjectId.ACCELEROMETER, "Accelerometer", IpsoResourceId.X_VALUE, "m/s2"
    ),
    IpsoObjectId.BAROMETER: IpsoObjectDefinition(
        IpsoObjectId.BAROMETER, "Barometer", IpsoResourceId.SENSOR_VALUE, "Pa"
    ),
    IpsoObjectId.PRESSURE: IpsoObjectDefinition(
        IpsoObjectId.PRESSURE, "Pressure", IpsoResourceId.SENSOR_VALUE, "Pa"
    ),
    IpsoObjectId.GYROMETER: IpsoObjectDefinition(
        IpsoObjectId.GYROMETER, "Gyrometer", IpsoResourceId.X_VALUE, "rad/s"
    ),
    IpsoObjectId.LOCATION: IpsoObjectDefinition(
        IpsoObjectId.LOCATION, "Location", IpsoResourceId.NUMERIC_LATITUDE, "lat"
    ),
}

IPSO_OBJECTS: Mapping[IpsoObjectId, IpsoObjectDefinition] = MappingProxyType(
    _OBJECT_DEFINITIONS
)

_RESOURCE_UNITS: Mapping[tuple[IpsoObjectId, IpsoResourceId], str] = MappingProxyType(
    {
        (definition.object_id, definition.value_resource_id): definition.default_unit
        for definition in _OBJECT_DEFINITIONS.values()
    }
    | {
        (IpsoObjectId.ACCELEROMETER, IpsoResourceId.Y_VALUE): "m/s2",
        (IpsoObjectId.ACCELEROMETER, IpsoResourceId.Z_VALUE): "m/s2",
        (IpsoObjectId.GYROMETER, IpsoResourceId.Y_VALUE): "rad/s",
        (IpsoObjectId.GYROMETER, IpsoResourceId.Z_VALUE): "rad/s",
        (IpsoObjectId.LOCATION, IpsoResourceId.NUMERIC_LONGITUDE): "lon",
        (IpsoObjectId.LOCATION, IpsoResourceId.NUMERIC_UNCERTAINTY): "m",
        (IpsoObjectId.LOCATION, IpsoResourceId.COMPASS_DIRECTION): "deg",
    }
)


def _validate_id(label: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an integer")
    if not (0 <= value <= _MAX_ID):
        raise ValueError(f"{label} {value} out of range [0, 65535]")
    return int(value)


def _parse_component(label: str, component: str) -> int:
    if not component or not component.isascii() or not component.isdecimal():
        raise ValueError(f"{label} must be an unsigned decimal integer")
    value = int(component)
    _validate_id(label, value)
    if str(value) != component:
        raise ValueError(f"{label} must use canonical decimal encoding")
    return value


@dataclass(frozen=True, slots=True)
class IpsoPath:
    """A canonical IPSO object/instance[/resource] relative path."""

    object_id: int
    instance_id: int = 0
    resource_id: int | None = None

    def __post_init__(self) -> None:
        _validate_id("object_id", self.object_id)
        _validate_id("instance_id", self.instance_id)
        if self.resource_id is not None:
            _validate_id("resource_id", self.resource_id)

    def __str__(self) -> str:
        path = f"{self.object_id}/{self.instance_id}"
        if self.resource_id is not None:
            path += f"/{self.resource_id}"
        return path

    @classmethod
    def parse(cls, name: str) -> IpsoPath:
        """Parse a canonical relative IPSO name.

        Leading slashes, signs, whitespace, leading zeroes, missing components,
        and identifiers outside the LwM2M 16-bit identifier space are rejected.
        """
        if not isinstance(name, str):
            raise TypeError("IPSO path must be a string")
        components = name.split("/")
        if len(components) not in (2, 3):
            raise ValueError("IPSO path must have 2 or 3 components")
        object_id = _parse_component("object_id", components[0])
        instance_id = _parse_component("instance_id", components[1])
        resource_id = (
            _parse_component("resource_id", components[2]) if len(components) == 3 else None
        )
        return cls(object_id, instance_id, resource_id)


def object_definition(object_id: int) -> IpsoObjectDefinition | None:
    """Return metadata for a supported object ID, or ``None`` if unknown."""
    _validate_id("object_id", object_id)
    try:
        known_id = IpsoObjectId(object_id)
    except ValueError:
        return None
    return IPSO_OBJECTS[known_id]


def default_unit(object_id: int, resource_id: int) -> str | None:
    """Return the LICHEN SenML unit for a known object/resource pair."""
    _validate_id("object_id", object_id)
    _validate_id("resource_id", resource_id)
    try:
        key = (IpsoObjectId(object_id), IpsoResourceId(resource_id))
    except ValueError:
        return None
    return _RESOURCE_UNITS.get(key)


def sensor_record(
    object_id: int,
    value: int | float | Decimal,
    *,
    instance_id: int = 0,
    resource_id: int | None = None,
    unit: str | None = None,
) -> SenmlRecord:
    """Create a numeric SenML record named with an IPSO resource path.

    If ``resource_id`` is omitted, known objects use their primary value
    resource and unknown objects use the reusable Sensor Value resource 5700.
    Units are inferred only for known object/resource pairs; an explicit
    ``unit`` always wins.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise TypeError("value must be a number")
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError("value must be finite")

    definition = object_definition(object_id)
    if resource_id is None:
        resource_id = (
            int(definition.value_resource_id)
            if definition is not None
            else int(IpsoResourceId.SENSOR_VALUE)
        )
    path = IpsoPath(object_id, instance_id, resource_id)
    record_unit = unit if unit is not None else default_unit(object_id, resource_id)
    return SenmlRecord(n=str(path), u=record_unit, v=value)
