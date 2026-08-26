# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Shared-vector tests for IPSO Smart Object SenML names."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.senml.codec import pack
from lichen.senml.ipso import (
    IpsoObjectId,
    IpsoPath,
    IpsoResourceId,
    default_unit,
    object_definition,
    sensor_record,
)

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "ipso_smart_objects.json"


def _vectors() -> dict[str, Any]:
    return json.loads(VECTORS_PATH.read_text())


def test_known_ids_match_oma_registry() -> None:
    assert int(IpsoObjectId.TEMPERATURE) == 3303
    assert int(IpsoObjectId.HUMIDITY) == 3304
    assert int(IpsoObjectId.ACCELEROMETER) == 3313
    assert int(IpsoObjectId.LOCATION) == 3336
    assert int(IpsoResourceId.SENSOR_VALUE) == 5700
    assert int(IpsoResourceId.NUMERIC_LATITUDE) == 6051


def test_shared_positive_vectors() -> None:
    document = _vectors()
    assert document["format_version"] == 2
    vectors = document["vectors"]
    assert isinstance(vectors, list)
    for vector in vectors:
        assert isinstance(vector, dict)
        path = IpsoPath(
            vector["object_id"], vector["instance_id"], vector.get("resource_id")
        )
        assert str(path) == vector["path"]
        assert IpsoPath.parse(vector["path"]) == path

        definition = object_definition(vector["object_id"])
        assert definition is not None
        assert definition.name == vector["object_name"]
        if vector.get("value") is not None:
            record = sensor_record(
                vector["object_id"],
                vector["value"],
                instance_id=vector["instance_id"],
                resource_id=vector.get("resource_id"),
            )
            assert record.n == vector["path"]
            assert record.u == vector["unit"]
            assert pack([record]).hex() == vector["cbor_hex"]


def test_shared_invalid_paths() -> None:
    document = _vectors()
    invalid_paths = document["invalid_paths"]
    assert isinstance(invalid_paths, list)
    for vector in invalid_paths:
        assert isinstance(vector, dict)
        with pytest.raises(ValueError, match=vector["python_error"]):
            IpsoPath.parse(vector["path"])


def test_compact_object_instance_name() -> None:
    path = IpsoPath(IpsoObjectId.TEMPERATURE, 7)
    assert str(path) == "3303/7"
    assert IpsoPath.parse(str(path)) == path


def test_unknown_object_uses_sensor_value_without_inventing_unit() -> None:
    record = sensor_record(12345, 1.5, instance_id=2)
    assert record.n == "12345/2/5700"
    assert record.u is None


def test_resource_specific_units() -> None:
    assert default_unit(3336, 6052) == "lon"
    assert default_unit(3336, 6053) == "m"
    assert default_unit(3313, 5704) == "m/s2"


@pytest.mark.parametrize("bad_value", [True, "1", None])
def test_sensor_record_rejects_non_numeric_values(bad_value: object) -> None:
    with pytest.raises(TypeError, match="value must be a number"):
        sensor_record(3303, bad_value)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_sensor_record_rejects_non_finite_values(bad_value: float) -> None:
    with pytest.raises(ValueError, match="value must be finite"):
        sensor_record(3303, bad_value)
