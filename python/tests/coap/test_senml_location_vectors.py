# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-validation tests for the SenML location profile vectors.

Consumes ``test/vectors/senml_location.json`` through ``lichen.senml`` — the
same ``profiles.location()`` + ``codec.pack()`` building blocks the
``SenMLLocationResource`` calls internally — asserting every positive vector
byte-exactly and exercising the committed error vectors (encoder range/finite
rejects and decoder type rejects).
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest

from lichen.senml.codec import SenmlRecord, pack, unpack
from lichen.senml.profiles import location as location_profile

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "senml_location.json"

# profiles.location() signature order; vector "fields" follow it after bn/bt.
_LOCATION_FIELD_ORDER = ("lat", "lon", "alt", "speed", "heading", "hacc", "vacc")


def _load_vectors() -> list[dict[str, Any]]:
    with open(VECTORS_PATH) as f:
        return json.load(f)["vectors"]


_ALL_VECTORS = _load_vectors()
POSITIVE_VECTORS = [v for v in _ALL_VECTORS if "error" not in v]
ENCODE_REJECTS = [v for v in _ALL_VECTORS if "error" in v and "cbor_hex" not in v]
DECODE_REJECTS = [v for v in _ALL_VECTORS if "error" in v and "cbor_hex" in v]


def _resolve(value: Any) -> Any:
    """Map documented string sentinels to the float values they stand in for."""
    if value == "NaN":
        return float("nan")
    return value


def _records_from_fields(fields: dict[str, Any]) -> list[SenmlRecord]:
    """Assemble the pack exactly as production code does.

    When base fields are present they ride on a leading base-only record;
    every remaining field becomes one record via ``profiles.location()``.
    """
    records: list[SenmlRecord] = []
    if "bn" in fields or "bt" in fields:
        records.append(SenmlRecord(bn=fields.get("bn"), bt=fields.get("bt")))
    kwargs = {
        name: _resolve(fields[name])
        for name in _LOCATION_FIELD_ORDER
        if name in fields
    }
    records.extend(location_profile(**kwargs))
    return records


class TestSenMLLocationEncoding:
    """Positive vectors must reproduce the committed CBOR byte-for-byte."""

    @pytest.mark.parametrize("vector", POSITIVE_VECTORS, ids=lambda v: v["id"])
    def test_encode_matches_cbor_hex(self, vector: dict[str, Any]) -> None:
        payload = pack(_records_from_fields(vector["fields"]))
        assert payload.hex() == vector["cbor_hex"]

    @pytest.mark.parametrize("vector", POSITIVE_VECTORS, ids=lambda v: v["id"])
    def test_round_trip_is_stable(self, vector: dict[str, Any]) -> None:
        wire = bytes.fromhex(vector["cbor_hex"])
        records = unpack(wire)
        assert pack(records) == wire

    def test_full_vector_semantics(self) -> None:
        v = next(v for v in POSITIVE_VECTORS if v["id"] == "senml-location-full")
        records = unpack(bytes.fromhex(v["cbor_hex"]))
        assert records[0].bn == "urn:dev:mac:0011223344556677:"
        assert records[0].bt == 1716742800
        assert [(r.n, r.u) for r in records[1:]] == [
            ("lat", "lat"),
            ("lon", "lon"),
            ("alt", "m"),
            ("speed", "m/s"),
            ("heading", "deg"),
            ("hacc", "m"),
            ("vacc", "m"),
        ]
        assert records[1].v == pytest.approx(37.774929)
        assert records[2].v == pytest.approx(-122.419416)

    def test_minimal_vector_has_no_base_record(self) -> None:
        v = next(v for v in POSITIVE_VECTORS if v["id"] == "senml-location-minimal")
        records = unpack(bytes.fromhex(v["cbor_hex"]))
        assert len(records) == 2
        assert all(r.bn is None and r.bt is None for r in records)


class TestSenMLLocationEncodeRejects:
    """Encoder-refusal vectors: input MUST raise ValueError with the pinned message."""

    @pytest.mark.parametrize("vector", ENCODE_REJECTS, ids=lambda v: v["id"])
    def test_encode_raises_with_oracle_message(self, vector: dict[str, Any]) -> None:
        with pytest.raises(ValueError) as excinfo:
            pack(_records_from_fields(vector["fields"]))
        assert str(excinfo.value) == vector["error"]

    def test_nan_coordinate_message(self) -> None:
        with pytest.raises(ValueError) as excinfo:
            location_profile(lat=float("nan"), lon=0.0)
        assert str(excinfo.value) == "lat nan is NaN or Inf"
        assert not math.isfinite(float("nan"))


class TestSenMLLocationDecodeRejects:
    """Decoder-refusal vectors: malformed packs MUST raise ValueError."""

    @pytest.mark.parametrize("vector", DECODE_REJECTS, ids=lambda v: v["id"])
    def test_decode_raises_with_oracle_message(self, vector: dict[str, Any]) -> None:
        wire = bytes.fromhex(vector["cbor_hex"])
        with pytest.raises(ValueError) as excinfo:
            unpack(wire)
        assert str(excinfo.value) == vector["error"]


class TestVectorPartition:
    """Every vector is either positive or exactly one kind of error case."""

    def test_partition_is_exhaustive(self) -> None:
        assert len(POSITIVE_VECTORS) + len(ENCODE_REJECTS) + len(DECODE_REJECTS) == len(
            _ALL_VECTORS
        )

    def test_error_vectors_pin_a_message(self) -> None:
        for v in ENCODE_REJECTS + DECODE_REJECTS:
            assert isinstance(v.get("error"), str) and v["error"], f"{v['id']}: missing error"
