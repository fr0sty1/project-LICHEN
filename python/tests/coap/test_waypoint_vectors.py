# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-validation tests for the waypoint CBOR vectors (spec 18.3.1).

Consumes ``test/vectors/waypoint.json``: every normal vector must encode
byte-exactly through the ordered-map CBOR codec and round-trip back to the
input; reject vectors pin truncated wire forms that decoders MUST refuse.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cbor2
import pytest

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "waypoint.json"

_REQUIRED_FIELDS = frozenset({"id", "name", "lat", "lon", "created", "creator"})
_OPTIONAL_FIELDS = frozenset({"alt", "icon", "color", "notes", "expires"})


def _load_vectors() -> list[dict[str, Any]]:
    with open(VECTORS_PATH) as f:
        return json.load(f)["vectors"]


_ALL_VECTORS = _load_vectors()
NORMAL_VECTORS = [v for v in _ALL_VECTORS if "reject" not in v]
REJECT_VECTORS = [v for v in _ALL_VECTORS if v.get("reject") == "truncated_cbor"]
_NORMALS_BY_NAME = {v["name"]: v for v in NORMAL_VECTORS}


class TestWaypointEncoding:
    """Normal vectors: ordered-map CBOR encode must match the committed bytes."""

    @pytest.mark.parametrize("vector", NORMAL_VECTORS, ids=lambda v: v["name"])
    def test_encode_matches_encoded_hex(self, vector: dict[str, Any]) -> None:
        encoded = cbor2.dumps(vector["input"])
        assert encoded.hex() == vector["encoded_hex"]

    @pytest.mark.parametrize("vector", NORMAL_VECTORS, ids=lambda v: v["name"])
    def test_decode_round_trips_to_input(self, vector: dict[str, Any]) -> None:
        decoded = cbor2.loads(bytes.fromhex(vector["encoded_hex"]))
        assert decoded == vector["input"]

    @pytest.mark.parametrize("vector", NORMAL_VECTORS, ids=lambda v: v["name"])
    def test_field_set_matches_spec(self, vector: dict[str, Any]) -> None:
        keys = set(vector["input"].keys())
        assert keys >= _REQUIRED_FIELDS, f"{vector['name']}: missing required field(s)"
        extra = keys - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
        assert not extra, f"{vector['name']}: unexpected field(s) {sorted(extra)}"


class TestWaypointRejects:
    """Reject vectors: truncated CBOR MUST fail to decode."""

    @pytest.mark.parametrize("vector", REJECT_VECTORS, ids=lambda v: v["name"])
    def test_truncated_wire_fails_decode(self, vector: dict[str, Any]) -> None:
        wire = bytes.fromhex(vector["encoded_hex"])
        with pytest.raises((ValueError, cbor2.CBORDecodeError)):
            cbor2.loads(wire)

    @pytest.mark.parametrize("vector", REJECT_VECTORS, ids=lambda v: v["name"])
    def test_derived_from_source_still_decodes(self, vector: dict[str, Any]) -> None:
        source = _NORMALS_BY_NAME.get(vector["derived_from"])
        assert source is not None, (
            f"{vector['name']}: derived_from '{vector['derived_from']}' is not a normal vector"
        )
        assert vector["encoded_hex"] != source["encoded_hex"]
        decoded = cbor2.loads(bytes.fromhex(source["encoded_hex"]))
        assert decoded == source["input"]

    def test_reject_prefixes_are_real_prefixes(self) -> None:
        for vector in REJECT_VECTORS:
            source = _NORMALS_BY_NAME[vector["derived_from"]]
            assert source["encoded_hex"].startswith(vector["encoded_hex"]), (
                f"{vector['name']}: reject bytes are not a prefix of {vector['derived_from']}"
            )
