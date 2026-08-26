# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RFC 8428 numeric-label parity against the shared literal oracle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cbor2
import pytest

from lichen.senml.codec import field_for_label, label_for_field

_VECTORS = (
    Path(__file__).parents[3] / "test" / "vectors" / "senml_labels.json"
)


def _vectors() -> list[dict[str, Any]]:
    document = json.loads(_VECTORS.read_text())
    assert document["format_version"] == 2
    return document["vectors"]


def test_complete_rfc8428_numeric_label_mapping() -> None:
    vectors = _vectors()
    assert len(vectors) == 15
    assert {vector["field"] for vector in vectors} == {
        "bn",
        "bt",
        "bu",
        "bv",
        "bs",
        "bver",
        "n",
        "u",
        "v",
        "vs",
        "vb",
        "vd",
        "s",
        "t",
        "ut",
    }
    assert len({vector["label"] for vector in vectors}) == len(vectors)

    for vector in vectors:
        field = str(vector["field"])
        label = int(vector["label"])
        expected_key = bytes.fromhex(str(vector["cbor_key_hex"]))
        assert field_for_label(label) == field
        assert label_for_field(field) == label
        assert cbor2.dumps(label) == expected_key
        assert cbor2.loads(expected_key) == label


def test_unknown_and_non_integer_labels_fail_safely() -> None:
    assert field_for_label(-7) is None
    assert field_for_label(9) is None
    assert label_for_field("future") is None
    with pytest.raises(TypeError, match="integer"):
        field_for_label(True)
    with pytest.raises(TypeError, match="string"):
        label_for_field(0)  # type: ignore[arg-type]
