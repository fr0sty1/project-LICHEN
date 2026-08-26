# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume the ASN/SFN derivation vectors through production Python code."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.link.channel import sfn_from_unix_time

ROOT = Path(__file__).resolve().parents[3]
VECTORS = ROOT / "test" / "vectors"
U32_MASK = (1 << 32) - 1


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_asn_sfn_document_matches_shared_schema() -> None:
    document = _load("asn_sfn_derivation.json")
    errors = sorted(
        Draft7Validator(_load("schema.json")).iter_errors(document),
        key=lambda error: list(error.path),
    )
    assert not errors, [error.message for error in errors]


def test_production_time_derivation_matches_every_asn_vector() -> None:
    document = _load("asn_sfn_derivation.json")
    for vector in document["vectors"]:
        values = vector["input"]
        expected = vector["expected"]
        asn = sfn_from_unix_time(
            values["unix_time_us"],
            values["interval_duration_us"],
            values["epoch_base_us"],
        )
        assert asn == expected["asn_u64"], vector["name"]
        assert asn & U32_MASK == expected["sfn_u32"], vector["name"]


def test_leap_boundary_and_sfn_rollover_are_consecutive() -> None:
    vectors = {vector["name"]: vector for vector in _load("asn_sfn_derivation.json")["vectors"]}

    before = vectors["leap_2016_last_representable_second_before"]
    after = vectors["leap_2016_first_representable_second_after"]
    assert after["input"]["unix_time_us"] - before["input"]["unix_time_us"] == 1_000_000
    assert after["expected"]["asn_u64"] - before["expected"]["asn_u64"] == 1

    maximum = vectors["sfn_u32_max"]["expected"]
    rollover = vectors["sfn_u32_rollover"]["expected"]
    assert maximum == {"asn_u64": U32_MASK, "sfn_u32": U32_MASK, "clamped": False}
    assert rollover == {"asn_u64": 1 << 32, "sfn_u32": 0, "clamped": False}
