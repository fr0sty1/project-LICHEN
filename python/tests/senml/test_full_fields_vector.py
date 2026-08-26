# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Python parity consumer for the complete Rust SenML pack oracle."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lichen.senml.codec import SenmlRecord, pack, unpack

_VECTOR = Path(__file__).parents[3] / "test" / "vectors" / "senml_full_fields.json"


def _record(fields: dict[str, Any]) -> SenmlRecord:
    values = dict(fields)
    if "vd_hex" in values:
        values["vd"] = bytes.fromhex(values.pop("vd_hex"))
    return SenmlRecord(**values)


def test_complete_rfc8428_pack_has_python_rust_byte_parity() -> None:
    document = json.loads(_VECTOR.read_text())
    records = [_record(fields) for fields in document["records"]]
    expected = bytes.fromhex(document["cbor_hex"])
    assert pack(records) == expected
    assert unpack(expected) == records
