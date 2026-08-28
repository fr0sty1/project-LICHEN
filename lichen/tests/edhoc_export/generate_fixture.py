# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Render the C fixture consumed by the Zephyr EDHOC exporter test."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = ROOT / "test" / "vectors" / "edhoc_export_rfc9529.json"

FIELDS = (
    "prk_4e3m",
    "th_4",
    "prk_out",
    "prk_exporter",
    "master_secret",
    "master_salt",
    "c_i",
    "c_r",
    "initiator_sender_id",
    "initiator_recipient_id",
    "responder_sender_id",
    "responder_recipient_id",
)


def render() -> str:
    vector = json.loads(VECTOR_PATH.read_text())["vectors"][0]
    lines = [
        "/* Generated from test/vectors/edhoc_export_rfc9529.json. */",
        "#ifndef LICHEN_TEST_EDHOC_EXPORT_FIXTURE_H_",
        "#define LICHEN_TEST_EDHOC_EXPORT_FIXTURE_H_",
        "",
        "#include <stdint.h>",
        "",
    ]
    for field in FIELDS:
        data = bytes.fromhex(vector[field])
        values = ", ".join(f"0x{byte:02x}" for byte in data)
        lines.append(f"static const uint8_t {field}[{len(data)}] = {{{values}}};")
    lines.extend(["", "#endif", ""])
    return "\n".join(lines)


if __name__ == "__main__":
    print(render(), end="")

