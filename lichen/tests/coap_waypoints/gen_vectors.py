#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate the Zephyr waypoint fixture directly from the shared JSON oracle."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _bytes(name: str, wire: bytes) -> list[str]:
    values = ", ".join(f"0x{value:02x}" for value in wire)
    return [f"static const uint8_t {name}[] = {{", f"  {values}", "};"]


def _table(name: str, vectors: list[dict[str, Any]]) -> list[str]:
    lines = [f"static const struct waypoint_wire_vector {name}[] = {{"]
    for index, vector in enumerate(vectors):
        lines.append(
            "  {"
            f".name = {json.dumps(vector['name'])}, "
            f".wire = waypoint_wire_{index}, "
            f".wire_len = sizeof(waypoint_wire_{index})"
            "},"
        )
    lines.append("};")
    return lines


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py INPUT_JSON OUTPUT_INC")

    source = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    vectors = source["vectors"]
    valid = [vector for vector in vectors if "reject" not in vector]
    rejected = [vector for vector in vectors if vector.get("reject") == "truncated_cbor"]
    ordered = valid + rejected
    lines = [
        "/* Generated from test/vectors/waypoint.json; do not edit. */",
        "",
    ]
    for index, vector in enumerate(ordered):
        lines.extend(_bytes(f"waypoint_wire_{index}", bytes.fromhex(vector["encoded_hex"])))
        lines.append("")
    lines.extend(_table("waypoint_valid_vectors", valid))
    lines.append("")

    # Table indexes refer to the arrays emitted after all valid vectors.
    shifted = []
    for index, vector in enumerate(rejected, start=len(valid)):
        shifted.append({**vector, "_index": index})
    lines.append("static const struct waypoint_wire_vector waypoint_reject_vectors[] = {")
    for vector in shifted:
        index = vector["_index"]
        lines.append(
            "  {"
            f".name = {json.dumps(vector['name'])}, "
            f".wire = waypoint_wire_{index}, "
            f".wire_len = sizeof(waypoint_wire_{index})"
            "},"
        )
    lines.append("};")
    lines.append("")
    Path(sys.argv[2]).write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    main()
