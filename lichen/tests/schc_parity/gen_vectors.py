#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate the bounded C consumer for canonical SCHC compression vectors."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HEX = re.compile(r"(?:[0-9a-f]{2})+")
KINDS = {
    None: "SCHC_PARITY_ROUND_TRIP",
    "fallback": "SCHC_PARITY_ROUND_TRIP",
    "malformed_input": "SCHC_PARITY_MALFORMED_INPUT",
    "malformed": "SCHC_PARITY_MALFORMED_COMPRESSED",
    "size_boundary": "SCHC_PARITY_SIZE_BOUNDARY",
}


def fail(message: str) -> None:
    raise ValueError(message)


def decode_hex(value: object, context: str) -> bytes:
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        fail(f"{context} must be nonempty lowercase even-length hexadecimal")
    return bytes.fromhex(value)


def require_keys(vector: dict[str, object], required: set[str], optional: set[str]) -> None:
    actual = set(vector)
    missing = required - actual
    extra = actual - required - optional
    if missing or extra:
        fail(
            f"{vector.get('name', '<unnamed>')} field mismatch: "
            f"missing={sorted(missing)}, extra={sorted(extra)}"
        )


def c_array(name: str, data: bytes) -> str:
    values = ", ".join(f"0x{byte:02x}" for byte in data) or "0"
    return f"static const uint8_t {name}[] = {{ {values} }};"


def load(path: Path) -> list[dict[str, object]]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                fail(f"duplicate object key: {key}")
            result[key] = value
        return result

    doc = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    if not isinstance(doc, dict) or doc.get("format_version") != 2:
        fail("SCHC compression corpus must be a format_version 2 object")
    vectors = doc.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        fail("vectors must be a nonempty array")
    names: set[str] = set()
    rules: set[int] = set()
    for vector in vectors:
        if not isinstance(vector, dict):
            fail("every vector must be an object")
        name = vector.get("name")
        if not isinstance(name, str) or not name or name in names:
            fail(f"invalid or duplicate vector name: {name!r}")
        names.add(name)
        category = vector.get("category")
        if category not in KINDS:
            fail(f"{name}: unsupported category {category!r}")
        common = {"name"}
        description = {"description"}
        if category == "malformed_input":
            require_keys(
                vector, common | {"category", "packet", "expect_error"}, description
            )
            decode_hex(vector["packet"], f"{name}.packet")
        elif category == "malformed":
            require_keys(
                vector,
                common | {"category", "rule_id", "compressed", "expect_error"},
                description,
            )
            decode_hex(vector["compressed"], f"{name}.compressed")
        elif category == "size_boundary":
            require_keys(
                vector,
                common
                | {
                    "category",
                    "rule_id",
                    "compressed_prefix",
                    "tail_byte",
                    "tail_length",
                    "expected_packet_size",
                },
                {"expect_error", "description"},
            )
            decode_hex(vector["compressed_prefix"], f"{name}.compressed_prefix")
            for field, maximum in (
                ("tail_byte", 255),
                ("tail_length", 22554),
                ("expected_packet_size", 65535),
            ):
                value = vector[field]
                if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                    fail(f"{name}.{field} must be an integer in [0, {maximum}]")
        else:
            optional = description | ({"category"} if category == "fallback" else set())
            require_keys(
                vector,
                common | {"rule_id", "packet", "compressed"},
                optional,
            )
            packet = decode_hex(vector["packet"], f"{name}.packet")
            compressed = decode_hex(vector["compressed"], f"{name}.compressed")
            if not packet or not compressed:
                fail(f"{name}: round-trip values must be nonempty")
        if "rule_id" in vector:
            rule_id = vector["rule_id"]
            if isinstance(rule_id, bool) or not isinstance(rule_id, int) or not 0 <= rule_id <= 255:
                fail(f"{name}.rule_id must be an octet")
            rules.add(rule_id)
    missing_rules = set(range(8)) - rules
    if missing_rules or 255 not in rules:
        fail(f"canonical rule coverage missing {sorted(missing_rules | ({255} - rules))}")
    return vectors


def generate(vectors: list[dict[str, object]]) -> str:
    lines = [
        "/* Generated from test/vectors/schc_compression.json; do not edit. */",
        "#ifndef LICHEN_SCHC_PARITY_VECTORS_H",
        "#define LICHEN_SCHC_PARITY_VECTORS_H",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "enum schc_parity_kind { SCHC_PARITY_ROUND_TRIP, SCHC_PARITY_MALFORMED_INPUT,",
        "  SCHC_PARITY_MALFORMED_COMPRESSED, SCHC_PARITY_SIZE_BOUNDARY };",
        "struct schc_parity_vector { const char *name; enum schc_parity_kind kind;",
        "  const uint8_t *packet; size_t packet_len; const uint8_t *compressed;",
        "  size_t compressed_len; uint8_t tail_byte; size_t tail_len;",
        "  size_t expected_packet_size; bool expect_error; };",
    ]
    entries: list[str] = []
    for index, vector in enumerate(vectors):
        prefix = f"schc_parity_{index}"
        category = vector.get("category")
        packet = b""
        compressed = b""
        if "packet" in vector:
            packet = decode_hex(vector["packet"], f"{vector['name']}.packet")
            lines.append(c_array(f"{prefix}_packet", packet))
        if "compressed" in vector:
            compressed = decode_hex(vector["compressed"], f"{vector['name']}.compressed")
            lines.append(c_array(f"{prefix}_compressed", compressed))
        elif "compressed_prefix" in vector:
            compressed = decode_hex(
                vector["compressed_prefix"], f"{vector['name']}.compressed_prefix"
            )
            lines.append(c_array(f"{prefix}_compressed", compressed))
        packet_ptr = f"{prefix}_packet" if packet else "NULL"
        compressed_ptr = f"{prefix}_compressed" if compressed else "NULL"
        entries.append(
            "  { "
            f'"{vector["name"]}", {KINDS[category]}, '
            f"{packet_ptr}, {len(packet)}, {compressed_ptr}, {len(compressed)}, "
            f"{vector.get('tail_byte', 0)}, {vector.get('tail_length', 0)}, "
            f"{vector.get('expected_packet_size', 0)}, "
            f"{'true' if 'expect_error' in vector else 'false'} }}"
        )
    lines.append("static const struct schc_parity_vector schc_parity_vectors[] = {")
    lines.append(",\n".join(entries))
    lines.extend(["};", "#endif"])
    return "\n".join(lines) + "\n"


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} INPUT.json OUTPUT.h", file=sys.stderr)
        return 2
    vectors = load(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(generate(vectors), encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
