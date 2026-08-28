# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate a C header from the canonical L2 dispatch vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path


KINDS = {
    "schc": "LICHEN_L2_PAYLOAD_SCHC",
    "routing": "LICHEN_L2_PAYLOAD_ROUTING",
    "unknown": "LICHEN_L2_PAYLOAD_UNKNOWN",
}


def _octets(data: bytes) -> str:
    return ", ".join(f"0x{value:02x}U" for value in data)


def generate(source: Path, destination: Path) -> None:
    document = json.loads(source.read_text(encoding="utf-8"))
    vectors = document["vectors"]
    lines = [
        "/* Generated from test/vectors/l2_payload.json. Do not edit. */",
        "#ifndef LICHEN_TEST_L2_DISPATCH_VECTORS_H_",
        "#define LICHEN_TEST_L2_DISPATCH_VECTORS_H_",
        "",
        "struct l2_dispatch_vector {",
        "\tconst char *name;",
        "\tconst uint8_t *wrapped;",
        "\tsize_t wrapped_len;",
        "\tuint8_t dispatch;",
        "\tenum lichen_l2_payload_kind expected;",
        "};",
        "",
    ]
    for index, vector in enumerate(vectors):
        wrapped = bytes.fromhex(vector["wrapped"])
        body = bytes.fromhex(vector["body"])
        if not wrapped or wrapped[0] != vector["dispatch"] or wrapped[1:] != body:
            raise ValueError(f"invalid L2 vector {vector['name']!r}")
        if vector["kind"] not in KINDS:
            raise ValueError(f"invalid kind in L2 vector {vector['name']!r}")
        lines.append(f"static const uint8_t l2_dispatch_wire_{index}[] = {{{_octets(wrapped)}}};")
    lines.extend(["", "static const struct l2_dispatch_vector l2_dispatch_vectors[] = {"])
    for index, vector in enumerate(vectors):
        lines.append(
            "\t{"
            f'"{vector["name"]}", l2_dispatch_wire_{index}, '
            f"sizeof(l2_dispatch_wire_{index}), 0x{vector['dispatch']:02x}U, "
            f"{KINDS[vector['kind']]}"
            "},"
        )
    lines.extend(
        [
            "};",
            "#define L2_DISPATCH_VECTOR_COUNT \\",
            "\t(sizeof(l2_dispatch_vectors) / sizeof(l2_dispatch_vectors[0]))",
            "",
            "#endif /* LICHEN_TEST_L2_DISPATCH_VECTORS_H_ */",
            "",
        ]
    )
    destination.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py SOURCE DESTINATION")
    generate(Path(sys.argv[1]), Path(sys.argv[2]))
