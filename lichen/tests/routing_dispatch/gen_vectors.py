#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import ipaddress
import json
import sys
from pathlib import Path


def c_bytes(address: str | None) -> str:
    if address is None:
        return "{0}"
    packed = ipaddress.IPv6Address(address).packed
    return "{" + ", ".join(f"0x{octet:02x}" for octet in packed) + "}"


def main() -> None:
    source, destination = map(Path, sys.argv[1:3])
    document = json.loads(source.read_text(encoding="utf-8"))
    rows = []
    decisions = {
        "forward": "LICHEN_ROUTE_FORWARD",
        "queue": "LICHEN_ROUTE_QUEUE",
        "drop": "LICHEN_ROUTE_DROP",
    }
    for case in document["cases"]:
        rows.append(
            "\t{\n"
            f'\t\t.name = "{case["name"]}",\n'
            f"\t\t.destination = {c_bytes(case['destination'])},\n"
            f"\t\t.local_route = {'true' if case['local_route'] else 'false'},\n"
            f"\t\t.local_discovery = {'true' if case['local_discovery'] else 'false'},\n"
            f"\t\t.rpl_parent = {'true' if case['rpl_parent'] else 'false'},\n"
            f"\t\t.expected_decision = {decisions[case['expected_decision']]},\n"
            f"\t\t.expected_next_hop = {c_bytes(case['expected_next_hop'])},\n"
            "\t},"
        )
    destination.write_text(
        "/* Generated from test/vectors/route_selection.json. */\n"
        "#ifndef ROUTE_SELECTION_VECTORS_H_\n"
        "#define ROUTE_SELECTION_VECTORS_H_\n\n"
        "struct route_selection_vector {\n"
        "\tconst char *name;\n"
        "\tuint8_t destination[16];\n"
        "\tbool local_route;\n"
        "\tbool local_discovery;\n"
        "\tbool rpl_parent;\n"
        "\tenum lichen_route_decision expected_decision;\n"
        "\tuint8_t expected_next_hop[16];\n"
        "};\n\n"
        "static const struct route_selection_vector route_selection_vectors[] = {\n"
        + "\n".join(rows)
        + "\n};\n\n"
        "#define ROUTE_SELECTION_VECTOR_COUNT "
        "(sizeof(route_selection_vectors) / sizeof(route_selection_vectors[0]))\n\n"
        "#endif /* ROUTE_SELECTION_VECTORS_H_ */\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
