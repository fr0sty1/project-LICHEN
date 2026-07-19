#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

import json
import sys
from pathlib import Path


def expand(value):
    if isinstance(value, str):
        return bytes.fromhex(value)
    output = bytearray()
    for part in value["parts"]:
        if isinstance(part, str):
            output.extend(bytes.fromhex(part))
        else:
            output.extend(bytes.fromhex(part["repeat_byte"]) * part["count"])
    return bytes(output)


def array(name, data):
    lines = [f"static const uint8_t {name}[] = {{"]
    for offset in range(0, len(data), 16):
        values = ", ".join(f"0x{byte:02x}" for byte in data[offset : offset + 16])
        lines.append(f"\t{values},")
    lines.append("};")
    return "\n".join(lines)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: gen_vectors.py INPUT_JSON OUTPUT_H")

    document = json.loads(Path(sys.argv[1]).read_text())
    byte_rows = []
    scenario_rows = []
    fragment_rows = []
    arrays = []
    scenario_names = set()

    for vector in document["vectors"]:
        name = vector["name"]
        if name in scenario_names:
            raise ValueError(f"duplicate scenario name: {name}")
        scenario_names.add(name)
        scenario_rows.append(
            (
                name,
                vector["category"],
                vector["provenance"],
                vector.get("packet_length", 0),
                vector.get("fragment_count", len(vector.get("fragments", []))),
                vector.get("rule_id", 0),
                vector.get("attempts_before", 0),
                vector.get("expect_status"),
                vector.get("expect_error"),
                vector.get("loss", {}).get("drop_fragment"),
            )
        )

        values = []
        if "packet" in vector:
            values.append(("packet", vector["packet"]))
        if "rcs" in vector:
            values.append(("rcs", vector["rcs"]))
        if "packet_sha256" in vector:
            values.append(("packet_sha256", vector["packet_sha256"]))
        if "trigger" in vector:
            values.append(("trigger", vector["trigger"]))
        if "expected_message" in vector:
            values.append(("expected_message", vector["expected_message"]))
        if "assigned_fcns" in vector:
            values.append(("assigned_fcns", bytes(vector["assigned_fcns"])))
        values.extend(
            (key, value)
            for key, value in vector.get("loss", {}).items()
            if key != "drop_fragment"
        )
        for rule_name, controls in vector.get("controls", {}).items():
            values.extend((f"{rule_name}_{key}", value) for key, value in controls.items())
        if "wire" in vector:
            values.append(("wire", vector["wire"]))

        fragment_names = set()
        for fragment in vector.get("fragments", []):
            if fragment["name"] in fragment_names:
                raise ValueError(f"duplicate fragment name in {name}: {fragment['name']}")
            fragment_names.add(fragment["name"])
            data = expand(fragment["wire"])
            symbol = f"schc_v_{len(arrays)}"
            arrays.append(array(symbol, data))
            byte_rows.append((name, fragment["name"], symbol, len(data)))
            fragment_rows.append(
                (
                    name,
                    fragment["name"],
                    fragment["kind"],
                    fragment["window"],
                    fragment["fcn"],
                    fragment["tile_ordinal"],
                    symbol,
                    len(data),
                )
            )

        for field_name, value in values:
            data = value if isinstance(value, bytes) else expand(value)
            symbol = f"schc_v_{len(arrays)}"
            arrays.append(array(symbol, data))
            byte_rows.append((name, field_name, symbol, len(data)))

    lines = [
        "/* Generated mechanically from test/vectors/schc_fragmentation.json. */",
        "/* SPDX-License-Identifier: GPL-3.0-or-later */",
        "",
        "#ifndef LICHEN_TEST_SCHC_FRAGMENTATION_VECTORS_H_",
        "#define LICHEN_TEST_SCHC_FRAGMENTATION_VECTORS_H_",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"#define SCHC_FRAGMENT_VECTOR_SOURCE_COUNT {len(document['vectors'])}U",
        f"#define SCHC_FRAGMENT_BYTE_VECTOR_COUNT {len(byte_rows)}U",
        f"#define SCHC_FRAGMENT_FRAGMENT_VECTOR_COUNT {len(fragment_rows)}U",
        "",
        "struct schc_fragment_byte_vector {",
        "\tconst char *scenario;",
        "\tconst char *field;",
        "\tconst uint8_t *data;",
        "\tsize_t len;",
        "};",
        "",
        "struct schc_fragment_scenario_vector {",
        "\tconst char *name;",
        "\tconst char *category;",
        "\tconst char *provenance;",
        "\tsize_t packet_len;",
        "\tsize_t fragment_count;",
        "\tuint8_t rule_id;",
        "\tuint8_t attempts_before;",
        "\tconst char *expect_status;",
        "\tconst char *expect_error;",
        "\tconst char *drop_fragment;",
        "};",
        "",
        "struct schc_fragment_fragment_vector {",
        "\tconst char *scenario;",
        "\tconst char *name;",
        "\tconst char *kind;",
        "\tuint8_t window;",
        "\tuint8_t fcn;",
        "\tsize_t tile_ordinal;",
        "\tconst uint8_t *wire;",
        "\tsize_t wire_len;",
        "};",
        "",
        *arrays,
        "",
        "static const struct schc_fragment_byte_vector schc_fragment_byte_vectors[] = {",
    ]
    lines.extend(
        f"\t{{ {json.dumps(scenario)}, {json.dumps(field)}, "
        f"{symbol}, {length}U }},"
        for scenario, field, symbol, length in byte_rows
    )
    lines.extend(
        [
            "};",
            "",
            "static const struct schc_fragment_scenario_vector "
            "schc_fragment_scenarios[] = {",
        ]
    )
    lines.extend(
        "\t{ "
        f"{json.dumps(name)}, {json.dumps(category)}, {json.dumps(provenance)}, "
        f"{packet_len}U, "
        f"{fragment_count}U, {rule_id}U, {attempts_before}U, "
        f"{json.dumps(status) if status else 'NULL'}, "
        f"{json.dumps(error) if error else 'NULL'}, "
        f"{json.dumps(drop) if drop else 'NULL'}"
        " },"
        for (
            name,
            category,
            provenance,
            packet_len,
            fragment_count,
            rule_id,
            attempts_before,
            status,
            error,
            drop,
        ) in scenario_rows
    )
    lines.extend(
        [
            "};",
            "",
            "static const struct schc_fragment_fragment_vector "
            "schc_fragment_fragments[] = {",
        ]
    )
    lines.extend(
        "\t{ "
        f"{json.dumps(scenario)}, {json.dumps(name)}, {json.dumps(kind)}, "
        f"{window}U, {fcn}U, {tile_ordinal}U, {symbol}, {length}U"
        " },"
        for scenario, name, kind, window, fcn, tile_ordinal, symbol, length in fragment_rows
    )
    lines.extend(["};", "", "#endif /* LICHEN_TEST_SCHC_FRAGMENTATION_VECTORS_H_ */", ""])
    Path(sys.argv[2]).write_text("\n".join(lines))


if __name__ == "__main__":
    main()
