#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate a bounded C fixture from canonical ASN/SFN vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

U64_MAX = (1 << 64) - 1
U32_MAX = (1 << 32) - 1


def integer(value: Any, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if not 0 <= value <= maximum:
        raise ValueError(f"{field} is outside the unsigned fixture range")
    return value


def boolean(value: Any, field: str) -> str:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return "true" if value else "false"


def generate(path: Path) -> str:
    document = json.loads(path.read_text(encoding="utf-8"))
    if set(document) != {"format_version", "name", "description", "spec", "vectors"}:
        raise ValueError("unexpected ASN/SFN document fields")
    if document["format_version"] != 2 or document["name"] != "asn_sfn_derivation":
        raise ValueError("expected asn_sfn_derivation format_version 2")
    if not isinstance(document["vectors"], list) or not document["vectors"]:
        raise ValueError("vectors must be a non-empty array")

    rows: list[str] = []
    names: set[str] = set()
    for index, vector in enumerate(document["vectors"]):
        if not isinstance(vector, dict):
            raise ValueError(f"vector {index} must be an object")
        required = {"name", "description", "boundary", "timescale", "input", "expected"}
        if set(vector) != required:
            raise ValueError(f"vector {index} has missing or extra fields")
        name = vector["name"]
        if not isinstance(name, str) or not name or name in names:
            raise ValueError(f"vector {index} has an invalid/duplicate name")
        names.add(name)
        if vector["timescale"] != "unix_utc":
            raise ValueError(f"{name}.timescale must be unix_utc")
        values = vector["input"]
        expected = vector["expected"]
        if not isinstance(values, dict) or not isinstance(expected, dict):
            raise ValueError(f"{name} input/expected must be objects")
        if not {"unix_time_us", "epoch_base_us", "interval_duration_us"} <= set(values):
            raise ValueError(f"{name} input is missing arithmetic fields")
        if set(values) - {
            "unix_time_us",
            "epoch_base_us",
            "interval_duration_us",
            "utc_label",
        }:
            raise ValueError(f"{name} input has extra fields")
        if set(expected) != {"asn_u64", "sfn_u32", "clamped"}:
            raise ValueError(f"{name} expected has missing or extra fields")

        unix = integer(values["unix_time_us"], f"{name}.unix_time_us", U64_MAX)
        epoch = integer(values["epoch_base_us"], f"{name}.epoch_base_us", U64_MAX)
        duration = integer(
            values["interval_duration_us"], f"{name}.interval_duration_us", U64_MAX
        )
        asn = integer(expected["asn_u64"], f"{name}.asn_u64", U64_MAX)
        sfn = integer(expected["sfn_u32"], f"{name}.sfn_u32", U32_MAX)
        clamped = boolean(expected["clamped"], f"{name}.clamped")
        if sfn != (asn & U32_MAX):
            raise ValueError(f"{name} has inconsistent ASN/SFN projections")
        if (duration == 0 or unix < epoch) != (clamped == "true"):
            raise ValueError(f"{name} has inconsistent clamp metadata")
        rows.append(
            f'\t{{ "{name}", UINT64_C({unix}), UINT64_C({epoch}), '
            f"UINT64_C({duration}), UINT64_C({asn}), UINT32_C({sfn}), {clamped} }},"
        )

    return f"""/* Generated from test/vectors/asn_sfn_derivation.json. */
#ifndef ASN_SFN_VECTORS_H_
#define ASN_SFN_VECTORS_H_

#include <stdbool.h>
#include <stdint.h>

struct asn_sfn_vector {{
\tconst char *name;
\tuint64_t unix_time_us;
\tuint64_t epoch_base_us;
\tuint64_t interval_duration_us;
\tuint64_t expected_asn;
\tuint32_t expected_sfn;
\tbool expected_clamped;
}};

static const struct asn_sfn_vector asn_sfn_vectors[] = {{
{chr(10).join(rows)}
}};

#define ASN_SFN_VECTOR_COUNT (sizeof(asn_sfn_vectors) / sizeof(asn_sfn_vectors[0]))

#endif /* ASN_SFN_VECTORS_H_ */
"""


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} INPUT.json OUTPUT.h", file=sys.stderr)
        return 2
    Path(sys.argv[2]).write_text(generate(Path(sys.argv[1])), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
