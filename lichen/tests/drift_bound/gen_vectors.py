#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate C fixtures from canonical CCP-7 drift and holdover vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def integer(value: Any, field: str, *, signed: bool = False) -> int:
    minimum = -(1 << 63) if signed else 0
    maximum = (1 << 63) - 1 if signed else (1 << 64) - 1
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{field} is outside the C fixture range")
    return value


def boolean(value: Any, field: str) -> str:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return "true" if value else "false"


def generate(path: Path) -> str:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("format_version") != 2 or not isinstance(
        document.get("vectors"), list
    ):
        raise ValueError("expected ccp7_holdover format_version 2")

    bounds: list[str] = []
    holdovers: list[str] = []
    ppm: list[str] = []
    for vector in document["vectors"]:
        if not isinstance(vector, dict) or not isinstance(vector.get("name"), str):
            raise ValueError("every vector requires a string name")
        name = vector["name"]
        category = vector.get("category")
        if category == "drift_bound":
            b0 = integer(vector.get("b0"), f"{name}.b0")
            rho = integer(vector.get("rho"), f"{name}.rho")
            h = integer(vector.get("h"), f"{name}.h")
            expected = integer(vector.get("expected_bound"), f"{name}.expected_bound")
            bounds.append(
                f'\t{{ "{name}", UINT64_C({b0}), UINT64_C({rho}), '
                f"UINT64_C({h}), UINT64_C({expected}) }},"
            )
        elif category == "holdover":
            measured = integer(
                vector.get("measured_drift_ppm"),
                f"{name}.measured_drift_ppm",
                signed=True,
            )
            guard = integer(vector.get("guard_ppm"), f"{name}.guard_ppm")
            expired = boolean(
                vector.get("expected_expired"), f"{name}.expected_expired"
            )
            holdovers.append(
                f'\t{{ "{name}", INT64_C({measured}), UINT32_C({guard}), {expired} }},'
            )
        elif category == "drift_ppm":
            delta = integer(vector.get("delta_ms"), f"{name}.delta_ms", signed=True)
            interval = integer(vector.get("beacon_interval_ms"), f"{name}.interval")
            expected_ppm = integer(
                vector.get("expected_ppm"), f"{name}.expected_ppm", signed=True
            )
            future = integer(
                vector.get("future_delta_ms"), f"{name}.future_delta_ms", signed=True
            )
            correction = integer(
                vector.get("expected_correction_ms"),
                f"{name}.expected_correction_ms",
                signed=True,
            )
            ppm.append(
                f'\t{{ "{name}", INT64_C({delta}), UINT64_C({interval}), '
                f"INT64_C({expected_ppm}), INT64_C({future}), INT64_C({correction}) }},"
            )
        elif category != "guard_budget":
            raise ValueError(f"{name}: unsupported category {category!r}")

    if not bounds or not holdovers or not ppm:
        raise ValueError("missing drift_bound, holdover, or drift_ppm vectors")
    return f"""/* Generated from test/vectors/ccp7_holdover.json. */
#ifndef DRIFT_BOUND_VECTORS_H_
#define DRIFT_BOUND_VECTORS_H_

#include <stdbool.h>
#include <stdint.h>

struct drift_bound_vector {{
\tconst char *name;
\tuint64_t initial_bound;
\tuint64_t rate;
\tuint64_t elapsed;
\tuint64_t expected;
}};

struct holdover_vector {{
\tconst char *name;
\tint64_t measured_ppm;
\tuint32_t guard_ppm;
\tbool expected_expired;
}};

struct drift_ppm_vector {{
\tconst char *name;
\tint64_t delta_ms;
\tuint64_t interval_ms;
\tint64_t expected_ppm;
\tint64_t future_delta_ms;
\tint64_t expected_correction_ms;
}};

static const struct drift_bound_vector drift_bound_vectors[] = {{
{chr(10).join(bounds)}
}};
static const struct holdover_vector holdover_vectors[] = {{
{chr(10).join(holdovers)}
}};
static const struct drift_ppm_vector drift_ppm_vectors[] = {{
{chr(10).join(ppm)}
}};

#define DRIFT_BOUND_VECTOR_COUNT (sizeof(drift_bound_vectors) / sizeof(drift_bound_vectors[0]))
#define HOLDOVER_VECTOR_COUNT (sizeof(holdover_vectors) / sizeof(holdover_vectors[0]))
#define DRIFT_PPM_VECTOR_COUNT (sizeof(drift_ppm_vectors) / sizeof(drift_ppm_vectors[0]))

#endif /* DRIFT_BOUND_VECTORS_H_ */
"""


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} INPUT.json OUTPUT.h", file=sys.stderr)
        return 2
    Path(sys.argv[2]).write_text(generate(Path(sys.argv[1])), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
