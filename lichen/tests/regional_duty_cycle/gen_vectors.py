#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""Generate strict C fixtures from canonical duty-cycle tracking vectors."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
PROFILES = {
    "EU868": ("LICHEN_DUTY_CYCLE_REGION_EU868", 10, None),
    "US915": ("LICHEN_DUTY_CYCLE_REGION_US915", 1000, 400),
}
MAX_TRANSMISSIONS = 3


def require_int(value: Any, name: str, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= maximum
    ):
        raise ValueError(f"{name} must be an integer in [0, {maximum}]")
    return value


def c_bool(value: Any, name: str) -> str:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be boolean")
    return "true" if value else "false"


def load_vectors(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("format_version") != 2 or not isinstance(
        document.get("vectors"), list
    ):
        raise ValueError("expected duty-cycle vector document format_version 2")
    return [
        vector for vector in document["vectors"] if vector.get("category") == "tracking"
    ]


def generate(path: Path) -> str:
    rows: list[str] = []
    for vector in load_vectors(path):
        name = vector.get("name")
        profile = vector.get("profile")
        transmissions = vector.get("transmissions")
        expected = vector.get("expected")
        if not isinstance(name, str) or not name or not isinstance(profile, dict):
            raise ValueError("tracking vector requires a non-empty name and profile")
        if (
            not isinstance(transmissions, list)
            or len(transmissions) > MAX_TRANSMISSIONS
        ):
            raise ValueError(f"{name}.transmissions exceeds bounded C fixture capacity")
        if not isinstance(expected, dict):
            raise ValueError(f"{name}.expected must be an object")

        region_name = profile.get("region")
        if region_name not in PROFILES:
            raise ValueError(f"{name}.profile.region is unsupported")
        region, duty_permille, dwell = PROFILES[region_name]
        if profile.get("duty_permille") != duty_permille:
            raise ValueError(f"{name}.profile.duty_permille is not canonical")
        if profile.get("window_ms") != 3_600_000:
            raise ValueError(f"{name}.profile.window_ms is not canonical")
        if profile.get("max_dwell_time_ms") != dwell:
            raise ValueError(f"{name}.profile.max_dwell_time_ms is not canonical")

        tx_rows: list[str] = []
        for index, tx in enumerate(transmissions):
            if not isinstance(tx, dict):
                raise ValueError(f"{name}.transmissions[{index}] must be an object")
            start = require_int(tx.get("start_ms"), f"{name}.start_ms", UINT64_MAX)
            duration = require_int(
                tx.get("duration_ms"), f"{name}.duration_ms", UINT32_MAX
            )
            if duration == 0:
                raise ValueError(f"{name}.duration_ms must be positive")
            tx_rows.append(f"{{ UINT64_C({start}), UINT32_C({duration}) }}")
        tx_rows.extend("{ 0, 0 }" for _ in range(MAX_TRANSMISSIONS - len(tx_rows)))

        query = require_int(vector.get("query_ms"), f"{name}.query_ms", UINT64_MAX)
        proposed = require_int(
            vector.get("proposed_duration_ms"),
            f"{name}.proposed_duration_ms",
            UINT32_MAX,
        )
        used = require_int(expected.get("used_ms"), f"{name}.used_ms", UINT32_MAX)
        remaining = require_int(
            expected.get("remaining_ms"), f"{name}.remaining_ms", UINT32_MAX
        )
        usage = require_int(
            expected.get("usage_permille"), f"{name}.usage_permille", 1000
        )
        can_transmit = c_bool(expected.get("can_transmit"), f"{name}.can_transmit")
        dwell_value = 0 if dwell is None else dwell
        rows.append(
            "\n".join(
                [
                    "\t{",
                    f'\t\t.name = "{name}",',
                    f"\t\t.region = {region},",
                    f"\t\t.duty_permille = UINT16_C({duty_permille}),",
                    f"\t\t.max_dwell_time_ms = UINT32_C({dwell_value}),",
                    f"\t\t.has_dwell_time = {'false' if dwell is None else 'true'},",
                    f"\t\t.tx_count = {len(transmissions)}u,",
                    f"\t\t.transmissions = {{ {', '.join(tx_rows)} }},",
                    f"\t\t.query_ms = UINT64_C({query}),",
                    f"\t\t.proposed_duration_ms = UINT32_C({proposed}),",
                    f"\t\t.expected_used_ms = UINT32_C({used}),",
                    f"\t\t.expected_remaining_ms = UINT32_C({remaining}),",
                    f"\t\t.expected_usage_permille = UINT16_C({usage}),",
                    f"\t\t.expected_can_transmit = {can_transmit},",
                    "\t},",
                ]
            )
        )

    if not rows:
        raise ValueError("no tracking vectors found")
    return f"""/* Generated from test/vectors/duty_cycle_calculation.json. */
#ifndef DUTY_CYCLE_VECTORS_H_
#define DUTY_CYCLE_VECTORS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <lichen/duty_cycle.h>

struct duty_cycle_tx_vector {{
\tuint64_t start_ms;
\tuint32_t duration_ms;
}};

struct duty_cycle_tracking_vector {{
\tconst char *name;
\tenum lichen_duty_cycle_region region;
\tuint16_t duty_permille;
\tuint32_t max_dwell_time_ms;
\tbool has_dwell_time;
\tsize_t tx_count;
\tstruct duty_cycle_tx_vector transmissions[{MAX_TRANSMISSIONS}];
\tuint64_t query_ms;
\tuint32_t proposed_duration_ms;
\tuint32_t expected_used_ms;
\tuint32_t expected_remaining_ms;
\tuint16_t expected_usage_permille;
\tbool expected_can_transmit;
}};

static const struct duty_cycle_tracking_vector duty_cycle_tracking_vectors[] = {{
{chr(10).join(rows)}
}};

#define DUTY_CYCLE_TRACKING_VECTOR_COUNT \\
\t(sizeof(duty_cycle_tracking_vectors) / sizeof(duty_cycle_tracking_vectors[0]))

#endif /* DUTY_CYCLE_VECTORS_H_ */
"""


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {Path(sys.argv[0]).name} INPUT.json OUTPUT.h", file=sys.stderr)
        return 2
    output = Path(sys.argv[2])
    output.write_text(generate(Path(sys.argv[1])), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
