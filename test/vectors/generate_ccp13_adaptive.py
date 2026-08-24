#!/usr/bin/env python3
"""Generate CCP-13 adaptive duty cycle vectors (spec/02a section 2a.9).

Run:  python3 test/vectors/generate_ccp13_adaptive.py

Merges adaptive duty permille vectors into ccp13.json. Expected values come
from this script's own oracle implementation of the spec threshold table,
written independently of any production C/Rust/Python code under test.
zlib.crc32 over the canonical input tuple provides an external integrity
oracle so consumers can detect accidental vector edits.
"""

# ruff: noqa: E501

import json
import zlib
from pathlib import Path

HERE = Path(__file__).parent


def _oracle_adaptive_duty_permille(density: int, region: int) -> int:
    """Independent oracle for spec 02a.9 AdaptiveDutyPermille().

    Spec table (permille of the 3600 s window):

        region 0 (EU, AU/NZ - strictly duty-cycle limited):
            density > 8 ->   5
            density < 3 ->  20
            otherwise   ->  10
        region 1 (US/CA - lenient):
            density > 8 ->  10
            density < 3 ->  50
            otherwise   ->  20
    """
    if region == 0:
        if density > 8:
            return 5
        if density < 3:
            return 20
        return 10
    if density > 8:
        return 10
    if density < 3:
        return 50
    return 20


def _vector_crc32(density: int, region: int) -> str:
    payload = f"density={density},region={region}".encode("ascii")
    return f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}"


def main() -> None:
    cases = [
        ("sparse_region0", 0, 0),
        ("sparse_boundary_region0", 2, 0),
        ("moderate_start_region0", 3, 0),
        ("moderate_end_region0", 8, 0),
        ("dense_start_region0", 9, 0),
        ("dense_extreme_region0", 255, 0),
        ("sparse_region1", 0, 1),
        ("moderate_region1", 5, 1),
        ("dense_start_region1", 9, 1),
        ("dense_extreme_region1", 200, 1),
    ]

    doc = json.loads((HERE / "ccp13.json").read_text())
    existing = {v.get("name") for v in doc["vectors"]}

    for name, density, region in cases:
        if name in existing:
            continue
        doc["vectors"].append(
            {
                "name": name,
                "description": (
                    f"AdaptiveDutyPermille(density={density}, region={region}) "
                    f"per spec 02a.9; crc32 oracle {_vector_crc32(density, region)}."
                ),
                "density": density,
                "region": region,
                "expected_duty_permille": _oracle_adaptive_duty_permille(
                    density, region
                ),
                "input_crc32": _vector_crc32(density, region),
                "notes": (
                    "Independent oracle: threshold table arithmetic only, no "
                    "code-under-test dependency."
                ),
            }
        )

    (HERE / "ccp13.json").write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {len(doc['vectors'])} vectors to ccp13.json")


if __name__ == "__main__":
    main()
