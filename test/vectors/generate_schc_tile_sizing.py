#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate checked SCHC tile-size vectors without importing LICHEN."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)

OUTPUT = VECTORS_DIR / "schc_tile_sizing.json"
U64_MAX = (1 << 64) - 1


def _capacity(mtu_bytes: int, widths: tuple[int, ...]) -> tuple[int | None, str | None]:
    total = 0
    for width in widths:
        if total > U64_MAX - width:
            return None, "arithmetic_overflow"
        total += width
    if mtu_bytes == 0:
        return None, "invalid_mtu"
    if mtu_bytes > U64_MAX // 8:
        return None, "arithmetic_overflow"
    available = mtu_bytes * 8
    if available < total + 8:
        return None, "no_payload"
    return (available - total) // 8, None


def _vector(
    name: str,
    mtu_bytes: int,
    rule_id_bits: int,
    dtag_bits: int,
    window_bits: int,
    fcn_bits: int,
    rcs_bits: int,
) -> dict[str, object]:
    common: dict[str, object] = {
        "name": name,
        "mtu_bytes": mtu_bytes,
        "rule_id_bits": rule_id_bits,
        "dtag_bits": dtag_bits,
        "window_bits": window_bits,
        "fcn_bits": fcn_bits,
        "rcs_bits": rcs_bits,
    }
    header = (rule_id_bits, dtag_bits, window_bits, fcn_bits)
    regular, regular_error = _capacity(mtu_bytes, header)
    terminal, terminal_error = _capacity(mtu_bytes, header + (rcs_bits,))
    error = regular_error or terminal_error
    if error is not None:
        return {**common, "outcome": "error", "expected_error": error}
    assert regular is not None and terminal is not None
    return {
        **common,
        "outcome": "ok",
        "regular_all0_capacity_bytes": regular,
        "all1_capacity_bytes": terminal,
        "tile_size_bytes": min(regular, terminal),
    }


def document() -> dict[str, object]:
    """Return independently calculated field-width and MTU boundary cases."""
    cases = [
        _vector("lichen_profile_mtu_185", 185, 8, 0, 1, 6, 32),
        _vector("minimum_profile_mtu", 7, 8, 0, 1, 6, 32),
        _vector("profile_mtu_underflow", 6, 8, 0, 1, 6, 32),
        _vector("zero_mtu", 0, 8, 0, 1, 6, 32),
        _vector("maximum_lora_payload", 255, 8, 0, 1, 6, 32),
        _vector("alternate_field_widths", 50, 3, 2, 2, 3, 32),
        _vector("wide_fields_and_rcs", 100, 16, 4, 3, 5, 64),
        _vector("no_rcs_profile", 20, 8, 1, 2, 3, 0),
        _vector("maximum_safe_u64_mtu", U64_MAX // 8, 8, 0, 1, 6, 32),
        _vector("mtu_multiplication_overflow", U64_MAX, 8, 0, 1, 6, 32),
        _vector("field_sum_overflow", 185, U64_MAX, 1, 0, 0, 0),
    ]
    return {
        "$schema": "./schema.json",
        "format_version": 2,
        "description": (
            "Byte-exact SCHC fragmentation tile sizing across MTU and "
            "Rule ID/DTag/window/FCN/RCS field-width boundaries."
        ),
        "oracle": {
            "basis": "RFC 8724 Section 8 and draft-lichen-schc-lora-00 Section 5.1",
            "derivation": (
                "capacity=floor((8*MTU-(RuleID+DTag+W+FCN+RCS))/8); "
                "a fixed tile is min(regular/All-0 capacity, All-1 capacity)"
            ),
            "implementation": "Standalone checked Python integer arithmetic; no LICHEN imports",
            "generator_command": "python3 test/vectors/generate_schc_tile_sizing.py",
        },
        "vectors": cases,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    print(f"Wrote {len(generated['vectors'])} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
