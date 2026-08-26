#!/usr/bin/env python3
# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate implementation-independent ASN/SFN wall-clock vectors."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TypedDict

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import atomic_write_json, json_bytes, read_bounded_exact  # noqa: E402

OUTPUT = VECTORS_DIR / "asn_sfn_derivation.json"
U32_MASK = (1 << 32) - 1
U64_MAX = (1 << 64) - 1


class DerivationInput(TypedDict, total=False):
    unix_time_us: int
    epoch_base_us: int
    interval_duration_us: int
    utc_label: str


class DerivationExpected(TypedDict):
    asn_u64: int
    sfn_u32: int
    clamped: bool


class DerivationVector(TypedDict):
    name: str
    description: str
    boundary: str
    timescale: str
    input: DerivationInput
    expected: DerivationExpected


class DerivationDocument(TypedDict):
    format_version: int
    name: str
    description: str
    spec: str
    vectors: list[DerivationVector]


def derive(
    unix_time_us: int,
    epoch_base_us: int,
    interval_duration_us: int,
) -> tuple[int, int, bool]:
    """Apply the literal spec arithmetic without importing LICHEN code."""
    if interval_duration_us == 0 or unix_time_us < epoch_base_us:
        return 0, 0, True
    asn = (unix_time_us - epoch_base_us) // interval_duration_us
    if not 0 <= asn <= U64_MAX:
        raise ValueError("oracle ASN is outside the unsigned 64-bit domain")
    return asn, asn & U32_MASK, False


def vector(
    name: str,
    description: str,
    boundary: str,
    unix_time_us: int,
    epoch_base_us: int,
    interval_duration_us: int,
    *,
    utc_label: str | None = None,
) -> DerivationVector:
    asn, sfn, clamped = derive(
        unix_time_us,
        epoch_base_us,
        interval_duration_us,
    )
    input_values: DerivationInput = {
        "unix_time_us": unix_time_us,
        "epoch_base_us": epoch_base_us,
        "interval_duration_us": interval_duration_us,
    }
    if utc_label is not None:
        input_values["utc_label"] = utc_label
    return {
        "name": name,
        "description": description,
        "boundary": boundary,
        "timescale": "unix_utc",
        "input": input_values,
        "expected": {
            "asn_u64": asn,
            "sfn_u32": sfn,
            "clamped": clamped,
        },
    }


def document() -> DerivationDocument:
    epoch_2024 = 1_704_067_200_000_000
    superframe_us = 2_000_000
    u32_max_time = epoch_2024 + U32_MASK * superframe_us
    return {
        "format_version": 2,
        "name": "asn_sfn_derivation",
        "description": (
            "Duration-parametric time-counter derivation from Unix UTC "
            "microseconds. With a slot duration, the unbounded quotient is an "
            "Absolute Slot Number (ASN, u64); with a superframe duration, its "
            "low 32 bits are the TDMA SFN. Recording both projections does not "
            "assert that slot and superframe durations are equal. "
            "Unix time has no distinct encoding for 23:59:60; the leap-second "
            "cases therefore pin the consecutive representable instants on "
            "either side of the 2016-12-31 leap second. Expected values come "
            "from this standalone integer-arithmetic oracle, not LICHEN code."
        ),
        "spec": "spec/09-packets-timing.md#147-tdma-superframe-number-sfn",
        "vectors": [
            vector(
                "at_epoch",
                "The configured epoch is ASN/SFN zero.",
                "epoch",
                epoch_2024,
                epoch_2024,
                superframe_us,
            ),
            vector(
                "before_epoch_clamps",
                "A wall-clock sample before the epoch cannot produce a negative ASN.",
                "epoch",
                epoch_2024 - 1,
                epoch_2024,
                superframe_us,
            ),
            vector(
                "last_microsecond_before_interval",
                "Integer division keeps the final microsecond of an interval in ASN zero.",
                "interval",
                epoch_2024 + superframe_us - 1,
                epoch_2024,
                superframe_us,
            ),
            vector(
                "first_microsecond_of_next_interval",
                "The exact interval boundary advances ASN and SFN to one.",
                "interval",
                epoch_2024 + superframe_us,
                epoch_2024,
                superframe_us,
            ),
            vector(
                "leap_2016_last_representable_second_before",
                "Unix UTC 2016-12-31T23:59:59Z is the last representable second before the leap boundary.",
                "leap_second",
                1_483_228_799_000_000,
                1_483_228_798_000_000,
                1_000_000,
                utc_label="2016-12-31T23:59:59Z",
            ),
            vector(
                "leap_2016_first_representable_second_after",
                "Unix UTC advances directly to 2017-01-01T00:00:00Z because 23:59:60 has no distinct Unix timestamp.",
                "leap_second",
                1_483_228_800_000_000,
                1_483_228_798_000_000,
                1_000_000,
                utc_label="2017-01-01T00:00:00Z",
            ),
            vector(
                "sfn_u32_max",
                "The final absolute interval before SFN epoch rollover maps to 0xffffffff.",
                "epoch_rollover",
                u32_max_time,
                epoch_2024,
                superframe_us,
            ),
            vector(
                "sfn_u32_rollover",
                "Absolute interval 2^32 is the SFN epoch rollover to wire value zero.",
                "epoch_rollover",
                u32_max_time + superframe_us,
                epoch_2024,
                superframe_us,
            ),
            vector(
                "sfn_u32_after_rollover",
                "The interval after SFN epoch rollover maps to one while the u64 count remains monotonic.",
                "epoch_rollover",
                u32_max_time + 2 * superframe_us,
                epoch_2024,
                superframe_us,
            ),
            vector(
                "asn_u64_max",
                "Unit-duration derivation reaches the maximum unsigned 64-bit ASN exactly.",
                "u64",
                U64_MAX,
                0,
                1,
            ),
            vector(
                "timestamps_near_u64_max",
                "Subtraction before division remains defined when both timestamps are near u64 max.",
                "u64",
                U64_MAX,
                U64_MAX - 10_000,
                1_000,
            ),
            vector(
                "zero_duration_clamps",
                "A zero interval duration is invalid and deterministically clamps to zero instead of dividing.",
                "invalid_config",
                epoch_2024 + 1,
                epoch_2024,
                0,
            ),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare canonical output byte-for-byte without writing",
    )
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        action = "Checked"
    else:
        atomic_write_json(OUTPUT, generated)
        action = "Wrote"
    print(f"{action} {len(generated['vectors'])} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
