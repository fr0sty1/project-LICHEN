#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate golden matrices for the exhaustive lollipop sweep.

The output is the 256x256 relation matrix (rows = incoming, columns =
current, chars E/N/S/I) derived ONLY from this independent transcription
of the oracle rust/lichen-rpl/src/routing.rs seq_is_newer() (lines 63-89)
and RFC 6550 Section 7.2 rule 3. It is never taken from the C code under
test.

Usage:
    python3 gen_golden_sweep.py dao > golden_lollipop_sweep.txt
    python3 gen_golden_sweep.py dodag > golden_dodag_version_sweep.txt
"""

import argparse

SEQUENCE_WINDOW = 16


def seq_is_newer(new_seq: int, old_seq: int) -> bool:
    """Transcription of routing.rs seq_is_newer() (lines 63-89).

    Region split at 128 (LOLLIPOP_CIRCULAR_BIT in Rust; LOLLIPOP_LINEAR_BASE
    in the C port): values below are the RFC circular region [0..127], values
    at or above the linear region [128..255].
    """
    new_low = new_seq < 128   # Rust: new_seq < LOLLIPOP_CIRCULAR_BIT
    old_low = old_seq < 128   # Rust: old_seq < LOLLIPOP_CIRCULAR_BIT

    if new_low == old_low:
        # Same-region branch: u8 wrapping_sub then & 0x7F == mod-128.
        diff = (new_seq - old_seq) % 128
        return 1 <= diff <= SEQUENCE_WINDOW
    if new_low:
        # New below 128, old at/above: Rust (true, false) arm.
        # 256u16 + new - old <= SEQUENCE_WINDOW
        return 256 + new_seq - old_seq <= SEQUENCE_WINDOW
    # New at/above 128, old below: Rust (false, true) arm.
    # 256u16 + old - new > SEQUENCE_WINDOW
    return 256 + old_seq - new_seq > SEQUENCE_WINDOW


def dodag_is_newer(new_seq: int, old_seq: int) -> bool:
    """Independent RFC 6550 Section 7.2 DODAG-version transcription.

    Unlike DAO replay sequencing, rule 3.2 tests the absolute same-region
    distance before ordering.  Values more than SEQUENCE_WINDOW apart are
    therefore incomparable rather than wrapping modulo 128.
    """
    if (new_seq < 128) == (old_seq < 128):
        return abs(new_seq - old_seq) <= SEQUENCE_WINDOW and new_seq > old_seq
    if new_seq < 128:
        return 256 + new_seq - old_seq <= SEQUENCE_WINDOW
    return 256 + old_seq - new_seq > SEQUENCE_WINDOW


def relation(incoming: int, current: int, newer: object) -> str:
    """Four-way classification; STALE iff the current value is newer."""
    if incoming == current:
        return "E"
    if newer(incoming, current):
        return "N"
    if newer(current, incoming):
        return "S"
    return "I"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("dao", "dodag"), nargs="?", default="dao")
    args = parser.parse_args()
    newer = seq_is_newer if args.kind == "dao" else dodag_is_newer
    counts = {"E": 0, "N": 0, "S": 0, "I": 0}
    for incoming in range(256):
        row = "".join(relation(incoming, current, newer) for current in range(256))
        for ch in row:
            counts[ch] += 1
        print(row)
    import sys

    print(f"counts: {counts} (sum {sum(counts.values())})", file=sys.stderr)


if __name__ == "__main__":
    main()
