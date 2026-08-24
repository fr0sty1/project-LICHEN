#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate golden_lollipop_sweep.txt for the exhaustive lollipop sweep.

The output is the 256x256 relation matrix (rows = incoming, columns =
current, chars E/N/S/I) derived ONLY from this independent transcription
of the oracle rust/lichen-rpl/src/routing.rs seq_is_newer() (lines 63-89)
and RFC 6550 Section 7.2 rule 3. It is never taken from the C code under
test.

Usage:
    python3 gen_golden_sweep.py > golden_lollipop_sweep.txt
"""

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


def relation(incoming: int, current: int) -> str:
    """Four-way classification; STALE iff the current value is newer."""
    if incoming == current:
        return "E"
    if seq_is_newer(incoming, current):
        return "N"
    if seq_is_newer(current, incoming):
        return "S"
    return "I"


def main() -> None:
    counts = {"E": 0, "N": 0, "S": 0, "I": 0}
    for incoming in range(256):
        row = "".join(relation(incoming, current) for current in range(256))
        for ch in row:
            counts[ch] += 1
        print(row)
    import sys

    print(f"counts: {counts} (sum {sum(counts.values())})", file=sys.stderr)


if __name__ == "__main__":
    main()
