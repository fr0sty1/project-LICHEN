#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail a build when Zephyr ELF/archive memory usage exceeds a budget."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Sequence


SIZE_ROW = re.compile(
    r"^\s*(?P<text>\d+)\s+(?P<data>\d+)\s+(?P<bss>\d+)\s+"
    r"\d+\s+[0-9a-fA-F]+\s+(?P<name>.+?)\s*$"
)


@dataclass(frozen=True)
class MemoryUsage:
    """GNU size fields and the corresponding embedded-memory costs."""

    text: int
    data: int
    bss: int

    @property
    def flash(self) -> int:
        return self.text + self.data

    @property
    def ram(self) -> int:
        return self.data + self.bss

    def add(self, other: MemoryUsage) -> MemoryUsage:
        return MemoryUsage(
            text=self.text + other.text,
            data=self.data + other.data,
            bss=self.bss + other.bss,
        )


def parse_size_output(output: str) -> MemoryUsage:
    """Parse GNU ``size -t`` output for one ELF or archive."""

    rows: list[tuple[str, MemoryUsage]] = []
    for line in output.splitlines():
        match = SIZE_ROW.match(line)
        if match is None:
            continue
        rows.append(
            (
                match.group("name"),
                MemoryUsage(
                    text=int(match.group("text")),
                    data=int(match.group("data")),
                    bss=int(match.group("bss")),
                ),
            )
        )

    totals = [usage for name, usage in rows if name == "(TOTALS)"]
    if len(totals) == 1:
        return totals[0]
    if len(rows) == 1:
        return rows[0][1]
    if not rows:
        raise ValueError("size output contained no memory row")
    raise ValueError("multi-object size output did not contain exactly one totals row")


def measure_artifact(path: Path, size_tool: str) -> MemoryUsage:
    """Measure an ELF or archive with the target toolchain's GNU size."""

    if not path.is_file():
        raise ValueError(f"artifact does not exist: {path}")
    completed = subprocess.run(
        [size_tool, "-t", os.fspath(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ValueError(f"size failed for {path}: {detail}")
    return parse_size_output(completed.stdout)


def budget_failures(
    usage: MemoryUsage, *, flash_limit: int, ram_limit: int
) -> list[str]:
    failures: list[str] = []
    if usage.flash > flash_limit:
        failures.append(f"flash {usage.flash} exceeds {flash_limit}")
    if usage.ram > ram_limit:
        failures.append(f"ram {usage.ram} exceeds {ram_limit}")
    return failures


def _positive_int(value: str) -> int:
    parsed = int(value, 0)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("budget must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Check conservative flash=text+data and RAM=data+bss totals. "
            "Multiple archives are summed; linker garbage collection can only "
            "reduce their eventual image cost."
        )
    )
    parser.add_argument(
        "--artifact",
        action="append",
        required=True,
        type=Path,
        help="Zephyr ELF or static archive; repeat to sum component archives",
    )
    parser.add_argument(
        "--size-tool",
        default=os.environ.get("ZEPHYR_SIZE", "size"),
        help="target GNU size executable (default: ZEPHYR_SIZE or size)",
    )
    parser.add_argument(
        "--flash-limit", required=True, type=_positive_int, help="flash bytes"
    )
    parser.add_argument(
        "--ram-limit", required=True, type=_positive_int, help="RAM bytes"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    total = MemoryUsage(0, 0, 0)
    measured: list[dict[str, object]] = []
    try:
        for artifact in args.artifact:
            usage = measure_artifact(artifact, args.size_tool)
            total = total.add(usage)
            measured.append({"artifact": os.fspath(artifact), **asdict(usage)})
    except (OSError, ValueError) as error:
        print(json.dumps({"ok": False, "error": str(error)}, sort_keys=True))
        return 2

    failures = budget_failures(
        total, flash_limit=args.flash_limit, ram_limit=args.ram_limit
    )
    report = {
        "ok": not failures,
        "artifacts": measured,
        "totals": {
            **asdict(total),
            "flash": total.flash,
            "ram": total.ram,
        },
        "limits": {"flash": args.flash_limit, "ram": args.ram_limit},
        "failures": failures,
    }
    print(json.dumps(report, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
