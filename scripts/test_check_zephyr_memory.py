# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the Zephyr ELF/archive memory budget gate."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_zephyr_memory import (  # noqa: E402
    MemoryUsage,
    budget_failures,
    parse_size_output,
)


def test_parse_single_elf() -> None:
    output = """\
   text    data     bss     dec     hex filename
 101000    2000   30000  133000   20788 zephyr.elf
"""
    assert parse_size_output(output) == MemoryUsage(101000, 2000, 30000)


def test_parse_archive_uses_totals_not_last_member() -> None:
    output = """\
   text data bss dec hex filename
    480    0   0 480 1e0 frame_pool.c.obj (ex link.a)
   1222    0   0 1222 4c6 tx_queue.c.obj (ex link.a)
   1702    0   0 1702 6a6 (TOTALS)
"""
    assert parse_size_output(output) == MemoryUsage(1702, 0, 0)


@pytest.mark.parametrize("output", ["", "text data bss dec hex filename"])
def test_parse_rejects_missing_measurement(output: str) -> None:
    with pytest.raises(ValueError, match="no memory row"):
        parse_size_output(output)


def test_parse_rejects_archive_without_totals() -> None:
    output = """\
1 2 3 6 6 first.o
4 5 6 15 f second.o
"""
    with pytest.raises(ValueError, match="totals row"):
        parse_size_output(output)


def test_flash_includes_initialized_data_and_ram_includes_bss() -> None:
    usage = MemoryUsage(text=100, data=20, bss=30)
    assert usage.flash == 120
    assert usage.ram == 50


def test_budget_boundary_is_inclusive() -> None:
    usage = MemoryUsage(text=100, data=20, bss=30)
    assert budget_failures(usage, flash_limit=120, ram_limit=50) == []


def test_budget_reports_each_exceeded_resource() -> None:
    usage = MemoryUsage(text=100, data=20, bss=30)
    assert budget_failures(usage, flash_limit=119, ram_limit=49) == [
        "flash 120 exceeds 119",
        "ram 50 exceeds 49",
    ]
