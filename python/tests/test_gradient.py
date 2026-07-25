# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the unified gradient table (spec section 11)."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.gradient import (
    GradientEntry,
    GradientSource,
    GradientTable,
)

DEST = IPv6Address("fd00::100")
HOP_A = IPv6Address("fe80::a")
HOP_B = IPv6Address("fe80::b")


def _entry(
    dest=DEST, next_hop=HOP_A, hop_count=3, seq_num=1, source=GradientSource.RREP, expires=1000
):
    return GradientEntry(dest, next_hop, hop_count, seq_num, source, expires)


def test_update_and_lookup() -> None:
    table = GradientTable()
    entry = _entry()
    assert table.update(entry) is True
    assert table.lookup(DEST) is entry
    assert len(table) == 1
    assert DEST in table


def test_lookup_missing_returns_none() -> None:
    assert GradientTable().lookup("fd00::dead") is None


def test_higher_priority_replaces_lower() -> None:
    table = GradientTable()
    table.update(_entry(source=GradientSource.DATA, seq_num=5))
    # An announce (high priority) replaces data even with a lower seq_num.
    announce = _entry(source=GradientSource.ANNOUNCE, seq_num=1, next_hop=HOP_B)
    assert table.update(announce) is True
    assert table.lookup(DEST).source is GradientSource.ANNOUNCE
    assert table.lookup(DEST).next_hop == HOP_B


def test_lower_priority_does_not_replace_higher() -> None:
    table = GradientTable()
    table.update(_entry(source=GradientSource.RREP, seq_num=1))
    # Fresher data (higher seq) must NOT displace a higher-priority RREP.
    assert table.update(_entry(source=GradientSource.DATA, seq_num=99)) is False
    assert table.lookup(DEST).source is GradientSource.RREP


def test_fresher_seq_num_wins_within_same_priority() -> None:
    table = GradientTable()
    table.update(_entry(source=GradientSource.RREP, seq_num=1, next_hop=HOP_A))
    assert table.update(_entry(source=GradientSource.RREP, seq_num=2, next_hop=HOP_B)) is True
    assert table.lookup(DEST).next_hop == HOP_B
    # Older seq is rejected.
    assert table.update(_entry(source=GradientSource.RREP, seq_num=1, next_hop=HOP_A)) is False


def test_lower_hop_count_wins_at_equal_priority_and_seq() -> None:
    table = GradientTable()
    table.update(_entry(seq_num=1, hop_count=5, next_hop=HOP_A))
    assert table.update(_entry(seq_num=1, hop_count=2, next_hop=HOP_B)) is True
    assert table.lookup(DEST).hop_count == 2
    # A worse (higher) hop count does not replace.
    assert table.update(_entry(seq_num=1, hop_count=9, next_hop=HOP_A)) is False


def test_expiry_via_lookup_and_expire_old() -> None:
    table = GradientTable()
    table.update(_entry(expires=1000))
    assert table.lookup(DEST, now=999) is not None
    assert table.lookup(DEST, now=1000) is None  # expires is inclusive
    assert table.expire_old(now=1000) == 1
    assert len(table) == 0


def test_expired_entry_is_replaced_regardless_of_priority() -> None:
    table = GradientTable()
    table.update(_entry(source=GradientSource.ANNOUNCE, seq_num=9, expires=1000))
    # Lower-priority data normally loses, but the announce has expired.
    data = _entry(source=GradientSource.DATA, seq_num=1, next_hop=HOP_B, expires=5000)
    assert table.update(data, now=2000) is True
    assert table.lookup(DEST, now=2000).source is GradientSource.DATA


def test_lru_eviction() -> None:
    table = GradientTable(max_entries=2)
    d1, d2, d3 = IPv6Address("fd00::1"), IPv6Address("fd00::2"), IPv6Address("fd00::3")
    table.update(_entry(dest=d1))
    table.update(_entry(dest=d2))
    # Touch d1 so d2 becomes least-recently-used.
    table.lookup(d1)
    table.update(_entry(dest=d3))
    assert d1 in table
    assert d3 in table
    assert d2 not in table  # evicted
    assert len(table) == 2


def test_remove() -> None:
    table = GradientTable()
    table.update(_entry())
    table.remove(DEST)
    assert DEST not in table


def test_invalid_capacity() -> None:
    with pytest.raises(ValueError):
        GradientTable(max_entries=0)
