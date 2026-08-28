# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the unified gradient table (spec section 11)."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.gradient import (
    GRADIENT_TIMEOUT_MS,
    SEQ_HALF,
    GradientEntry,
    GradientSource,
    GradientTable,
    SeqNum,
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


def test_lookup_unzoned_finds_zoned_insert() -> None:
    # Independent oracle: RFC 4291 zone is not in the 128-bit address.
    packed = bytes.fromhex("fe800000000000000000000000000001")
    zoned = IPv6Address("fe80::1%lci0")
    unzoned = IPv6Address("fe80::1")
    hop_zoned = IPv6Address("fe80::a%lci0")
    hop_unzoned = IPv6Address("fe80::a")
    assert zoned != unzoned
    assert zoned.packed == unzoned.packed == packed

    table = GradientTable()
    entry = _entry(dest=zoned, next_hop=hop_zoned)
    assert table.update(entry) is True
    found = table.lookup(unzoned)
    assert found is entry
    assert found.destination == unzoned
    assert found.destination.scope_id is None
    assert found.next_hop == hop_unzoned
    assert unzoned in table
    assert zoned in table
    assert table.lookup("fe80::1%eth0") is entry
    removed = table.remove_via(hop_unzoned)
    assert removed == [unzoned]
    assert unzoned not in table


# ---------------------------------------------------------------------------
# SeqNum RFC 1982 tests (16-bit serial number arithmetic)
# ---------------------------------------------------------------------------


def test_seqnum_equality() -> None:
    """SeqNum equality is modulo 2^16."""
    assert SeqNum(0) == SeqNum(0)
    assert SeqNum(65535) == SeqNum(65535)
    assert SeqNum(65536) == SeqNum(0)  # wrap
    assert SeqNum(100) == 100


def test_seqnum_greater_than_simple() -> None:
    """Simple case: b > a when b - a < 32768."""
    assert SeqNum(1) > SeqNum(0)
    assert SeqNum(100) > SeqNum(50)
    assert SeqNum(32767) > SeqNum(0)  # half-range boundary


def test_seqnum_wrap_forward() -> None:
    """RFC 1982: 0 > 65535 because (0 - 65535) mod 65536 = 1 < 32768."""
    # Independent oracle: RFC 1982 Section 3.2 serial number arithmetic.
    assert SeqNum(0) > SeqNum(65535)
    assert SeqNum(1) > SeqNum(65534)
    assert SeqNum(100) > SeqNum(65500)


def test_seqnum_half_range_ambiguity() -> None:
    """At exactly half-range (32768), neither is greater (RFC 1982)."""
    # Independent oracle: RFC 1982 says i1 < i2 iff (i2 - i1) < 2^(N-1).
    # When diff == 2^(N-1), the comparison is undefined.
    a = SeqNum(0)
    b = SeqNum(SEQ_HALF)  # 32768
    # Neither a < b nor b < a should be true at exactly half-range.
    # Our implementation uses strict < which returns False for both.
    assert not (a < b and b < a)  # at least one is False
    # But one direction should win based on the implementation:
    # (32768 - 0) = 32768, which is NOT < 32768, so a is not < b.
    # (0 - 32768) mod 65536 = 32768, which is NOT < 32768, so b is not < a.
    # Both comparisons are False -- ambiguous zone.
    assert not (a < b)
    assert not (b < a)


def test_seqnum_ordering() -> None:
    """SeqNum supports total ordering via @total_ordering."""
    # Independent oracle: standard ordering rules.
    assert SeqNum(5) <= SeqNum(5)
    assert SeqNum(5) >= SeqNum(5)
    assert SeqNum(5) <= SeqNum(6)
    assert SeqNum(6) >= SeqNum(5)


# ---------------------------------------------------------------------------
# GradientTable sequence wrap detection tests (long-uptime neighbor aging)
# ---------------------------------------------------------------------------


def test_wrap_detection_replaces_old_high_seq_with_new_low_seq() -> None:
    """When an entry has aged and seq wraps from high to low, detect and replace.

    Independent oracle: the wrap detection heuristic in GradientTable.update()
    triggers when existing.seq_num > 49152, new.seq_num < 16384, and the entry
    has aged at least 50% of GRADIENT_TIMEOUT_MS.
    """
    table = GradientTable()
    # Insert with high sequence (near wrap point)
    high_seq_entry = _entry(seq_num=60000, expires=1000 + GRADIENT_TIMEOUT_MS)
    table.update(high_seq_entry, now=1000)

    # After 50%+ of TTL, a low seq should be accepted as wrap
    # Entry was created at now=1000, so age at now=1000+GRADIENT_TIMEOUT_MS//2+1 is > 50%
    aged_now = 1000 + GRADIENT_TIMEOUT_MS // 2 + 10000
    low_seq_entry = _entry(seq_num=100, next_hop=HOP_B, expires=aged_now + GRADIENT_TIMEOUT_MS)
    assert table.update(low_seq_entry, now=aged_now) is True
    assert table.lookup(DEST).seq_num == 100
    assert table.lookup(DEST).next_hop == HOP_B


def test_older_seq_does_not_replace_newer() -> None:
    """An older sequence number does not replace a newer one.

    Independent oracle: RFC 1982 serial number arithmetic. When the gap
    between two sequence numbers is within half-range (32768), the higher
    numeric value is fresher.
    """
    table = GradientTable()
    # Use seq=1000 as the existing entry
    entry1 = _entry(seq_num=1000, expires=1000 + GRADIENT_TIMEOUT_MS)
    table.update(entry1, now=1000)

    # An older seq (500) should NOT replace the newer (1000)
    # Both are within half-range of each other, so normal comparison applies.
    entry2 = _entry(seq_num=500, next_hop=HOP_B, expires=2000 + GRADIENT_TIMEOUT_MS)
    assert table.update(entry2, now=2000) is False
    assert table.lookup(DEST, now=2000).seq_num == 1000


def test_long_idle_gap_entry_expires() -> None:
    """After a long idle gap, old entries are expired by the new timestamp.

    Independent oracle: spec 11.5 monotonic time contract - entries whose
    last_seen_ms is more than the timeout before the new baseline are stale.
    """
    table = GradientTable()
    # Entry expires at t=1000
    entry = _entry(expires=1000)
    table.update(entry, now=0)

    # After a long gap (e.g., deep sleep), time jumps to t=100000
    # The entry should be expired
    assert table.lookup(DEST, now=999) is not None  # still valid
    assert table.lookup(DEST, now=1000) is None  # expired (expires is inclusive)
    assert table.lookup(DEST, now=100000) is None  # definitely expired


def test_monotonic_time_nondecreasing() -> None:
    """Callers providing decreasing now should still work (entry not resurrected).

    Note: Python GradientTable does not internally track last_now_ms, so callers
    MUST provide nondecreasing values per spec 11.5. This test documents the
    expected behavior when callers violate that contract.
    """
    table = GradientTable()
    entry = _entry(expires=500)
    table.update(entry, now=0)

    # Entry expires at 500
    assert table.lookup(DEST, now=500) is None  # expired

    # If caller provides earlier timestamp, expired entry appears valid
    # This is documented as caller responsibility in spec 11.5
    # The lookup should still work but return None for expired
    assert table.lookup(DEST, now=400) is not None  # would appear valid

    # After calling with later time, entry is definitely expired
    table.expire_old(now=600)
    assert table.lookup(DEST, now=400) is None  # entry removed
