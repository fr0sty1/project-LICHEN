# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LOADng route cache (spec 9.6, B2.2)."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.loadng.cache import RouteCache, RouteEntry

DEST = IPv6Address("fd00::100")
HOP = IPv6Address("fe80::a")


def _entry(dest=DEST, next_hop=HOP, hop_count=2, metric=200, seq_num=1, valid_until=1000):
    return RouteEntry(dest, next_hop, hop_count, metric, seq_num, valid_until)


def test_add_and_lookup() -> None:
    cache = RouteCache()
    entry = _entry()
    cache.add(entry)
    assert cache.lookup(DEST) is entry
    assert DEST in cache
    assert len(cache) == 1


def test_lookup_missing() -> None:
    assert RouteCache().lookup("fd00::dead") is None


def test_add_replaces_existing() -> None:
    cache = RouteCache()
    cache.add(_entry(metric=200))
    cache.add(_entry(metric=50, next_hop=IPv6Address("fe80::b")))
    assert cache.lookup(DEST).metric == 50
    assert len(cache) == 1


def test_expiry_via_lookup_and_expire_old() -> None:
    cache = RouteCache()
    cache.add(_entry(valid_until=1000))
    assert cache.lookup(DEST, now=999) is not None
    assert cache.lookup(DEST, now=1000) is None  # inclusive expiry
    assert cache.expire_old(now=1000) == 1
    assert len(cache) == 0


def test_refresh_extends_validity() -> None:
    cache = RouteCache(route_timeout_ms=300_000)
    cache.add(_entry(valid_until=1000))
    assert cache.refresh(DEST, now=500) is True
    assert cache.lookup(DEST).valid_until == 500 + 300_000
    assert cache.lookup(DEST, now=100_000) is not None


def test_refresh_missing_returns_false() -> None:
    assert RouteCache().refresh("fd00::dead", now=0) is False


def test_lru_eviction() -> None:
    cache = RouteCache(max_entries=2)
    d1, d2, d3 = IPv6Address("fd00::1"), IPv6Address("fd00::2"), IPv6Address("fd00::3")
    cache.add(_entry(dest=d1))
    cache.add(_entry(dest=d2))
    cache.lookup(d1)  # touch d1 -> d2 is now LRU
    cache.add(_entry(dest=d3))
    assert d1 in cache
    assert d3 in cache
    assert d2 not in cache
    assert len(cache) == 2


def test_remove() -> None:
    cache = RouteCache()
    cache.add(_entry())
    cache.remove(DEST)
    assert DEST not in cache


def test_invalid_capacity() -> None:
    with pytest.raises(ValueError):
        RouteCache(max_entries=0)


def test_add_rejects_stale_seq_num() -> None:
    """Stale route update (older seq_num) should be rejected."""
    cache = RouteCache()
    cache.add(_entry(seq_num=100, metric=200))
    cache.add(_entry(seq_num=50, metric=50))  # stale seq, even better metric
    assert cache.lookup(DEST).seq_num == 100
    assert cache.lookup(DEST).metric == 200


def test_add_accepts_fresher_seq_num() -> None:
    """Fresher route update (newer seq_num) should be accepted."""
    cache = RouteCache()
    cache.add(_entry(seq_num=50, metric=50))
    cache.add(_entry(seq_num=100, metric=200))  # fresher seq, worse metric still accepted
    assert cache.lookup(DEST).seq_num == 100
    assert cache.lookup(DEST).metric == 200


def test_add_same_seq_better_metric() -> None:
    """Same seq_num: accept only if metric is strictly better."""
    cache = RouteCache()
    cache.add(_entry(seq_num=100, metric=200))
    cache.add(_entry(seq_num=100, metric=150))  # same seq, better metric
    assert cache.lookup(DEST).metric == 150


def test_add_same_seq_worse_metric() -> None:
    """Same seq_num: reject if metric is worse or equal."""
    cache = RouteCache()
    cache.add(_entry(seq_num=100, metric=100))
    cache.add(_entry(seq_num=100, metric=200))  # same seq, worse metric
    assert cache.lookup(DEST).metric == 100
    cache.add(_entry(seq_num=100, metric=100))  # same seq, same metric
    assert cache.lookup(DEST).metric == 100


def test_seq_num_wraparound() -> None:
    """Sequence number freshness handles 16-bit wraparound correctly.

    Uses RFC 1982 serial number arithmetic: if diff = (new - old) mod 2^16
    is in [1, 2^15), then new is fresher. Otherwise, old is fresher or equal.
    """
    cache = RouteCache()
    # seq_num 65530 exists; seq_num 5 (wrapped) is 11 positions ahead → fresher
    cache.add(_entry(seq_num=65530, metric=100))
    cache.add(_entry(seq_num=5, metric=200))  # wrapped around, fresher
    assert cache.lookup(DEST).seq_num == 5
    # Reverse: seq_num 5 exists; seq_num 65530 is 65525 positions "ahead" (>32768) → stale
    cache2 = RouteCache()
    cache2.add(_entry(seq_num=5, metric=100))
    cache2.add(_entry(seq_num=65530, metric=200))  # pre-wrap, stale relative to post-wrap 5
    assert cache2.lookup(DEST).seq_num == 5  # original kept
