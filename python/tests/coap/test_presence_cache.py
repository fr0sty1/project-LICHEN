# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the /presence/cache CoAP resource (spec 18.5.2)."""

from __future__ import annotations

import asyncio

import aiocoap
import cbor2
import pytest
from aiocoap import GET, Message

from lichen.coap.resources import PresenceCacheResource, StaticNodeInfo, build_site
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.presence import PresenceError

_NODE_A = "200::1111"
_NODE_B = "200::2222"
_T0 = 1_716_742_800.0


class _Clock:
    def __init__(self, t: float) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


async def _setup(
    time_source: float | None = None,
) -> tuple[aiocoap.Context, aiocoap.Context, PresenceCacheResource, _Clock]:
    net = InMemoryNetwork()
    clock = _Clock(time_source if time_source is not None else _T0 + 100.0)
    cache = PresenceCacheResource(time_source=clock)
    info = StaticNodeInfo(status={"rank": 256})
    site = build_site(info, presence_cache_resource=cache)
    server = await create_lichen_context(net.channel("srv"), "srv", site=site)
    client = await create_lichen_context(net.channel("cli"), "cli")
    return client, server, cache, clock


class TestPresenceCacheGet:
    async def test_empty_returns_empty_nodes_list(self) -> None:
        client, server, _, _ = await _setup()
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            assert resp.code == aiocoap.CONTENT
            assert resp.opt.content_format == 60
            assert cbor2.loads(resp.payload) == {"nodes": []}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_recorded_node_appears_with_age_s(self) -> None:
        client, server, cache, _ = await _setup(time_source=_T0 + 30.0)
        try:
            cache.record(_NODE_A, "available", ts=_T0, battery=87)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            data = cbor2.loads(resp.payload)
            assert data == {
                "nodes": [
                    {
                        "addr": _NODE_A,
                        "status": "available",
                        "battery": 87,
                        "age_s": 30,
                    }
                ]
            }
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_battery_omitted_when_not_provided(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "away", ts=_T0)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            node = cbor2.loads(resp.payload)["nodes"][0]
            assert "battery" not in node
            assert node["status"] == "away"
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_two_nodes_both_returned(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0, battery=87)
            cache.record(_NODE_B, "away", ts=_T0 + 1.0)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            addrs = {n["addr"] for n in cbor2.loads(resp.payload)["nodes"]}
            assert addrs == {_NODE_A, _NODE_B}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_record_updates_existing_entry(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0, battery=87)
            cache.record(_NODE_A, "busy", ts=_T0 + 60.0, battery=40)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            nodes = cbor2.loads(resp.payload)["nodes"]
            assert len(nodes) == 1
            assert nodes[0]["status"] == "busy"
            assert nodes[0]["battery"] == 40
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_evict_removes_peer(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0)
            cache.record(_NODE_B, "away", ts=_T0)
            cache.evict(_NODE_A)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            nodes = cbor2.loads(resp.payload)["nodes"]
            assert len(nodes) == 1
            assert nodes[0]["addr"] == _NODE_B
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_evict_missing_peer_is_noop(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.evict(_NODE_A)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            assert cbor2.loads(resp.payload) == {"nodes": []}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_purge_older_than_removes_stale(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0)
            cache.record(_NODE_B, "away", ts=_T0 + 200.0)
            evicted = cache.purge_older_than(_T0 + 100.0)
            assert evicted == 1
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            nodes = cbor2.loads(resp.payload)["nodes"]
            assert len(nodes) == 1
            assert nodes[0]["addr"] == _NODE_B
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_purge_no_stale_returns_zero(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0 + 500.0)
            assert cache.purge_older_than(_T0) == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_purge_older_than_boundary_retains_exact_match(self) -> None:
        """purge_older_than(ts) does NOT purge entries with timestamp == ts.

        The implementation uses < comparison, so entries exactly at the cutoff
        are retained.
        """
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0)
            # Cutoff equals entry's timestamp - entry should be retained
            evicted = cache.purge_older_than(_T0)
            assert evicted == 0
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            nodes = cbor2.loads(resp.payload)["nodes"]
            assert len(nodes) == 1
            assert nodes[0]["addr"] == _NODE_A
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_future_ts_capped_to_now(self) -> None:
        """Future ts is capped to now so age_s reflects hear time and purge works."""
        client, server, cache, clock = await _setup(time_source=_T0)
        try:
            # Record with ts far in the future
            cache.record(_NODE_A, "available", ts=_T0 + 9999.0)
            # age_s should be 0 (capped ts = now, so now - ts = 0)
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            node = cbor2.loads(resp.payload)["nodes"][0]
            assert node["age_s"] == 0

            # Advance clock by 60s
            clock.t = _T0 + 60.0
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            node = cbor2.loads(resp.payload)["nodes"][0]
            # age_s should now be 60, not still 0
            assert node["age_s"] == 60

            # Purge should work: cutoff = now - 30 = _T0 + 30
            # Stored ts was capped to _T0, so _T0 < _T0 + 30 -> evicted
            evicted = cache.purge_older_than(_T0 + 30.0)
            assert evicted == 1
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            assert cbor2.loads(resp.payload) == {"nodes": []}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_age_s_clamped_when_clock_goes_backwards(self) -> None:
        client, server, cache, clock = await _setup(time_source=_T0 + 30.0)
        try:
            cache.record(_NODE_A, "available", ts=_T0)
            clock.t = _T0 - 50.0
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            assert cbor2.loads(resp.payload)["nodes"][0]["age_s"] == 0
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_record_rejects_unknown_status(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            with pytest.raises(PresenceError):
                cache.record(_NODE_A, "invisible", ts=_T0)
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_not_exposed_without_resource(self) -> None:
        net = InMemoryNetwork()
        info = StaticNodeInfo(status={"rank": 1})
        site = build_site(info)
        server = await create_lichen_context(net.channel("srv"), "srv", site=site)
        client = await create_lichen_context(net.channel("cli"), "cli")
        try:
            resp = await client.request(Message(code=GET, uri="coap://srv/presence/cache")).response
            assert resp.code == aiocoap.NOT_FOUND
        finally:
            await client.shutdown()
            await server.shutdown()


class TestPresenceCacheObserve:
    async def test_observe_notified_on_record(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0)
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence/cache"))
            first = await req.response
            assert len(cbor2.loads(first.payload)["nodes"]) == 1

            obs_iter = req.observation.__aiter__()
            cache.record(_NODE_B, "away", ts=_T0 + 60.0)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            addrs = {n["addr"] for n in cbor2.loads(note.payload)["nodes"]}
            assert _NODE_B in addrs
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_evict(self) -> None:
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0)
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence/cache"))
            await req.response
            obs_iter = req.observation.__aiter__()
            cache.evict(_NODE_A)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            assert cbor2.loads(note.payload) == {"nodes": []}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_not_notified_on_identical_record(self) -> None:
        """Identical record() (same addr, status, battery, ts) does not notify."""
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0, battery=87)
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence/cache"))
            await req.response
            obs_iter = req.observation.__aiter__()

            # Re-record with identical values - should NOT notify
            cache.record(_NODE_A, "available", ts=_T0, battery=87)

            # Record a different node to trigger a notification
            cache.record(_NODE_B, "away", ts=_T0 + 60.0)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)

            # First notification should include NODE_B (the change), not be
            # an intermediate notification from the identical re-record
            addrs = {n["addr"] for n in cbor2.loads(note.payload)["nodes"]}
            assert addrs == {_NODE_A, _NODE_B}
        finally:
            await client.shutdown()
            await server.shutdown()

    async def test_observe_notified_on_changed_record(self) -> None:
        """Changed record() (different status, battery, or ts) does notify."""
        client, server, cache, _ = await _setup()
        try:
            cache.record(_NODE_A, "available", ts=_T0, battery=87)
            req = client.request(Message(code=GET, observe=0, uri="coap://srv/presence/cache"))
            await req.response
            obs_iter = req.observation.__aiter__()

            # Re-record with different status - should notify
            cache.record(_NODE_A, "busy", ts=_T0, battery=87)
            note = await asyncio.wait_for(obs_iter.__anext__(), timeout=5.0)
            node = cbor2.loads(note.payload)["nodes"][0]
            assert node["status"] == "busy"
        finally:
            await client.shutdown()
            await server.shutdown()


class TestPresenceCacheIPv6Canonicalization:
    """Tests for IPv6 address validation and canonicalization."""

    def test_record_rejects_non_ipv6_addr(self) -> None:
        """record() rejects strings that are not valid IPv6 addresses."""
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock)
        with pytest.raises(ValueError, match="valid IPv6"):
            cache.record("not-an-ip", "available", ts=_T0)

    def test_record_rejects_ipv4_addr(self) -> None:
        """record() rejects IPv4 addresses (IPv6 only)."""
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock)
        with pytest.raises(ValueError, match="valid IPv6"):
            cache.record("192.168.1.1", "available", ts=_T0)

    def test_record_rejects_empty_string(self) -> None:
        """record() rejects empty strings."""
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock)
        with pytest.raises(ValueError, match="valid IPv6"):
            cache.record("", "available", ts=_T0)

    def test_record_rejects_none_addr(self) -> None:
        """record() rejects None as address."""
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock)
        with pytest.raises(ValueError, match="must be a string"):
            cache.record(None, "available", ts=_T0)  # type: ignore[arg-type]

    def test_record_rejects_non_string_types(self) -> None:
        """record() rejects non-string types (int, list, etc.)."""
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock)
        with pytest.raises(ValueError, match="must be a string"):
            cache.record(12345, "available", ts=_T0)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="must be a string"):
            cache.record(["200::1"], "available", ts=_T0)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="must be a string"):
            cache.record({"addr": "200::1"}, "available", ts=_T0)  # type: ignore[arg-type]

    def test_equivalent_spellings_same_cache_slot(self) -> None:
        """Compressed and expanded IPv6 forms occupy the same cache slot."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock)

        # Record with compressed form (note: 0200::1111 canonicalizes to 200::1111)
        cache.record("200::1111", "available", ts=_T0, battery=87)
        assert len(cache._nodes) == 1

        # Update with expanded form - should update same entry, not create new
        cache.record("0200:0:0:0:0:0:0:1111", "busy", ts=_T0 + 60.0, battery=50)
        assert len(cache._nodes) == 1

        snap = cache.snapshot()
        assert len(snap.nodes) == 1
        assert snap.nodes[0].status == "busy"
        assert snap.nodes[0].battery == 50

    def test_case_variants_same_cache_slot(self) -> None:
        """Case variants of IPv6 address occupy the same cache slot."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock)

        cache.record("200::AAAA", "available", ts=_T0)
        cache.record("200::aaaa", "busy", ts=_T0 + 10.0)

        assert len(cache._nodes) == 1
        snap = cache.snapshot()
        assert snap.nodes[0].status == "busy"

    def test_evict_with_expanded_form_hits_compressed_entry(self) -> None:
        """evict() with expanded form removes entry recorded with compressed form."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock)

        cache.record("200::1111", "available", ts=_T0)
        assert len(cache._nodes) == 1

        # Evict using expanded spelling
        cache.evict("0200:0:0:0:0:0:0:1111")
        assert len(cache._nodes) == 0

    def test_evict_with_compressed_form_hits_expanded_entry(self) -> None:
        """evict() with compressed form removes entry recorded with expanded form."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock)

        cache.record("0200:0:0:0:0:0:0:2222", "available", ts=_T0)
        assert len(cache._nodes) == 1

        cache.evict("200::2222")
        assert len(cache._nodes) == 0

    def test_evict_rejects_invalid_ipv6(self) -> None:
        """evict() rejects invalid IPv6 addresses."""
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock)
        with pytest.raises(ValueError, match="valid IPv6"):
            cache.evict("garbage")

    def test_snapshot_returns_canonical_addr(self) -> None:
        """snapshot() returns addresses in canonical (compressed) form."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock)

        # Record with expanded form
        cache.record("0200:0:0:0:0:0:0:1111", "available", ts=_T0)

        snap = cache.snapshot()
        # Should be canonicalized to compressed form
        assert snap.nodes[0].addr == "200::1111"


class TestPresenceCacheMaxEntries:
    """Tests for bounded cache size (max_entries)."""

    def test_default_max_entries_is_100(self) -> None:
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock)
        assert cache._max_entries == 100

    def test_custom_max_entries(self) -> None:
        clock = _Clock(_T0)
        cache = PresenceCacheResource(time_source=clock, max_entries=5)
        assert cache._max_entries == 5

    def test_max_entries_zero_raises_valueerror(self) -> None:
        """max_entries=0 is rejected: cache would evict immediately."""
        clock = _Clock(_T0)
        with pytest.raises(ValueError, match="positive integer"):
            PresenceCacheResource(time_source=clock, max_entries=0)

    def test_max_entries_negative_raises_valueerror(self) -> None:
        """Negative max_entries is rejected."""
        clock = _Clock(_T0)
        with pytest.raises(ValueError, match="positive integer"):
            PresenceCacheResource(time_source=clock, max_entries=-1)

    def test_max_entries_bool_raises_valueerror(self) -> None:
        """Boolean max_entries is rejected (bool is a subclass of int)."""
        clock = _Clock(_T0)
        with pytest.raises(ValueError, match="positive integer"):
            PresenceCacheResource(time_source=clock, max_entries=True)

    def test_overflow_evicts_oldest_by_timestamp(self) -> None:
        """When cache exceeds max_entries, oldest entries (by ts) are evicted."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock, max_entries=3)

        # Insert 3 nodes with different timestamps
        cache.record("200::1", "available", ts=_T0 + 10.0)
        cache.record("200::2", "available", ts=_T0 + 30.0)
        cache.record("200::3", "available", ts=_T0 + 20.0)
        assert len(cache._nodes) == 3

        # Insert a 4th node - oldest (ts=_T0+10) should be evicted
        cache.record("200::4", "available", ts=_T0 + 40.0)
        assert len(cache._nodes) == 3
        assert "200::1" not in cache._nodes
        assert "200::2" in cache._nodes
        assert "200::3" in cache._nodes
        assert "200::4" in cache._nodes

    def test_overflow_evicts_multiple_if_needed(self) -> None:
        """Multiple oldest entries are evicted if multiple exceed the cap."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock, max_entries=2)

        cache.record("200::1", "available", ts=_T0 + 10.0)
        cache.record("200::2", "available", ts=_T0 + 20.0)
        cache.record("200::3", "available", ts=_T0 + 30.0)

        # Should have evicted the oldest, leaving 2
        assert len(cache._nodes) == 2
        assert "200::1" not in cache._nodes

    def test_update_existing_entry_does_not_trigger_eviction(self) -> None:
        """Updating an existing entry does not increase count, no eviction."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock, max_entries=2)

        cache.record("200::1", "available", ts=_T0 + 10.0)
        cache.record("200::2", "away", ts=_T0 + 20.0)
        assert len(cache._nodes) == 2

        # Update existing entry - should not evict
        cache.record("200::1", "busy", ts=_T0 + 50.0)
        assert len(cache._nodes) == 2
        assert cache._nodes["200::1"]["status"] == "busy"
        assert "200::2" in cache._nodes

    def test_snapshot_bounded_by_max_entries(self) -> None:
        """Snapshot returns at most max_entries nodes."""
        clock = _Clock(_T0 + 100.0)
        cache = PresenceCacheResource(time_source=clock, max_entries=3)

        for i in range(10):
            cache.record(f"200::{i}", "available", ts=_T0 + float(i))

        snap = cache.snapshot()
        assert len(snap.nodes) == 3
        # Should have the 3 newest (highest ts)
        addrs = {n.addr for n in snap.nodes}
        assert addrs == {"200::7", "200::8", "200::9"}
