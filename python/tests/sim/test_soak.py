# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Long-duration stability soak tests (bead g3sz).

These tests verify system stability under extended simulated time:
- Memory bounds: gradient table size stays bounded
- Sequence numbers: monotonic, no wrap issues
- Route expiry: stale entries removed correctly
- Trickle timer: intervals don't drift over time

Run with:
    pytest tests/sim/test_soak.py -v --timeout=300
    LICHEN_SOAK_FAST=1 pytest tests/sim/test_soak.py -v  # Quick validation

Times are simulated (not wall clock), so 24h tests complete in seconds.
"""

from __future__ import annotations

import os
from ipaddress import IPv6Address

import pytest

from lichen.gradient import (
    GRADIENT_TIMEOUT_MS,
    MAX_ENTRIES,
    SEQ_BITS,
    GradientEntry,
    GradientSource,
    GradientTable,
    SeqNum,
)
from lichen.rpl.trickle import TrickleTimer
from lichen.sim.simulation import Simulation, TimeMode

# Simulated time constants (microseconds)
US_PER_MS = 1_000
US_PER_SEC = 1_000_000
US_PER_MIN = 60 * US_PER_SEC
US_PER_HOUR = 60 * US_PER_MIN

# Test durations in simulated hours
SOAK_DURATIONS_HOURS = [1, 6, 24]

# For fast CI runs, use shorter durations
if os.environ.get("LICHEN_SOAK_FAST"):
    SOAK_DURATIONS_HOURS = [1]


def _make_ipv6(suffix: int) -> IPv6Address:
    """Create a link-local IPv6 address from an integer suffix."""
    return IPv6Address(f"fe80::{suffix:x}")


class TestGradientTableMemoryBounds:
    """Verify gradient table memory stays bounded over long durations."""

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_table_size_bounded_under_churn(self, duration_hours: int) -> None:
        """Gradient table respects max_entries under continuous route churn.

        Simulates a mesh where routes are constantly added and updated.
        The table must never exceed its configured maximum size.
        """
        table = GradientTable(max_entries=MAX_ENTRIES)
        duration_ms = duration_hours * 60 * 60 * 1000  # Convert to ms

        # Simulate route updates every 10 seconds
        update_interval_ms = 10_000
        steps = duration_ms // update_interval_ms

        max_observed_size = 0
        route_counter = 0

        for step in range(steps):
            now_ms = step * update_interval_ms

            # Add new routes (more than max_entries to force eviction)
            for _ in range(3):
                dest = _make_ipv6(route_counter % (MAX_ENTRIES * 2))
                next_hop = _make_ipv6(0x1000 + route_counter % 10)
                entry = GradientEntry(
                    destination=dest,
                    next_hop=next_hop,
                    hop_count=route_counter % 5 + 1,
                    seq_num=route_counter % (1 << SEQ_BITS),
                    source=GradientSource.ANNOUNCE,
                    expires=now_ms + GRADIENT_TIMEOUT_MS,
                )
                table.update(entry, now=now_ms)
                route_counter += 1

            # Expire old routes periodically
            if step % 100 == 0:
                table.expire_old(now_ms)

            max_observed_size = max(max_observed_size, len(table))

            # Assert invariant holds at every step
            assert len(table) <= MAX_ENTRIES, (
                f"Table exceeded max at step {step}: {len(table)} > {MAX_ENTRIES}"
            )

        # Final assertions
        assert max_observed_size <= MAX_ENTRIES
        assert len(table) <= MAX_ENTRIES

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_expired_routes_are_cleaned(self, duration_hours: int) -> None:
        """Routes expire correctly over long durations.

        After GRADIENT_TIMEOUT_MS, routes should be eligible for expiration.
        """
        table = GradientTable(max_entries=MAX_ENTRIES)
        duration_ms = duration_hours * 60 * 60 * 1000

        # Add routes at time 0
        num_routes = 20
        for i in range(num_routes):
            entry = GradientEntry(
                destination=_make_ipv6(i),
                next_hop=_make_ipv6(0x1000),
                hop_count=1,
                seq_num=i,
                source=GradientSource.ANNOUNCE,
                expires=GRADIENT_TIMEOUT_MS,  # Expire at exactly GRADIENT_TIMEOUT_MS
            )
            table.update(entry, now=0)

        assert len(table) == num_routes

        # Advance time past expiration
        expired_count = table.expire_old(GRADIENT_TIMEOUT_MS + 1)
        assert expired_count == num_routes, f"Expected {num_routes} expired, got {expired_count}"
        assert len(table) == 0

        # Continue simulation to verify no ghost entries reappear
        check_points = [duration_ms // 4, duration_ms // 2, duration_ms]
        for check_time in check_points:
            expired = table.expire_old(check_time)
            assert expired == 0, f"Ghost entries at time {check_time}"
            assert len(table) == 0


class TestSequenceNumberProgression:
    """Verify sequence number handling at boundaries."""

    def test_seqnum_rfc1982_comparison(self) -> None:
        """SeqNum comparison follows RFC 1982 serial number arithmetic."""
        # Basic ordering
        assert SeqNum(0) < SeqNum(1)
        assert SeqNum(100) < SeqNum(200)

        # Wraparound: 65535 should be less than 0 when close
        # RFC 1982: a < b iff (b - a) mod 2^N < 2^(N-1)
        assert SeqNum(65535) < SeqNum(100)  # 65535 is "older" than 100 after wrap
        assert SeqNum(65500) < SeqNum(50)   # Similar wrap case

        # Large gaps: comparison becomes undefined per RFC 1982
        # but our implementation should not crash
        seq_mid = SeqNum(32768)
        seq_zero = SeqNum(0)
        # Just verify no exception
        _ = seq_mid < seq_zero
        _ = seq_zero < seq_mid

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_sequence_progression_no_issues_at_wrap(self, duration_hours: int) -> None:
        """Sequence numbers progress correctly through 2^16 wraparound.

        The gradient table uses 16-bit sequence numbers. Over long durations,
        nodes may wrap their sequence counters multiple times. The table must
        handle this correctly.
        """
        table = GradientTable(max_entries=MAX_ENTRIES)
        dest = _make_ipv6(1)
        next_hop = _make_ipv6(2)

        duration_ms = duration_hours * 60 * 60 * 1000
        update_interval_ms = 1000  # Update every second
        steps = duration_ms // update_interval_ms

        # Track sequence numbers to detect unexpected behavior
        updates_accepted = 0

        for step in range(steps):
            now_ms = step * update_interval_ms
            seq = step % (1 << SEQ_BITS)

            entry = GradientEntry(
                destination=dest,
                next_hop=next_hop,
                hop_count=1,
                seq_num=seq,
                source=GradientSource.ANNOUNCE,
                expires=now_ms + GRADIENT_TIMEOUT_MS,
            )

            accepted = table.update(entry, now=now_ms)
            if accepted:
                updates_accepted += 1

            # Verify no crash or corruption
            existing = table.lookup(dest, now=now_ms)
            if existing is not None:
                assert 0 <= existing.seq_num < (1 << SEQ_BITS)

        # Should have accepted updates (exact count depends on RFC 1982 logic)
        assert updates_accepted > 0
        assert len(table) <= MAX_ENTRIES

    def test_seq_wrap_at_boundary(self) -> None:
        """Test exact behavior at 2^16-1 to 0 transition."""
        table = GradientTable(max_entries=MAX_ENTRIES)
        dest = _make_ipv6(1)
        next_hop = _make_ipv6(2)

        # Insert with high sequence number
        entry_high = GradientEntry(
            destination=dest,
            next_hop=next_hop,
            hop_count=1,
            seq_num=65530,
            source=GradientSource.ANNOUNCE,
            expires=1_000_000,
        )
        assert table.update(entry_high, now=0)

        # After time passes, a wrap to low sequence should be accepted
        # The wrap-detection heuristic in gradient.py checks:
        # - existing seq > 49152 (3/4 of range)
        # - new seq < 16384 (1/4 of range)
        # - entry aged at least 50% of TTL
        entry_wrap = GradientEntry(
            destination=dest,
            next_hop=next_hop,
            hop_count=1,
            seq_num=10,  # Low seq after wrap
            source=GradientSource.ANNOUNCE,
            expires=1_000_000,
        )

        # After 50% of TTL (300_000 ms), wrap should be detected
        now_after_aging = GRADIENT_TIMEOUT_MS // 2 + 1
        accepted = table.update(entry_wrap, now=now_after_aging)

        # The wrap heuristic should accept this
        assert accepted, "Wrap detection failed: new entry with wrapped seq should be accepted"

        existing = table.lookup(dest, now=now_after_aging)
        assert existing is not None
        assert existing.seq_num == 10


class TestTrickleTimerStability:
    """Verify Trickle timer behavior over long durations."""

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_trickle_interval_no_drift(self, duration_hours: int) -> None:
        """Trickle timer intervals don't drift over extended operation.

        The timer doubles until max_interval, then stays there. We verify
        that interval boundaries are calculated exactly, with no cumulative
        drift from floating-point errors.
        """
        imin_ms = 4000
        imax_doublings = 8  # max_interval = 4000 * 256 = 1_024_000 ms
        k = 10

        # Deterministic RNG for reproducibility
        timer = TrickleTimer(imin_ms, imax_doublings, k, rng=lambda: 0.5)
        timer.start(0)

        duration_ms = duration_hours * 60 * 60 * 1000
        intervals_completed = 0
        expected_max_interval = imin_ms << imax_doublings

        # Track cumulative time to detect drift
        cumulative_time_ms = 0
        last_interval_start = 0

        while cumulative_time_ms < duration_ms:
            # Process transmit event
            event_type, event_time = timer.next_event()
            assert event_type == "transmit"
            assert event_time >= cumulative_time_ms, "Transmit time went backwards"

            timer.fire_transmit()

            # Process expire event
            event_type, event_time = timer.next_event()
            assert event_type == "expire"
            assert event_time == timer.interval_end

            # Verify interval is correct
            actual_interval = timer.interval_end - last_interval_start
            if intervals_completed < imax_doublings:
                expected_interval = imin_ms << intervals_completed
            else:
                expected_interval = expected_max_interval

            assert actual_interval == expected_interval, (
                f"Interval {intervals_completed}: expected {expected_interval}, "
                f"got {actual_interval}"
            )

            # Advance to end of interval
            last_interval_start = timer.interval_end
            cumulative_time_ms = timer.interval_end
            timer.expire(cumulative_time_ms)
            intervals_completed += 1

            # After reaching max, interval should stay constant
            if intervals_completed > imax_doublings:
                assert timer.interval == expected_max_interval

        # Verify we completed a reasonable number of intervals
        # At max interval of ~17 minutes, 1 hour should have ~3-4 intervals after doubling phase
        min_expected_intervals = imax_doublings + (duration_hours * 60 // 17)
        assert intervals_completed >= min_expected_intervals, (
            f"Too few intervals completed: {intervals_completed} < {min_expected_intervals}"
        )

    def test_trickle_reset_behavior(self) -> None:
        """Trickle timer reset correctly shrinks interval to Imin."""
        imin_ms = 100
        imax_doublings = 4
        timer = TrickleTimer(imin_ms, imax_doublings, k=2, rng=lambda: 0.0)
        timer.start(0)

        # Double a few times
        for _ in range(3):
            timer.expire(timer.interval_end)

        assert timer.interval == imin_ms * 8  # 100 * 2^3 = 800

        # Reset should return to Imin
        timer.reset(now=5000)
        assert timer.interval == imin_ms
        assert timer.interval_start == 5000

    def test_trickle_counter_saturation(self) -> None:
        """Trickle timer counter saturates at max value without overflow.

        RFC 6206 requires counter not to wrap.
        """
        timer = TrickleTimer(100, 4, k=10, rng=lambda: 0.0)
        timer.start(0)

        # Set counter near max
        timer.counter = (1 << 32) - 1

        # Incrementing should saturate, not wrap
        timer.heard_consistent()
        assert timer.counter == (1 << 32) - 1

        # should_transmit must work correctly with saturated counter
        assert not timer.should_transmit()


class TestSimulationStability:
    """Verify simulation engine stability over long durations."""

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_simulation_advance_no_exceptions(self, duration_hours: int) -> None:
        """Simulation advances time without crashes or exceptions.

        Creates a simple mesh and advances simulated time, verifying no
        internal state corruption.
        """
        sim = Simulation(sim_id="soak-test", time_mode=TimeMode.BARRIER_SYNC)

        # Create a small mesh
        node_count = 5
        for i in range(node_count):
            sim.add_node(f"node-{i}", x=i * 100.0, y=0.0, z=0.0)

        duration_us = duration_hours * US_PER_HOUR
        step_us = US_PER_MIN  # Advance 1 minute at a time

        time_us = 0
        steps = 0

        while time_us < duration_us:
            time_us = min(time_us + step_us, duration_us)
            sim.advance_to(time_us)
            steps += 1

            # Verify time advanced correctly
            assert sim.current_time_us == time_us

        # Should complete without exception
        assert sim.current_time_us == duration_us
        assert steps == duration_hours * 60

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_event_queue_bounded(self, duration_hours: int) -> None:
        """Event queue size stays bounded during simulation.

        Excessive event accumulation would indicate a memory leak.
        """
        sim = Simulation(sim_id="soak-events", time_mode=TimeMode.BARRIER_SYNC)

        for i in range(3):
            sim.add_node(f"node-{i}", x=i * 100.0, y=0.0, z=0.0)

        duration_us = duration_hours * US_PER_HOUR
        step_us = US_PER_MIN * 10  # 10-minute steps
        max_queue_size = 0

        time_us = 0
        while time_us < duration_us:
            # Periodic transmissions generate events
            if time_us % (US_PER_MIN * 5) == 0:
                sim.start_transmission("node-0", b"heartbeat")

            time_us = min(time_us + step_us, duration_us)
            sim.advance_to(time_us)

            queue_size = len(sim.event_queue)
            max_queue_size = max(max_queue_size, queue_size)

            # Event queue should not grow unboundedly
            # A reasonable upper bound: pending events for all nodes
            reasonable_max = 100
            assert queue_size < reasonable_max, (
                f"Event queue grew too large: {queue_size} at time {time_us}"
            )

        # Queue should be nearly empty at end (all events processed)
        final_size = len(sim.event_queue)
        assert final_size < 10, f"Events leaked: {final_size} remaining"


class TestStaleRouteCleanup:
    """Verify stale routes are correctly removed."""

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_continuous_expire_removes_stale(self, duration_hours: int) -> None:
        """Routes are correctly expired throughout simulation.

        Adds routes with varying expiration times and verifies they are
        removed at the correct time. Uses a subset of MAX_ENTRIES to avoid
        LRU eviction interfering with expiration testing.
        """
        table = GradientTable(max_entries=MAX_ENTRIES)
        duration_ms = duration_hours * 60 * 60 * 1000

        # Add routes with staggered expiration
        # Limit to MAX_ENTRIES / 2 to avoid LRU eviction
        routes_added = 0
        routes_expired = 0
        max_routes = MAX_ENTRIES // 2

        # Add routes at the start, with staggered expiration times
        for i in range(max_routes):
            dest = _make_ipv6(i)
            # Stagger expiration times across the duration
            expire_time = GRADIENT_TIMEOUT_MS + (i * duration_ms // max_routes)
            entry = GradientEntry(
                destination=dest,
                next_hop=_make_ipv6(0x1000),
                hop_count=1,
                seq_num=i,
                source=GradientSource.ANNOUNCE,
                expires=expire_time,
            )
            table.update(entry, now=0)
            routes_added += 1

        assert len(table) == routes_added

        # Simulate time passing with periodic expiration checks
        check_interval_ms = 60 * 1000  # Check every minute
        max_check_time = duration_ms + GRADIENT_TIMEOUT_MS + 1

        for check_time in range(0, max_check_time, check_interval_ms):
            expired = table.expire_old(check_time)
            routes_expired += expired

            # Verify lookups return None for expired entries
            for dest_num in range(routes_added):
                dest = _make_ipv6(dest_num)
                result = table.lookup(dest, now=check_time)
                if result is not None:
                    assert result.expires > check_time, (
                        f"Lookup returned expired entry: expires={result.expires}, now={check_time}"
                    )

        # All routes should eventually expire
        assert routes_expired == routes_added, (
            f"Expected {routes_added} routes to expire, got {routes_expired}"
        )
        assert len(table) == 0, f"Table not empty after full expiration: {len(table)} entries"

    @pytest.mark.parametrize("duration_hours", SOAK_DURATIONS_HOURS)
    def test_continuous_churn_with_expiration(self, duration_hours: int) -> None:
        """Routes are added and expire correctly under continuous churn.

        This tests the more realistic scenario where routes are constantly
        being added and expired throughout the simulation.
        """
        table = GradientTable(max_entries=MAX_ENTRIES)
        duration_ms = duration_hours * 60 * 60 * 1000

        # Add routes every 10 minutes
        add_interval_ms = 10 * 60 * 1000
        check_interval_ms = 60 * 1000

        routes_added = 0
        routes_expired = 0

        for time_ms in range(0, duration_ms, check_interval_ms):
            # Add a new route every add_interval_ms
            if time_ms % add_interval_ms == 0:
                dest = _make_ipv6(routes_added)
                entry = GradientEntry(
                    destination=dest,
                    next_hop=_make_ipv6(0x1000),
                    hop_count=1,
                    seq_num=routes_added % (1 << SEQ_BITS),
                    source=GradientSource.ANNOUNCE,
                    expires=time_ms + GRADIENT_TIMEOUT_MS,
                )
                table.update(entry, now=time_ms)
                routes_added += 1

            # Expire old routes
            expired = table.expire_old(time_ms)
            routes_expired += expired

            # Table should never exceed max
            assert len(table) <= MAX_ENTRIES

        # Final expiration pass
        routes_expired += table.expire_old(duration_ms + GRADIENT_TIMEOUT_MS + 1)

        # Verify all routes eventually expired or were evicted
        # (with LRU eviction, some may be evicted before expiring)
        assert len(table) == 0, f"Table not empty: {len(table)} entries"

    def test_remove_via_clears_routes_through_next_hop(self) -> None:
        """remove_via removes all routes through a specific next hop."""
        table = GradientTable(max_entries=MAX_ENTRIES)
        next_hop_a = _make_ipv6(0x1000)
        next_hop_b = _make_ipv6(0x2000)

        # Add routes through two different next hops
        for i in range(10):
            entry_a = GradientEntry(
                destination=_make_ipv6(i),
                next_hop=next_hop_a,
                hop_count=1,
                seq_num=i,
                source=GradientSource.ANNOUNCE,
                expires=1_000_000,
            )
            entry_b = GradientEntry(
                destination=_make_ipv6(i + 100),
                next_hop=next_hop_b,
                hop_count=1,
                seq_num=i,
                source=GradientSource.ANNOUNCE,
                expires=1_000_000,
            )
            table.update(entry_a, now=0)
            table.update(entry_b, now=0)

        assert len(table) == 20

        # Remove routes through next_hop_a
        removed = table.remove_via(next_hop_a)
        assert len(removed) == 10
        assert len(table) == 10

        # Verify remaining routes use next_hop_b
        for entry in table.entries():
            assert entry.next_hop == next_hop_b
