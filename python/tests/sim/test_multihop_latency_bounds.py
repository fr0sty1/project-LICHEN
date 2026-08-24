# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Test B.5.4: Multi-hop latency bounds under congestion (bead 8.19.4).

Tests that end-to-end delay remains bounded under congestion load across
multi-hop mesh topologies. This validates that the protocol maintains
predictable latency even when the network is under stress.

Key assertions:
1. Latency p99 stays below a defined upper bound
2. No catastrophic latency spikes (no delivery > MAX_LATENCY_US)
3. Per-hop latency remains bounded by HOP_LATENCY_BUDGET_US

Test methodology:
- Create multi-hop line/mesh topologies
- Inject congestion via concurrent transmissions from multiple nodes
- Measure per-hop latency during relay operations
- Verify latency bounds hold under load

The radio is readable while a TX is in-flight and gone after TxEndEvent, so
non-delayed hops are polled at medium-airtime-1 µs. That poll time is not the
latency oracle: each sample is floored against the independent Semtech formula
in lichen.timing.airtime.airtime_us_with_params (not lora_medium.airtime_us).
LatencyRule hops are probed at airtime-1 (must miss) then at end+added_us.
None after CATASTROPHIC_LATENCY_US is a bound failure, not a skip. A dedicated
injected-delay test makes CATASTROPHIC fire on an observed sample.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

import pytest

from lichen.timing.airtime import airtime_us_with_params

# Simulator imports are optional - only needed when lora_medium Rust extension is built.
# Import lazily to allow CI to collect (and skip) these tests without the native module.
if TYPE_CHECKING:
    from lichen.sim import ChaosEngine, DegradeRule, LatencyRule
    from lichen.sim.simulation import Simulation

# Check if simulator is available (requires lora_medium Rust extension)
try:
    from lora_medium import airtime_us as medium_airtime_us

    from lichen.sim import ChaosEngine, DegradeRule, LatencyRule
    from lichen.sim.simulation import Simulation, TimeMode

    HAS_SIMULATOR = True
except ImportError:
    HAS_SIMULATOR = False

    class TimeMode:  # type: ignore[no-redef]
        """Stub for when simulator is not available."""

        BARRIER_SYNC = None

    # Stubs for type checking only
    ChaosEngine = None  # type: ignore[misc, assignment]
    DegradeRule = None  # type: ignore[misc, assignment]
    LatencyRule = None  # type: ignore[misc, assignment]
    Simulation = None  # type: ignore[misc, assignment]
    medium_airtime_us = None  # type: ignore[misc, assignment]

# --- Latency budget constants (microseconds) ---

# Per-hop latency budget: 300ms max per hop (includes ~250ms TX time at SF10)
HOP_LATENCY_BUDGET_US = 300_000

# Maximum acceptable p99 latency for any single delivery
MAX_P99_LATENCY_US = 500_000  # 500ms

# Catastrophic latency threshold (no delivery should exceed this)
CATASTROPHIC_LATENCY_US = 1_000_000  # 1 second

# Minimum deliveries required for statistical validity
MIN_DELIVERIES_FOR_STATS = 10

# Chaos LatencyRule injection used by the added-delay test
CHAOS_ADDED_US = 50_000

# Distinct per-hop added delays for the consistency test (stacked on PHY airtime).
CONSISTENCY_HOP1_ADDED_US = 10_000
CONSISTENCY_HOP3_ADDED_US = 40_000

# Injected delay used to force CATASTROPHIC_LATENCY_US to fire on a real RX.
CATASTROPHIC_INJECTED_US = CATASTROPHIC_LATENCY_US + 100_000

# Independent spec floor (header-only SF10 airtime); not lora_medium.
SPEC_AIRTIME_FLOOR_US = airtime_us_with_params(0)


class LatencyResult(NamedTuple):
    """Harness-side latency summary from sim.current_time_us samples."""

    deliveries: int
    min_latency_us: int | None
    max_latency_us: int | None
    mean_latency_us: float | None
    p50_latency_us: int | None
    p95_latency_us: int | None
    p99_latency_us: int | None


def _percentile(samples: list[int], p: float) -> int:
    """Nearest-rank percentile of harness elapsed-time samples."""
    ordered = sorted(samples)
    idx = int((p / 100.0) * len(ordered))
    idx = min(idx, len(ordered) - 1)
    return ordered[idx]


def _latency_result_from_samples(samples: list[int]) -> LatencyResult:
    """Build LatencyResult from harness elapsed times (not CUT metrics)."""
    if not samples:
        return LatencyResult(0, None, None, None, None, None, None)
    return LatencyResult(
        deliveries=len(samples),
        min_latency_us=min(samples),
        max_latency_us=max(samples),
        mean_latency_us=sum(samples) / len(samples),
        p50_latency_us=_percentile(samples, 50.0),
        p95_latency_us=_percentile(samples, 95.0),
        p99_latency_us=_percentile(samples, 99.0),
    )


def _spec_airtime_us(payload_len: int) -> int:
    """Semtech SF10 airtime from spec 09-packets-timing.md, not lora_medium."""
    return airtime_us_with_params(payload_len)


def _poll_after_hop_airtime(
    sim: Simulation,
    rx_node: str,
    payload: bytes,
    tx_start_us: int,
    extra_delay_us: int = 0,
    *,
    require_rx: bool = True,
    fail_after_us: int = CATASTROPHIC_LATENCY_US,
) -> tuple[tuple[bytes, int, int] | None, int, int]:
    """Probe RX at medium airtime-1, then at LatencyRule eligibility if needed.

    Poll scheduling uses lora_medium airtime so TxEndEvent is not missed.
    The latency floor is the independent spec formula. extra_delay_us hops
    must miss at airtime-1. require_rx treats None after fail_after_us as a
    catastrophic bound failure rather than a skip.

    Returns (result, elapsed_us, spec_airtime_us).
    """
    if medium_airtime_us is None:
        raise RuntimeError("lora_medium airtime_us is required")
    medium_at = medium_airtime_us(len(payload))
    spec_at = _spec_airtime_us(len(payload))
    assert medium_at >= spec_at - 1, (
        f"lora_medium airtime {medium_at}us undercuts spec formula {spec_at}us"
    )

    early_at = tx_start_us + medium_at - 1
    sim.advance_to(early_at)
    early = sim.get_rx_result(rx_node)

    if extra_delay_us > 0:
        if early is not None:
            raise AssertionError(
                f"LatencyRule packet readable at airtime-1 "
                f"({sim.current_time_us - tx_start_us}us) before added_us={extra_delay_us}"
            )
        sim.advance_to(tx_start_us + medium_at + extra_delay_us)
        result = sim.get_rx_result(rx_node)
    else:
        result = early

    if result is None and require_rx:
        deadline = tx_start_us + fail_after_us
        if sim.current_time_us < deadline:
            sim.advance_to(deadline)
            result = sim.get_rx_result(rx_node)
        if result is None:
            elapsed = sim.current_time_us - tx_start_us
            raise AssertionError(
                f"Catastrophic latency spike: no RX at {rx_node} by {elapsed}us "
                f"> {fail_after_us}us (delay treated as loss)"
            )

    elapsed = sim.current_time_us - tx_start_us
    if result is not None:
        data, _, _ = result
        assert data == payload, f"payload mismatch: {data!r} != {payload!r}"
        floor = spec_at + extra_delay_us if extra_delay_us > 0 else spec_at - 1
        assert elapsed >= floor, (
            f"Harness elapsed {elapsed}us below spec airtime floor {floor}us "
            f"(spec={spec_at}, extra={extra_delay_us})"
        )

    tx_end = tx_start_us + medium_at
    if sim.current_time_us < tx_end:
        sim.advance_to(tx_end)
    return result, elapsed, spec_at


def _assert_harness_oracles(
    sim: Simulation,
    harness_samples: list[int],
    *,
    min_deliveries: int = MIN_DELIVERIES_FOR_STATS,
    max_hop_us: int = HOP_LATENCY_BUDGET_US,
    max_p99_us: int = MAX_P99_LATENCY_US,
    max_any_us: int = CATASTROPHIC_LATENCY_US,
    min_floor_us: int = SPEC_AIRTIME_FLOOR_US - 1,
) -> LatencyResult:
    """Assert harness elapsed times (and matching CUT stats) are in budget."""
    assert len(harness_samples) >= min_deliveries, (
        f"Insufficient deliveries: {len(harness_samples)} < {min_deliveries}"
    )
    harness = _latency_result_from_samples(harness_samples)
    stats = sim.metrics.latency_stats()

    assert harness.min_latency_us is not None and harness.min_latency_us > 0, (
        "min_us is 0 or None; test polled at TX-start instead of after airtime"
    )
    assert harness.min_latency_us >= min_floor_us, (
        f"Harness min {harness.min_latency_us}us is below spec floor {min_floor_us}us"
    )
    assert harness.max_latency_us is not None, (
        f"max_us missing despite {harness.deliveries} deliveries"
    )
    assert harness.max_latency_us <= max_hop_us, (
        f"Harness max {harness.max_latency_us}us exceeds hop budget {max_hop_us}us"
    )
    assert harness.max_latency_us <= max_any_us, (
        f"Catastrophic latency spike: {harness.max_latency_us}us > {max_any_us}us"
    )
    assert harness.p99_latency_us is not None, (
        f"p99 missing despite {harness.deliveries} deliveries"
    )
    assert harness.p99_latency_us <= max_p99_us, (
        f"Harness p99 {harness.p99_latency_us}us exceeds {max_p99_us}us"
    )

    # CUT telemetry must reproduce the harness clock, not score itself.
    assert stats.count == harness.deliveries
    assert stats.min_us == harness.min_latency_us
    assert stats.max_us == harness.max_latency_us
    assert stats.p99_us == harness.p99_latency_us
    return harness


def _assert_hop_consistency(
    per_hop: list[list[int]],
    *,
    max_ratio: float = 2.0,
    min_deliveries: int = MIN_DELIVERIES_FOR_STATS,
) -> None:
    """Hop-1 vs last-hop mean latency must stay within max_ratio."""
    assert len(per_hop) >= 2
    for hop_idx, hop_samples in enumerate(per_hop, start=1):
        assert len(hop_samples) >= min_deliveries, f"Hop {hop_idx} deliveries: {len(hop_samples)}"
        assert min(hop_samples) > 0
    mean_first = sum(per_hop[0]) / len(per_hop[0])
    mean_last = sum(per_hop[-1]) / len(per_hop[-1])
    hop_ratio = max(mean_first, mean_last) / min(mean_first, mean_last)
    last_idx = len(per_hop)
    assert hop_ratio <= max_ratio, (
        f"Hop-1 vs hop-{last_idx} mean ratio {hop_ratio:.2f} "
        f"(means {mean_first:.0f}/{mean_last:.0f})"
    )


@pytest.mark.skipif(not HAS_SIMULATOR, reason="Requires lora_medium Rust extension")
class TestMultiHopLatencyBounds:
    """Tests for multi-hop latency bounds under congestion."""

    def test_three_node_line_latency_bounded(self) -> None:
        """Three-node line topology maintains bounded per-hop latency.

        Topology: A(0m) -- B(100m) -- C(200m)
        Test: A transmits multiple packets, B relays to C.
        Verify: Per-hop latency stays within budget.
        """
        sim = Simulation(sim_id="latency-3node", time_mode=TimeMode.BARRIER_SYNC, seed=42)

        sim.add_node("a", x=0.0, y=0.0, z=0.0)
        sim.add_node("b", x=100.0, y=0.0, z=0.0)
        sim.add_node("c", x=200.0, y=0.0, z=0.0)

        samples: list[int] = []
        num_packets = 20
        for i in range(num_packets):
            payload = f"pkt-{i}".encode()
            tx_start = sim.current_time_us
            sim.start_transmission("a", payload)
            result_b, elapsed_b, _spec_b = _poll_after_hop_airtime(sim, "b", payload, tx_start)
            assert result_b is not None
            samples.append(elapsed_b)
            data, _, _ = result_b
            relay_start = sim.current_time_us
            sim.start_transmission("b", data)
            _result_c, elapsed_c, _spec_c = _poll_after_hop_airtime(sim, "c", data, relay_start)
            samples.append(elapsed_c)

        _assert_harness_oracles(sim, samples)

    def test_five_node_line_latency_bounded(self) -> None:
        """Five-node line topology maintains bounded per-hop latency.

        Topology: A(0m) -- B(75m) -- C(150m) -- D(225m) -- E(300m)
        Test: A transmits, each node relays to next.
        Verify: Per-hop latency stays within budget across all hops.
        """
        sim = Simulation(sim_id="latency-5node", time_mode=TimeMode.BARRIER_SYNC, seed=42)

        nodes = ["a", "b", "c", "d", "e"]
        for i, node_id in enumerate(nodes):
            sim.add_node(node_id, x=i * 75.0, y=0.0, z=0.0)

        samples: list[int] = []
        num_packets = 15
        for pkt_idx in range(num_packets):
            payload = f"pkt-{pkt_idx}".encode()
            current = payload
            tx_start = sim.current_time_us
            sim.start_transmission("a", current)

            for relay_idx in range(1, len(nodes)):
                result, elapsed, _spec_at = _poll_after_hop_airtime(
                    sim, nodes[relay_idx], current, tx_start
                )
                assert result is not None
                samples.append(elapsed)
                if relay_idx < len(nodes) - 1:
                    current = result[0]
                    tx_start = sim.current_time_us
                    sim.start_transmission(nodes[relay_idx], current)

        _assert_harness_oracles(sim, samples)

    def test_latency_under_concurrent_transmissions(self) -> None:
        """Latency remains bounded under concurrent TX congestion.

        Creates a congestion scenario where multiple nodes transmit
        simultaneously, causing potential collisions.
        """
        sim = Simulation(sim_id="latency-congestion", time_mode=TimeMode.BARRIER_SYNC, seed=42)

        # Overlapping coverage: B is closer to A than to C so LoRa capture
        # can deliver at B while simultaneous C TX still collides at D.
        # An equal-sided 80m square loses every packet (equal RSSI).
        sim.add_node("a", x=0.0, y=0.0, z=0.0)
        sim.add_node("b", x=30.0, y=0.0, z=0.0)
        sim.add_node("c", x=0.0, y=80.0, z=0.0)
        sim.add_node("d", x=80.0, y=80.0, z=0.0)

        samples: list[int] = []
        num_rounds = 10
        for round_idx in range(num_rounds):
            payload_a = f"a-{round_idx}".encode()
            payload_c = f"c-{round_idx}".encode()
            spec_floor = min(_spec_airtime_us(len(payload_a)), _spec_airtime_us(len(payload_c))) - 1
            medium_wait = (
                max(medium_airtime_us(len(payload_a)), medium_airtime_us(len(payload_c))) - 1
            )
            assert medium_wait >= spec_floor, (
                f"lora_medium wait {medium_wait}us undercuts spec floor {spec_floor}us"
            )
            tx_start = sim.current_time_us
            sim.start_transmission("a", payload_a)
            sim.start_transmission("c", payload_c)
            sim.advance_to(tx_start + medium_wait)
            for rx_node in ("b", "d"):
                result = sim.get_rx_result(rx_node)
                if result:
                    elapsed = sim.current_time_us - tx_start
                    assert elapsed >= spec_floor
                    assert result[0] in (payload_a, payload_c)
                    samples.append(elapsed)
            sim.advance_to(tx_start + medium_wait + 1)

        _assert_harness_oracles(sim, samples)

    def test_latency_consistent_across_hops(self) -> None:
        """Per-hop latency remains consistent regardless of hop position.

        Verifies that being hop 1 vs hop 4 in a chain doesn't affect
        the per-hop latency (within bounds).
        """
        # Distinct per-hop LatencyRule delays so hop-1 vs hop-3 is not airtime-1
        # vs airtime-1. n1 delay applies to n0->n1 and n1->n2; n3 only to n2->n3.
        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="n1", added_us=CONSISTENCY_HOP1_ADDED_US))
        chaos.add_rule(LatencyRule(node_id="n3", added_us=CONSISTENCY_HOP3_ADDED_US))
        sim = Simulation(
            sim_id="latency-consistency",
            time_mode=TimeMode.BARRIER_SYNC,
            chaos_engine=chaos,
            seed=42,
        )

        for i in range(4):
            sim.add_node(f"n{i}", x=i * 75.0, y=0.0, z=0.0)

        hop_extra = (
            CONSISTENCY_HOP1_ADDED_US,
            CONSISTENCY_HOP1_ADDED_US,
            CONSISTENCY_HOP3_ADDED_US,
        )
        samples: list[int] = []
        per_hop: list[list[int]] = [[] for _ in range(3)]
        num_packets = 15
        for pkt_idx in range(num_packets):
            payload = f"pkt-{pkt_idx}".encode()
            current = payload
            tx_start = sim.current_time_us
            sim.start_transmission("n0", current)

            for hop in range(1, 4):
                extra = hop_extra[hop - 1]
                result, elapsed, _spec_at = _poll_after_hop_airtime(
                    sim, f"n{hop}", current, tx_start, extra_delay_us=extra
                )
                assert result is not None
                samples.append(elapsed)
                per_hop[hop - 1].append(elapsed)
                if hop < 3:
                    current = result[0]
                    tx_start = sim.current_time_us
                    sim.start_transmission(f"n{hop}", current)

        harness = _assert_harness_oracles(
            sim,
            samples,
            min_floor_us=SPEC_AIRTIME_FLOOR_US + CONSISTENCY_HOP1_ADDED_US - 1,
        )
        _assert_hop_consistency(per_hop)
        assert min(per_hop[0]) != min(per_hop[2]), (
            "hop-1 and hop-3 samples are identical; injected delays were not applied"
        )

        for hop_idx, hop_samples in enumerate(per_hop, start=1):
            assert max(hop_samples) <= HOP_LATENCY_BUDGET_US, (
                f"Hop {hop_idx} max {max(hop_samples)}us exceeds hop budget"
            )

        assert harness.min_latency_us is not None and harness.max_latency_us is not None
        assert harness.min_latency_us > 0, (
            f"min_us is 0 (max={harness.max_latency_us}us); cannot compute variance ratio"
        )
        ratio = harness.max_latency_us / harness.min_latency_us
        assert ratio <= 2.0, (
            f"Latency variance too high: min={harness.min_latency_us}us, "
            f"max={harness.max_latency_us}us, ratio={ratio:.2f}"
        )


@pytest.mark.skipif(not HAS_SIMULATOR, reason="Requires lora_medium Rust extension")
class TestMultiHopLatencyWithChaos:
    """Tests for multi-hop latency bounds with chaos injection."""

    def test_latency_bounded_with_added_delay(self) -> None:
        """Latency remains bounded even with chaos-injected delay.

        Uses ChaosEngine to add artificial latency to transmissions,
        simulating network congestion or interference.
        """
        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="relay", added_us=CHAOS_ADDED_US))

        sim = Simulation(
            sim_id="latency-chaos",
            time_mode=TimeMode.BARRIER_SYNC,
            chaos_engine=chaos,
            seed=42,
        )

        sim.add_node("src", x=0.0, y=0.0, z=0.0)
        sim.add_node("relay", x=75.0, y=0.0, z=0.0)
        sim.add_node("dst", x=150.0, y=0.0, z=0.0)

        samples: list[int] = []
        relay_samples: list[int] = []
        num_packets = 10
        for i in range(num_packets):
            payload = f"chaos-{i}".encode()
            tx_start = sim.current_time_us
            sim.start_transmission("src", payload)
            result, elapsed, _spec_at = _poll_after_hop_airtime(
                sim, "relay", payload, tx_start, extra_delay_us=CHAOS_ADDED_US
            )
            assert result is not None
            samples.append(elapsed)
            relay_samples.append(elapsed)
            relay_start = sim.current_time_us
            sim.start_transmission("relay", result[0])
            # LatencyRule matches sender or receiver, so relay's TX is
            # delayed at dst as well. Dual-probe inside the helper.
            _result_dst, elapsed_dst, _spec_dst = _poll_after_hop_airtime(
                sim, "dst", result[0], relay_start, extra_delay_us=CHAOS_ADDED_US
            )
            samples.append(elapsed_dst)

        harness = _assert_harness_oracles(
            sim,
            samples,
            max_hop_us=HOP_LATENCY_BUDGET_US + CHAOS_ADDED_US,
            min_floor_us=SPEC_AIRTIME_FLOOR_US + CHAOS_ADDED_US - 1,
        )
        assert len(relay_samples) >= MIN_DELIVERIES_FOR_STATS, (
            f"Insufficient LatencyRule deliveries: {len(relay_samples)}; "
            "polling missed delayed packets or ChaosEngine did not apply"
        )
        assert min(relay_samples) >= CHAOS_ADDED_US
        assert harness.max_latency_us is not None
        assert harness.max_latency_us >= CHAOS_ADDED_US

    def test_latency_bounded_with_degraded_signal(self) -> None:
        """Latency remains bounded with degraded signal quality.

        Uses ChaosEngine to degrade RSSI, which may affect delivery
        but should not cause unbounded latency growth.
        """
        chaos = ChaosEngine()
        chaos.add_rule(DegradeRule(node_id="dst", rssi_penalty_db=20.0))

        sim = Simulation(
            sim_id="latency-degrade",
            time_mode=TimeMode.BARRIER_SYNC,
            chaos_engine=chaos,
            seed=42,
        )

        sim.add_node("src", x=0.0, y=0.0, z=0.0)
        sim.add_node("dst", x=80.0, y=0.0, z=0.0)

        samples: list[int] = []
        num_packets = 15
        for i in range(num_packets):
            payload = f"degrade-{i}".encode()
            tx_start = sim.current_time_us
            sim.start_transmission("src", payload)
            result, elapsed, _spec_at = _poll_after_hop_airtime(
                sim, "dst", payload, tx_start, require_rx=False
            )
            if result:
                samples.append(elapsed)

        _assert_harness_oracles(sim, samples)


@pytest.mark.skipif(not HAS_SIMULATOR, reason="Requires lora_medium Rust extension")
class TestMultiHopLatencyStress:
    """Stress tests for multi-hop latency under heavy load."""

    def test_sustained_load_latency_bounded(self) -> None:
        """Latency remains bounded under sustained high load.

        Runs a longer simulation with continuous packet transmission
        to verify latency stability over time.
        """
        sim = Simulation(sim_id="latency-stress", time_mode=TimeMode.BARRIER_SYNC, seed=42)

        for i in range(5):
            sim.add_node(f"n{i}", x=i * 70.0, y=0.0, z=0.0)

        samples: list[int] = []
        num_packets = 50
        for pkt_idx in range(num_packets):
            payload = f"stress-{pkt_idx}".encode()
            current = payload
            tx_start = sim.current_time_us
            sim.start_transmission("n0", current)

            for hop in range(1, 5):
                result, elapsed, _spec_at = _poll_after_hop_airtime(
                    sim, f"n{hop}", current, tx_start
                )
                assert result is not None
                samples.append(elapsed)
                if hop < 4:
                    current = result[0]
                    tx_start = sim.current_time_us
                    sim.start_transmission(f"n{hop}", current)

        harness = _assert_harness_oracles(sim, samples, min_deliveries=20)
        assert harness.p95_latency_us is not None
        assert harness.p95_latency_us <= HOP_LATENCY_BUDGET_US, (
            f"p95 latency {harness.p95_latency_us}us exceeds budget"
        )
        assert harness.max_latency_us is not None and harness.p99_latency_us is not None
        assert harness.max_latency_us <= 2 * harness.p99_latency_us, (
            f"Max latency {harness.max_latency_us}us too high vs p99 {harness.p99_latency_us}us"
        )

    def test_bursty_traffic_latency_bounded(self) -> None:
        """Latency remains bounded under bursty traffic patterns.

        Simulates traffic bursts followed by quiet periods.
        """
        sim = Simulation(sim_id="latency-bursty", time_mode=TimeMode.BARRIER_SYNC, seed=42)

        sim.add_node("src", x=0.0, y=0.0, z=0.0)
        sim.add_node("relay", x=75.0, y=0.0, z=0.0)
        sim.add_node("dst", x=150.0, y=0.0, z=0.0)

        samples: list[int] = []
        num_bursts = 5
        packets_per_burst = 5

        for burst in range(num_bursts):
            for i in range(packets_per_burst):
                payload = f"burst{burst}-{i}".encode()
                tx_start = sim.current_time_us
                sim.start_transmission("src", payload)
                result, elapsed, _spec_at = _poll_after_hop_airtime(sim, "relay", payload, tx_start)
                assert result is not None
                samples.append(elapsed)
                relay_start = sim.current_time_us
                sim.start_transmission("relay", result[0])
                _result_dst, elapsed_dst, _spec_dst = _poll_after_hop_airtime(
                    sim, "dst", result[0], relay_start
                )
                samples.append(elapsed_dst)

            sim.advance_to(sim.current_time_us + 1_000_000)

        _assert_harness_oracles(sim, samples)


def test_hop_consistency_oracle_rejects_gt_2x_ratio() -> None:
    """Hop-1 vs hop-3 mean ratio > 2 must fail (not airtime-1 vs airtime-1)."""
    with pytest.raises(AssertionError, match="Hop-1 vs hop-3"):
        _assert_hop_consistency(
            [[100_000] * 10, [150_000] * 10, [300_000] * 10],
        )


@pytest.mark.skipif(not HAS_SIMULATOR, reason="Requires lora_medium Rust extension")
class TestCatastrophicLatencyInjection:
    """CATASTROPHIC_LATENCY_US must fire on observed delay, not only on wait."""

    def test_injected_delay_makes_catastrophic_fire(self) -> None:
        """LatencyRule > 1s is sampled as elapsed and fails the catastrophic bound."""
        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="dst", added_us=CATASTROPHIC_INJECTED_US))
        sim = Simulation(
            sim_id="latency-catastrophic",
            time_mode=TimeMode.BARRIER_SYNC,
            chaos_engine=chaos,
            seed=42,
        )
        sim.add_node("src", x=0.0, y=0.0, z=0.0)
        sim.add_node("dst", x=80.0, y=0.0, z=0.0)

        payload = b"late"
        spec_at = _spec_airtime_us(len(payload))
        tx_start = sim.current_time_us
        sim.start_transmission("src", payload)
        result, elapsed, spec_at = _poll_after_hop_airtime(
            sim,
            "dst",
            payload,
            tx_start,
            extra_delay_us=CATASTROPHIC_INJECTED_US,
            fail_after_us=CATASTROPHIC_INJECTED_US + spec_at + 1_000_000,
        )
        assert result is not None
        assert elapsed > CATASTROPHIC_LATENCY_US
        # Hop budget is raised so the catastrophic ceiling is the one that fires.
        with pytest.raises(AssertionError, match="Catastrophic latency spike"):
            _assert_harness_oracles(
                sim,
                [elapsed],
                min_deliveries=1,
                max_hop_us=elapsed + 1,
                min_floor_us=spec_at,
            )

    def test_hold_past_budget_is_bound_failure_not_skip(self) -> None:
        """A 10s hold is a CATASTROPHIC failure, not a skipped sample."""
        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="dst", added_us=10_000_000))
        sim = Simulation(
            sim_id="latency-hold",
            time_mode=TimeMode.BARRIER_SYNC,
            chaos_engine=chaos,
            seed=42,
        )
        sim.add_node("src", x=0.0, y=0.0, z=0.0)
        sim.add_node("dst", x=80.0, y=0.0, z=0.0)

        payload = b"held"
        tx_start = sim.current_time_us
        sim.start_transmission("src", payload)
        # extra_delay_us=0: poll at airtime-1 (miss), then at CATASTROPHIC (still miss).
        with pytest.raises(AssertionError, match="Catastrophic latency spike"):
            _poll_after_hop_airtime(sim, "dst", payload, tx_start)

    def test_consistency_ratio_fails_when_injected_hops_diverge(self) -> None:
        """Hop-1 vs hop-3 delays differing by more than 2x fail the ratio check."""
        hop1_added = 10_000
        hop3_added = 400_000
        chaos = ChaosEngine()
        chaos.add_rule(LatencyRule(node_id="n1", added_us=hop1_added))
        chaos.add_rule(LatencyRule(node_id="n3", added_us=hop3_added))
        sim = Simulation(
            sim_id="latency-diverge",
            time_mode=TimeMode.BARRIER_SYNC,
            chaos_engine=chaos,
            seed=42,
        )
        for i in range(4):
            sim.add_node(f"n{i}", x=i * 75.0, y=0.0, z=0.0)

        hop_extra = (hop1_added, hop1_added, hop3_added)
        per_hop: list[list[int]] = [[] for _ in range(3)]
        payload = b"div"
        current = payload
        tx_start = sim.current_time_us
        sim.start_transmission("n0", current)
        for hop in range(1, 4):
            extra = hop_extra[hop - 1]
            spec_at = _spec_airtime_us(len(current))
            result, elapsed, _got_spec = _poll_after_hop_airtime(
                sim,
                f"n{hop}",
                current,
                tx_start,
                extra_delay_us=extra,
                fail_after_us=hop3_added + spec_at + 1_000_000,
            )
            assert result is not None
            per_hop[hop - 1].append(elapsed)
            if hop < 3:
                current = result[0]
                tx_start = sim.current_time_us
                sim.start_transmission(f"n{hop}", current)

        with pytest.raises(AssertionError, match="Hop-1 vs hop-3"):
            _assert_hop_consistency(per_hop, min_deliveries=1)
