# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the Trickle timer (RFC 6206).

Times are integer milliseconds; the RNG is injected so transmit instants are
deterministic. With ``rng=lambda: 0.0`` the transmit time is exactly I/2 after
the interval start (the low end of [I/2, I)).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from lichen.rpl.trickle import TrickleTimer


def _timer(rng_value: float = 0.0, *, imin: int = 100, imax: int = 4, k: int = 2) -> TrickleTimer:
    return TrickleTimer(imin, imax, k, rng=lambda: rng_value)


def _canonical_trickle_vectors() -> dict[str, dict[str, Any]]:
    vector_path = Path(__file__).resolve().parents[3] / "test" / "vectors" / "packets-timing.json"
    document = cast(dict[str, Any], json.loads(vector_path.read_text()))
    vectors = cast(list[dict[str, Any]], document["vectors"])
    return {vector["name"]: vector for vector in vectors if vector["name"].startswith("trickle_")}


def test_state_machine_matches_canonical_packets_timing_vectors() -> None:
    vectors = _canonical_trickle_vectors()
    constants = vectors["trickle_constants"]
    timer = TrickleTimer(
        imin_ms=constants["Imin_ms"],
        imax_doublings=8,
        k=constants["k"],
        rng=lambda: 0.0,
    )
    assert timer.max_interval == constants["Imax_exact_ms"]

    profile = vectors["trickle_profile_math"]
    profile_timer = TrickleTimer.lichen_profile(rng=lambda: 0.0)
    profile_timer.start(0)
    for index, expected_interval in enumerate(profile["interval_sequence_ms"]):
        assert profile_timer.interval == expected_interval
        assert profile_timer.interval_start + (expected_interval + 1) // 2 <= (
            profile_timer.transmit_time
        ) < profile_timer.interval_end
        if index + 1 < len(profile["interval_sequence_ms"]):
            profile_timer.expire(profile_timer.interval_end)
    assert profile_timer.max_interval == profile["Imax_exact_ms"]
    assert profile_timer.k == profile["k"]

    for transmit_case in profile["transmit_cases"]:
        interval = transmit_case["interval_ms"]
        half = (interval + 1) // 2
        span = interval - half
        offset = transmit_case["rand_offset_ms"]
        sample_value: float = offset / span
        endpoint = TrickleTimer(
            interval,
            0,
            profile["k"],
            rng=cast(Any, lambda sample_value=sample_value: sample_value),
        )
        endpoint.start(0)
        assert endpoint.transmit_time == transmit_case["expected_transmit_offset_ms"]
        assert half <= endpoint.transmit_time < interval

    timer.start(0)
    started = vectors["trickle_interval_start"]
    assert timer.interval == started["interval"]
    assert timer.interval_start == started["interval_start"]
    assert timer.transmit_time == started["transmit_time"]
    assert timer.interval_end == started["interval_end"]

    timer.heard_consistent()
    consistent = vectors["trickle_heard_consistent"]
    assert timer.counter == consistent["counter"]
    assert timer.should_transmit() is consistent["should_transmit"]

    for _ in range(20):
        timer.heard_consistent()
    suppressed = vectors["trickle_suppressed_at_k"]
    assert timer.counter == suppressed["counter"]
    assert timer.should_transmit() is suppressed["should_transmit"]

    expiring = TrickleTimer(
        imin_ms=constants["Imin_ms"],
        imax_doublings=8,
        k=constants["k"],
        rng=lambda: 0.0,
    )
    expiring.start(0)
    expiring.fire_transmit()
    expiring.expire(expiring.interval_end)
    assert expiring.interval == vectors["trickle_expire_double"]["interval_after_expire"]

    consistency = vectors["trickle_consistency_detection"]
    scope = bytes.fromhex(consistency["scope_dodag_id_hex"])
    for case in consistency["cases"]:
        scoped = TrickleTimer(
            consistency["Imin_ms"],
            8,
            consistency["k"],
            rng=lambda: 0.0,
            dodag_id=scope,
            dodag_version=consistency["scope_version"],
        )
        if case["active"]:
            scoped.start(0)
        if case["after_transmit"]:
            scoped.fire_transmit()
        scoped.counter = case["counter_before"]
        interval_state = (scoped.interval, scoped.interval_start, scoped.transmit_time)
        accepted = scoped.heard_consistent(
            bytes.fromhex(case["observed_dodag_id_hex"]),
            case["observed_version"],
        )
        assert accepted is case["expected_accepted"]
        assert scoped.counter == case["expected_counter_after"]
        assert scoped.should_transmit() is case["expected_should_transmit"]
        assert (scoped.interval, scoped.interval_start, scoped.transmit_time) == interval_state

    reset_vector = vectors["trickle_inconsistency_resets"]
    samples = iter(
        [reset_vector["initial_rand_offset_ms"]]
        + [step["rand_offset_ms"] for step in reset_vector["steps"]]
    )
    reset_timer = TrickleTimer(
        imin_ms=reset_vector["Imin_ms"],
        imax_doublings=8,
        k=reset_vector["k"],
        rng=lambda: next(samples) / (reset_vector["Imin_ms"] // 2),
    )
    reset_timer.start(0)
    for step in reset_vector["steps"]:
        reset_timer.heard_consistent()
        if step["fire_before_reset"]:
            reset_timer.fire_transmit()
        reset_timer.reset(step["now_ms"])
        assert reset_timer.interval == step["expected_interval_ms"]
        assert reset_timer.counter == step["expected_counter"]
        assert reset_timer.transmit_time == step["expected_transmit_time_ms"]
        assert reset_timer.interval_end == step["expected_interval_end_ms"]


def test_max_interval_is_imin_shifted_by_doublings() -> None:
    t = TrickleTimer(100, 4, 2)
    assert t.max_interval == 1600
    t2 = TrickleTimer(1000, 31, 10)
    assert t2.max_interval == (1 << 32) - 1
    t3 = TrickleTimer(1000, 32, 10)
    assert t3.max_interval == (1 << 32) - 1
    t4 = TrickleTimer(1000, 0, 10)
    assert t4.max_interval == 1000


def test_start_sets_first_interval_and_transmit_time() -> None:
    t = _timer(rng_value=0.0)
    t.start(0)
    assert t.interval == 100
    assert t.counter == 0
    assert t.transmit_time == 50  # I/2 with rng=0
    assert t.interval_end == 100


def test_transmit_time_within_half_to_full_interval() -> None:
    # rng just below 1 -> transmit time approaches I (exclusive upper bound).
    t = _timer(rng_value=0.999, imin=100)
    t.start(0)
    assert 50 <= t.transmit_time < 100


def test_odd_interval_bias_free() -> None:
    # I=5 odd: half=(5+1)//2=3, range=2; transmit in [3,5). Matches Rust/C.
    # rng=0.0 -> + int(0*2)=3; rng=0.6 -> int(1.2)=1 -> 4
    t = _timer(rng_value=0.0, imin=5)
    t.start(0)
    assert t.transmit_time == 3
    assert t.interval_end == 5

    t2 = _timer(rng_value=0.6, imin=5)
    t2.start(0)
    assert t2.transmit_time == 4


@pytest.mark.parametrize("sample", [-0.1, 1.0, float("inf"), float("nan"), "0.5", True])
def test_invalid_rng_samples_are_rejected(sample: object) -> None:
    timer = TrickleTimer(100, 4, 2, rng=cast(Any, lambda: sample))
    with pytest.raises(ValueError, match=r"finite value in \[0, 1\)"):
        timer.start(0)


def test_should_transmit_when_below_redundancy() -> None:
    t = _timer(k=2)
    t.start(0)
    assert t.should_transmit() is True
    t.heard_consistent()
    assert t.should_transmit() is True  # counter 1 < k 2
    t.heard_consistent()
    assert t.should_transmit() is False  # counter 2 >= k 2


def test_scoped_consistency_requires_active_exact_dodag_and_version() -> None:
    scope = bytes.fromhex("20010db8000000000000000000000001")
    t = TrickleTimer(100, 4, 2, rng=lambda: 0.0, dodag_id=scope, dodag_version=7)
    assert t.heard_consistent(scope, 7) is False
    t.start(0)
    assert t.heard_consistent(scope, 8) is False
    assert t.heard_consistent(scope[:-1] + b"\x02", 7) is False
    assert t.heard_consistent() is False
    assert t.counter == 0
    assert t.heard_consistent(scope, 7) is True
    assert t.counter == 1
    t.fire_transmit()
    assert t.heard_consistent(scope, 7) is True
    assert t.counter == 2


def test_scope_change_and_inconsistency_reset_remain_separate() -> None:
    first = bytes.fromhex("20010db8000000000000000000000001")
    second = bytes.fromhex("20010db8000000000000000000000002")
    t = TrickleTimer(100, 4, 2, rng=lambda: 0.0, dodag_id=first, dodag_version=7)
    t.start(10)
    t.heard_consistent(first, 7)
    state_before = (t.interval_start, t.transmit_time, t.counter, t._generation)
    assert t.heard_consistent(second, 8) is False
    assert (t.interval_start, t.transmit_time, t.counter, t._generation) == state_before
    t.set_scope(second, 8)
    assert (t.interval_start, t.transmit_time, t.counter, t._generation) == state_before
    t.reset(20)
    assert t.counter == 0
    assert t.heard_consistent(second, 8) is True


def test_expire_doubles_interval_and_caps() -> None:
    t = _timer(imin=100, imax=2)  # max = 400
    t.start(0)
    assert t.interval == 100
    t.expire(t.interval_end)
    assert t.interval == 200
    assert t.interval_start == 100
    t.expire(t.interval_end)
    assert t.interval == 400
    t.expire(t.interval_end)
    assert t.interval == 400  # capped at max_interval


def test_expire_resets_counter_and_transmit_time() -> None:
    t = _timer(rng_value=0.0, imin=100)
    t.start(0)
    t.heard_consistent()
    t.expire(100)  # new interval at t=100, I=200
    assert t.counter == 0
    assert t.interval == 200
    assert t.transmit_time == 100 + 100  # start + I/2


def test_reset_shrinks_to_imin() -> None:
    t = _timer(imin=100, imax=4)
    t.start(0)
    t.expire(t.interval_end)
    t.expire(t.interval_end)
    assert t.interval == 400
    t.reset(now=1000)
    assert t.interval == 100
    assert t.interval_start == 1000


def test_reset_at_imin_restarts_and_resamples() -> None:
    samples = iter((0.0, 0.5))
    t = TrickleTimer(100, 4, 2, rng=lambda: next(samples))
    t.start(0)
    t.heard_consistent()
    t.reset(now=500)
    assert t.interval == 100
    assert t.interval_start == 500
    assert t.counter == 0
    assert t.transmit_time == 575


def test_repeated_inconsistency_always_starts_a_fresh_interval() -> None:
    samples = iter((0.0, 0.25, 0.75))
    t = TrickleTimer(100, 4, 2, rng=lambda: next(samples))
    t.start(0)
    t.reset(10)
    first_generation = t._generation
    assert t.transmit_time == 72
    t.heard_consistent()
    t.reset(20)
    assert t._generation == first_generation + 1
    assert t.counter == 0
    assert t.transmit_time == 107


def test_reset_after_transmit_reenters_transmit_phase() -> None:
    t = _timer(rng_value=0.0, imin=100)
    t.start(0)
    assert t.fire_transmit()
    t.heard_consistent()
    t.reset(60)
    assert t.counter == 0
    assert t.next_event() == ("transmit", 110)


def test_reset_at_monotonic_limit_stops_cleanly_and_can_recover() -> None:
    t = _timer(rng_value=0.0, imin=100)
    t.start(0)
    t.heard_consistent()
    t.reset(((1 << 64) - 1) - 100)
    assert t.stopped is False
    assert t.interval_end == (1 << 64) - 1
    t.reset(((1 << 64) - 1) - 99)
    assert t.stopped is True
    assert t.counter == 0
    assert t.next_event() == ("stopped", ((1 << 64) - 1) - 99)
    t.reset(0)
    assert t.stopped is False
    assert t.next_event() == ("transmit", 50)


@pytest.mark.parametrize("now", [-1, 1 << 64, 1.5, True])
def test_reset_rejects_out_of_domain_monotonic_time(now: object) -> None:
    t = _timer(imin=100)
    with pytest.raises(ValueError, match="u64 monotonic"):
        t.reset(now)  # type: ignore[arg-type]


def test_reset_from_uninitialized_starts_timer() -> None:
    t = _timer(imin=100)
    # Before start(): _generation==0 is sentinel (interval==imin but triggers)
    assert t._generation == 0
    assert t.interval == 100
    t.reset(now=0)
    assert t.interval == 100
    assert t._generation == 1
    assert t.interval_start == 0
    assert t.transmit_time == 50  # rng=0.0 -> exactly I/2


def test_next_event_transmit_then_expire() -> None:
    t = _timer(rng_value=0.0, imin=100)
    t.start(0)
    assert t.next_event() == ("transmit", 50)
    assert t.fire_transmit() is True
    assert t.next_event() == ("expire", 100)


def test_invalid_parameters_rejected() -> None:
    with pytest.raises(ValueError):
        TrickleTimer(0, 4, 2)
    with pytest.raises(ValueError):
        TrickleTimer(100, -1, 2)
    with pytest.raises(ValueError, match="configured together"):
        TrickleTimer(100, 4, 2, dodag_id=bytes(16))
    with pytest.raises(ValueError, match="exactly 16"):
        TrickleTimer(100, 4, 2, dodag_id=bytes(15), dodag_version=0)
    with pytest.raises(ValueError, match="u8"):
        TrickleTimer(100, 4, 2, dodag_id=bytes(16), dodag_version=256)


def test_counter_saturates_on_overflow() -> None:
    """RFC 6206 §4.2: counter must not wrap; saturate at maximum."""
    t = _timer(k=10)
    t.start(0)
    t.counter = (1 << 32) - 1
    t.heard_consistent()
    assert t.counter == (1 << 32) - 1, "counter saturates at max"
    assert not t.should_transmit(), "counter >= k: should not transmit"


def test_zero_k_redundancy_constant() -> None:
    """k=0: even counter=0 is never < k, so should_transmit always false.

    RFC 6206 §4.2 does not explicitly forbid k=0, but it makes the
    timer operationally inert (never transmits). The timer must not
    crash or enter an invalid state.
    """
    t = TrickleTimer(100, 4, 0, rng=lambda: 0.0)
    t.start(0)
    assert not t.should_transmit(), "k=0: should_transmit false at start"
    assert not t.fire_transmit(), "k=0: fire_transmit returns false"
    t.heard_consistent()
    assert not t.should_transmit(), "k=0: still false after hearing"
    assert t.counter == 1, "k=0: heard_consistent still increments counter"


def test_zero_counter_should_transmit_with_positive_k() -> None:
    """counter=0 < k=1 is true per RFC 6206 §4.2 step 4."""
    t = _timer(k=1)
    t.start(0)
    assert t.should_transmit(), "counter=0 < k=1"
    assert t.fire_transmit(), "fire_transmit returns true when c < k"


def test_heard_consistent_does_not_overflow_at_max_counter() -> None:
    """heardt_consistent at UINT32_MAX must saturate, not wrap.

    Regression: Python unsigned ints don't overflow, but the counter
    must not grow past 2^32-1 to match Rust/C behavior.
    """
    t = _timer(k=10)
    t.start(0)
    t.counter = (1 << 32) - 1
    t.heard_consistent()
    assert t.counter == (1 << 32) - 1, "must not exceed max u32"

    # Even after saturating, should_transmit must work correctly
    assert not t.should_transmit(), "counter >= k: should not transmit"


@pytest.mark.asyncio
async def test_run_loop_transmits_with_fake_clock() -> None:
    # Fake clock: each sleep(ms) advances the clock by ms exactly.
    clock = {"now": 0}

    async def fake_sleep(ms: float) -> None:
        clock["now"] += int(ms)

    transmissions: list[int] = []

    async def on_transmit() -> None:
        transmissions.append(clock["now"])

    t = TrickleTimer(100, 2, k=5, rng=lambda: 0.0)
    await t.run(
        on_transmit,
        now_fn=lambda: clock["now"],
        sleep_fn=fake_sleep,
        max_intervals=3,
    )

    # k=5 and no consistent messages heard -> transmit every interval.
    # Interval 1: start 0, t=50 -> transmit at 50, expire at 100.
    # Interval 2: I=200, start 100, t=200 -> transmit at 200, expire at 300.
    # Interval 3: I=400, start 300, t=500 -> transmit at 500.
    assert transmissions == [50, 200, 500]
