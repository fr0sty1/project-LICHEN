# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the Trickle timer (RFC 6206).

Times are integer milliseconds; the RNG is injected so transmit instants are
deterministic. With ``rng=lambda: 0.0`` the transmit time is exactly I/2 after
the interval start (the low end of [I/2, I)).
"""

from __future__ import annotations

import pytest

from lichen.rpl.trickle import TrickleTimer


def _timer(rng_value: float = 0.0, *, imin: int = 100, imax: int = 4, k: int = 2):
    return TrickleTimer(imin, imax, k, rng=lambda: rng_value)


def test_max_interval_is_imin_shifted_by_doublings() -> None:
    t = TrickleTimer(100, 4, 2)
    assert t.max_interval == 100 << 4  # 1600


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


def test_should_transmit_when_below_redundancy() -> None:
    t = _timer(k=2)
    t.start(0)
    assert t.should_transmit() is True
    t.heard_consistent()
    assert t.should_transmit() is True  # counter 1 < k 2
    t.heard_consistent()
    assert t.should_transmit() is False  # counter 2 >= k 2


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


def test_reset_is_noop_at_imin() -> None:
    t = _timer(imin=100)
    t.start(0)
    t.heard_consistent()
    t.reset(now=500)
    # Still in the first interval; not restarted (interval_start unchanged).
    assert t.interval == 100
    assert t.interval_start == 0
    assert t.counter == 1


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
