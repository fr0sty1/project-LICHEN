# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""DIS solicitation behavior from RFC 6550 Section 8.3."""

from ipaddress import IPv6Address

import pytest

from lichen.rpl.dis import DisAction, handle_authenticated_dis
from lichen.rpl.messages import DIS, RplError, RplOption, RplOptionType
from lichen.rpl.trickle import TrickleTimer

DODAG_ID = IPv6Address("200:1234::1")
OTHER_DODAG_ID = IPv6Address("200:1234::2")


def _timer() -> TrickleTimer:
    timer = TrickleTimer(4_000, 8, 10, rng=lambda: 0.0)
    timer.start(0)
    timer.expire(4_000)
    timer.heard_consistent()
    return timer


def _solicited(
    *,
    flags: int,
    instance: int = 7,
    dodag_id: IPv6Address = DODAG_ID,
    version: int = 9,
) -> RplOption:
    return RplOption(
        RplOptionType.SOLICITED_INFORMATION,
        bytes((instance, flags)) + dodag_id.packed + bytes((version,)),
    )


def _handle(
    wire: bytes,
    timer: TrickleTimer,
    *,
    multicast: bool,
) -> DisAction:
    return handle_authenticated_dis(
        wire,
        destination_is_multicast=multicast,
        rpl_instance_id=7,
        dodag_id=DODAG_ID,
        version=9,
        trickle=timer,
        now_ms=10_000,
    )


def test_multicast_dis_without_predicates_resets_trickle() -> None:
    timer = _timer()
    assert timer.interval == 8_000 and timer.counter == 1

    action = _handle(DIS(flags=0xFF).to_bytes(), timer, multicast=True)

    assert action is DisAction.RESET_TRICKLE
    assert timer.interval == 4_000
    assert timer.interval_start == 10_000
    assert timer.counter == 0


@pytest.mark.parametrize("flags", [0x00, 0x20, 0x40, 0x80, 0xE0, 0xFF])
def test_multicast_matching_enabled_predicates_resets(flags: int) -> None:
    timer = _timer()
    wire = DIS(options=[_solicited(flags=flags)]).to_bytes()

    assert _handle(wire, timer, multicast=True) is DisAction.RESET_TRICKLE
    assert timer.interval_start == 10_000


@pytest.mark.parametrize(
    "option",
    [
        _solicited(flags=0x40, instance=8),
        _solicited(flags=0x20, dodag_id=OTHER_DODAG_ID),
        _solicited(flags=0x80, version=10),
    ],
)
def test_multicast_nonmatching_enabled_predicate_is_ignored(option: RplOption) -> None:
    timer = _timer()
    before = (timer.interval, timer.interval_start, timer.counter, timer.transmit_time)

    assert _handle(DIS(options=[option]).to_bytes(), timer, multicast=True) is DisAction.IGNORE
    assert (timer.interval, timer.interval_start, timer.counter, timer.transmit_time) == before


def test_disabled_predicates_ignore_their_carried_values_and_reserved_flags() -> None:
    timer = _timer()
    option = _solicited(
        flags=0x1F,
        instance=255,
        dodag_id=OTHER_DODAG_ID,
        version=255,
    )

    assert _handle(DIS(options=[option]).to_bytes(), timer, multicast=True) is (
        DisAction.RESET_TRICKLE
    )


@pytest.mark.parametrize("options", [[], [_solicited(flags=0xE0)]])
def test_unicast_match_requests_dio_with_configuration_without_reset(
    options: list[RplOption],
) -> None:
    timer = _timer()
    before = (timer.interval, timer.interval_start, timer.counter, timer.transmit_time)

    assert _handle(DIS(options=options).to_bytes(), timer, multicast=False) is (
        DisAction.UNICAST_DIO_WITH_CONFIGURATION
    )
    assert (timer.interval, timer.interval_start, timer.counter, timer.transmit_time) == before


def test_unicast_predicate_mismatch_is_ignored_without_reset() -> None:
    timer = _timer()
    before = (timer.interval, timer.interval_start, timer.counter, timer.transmit_time)
    wire = DIS(options=[_solicited(flags=0x80, version=8)]).to_bytes()

    assert _handle(wire, timer, multicast=False) is DisAction.IGNORE
    assert (timer.interval, timer.interval_start, timer.counter, timer.transmit_time) == before


@pytest.mark.parametrize(
    "wire,match",
    [
        (b"\x00", "too short"),
        (b"\x00\x01", "reserved field"),
        (b"\x00\x00\x07", "truncated RPL option header"),
        (b"\x00\x00\x07\x13" + bytes(18), "runs past"),
        (DIS(options=[RplOption(RplOptionType.SOLICITED_INFORMATION, bytes(18))]).to_bytes(), "19"),
        (
            DIS(options=[_solicited(flags=0), _solicited(flags=0)]).to_bytes(),
            "duplicate",
        ),
    ],
)
def test_malformed_dis_fails_before_timer_mutation(wire: bytes, match: str) -> None:
    timer = _timer()
    before = (timer.interval, timer.interval_start, timer.counter, timer.transmit_time)

    with pytest.raises(RplError, match=match):
        _handle(wire, timer, multicast=True)

    assert (timer.interval, timer.interval_start, timer.counter, timer.transmit_time) == before


def test_padding_and_unknown_options_do_not_hide_valid_solicitation() -> None:
    timer = _timer()
    wire = DIS(
        options=[
            RplOption(RplOptionType.PAD1),
            RplOption(0xEE, b"unknown"),
            _solicited(flags=0xE0),
        ]
    ).to_bytes()

    assert _handle(wire, timer, multicast=True) is DisAction.RESET_TRICKLE
