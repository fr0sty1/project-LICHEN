# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GNSS PPS edge association tests shared conceptually with Rust."""

from __future__ import annotations

import pytest

from lichen.link.channel import sfn_from_unix_time
from lichen.timing.pps import (
    MICROS_PER_SECOND,
    EdgeCapture,
    PpsAssociator,
    PpsError,
)

BUILD_EPOCH_S = 1_704_067_200
UINT64_MAX = (1 << 64) - 1


def associator(maximum_message_delay_ns: int = 500_000) -> PpsAssociator:
    return PpsAssociator(BUILD_EPOCH_S, maximum_message_delay_ns)


def assert_error(code: str, callback: object) -> None:
    assert callable(callback)
    with pytest.raises(PpsError) as caught:
        callback()
    assert caught.value.code == code


def test_associates_edge_with_sub_microsecond_capture_precision() -> None:
    state = associator()
    assert state.capture_edge(10_000_000_123) == EdgeCapture()

    association = state.associate_gnss_second(BUILD_EPOCH_S + 4, 10_000_125_579)
    assert association.edge_monotonic_ns == 10_000_000_123
    assert association.message_monotonic_ns == 10_000_125_579
    assert association.message_delay_ns == 125_456
    assert association.unix_time_us == 1_704_067_204_000_000
    assert state.pending_edge_ns is None
    assert state.last_association == association


@pytest.mark.parametrize(
    "epoch,window,code",
    [
        (0, 1, "zero_build_epoch"),
        (UINT64_MAX, 1, "build_epoch_overflow"),
        (BUILD_EPOCH_S, 0, "zero_association_window"),
        (-1, 1, "invalid_uint64"),
        (True, 1, "invalid_uint64"),
        (BUILD_EPOCH_S, 1.5, "invalid_uint64"),
    ],
)
def test_configuration_rejects_invalid_epoch_and_window(
    epoch: object, window: object, code: str
) -> None:
    assert_error(code, lambda: PpsAssociator(epoch, window))  # type: ignore[arg-type]


def test_edge_capture_is_strictly_monotonic_and_transactional() -> None:
    state = associator()
    state.capture_edge(20)
    for invalid in (20, 19):
        assert_error("edge_out_of_order", lambda invalid=invalid: state.capture_edge(invalid))
        assert state.pending_edge_ns == 20


def test_replacing_unassociated_edge_is_observable_and_uses_newest() -> None:
    state = associator()
    state.capture_edge(1_000_000)
    capture = state.capture_edge(2_000_000)
    assert capture.replaced_unassociated
    assert capture.previous_edge_ns == 1_000_000
    association = state.associate_gnss_second(BUILD_EPOCH_S, 2_100_000)
    assert association.edge_monotonic_ns == 2_000_000


def test_missing_early_and_stale_edges_reject_without_consumption() -> None:
    state = associator()
    assert_error(
        "no_pending_edge", lambda: state.associate_gnss_second(BUILD_EPOCH_S, 1)
    )

    state.capture_edge(1_000_000)
    assert_error(
        "message_before_edge",
        lambda: state.associate_gnss_second(BUILD_EPOCH_S, 999_999),
    )
    assert_error(
        "stale_edge",
        lambda: state.associate_gnss_second(BUILD_EPOCH_S, 1_500_001),
    )
    assert state.pending_edge_ns == 1_000_000

    boundary = state.associate_gnss_second(BUILD_EPOCH_S, 1_500_000)
    assert boundary.message_delay_ns == 500_000


def test_epoch_and_unix_microsecond_overflow_fail_closed() -> None:
    state = associator()
    state.capture_edge(100)
    assert_error(
        "gnss_second_below_build_epoch",
        lambda: state.associate_gnss_second(BUILD_EPOCH_S - 1, 101),
    )
    assert state.pending_edge_ns == 100

    maximum_second = UINT64_MAX // MICROS_PER_SECOND
    large_epoch = PpsAssociator(maximum_second, 10)
    large_epoch.capture_edge(200)
    assert_error(
        "unix_time_overflow",
        lambda: large_epoch.associate_gnss_second(maximum_second + 1, 201),
    )
    assert large_epoch.pending_edge_ns == 200


def test_successes_require_increasing_message_timestamps_and_gnss_seconds() -> None:
    state = associator()
    state.capture_edge(1_000)
    first = state.associate_gnss_second(BUILD_EPOCH_S + 1, 1_100)

    state.capture_edge(2_000)
    assert_error(
        "message_out_of_order",
        lambda: state.associate_gnss_second(BUILD_EPOCH_S + 2, 1_100),
    )
    assert_error(
        "gnss_second_out_of_order",
        lambda: state.associate_gnss_second(BUILD_EPOCH_S + 1, 2_100),
    )
    assert state.pending_edge_ns == 2_000
    assert state.last_association == first

    second = state.associate_gnss_second(BUILD_EPOCH_S + 2, 2_100)
    assert second.unix_second == BUILD_EPOCH_S + 2


def test_association_projects_deterministically_to_sfn() -> None:
    state = associator()
    state.capture_edge(9_000_000)
    association = state.associate_gnss_second(BUILD_EPOCH_S + 4, 9_100_000)
    assert sfn_from_unix_time(association.unix_time_us) == 2


def test_pending_edge_can_be_discarded_without_resetting_order_history() -> None:
    state = associator()
    state.capture_edge(42)
    assert state.discard_pending_edge() == 42
    assert state.discard_pending_edge() is None
    assert state.pending_edge_ns is None
    assert_error("edge_out_of_order", lambda: state.capture_edge(42))
    assert state.capture_edge(43) == EdgeCapture()


def test_independent_associators_share_no_process_global_state() -> None:
    left = associator()
    right = associator()
    left.capture_edge(10)
    right.capture_edge(10)
    assert left.associate_gnss_second(BUILD_EPOCH_S, 11) == right.associate_gnss_second(
        BUILD_EPOCH_S, 11
    )
