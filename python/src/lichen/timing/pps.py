# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""GNSS pulse-per-second edge capture and UTC-second association.

The hardware or operating-system integration captures rising PPS edges in one
monotonic nanosecond clock domain.  A later, time-valid GNSS message names the
UTC second at that edge.  This module deliberately performs no I/O: callers
validate the GNSS time-valid indication before association.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

MICROS_PER_SECOND: Final[int] = 1_000_000
_UINT64_MAX: Final[int] = (1 << 64) - 1


class PpsError(ValueError):
    """PPS configuration, capture, or association failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _u64(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PpsError("invalid_uint64", f"{name} must be an integer")
    if not 0 <= value <= _UINT64_MAX:
        raise PpsError("invalid_uint64", f"{name} must be uint64")
    return value


@dataclass(frozen=True, slots=True)
class EdgeCapture:
    """Result of capturing a PPS edge.

    ``previous_edge_ns`` is set when the new edge replaced an unassociated
    edge.  Only the newer edge remains eligible for association.
    """

    previous_edge_ns: int | None = None

    @property
    def replaced_unassociated(self) -> bool:
        """Whether an unassociated edge was replaced."""
        return self.previous_edge_ns is not None


@dataclass(frozen=True, slots=True)
class PpsAssociation:
    """Validated mapping between a monotonic PPS edge and one UTC second."""

    edge_monotonic_ns: int
    message_monotonic_ns: int
    unix_second: int
    unix_time_us: int
    message_delay_ns: int


class PpsAssociator:
    """Bounded PPS edge capture and GNSS-second association state.

    All monotonic values are integer nanoseconds in one caller-defined clock
    domain.  Rejected captures and associations are transactional: they leave
    the pending edge and most recent successful association unchanged.
    """

    __slots__ = (
        "_firmware_build_epoch_s",
        "_last_association",
        "_last_edge_ns",
        "_last_gnss_second",
        "_last_message_ns",
        "_maximum_message_delay_ns",
        "_pending_edge_ns",
    )

    def __init__(self, firmware_build_epoch_s: int, maximum_message_delay_ns: int) -> None:
        epoch = _u64(firmware_build_epoch_s, "firmware_build_epoch_s")
        delay = _u64(maximum_message_delay_ns, "maximum_message_delay_ns")
        if epoch == 0:
            raise PpsError("zero_build_epoch", "firmware build epoch must be non-zero")
        if epoch > _UINT64_MAX // MICROS_PER_SECOND:
            raise PpsError("build_epoch_overflow", "firmware build epoch overflows microseconds")
        if delay == 0:
            raise PpsError("zero_association_window", "association window must be non-zero")

        self._firmware_build_epoch_s = epoch
        self._maximum_message_delay_ns = delay
        self._last_edge_ns: int | None = None
        self._pending_edge_ns: int | None = None
        self._last_message_ns: int | None = None
        self._last_gnss_second: int | None = None
        self._last_association: PpsAssociation | None = None

    @property
    def pending_edge_ns(self) -> int | None:
        """The edge currently awaiting a time-valid GNSS message."""
        return self._pending_edge_ns

    @property
    def last_association(self) -> PpsAssociation | None:
        """The most recent successful association."""
        return self._last_association

    def capture_edge(self, edge_monotonic_ns: int) -> EdgeCapture:
        """Capture a strictly increasing PPS rising-edge timestamp."""
        edge = _u64(edge_monotonic_ns, "edge_monotonic_ns")
        if self._last_edge_ns is not None and edge <= self._last_edge_ns:
            raise PpsError(
                "edge_out_of_order",
                f"PPS edge {edge} did not advance past {self._last_edge_ns}",
            )

        outcome = EdgeCapture(self._pending_edge_ns)
        self._last_edge_ns = edge
        self._pending_edge_ns = edge
        return outcome

    def associate_gnss_second(
        self, unix_second: int, message_monotonic_ns: int
    ) -> PpsAssociation:
        """Associate the pending edge with a validated GNSS UTC second.

        ``maximum_message_delay_ns`` is inclusive.  A failure never consumes
        the pending edge, allowing the caller to retry or discard it explicitly.
        """
        if self._pending_edge_ns is None:
            raise PpsError("no_pending_edge", "no PPS edge is awaiting association")

        second = _u64(unix_second, "unix_second")
        received = _u64(message_monotonic_ns, "message_monotonic_ns")
        edge = self._pending_edge_ns

        if self._last_message_ns is not None and received <= self._last_message_ns:
            raise PpsError(
                "message_out_of_order",
                f"GNSS message {received} did not advance past {self._last_message_ns}",
            )
        if received < edge:
            raise PpsError(
                "message_before_edge",
                f"GNSS message {received} precedes PPS edge {edge}",
            )
        message_delay_ns = received - edge
        if message_delay_ns > self._maximum_message_delay_ns:
            raise PpsError(
                "stale_edge",
                f"PPS edge age {message_delay_ns} exceeds {self._maximum_message_delay_ns}",
            )
        if second < self._firmware_build_epoch_s:
            raise PpsError(
                "gnss_second_below_build_epoch",
                f"GNSS second {second} predates build epoch {self._firmware_build_epoch_s}",
            )
        if self._last_gnss_second is not None and second <= self._last_gnss_second:
            raise PpsError(
                "gnss_second_out_of_order",
                f"GNSS second {second} did not advance past {self._last_gnss_second}",
            )
        if second > _UINT64_MAX // MICROS_PER_SECOND:
            raise PpsError("unix_time_overflow", f"GNSS second {second} overflows microseconds")

        association = PpsAssociation(
            edge_monotonic_ns=edge,
            message_monotonic_ns=received,
            unix_second=second,
            unix_time_us=second * MICROS_PER_SECOND,
            message_delay_ns=message_delay_ns,
        )
        self._pending_edge_ns = None
        self._last_message_ns = received
        self._last_gnss_second = second
        self._last_association = association
        return association

    def discard_pending_edge(self) -> int | None:
        """Discard and return the pending edge while retaining order history."""
        edge = self._pending_edge_ns
        self._pending_edge_ns = None
        return edge
