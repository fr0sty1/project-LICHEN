# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""RPL DAO message types and parsing helpers.

This module provides the RPL Target (type 5) and Transit Information (type 6)
option codecs, along with supporting types for DAO processing.
"""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address

from lichen.rpl.messages import RplOption, RplOptionType
from lichen.rpl.routing import MAX_ROUTE_HOPS

# RPL Target Descriptor option type (RFC 6550 6.7.9)
TARGET_DESCRIPTOR = 9

# Loop/runaway guard when assembling source routes
MAX_CHAIN = 64

# Default freshness retention period
DEFAULT_FRESHNESS_RETENTION_SECONDS = 3600.0

# Alias for vector oracle compatibility
MAX_ROUTE_HOPS_ALIAS = MAX_ROUTE_HOPS


class DaoError(Exception):
    """Raised on malformed, stale, or unrouteable DAO state."""

    def __init__(self, message: str, *, reason: str = "rejected") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass
class RplTarget:
    """RPL Target option (RFC 6550 6.7.7); a full /128 target by default."""

    target: IPv6Address
    prefix_length: int = 128

    def __post_init__(self) -> None:
        if not (0 <= self.prefix_length <= 128):
            raise DaoError(f"prefix_length must be between 0 and 128, got {self.prefix_length}")

    def to_option(self) -> RplOption:
        if not (0 <= self.prefix_length <= 128):
            raise DaoError(f"prefix_length must be between 0 and 128, got {self.prefix_length}")
        nbytes = (self.prefix_length + 7) // 8
        data = bytes([0, self.prefix_length]) + self.target.packed[:nbytes]
        return RplOption(RplOptionType.RPL_TARGET, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> RplTarget:
        if opt.type != RplOptionType.RPL_TARGET:
            raise DaoError(f"not an RPL Target option: type {opt.type}")
        if len(opt.data) < 2:
            raise DaoError("RPL Target option too short")
        prefix_length = opt.data[1]
        if not (0 <= prefix_length <= 128):
            raise DaoError(f"prefix_length must be between 0 and 128, got {prefix_length}")
        nbytes = (prefix_length + 7) // 8
        if len(opt.data) != 2 + nbytes:
            raise DaoError("RPL Target option has non-canonical length")
        prefix = bytearray(opt.data[2:])
        if prefix_length % 8 and prefix:
            prefix[-1] &= 0xFF << (8 - prefix_length % 8)
        return cls(IPv6Address(bytes(prefix).ljust(16, b"\x00")), prefix_length)


@dataclass
class TransitInformation:
    """Transit Information option (RFC 6550 6.7.8) carrying the parent address.

    Per RFC 6550, the Parent Address field is only present when the E (External)
    flag is set in the first byte.
    """

    parent_address: IPv6Address | None = None
    path_lifetime: int = 255
    path_sequence: int = 0
    path_control: int = 0x80
    external: bool = False

    def to_option(self) -> RplOption:
        if self.external:
            raise DaoError("external encoding not supported")
        e_flag = 0x80 if self.parent_address is not None else 0x00
        data = bytes([e_flag, self.path_control, self.path_sequence, self.path_lifetime])
        if self.parent_address is not None:
            data += self.parent_address.packed
        return RplOption(RplOptionType.TRANSIT_INFORMATION, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> TransitInformation:
        if opt.type != RplOptionType.TRANSIT_INFORMATION:
            raise DaoError(f"not a Transit Information option: type {opt.type}")
        if len(opt.data) < 4:
            raise DaoError("Transit Information option too short")
        if (opt.data[0] & 0x7F) != 0:
            raise DaoError("flags must be zero")
        e_flag = opt.data[0] & 0x80
        if e_flag:
            if len(opt.data) < 4 + 16:
                raise DaoError("Transit Information option must contain parent address")
            parent = IPv6Address(opt.data[4:20])
        else:
            parent = None
        return cls(
            parent_address=parent,
            path_control=opt.data[1],
            path_sequence=opt.data[2],
            path_lifetime=opt.data[3],
            external=False,
        )


@dataclass(frozen=True, order=True)
class Candidate:
    """Internal candidate representation for DAO processing."""

    parent: IPv6Address
    path_control: int
    path_lifetime: int
    external: bool


@dataclass(frozen=True)
class Update:
    """Internal update representation from DAO parsing."""

    target: IPv6Address
    candidate: Candidate
    path_sequence: int
    descriptor: int | None


@dataclass(frozen=True)
class Freshness:
    """Internal freshness tracking for DAO targets."""

    sequence: int
    active_until: float | None
    retain_until: float
    updated_at: float

    def reclaimable(self, now: float) -> bool:
        return (
            self.active_until is not None and self.active_until <= now and self.retain_until <= now
        )


@dataclass(frozen=True)
class DaoOutcome:
    """Non-throwing result for post-provenance route-state processing."""

    accepted: bool
    state_changed: bool
    refreshed: bool
    reason: str


def sequence_is_newer(new: int, old: int) -> bool:
    """Compare RFC 6550 eight-bit lollipop counters."""
    if new < 128 and old < 128:
        return 1 <= ((new - old) & 0x7F) <= 16
    if new < 128 <= old:
        return 256 + new - old <= 16
    if old < 128 <= new:
        return 256 + old - new > 16
    return 1 <= ((new - old) & 0xFF) <= 16


def sequence_relation(new: int, old: int) -> str:
    """Return the relationship between two sequence numbers."""
    if new == old:
        return "equal"
    if sequence_is_newer(new, old):
        return "newer"
    if sequence_is_newer(old, new):
        return "stale"
    return "incomparable"


# Aliases for internal use (preserve underscore convention for private names)
_Candidate = Candidate
_Update = Update
_Freshness = Freshness
_sequence_is_newer = sequence_is_newer
_sequence_relation = sequence_relation
