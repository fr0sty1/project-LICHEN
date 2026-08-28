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

    DATA_LENGTH = 18

    target: IPv6Address
    prefix_length: int = 128

    def __post_init__(self) -> None:
        if not (0 <= self.prefix_length <= 128):
            raise DaoError(f"prefix_length must be between 0 and 128, got {self.prefix_length}")

    def to_option(self) -> RplOption:
        if self.prefix_length != 128:
            raise DaoError("LICHEN RPL Target prefix_length must be 128")
        data = bytes([0, self.prefix_length]) + self.target.packed
        return RplOption(RplOptionType.RPL_TARGET, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> RplTarget:
        if opt.type != RplOptionType.RPL_TARGET:
            raise DaoError(f"not an RPL Target option: type {opt.type}")
        if len(opt.data) != cls.DATA_LENGTH:
            raise DaoError("RPL Target option must have Data Length 18")
        if opt.data[0] != 0:
            raise DaoError("RPL Target flags must be zero")
        prefix_length = opt.data[1]
        if prefix_length != 128:
            raise DaoError("LICHEN RPL Target prefix_length must be 128")
        return cls(IPv6Address(opt.data[2:]), prefix_length)


@dataclass
class TransitInformation:
    """LICHEN Transit Information option (RFC 6550 6.7.8).

    The RFC E bit describes external ownership; it is not a parent-presence
    bit. This profile always carries the Parent Address using Data Length 20.
    """

    parent_address: IPv6Address | None = None
    path_lifetime: int = 255
    path_sequence: int = 0
    path_control: int = 0x80
    external: bool = False

    def to_option(self) -> RplOption:
        if self.parent_address is None:
            raise DaoError("LICHEN Transit Information requires a Parent Address")
        e_flag = 0x80 if self.external else 0x00
        data = bytes(
            [e_flag, self.path_control, self.path_sequence, self.path_lifetime]
        ) + self.parent_address.packed
        return RplOption(RplOptionType.TRANSIT_INFORMATION, data)

    @classmethod
    def from_option(cls, opt: RplOption) -> TransitInformation:
        if opt.type != RplOptionType.TRANSIT_INFORMATION:
            raise DaoError(f"not a Transit Information option: type {opt.type}")
        if len(opt.data) != 20:
            raise DaoError("Transit Information option must have Data Length 20")
        if (opt.data[0] & 0x7F) != 0:
            raise DaoError("flags must be zero")
        external = bool(opt.data[0] & 0x80)
        parent = IPv6Address(opt.data[4:20])
        return cls(
            parent_address=parent,
            path_control=opt.data[1],
            path_sequence=opt.data[2],
            path_lifetime=opt.data[3],
            external=external,
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
