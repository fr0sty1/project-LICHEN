# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from ipaddress import IPv6Address

from lichen.ipv6.icmpv6 import Icmpv6Message

"""LOADng control message codecs (spec section 10, appendix B2).

LOADng provides reactive peer-to-peer route discovery. Messages are ICMPv6
type 158, with the code selecting the message: RREQ (0), RREP (1), RERR (2),
RACK (3, reserved here).

Wire format follows the spec section 10.3/10.4 diagrams: a fixed field block
followed by an optional Schnorr signature carried as opaque bytes. The signature
is produced and verified by the link/security layer (issue 9a9); these codecs
only serialize it, so they are independent of the signature scheme. Per spec
B2.3 the default metric is hop count, so no separate metric field is carried
(the issue's "Metric" field is folded into hop count / hop limit).

The default unsigned signature is empty; a signed message carries 48 bytes.
"""

LOADNG_ICMPV6_TYPE = 158
INITIAL_HOP_LIMIT = 4
# Spec appendix B2.1: RREQ flood bound. The hop field is one wire byte, but
# values above 15 are malformed. 0 is in range: RREQ hop_limit=0 is terminal
# (do not rebroadcast); RREP hop_count=0 is the destination itself.
MAX_HOP_LIMIT = 15
SIGNATURE_LENGTH = 48

_RREQ_RREP_PREFIX = 36  # flags(1) hop(1) seq(2) originator(16) destination(16)
_RERR_PREFIX = 18  # flags(1) error_code(1) unreachable(16)


def _validate_hop(value: int, field: str) -> None:
    """Reject hop_limit/hop_count outside 0..=MAX_HOP_LIMIT (spec B2.1)."""
    if not 0 <= value <= MAX_HOP_LIMIT:
        raise LoadngError(f"{field} out of range: {value}")


def _validate_u8(value: int, field: str) -> None:
    """Reject a one-byte wire field outside 0..=255."""
    if not 0 <= value <= 255:
        raise LoadngError(f"{field} out of range: {value}")


def _parse_signature(data: bytes, offset: int) -> bytes:
    sig = data[offset:]
    if len(sig) not in (0, SIGNATURE_LENGTH):
        raise LoadngError(f"invalid signature length: {len(sig)}, expected 0 or {SIGNATURE_LENGTH}")
    return sig


class LoadngCode(IntEnum):
    """ICMPv6 code for LOADng messages (spec B2.4)."""

    RREQ = 0
    RREP = 1
    RERR = 2
    RACK = 3


class LoadngError(Exception):
    """Raised when a LOADng message is malformed."""


@dataclass
class RREQ:
    """Route Request, flooded toward a destination (spec 10.3)."""

    originator: IPv6Address
    destination: IPv6Address
    seq_num: int
    hop_limit: int = INITIAL_HOP_LIMIT
    flags: int = 0
    signature: bytes = field(default=b"")

    def to_bytes(self) -> bytes:
        if not 0 <= self.seq_num <= 0xFFFF:
            raise LoadngError(f"seq_num out of range: {self.seq_num}")
        _validate_hop(self.hop_limit, "hop_limit")
        _validate_u8(self.flags, "flags")
        return (
            bytes([self.flags, self.hop_limit])
            + self.seq_num.to_bytes(2, "big")
            + IPv6Address(self.originator).packed
            + IPv6Address(self.destination).packed
            + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> RREQ:
        if len(data) < _RREQ_RREP_PREFIX:
            raise LoadngError(f"RREQ too short: {len(data)} bytes")
        signature = data[36:]
        if len(signature) not in (0, SIGNATURE_LENGTH):
            raise LoadngError(
                f"invalid signature length: {len(signature)}, expected 0 or {SIGNATURE_LENGTH}"
            )
        hop_limit = data[1]
        _validate_hop(hop_limit, "hop_limit")
        return cls(
            flags=data[0],
            hop_limit=hop_limit,
            seq_num=int.from_bytes(data[2:4], "big"),
            originator=IPv6Address(data[4:20]),
            destination=IPv6Address(data[20:36]),
            signature=_parse_signature(data, 36),
        )


@dataclass
class RREP:
    """Route Reply, unicast back along the reverse path (spec 10.4)."""

    originator: IPv6Address
    destination: IPv6Address
    seq_num: int
    hop_count: int = 0
    flags: int = 0
    signature: bytes = field(default=b"")

    def to_bytes(self) -> bytes:
        if not 0 <= self.seq_num <= 0xFFFF:
            raise LoadngError(f"seq_num out of range: {self.seq_num}")
        _validate_hop(self.hop_count, "hop_count")
        _validate_u8(self.flags, "flags")
        return (
            bytes([self.flags, self.hop_count])
            + self.seq_num.to_bytes(2, "big")
            + IPv6Address(self.originator).packed
            + IPv6Address(self.destination).packed
            + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> RREP:
        if len(data) < _RREQ_RREP_PREFIX:
            raise LoadngError(f"RREP too short: {len(data)} bytes")
        signature = data[36:]
        if len(signature) not in (0, SIGNATURE_LENGTH):
            raise LoadngError(
                f"invalid signature length: {len(signature)}, expected 0 or {SIGNATURE_LENGTH}"
            )
        hop_count = data[1]
        _validate_hop(hop_count, "hop_count")
        return cls(
            flags=data[0],
            hop_count=hop_count,
            seq_num=int.from_bytes(data[2:4], "big"),
            originator=IPv6Address(data[4:20]),
            destination=IPv6Address(data[20:36]),
            signature=signature,
        )


@dataclass
class RERR:
    """Route Error, sent toward sources when a link fails (spec 10.6)."""

    unreachable: IPv6Address
    error_code: int = 0
    flags: int = 0
    signature: bytes = field(default=b"")

    def to_bytes(self) -> bytes:
        _validate_u8(self.error_code, "error_code")
        _validate_u8(self.flags, "flags")
        return (
            bytes([self.flags, self.error_code])
            + IPv6Address(self.unreachable).packed
            + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> RERR:
        if len(data) < _RERR_PREFIX:
            raise LoadngError(f"RERR too short: {len(data)} bytes")
        signature = data[18:]
        if len(signature) not in (0, SIGNATURE_LENGTH):
            raise LoadngError(
                f"invalid signature length: {len(signature)}, expected 0 or {SIGNATURE_LENGTH}"
            )
        return cls(
            flags=data[0],
            error_code=data[1],
            unreachable=IPv6Address(data[2:18]),
            signature=signature,
        )


LoadngMessage = RREQ | RREP | RERR

_CODE_BY_TYPE = {RREQ: LoadngCode.RREQ, RREP: LoadngCode.RREP, RERR: LoadngCode.RERR}
_CLASS_BY_CODE: dict[LoadngCode, type[LoadngMessage]] = {
    LoadngCode.RREQ: RREQ,
    LoadngCode.RREP: RREP,
    LoadngCode.RERR: RERR,
}


def to_icmpv6(message: LoadngMessage) -> Icmpv6Message:
    """Wrap a LOADng message as an ICMPv6 type-158 message."""
    try:
        code = _CODE_BY_TYPE[type(message)]
    except KeyError:
        raise LoadngError(f"unsupported message type: {type(message).__name__}") from None
    return Icmpv6Message(LOADNG_ICMPV6_TYPE, int(code), message.to_bytes())


def from_icmpv6(msg: Icmpv6Message) -> LoadngMessage:
    """Parse an ICMPv6 type-158 message into the matching LOADng message."""
    if msg.type != LOADNG_ICMPV6_TYPE:
        raise LoadngError(f"not a LOADng message: ICMPv6 type {msg.type}")
    try:
        cls = _CLASS_BY_CODE[LoadngCode(msg.code)]
    except (ValueError, KeyError) as exc:
        raise LoadngError(f"unsupported LOADng code: {msg.code}") from exc
    return cls.from_bytes(msg.body)
