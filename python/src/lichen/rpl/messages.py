# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from ipaddress import IPv6Address
from typing import Union

from lichen.ipv6.icmpv6 import Icmpv6Message

"""RPL control message codecs (RFC 6550, spec section 8).

RPL control messages are ICMPv6 type 155, with the code selecting the message:
DIS (0), DIO (1), DAO (2), DAO-ACK (3). Each base object is followed by a chain
of RPL options in the standard Type/Length/Value form (Pad1 is a lone zero
byte).

This module covers the message *framing*; typed option payloads (DODAG
Configuration, Prefix Information, Transit Information, ...) are carried as
generic :class:`RplOption` values and built out by the DODAG state machine.

LICHEN uses RPLInstanceID 0 and Non-Storing mode (MOP=1) per spec B.2.
"""

RPL_ICMPV6_TYPE = 155
DIO_BASE_LENGTH = 24
DODAGID_LENGTH = 16


class RplCode(IntEnum):
    """ICMPv6 code for RPL control messages (RFC 6550 6.1)."""

    DIS = 0
    DIO = 1
    DAO = 2
    DAO_ACK = 3


class RplOptionType(IntEnum):
    """RPL control message option types (RFC 6550 6.7)."""

    PAD1 = 0
    PADN = 1
    DAG_METRIC_CONTAINER = 2
    ROUTE_INFORMATION = 3
    DODAG_CONFIGURATION = 4
    RPL_TARGET = 5
    TRANSIT_INFORMATION = 6
    SOLICITED_INFORMATION = 7
    PREFIX_INFORMATION = 8


class ModeOfOperation(IntEnum):
    """RPL Mode of Operation (RFC 6550 6.3.1)."""

    NO_DOWNWARD = 0
    NON_STORING = 1
    STORING_NO_MULTICAST = 2
    STORING_MULTICAST = 3


class RplError(Exception):
    """Raised when an RPL message is malformed."""


@dataclass
class RplOption:
    """A single RPL option in Type/Length/Value form (Pad1 has no length)."""

    type: int
    data: bytes = b""

    def to_bytes(self) -> bytes:
        if self.type == RplOptionType.PAD1:
            if self.data:
                raise RplError("Pad1 option carries no data")
            return b"\x00"
        if not 0 <= self.type <= 255:
            raise RplError(f"option type out of range: {self.type}")
        if len(self.data) > 0xFF:
            raise RplError(f"option data too long: {len(self.data)} bytes")
        return bytes([self.type, len(self.data)]) + self.data


def _options_to_bytes(options: list[RplOption]) -> bytes:
    return b"".join(opt.to_bytes() for opt in options)


def _parse_options(data: bytes) -> list[RplOption]:
    options: list[RplOption] = []
    i = 0
    while i < len(data):
        opt_type = data[i]
        if opt_type == RplOptionType.PAD1:
            options.append(RplOption(RplOptionType.PAD1))
            i += 1
            continue
        if i + 2 > len(data):
            raise RplError("truncated RPL option header")
        length = data[i + 1]
        if i + 2 + length > len(data):
            raise RplError("RPL option runs past end of message")
        options.append(RplOption(opt_type, data[i + 2 : i + 2 + length]))
        i += 2 + length
    return options


@dataclass
class DIS:
    """DODAG Information Solicitation (RFC 6550 6.2)."""

    flags: int = 0
    reserved: int = 0
    options: list[RplOption] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        if not 0 <= self.flags <= 0xFF:
            raise RplError(f"flags out of range: {self.flags}")
        if not 0 <= self.reserved <= 0xFF:
            raise RplError(f"reserved out of range: {self.reserved}")
        return bytes([self.flags, self.reserved]) + _options_to_bytes(self.options)

    @classmethod
    def from_bytes(cls, data: bytes) -> DIS:
        if len(data) < 2:
            raise RplError(f"DIS too short: {len(data)} bytes")
        reserved = data[1]
        if reserved != 0:
            raise RplError(f"DIS reserved field must be zero per RFC 6550 §6.2, got {reserved}")
        return cls(
            flags=data[0], reserved=reserved, options=_parse_options(data[2:])
        )


@dataclass
class DIO:
    """DODAG Information Object (RFC 6550 6.3)."""

    rpl_instance_id: int
    version: int
    rank: int
    dtsn: int
    dodag_id: IPv6Address
    grounded: bool = False
    mode_of_operation: int = ModeOfOperation.NON_STORING
    preference: int = 0
    flags: int = 0
    reserved: int = 0
    options: list[RplOption] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.dodag_id = (
            self.dodag_id
            if isinstance(self.dodag_id, IPv6Address)
            else IPv6Address(self.dodag_id)
        )

    def to_bytes(self) -> bytes:
        if not 0 <= self.rpl_instance_id <= 0xFF:
            raise RplError(f"rpl_instance_id out of range: {self.rpl_instance_id}")
        if not 0 <= self.version <= 0xFF:
            raise RplError(f"version out of range: {self.version}")
        if not 0 <= self.rank <= 0xFFFF:
            raise RplError(f"rank out of range: {self.rank}")
        if not 0 <= self.dtsn <= 0xFF:
            raise RplError(f"dtsn out of range: {self.dtsn}")
        if not 0 <= self.mode_of_operation <= 7:
            raise RplError(f"mode_of_operation out of range: {self.mode_of_operation}")
        if not 0 <= self.preference <= 7:
            raise RplError(f"preference out of range: {self.preference}")
        if not 0 <= self.flags <= 0xFF:
            raise RplError(f"flags out of range: {self.flags}")
        if not 0 <= self.reserved <= 0xFF:
            raise RplError(f"reserved out of range: {self.reserved}")
        gmop_prf = (
            (int(self.grounded) << 7)
            | (self.mode_of_operation << 3)
            | self.preference
        )
        return (
            bytes([self.rpl_instance_id, self.version])
            + self.rank.to_bytes(2, "big")
            + bytes([gmop_prf, self.dtsn, self.flags, self.reserved])
            + self.dodag_id.packed
            + _options_to_bytes(self.options)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> DIO:
        if len(data) < DIO_BASE_LENGTH:
            raise RplError(f"DIO too short: {len(data)} bytes")
        if data[7] != 0:
            raise RplError(f"DIO reserved field must be zero per RFC 6550 §6.3, got {data[7]}")
        gmop_prf = data[4]
        return cls(
            rpl_instance_id=data[0],
            version=data[1],
            rank=int.from_bytes(data[2:4], "big"),
            grounded=bool(gmop_prf & 0x80),
            mode_of_operation=(gmop_prf >> 3) & 0x7,
            preference=gmop_prf & 0x7,
            dtsn=data[5],
            flags=data[6],
            reserved=data[7],
            dodag_id=IPv6Address(data[8:24]),
            options=_parse_options(data[24:]),
        )


@dataclass
class DAO:
    """Destination Advertisement Object (RFC 6550 6.4).

    ``dodag_id`` is present on the wire iff it is set (the D flag).
    """

    rpl_instance_id: int
    dao_sequence: int
    dodag_id: IPv6Address | None = None
    ack_requested: bool = False
    flags: int = 0
    reserved: int = 0
    options: list[RplOption] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.dodag_id is not None and not isinstance(self.dodag_id, IPv6Address):
            self.dodag_id = IPv6Address(self.dodag_id)

    def to_bytes(self) -> bytes:
        for name, val in [
            ("rpl_instance_id", self.rpl_instance_id),
            ("dao_sequence", self.dao_sequence),
            ("reserved", self.reserved),
            ("flags", self.flags),
        ]:
            if not 0 <= val <= 255:
                raise RplError(f"{name} out of range: {val}")
        d_flag = self.dodag_id is not None
        kd = (
            (int(self.ack_requested) << 7)
            | (int(d_flag) << 6)
            | (self.flags & 0x3F)
        )
        out = bytes([self.rpl_instance_id, kd, self.reserved, self.dao_sequence])
        if self.dodag_id is not None:
            out += self.dodag_id.packed
        return out + _options_to_bytes(self.options)

    @classmethod
    def from_bytes(cls, data: bytes) -> DAO:
        if len(data) < 4:
            raise RplError(f"DAO too short: {len(data)} bytes")
        kd = data[1]
        reserved = data[2]
        d_flag = bool(kd & 0x40)
        offset = 4
        dodag_id = None
        if d_flag:
            if len(data) < 4 + DODAGID_LENGTH:
                raise RplError("DAO D flag set but DODAGID missing")
            dodag_id = IPv6Address(data[4:20])
            offset = 20
        return cls(
            rpl_instance_id=data[0],
            ack_requested=bool(kd & 0x80),
            flags=kd & 0x3F,
            reserved=reserved,
            dao_sequence=data[3],
            dodag_id=dodag_id,
            options=_parse_options(data[offset:]),
        )


@dataclass
class DAOAck:
    """DAO Acknowledgement (RFC 6550 6.5)."""

    rpl_instance_id: int
    dao_sequence: int
    status: int = 0
    dodag_id: IPv6Address | None = None
    flags: int = 0
    options: list[RplOption] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.dodag_id is not None and not isinstance(self.dodag_id, IPv6Address):
            self.dodag_id = IPv6Address(self.dodag_id)

    def to_bytes(self) -> bytes:
        for name, val in [
            ("rpl_instance_id", self.rpl_instance_id),
            ("dao_sequence", self.dao_sequence),
            ("status", self.status),
            ("flags", self.flags),
        ]:
            if not 0 <= val <= 255:
                raise RplError(f"{name} out of range: {val}")
        d_flag = self.dodag_id is not None
        d_byte = (int(d_flag) << 7) | (self.flags & 0x7F)
        out = bytes(
            [self.rpl_instance_id, d_byte, self.dao_sequence, self.status]
        )
        if self.dodag_id is not None:
            out += self.dodag_id.packed
        return out + _options_to_bytes(self.options)

    @classmethod
    def from_bytes(cls, data: bytes) -> DAOAck:
        if len(data) < 4:
            raise RplError(f"DAO-ACK too short: {len(data)} bytes")
        d_byte = data[1]
        d_flag = bool(d_byte & 0x80)
        offset = 4
        dodag_id = None
        if d_flag:
            if len(data) < 4 + DODAGID_LENGTH:
                raise RplError("DAO-ACK D flag set but DODAGID missing")
            dodag_id = IPv6Address(data[4:20])
            offset = 20
        return cls(
            rpl_instance_id=data[0],
            flags=d_byte & 0x7F,
            dao_sequence=data[2],
            status=data[3],
            dodag_id=dodag_id,
            options=_parse_options(data[offset:]),
        )


RplMessage = Union[DIS, DIO, DAO, DAOAck]

_CODE_BY_TYPE = {
    DIS: RplCode.DIS,
    DIO: RplCode.DIO,
    DAO: RplCode.DAO,
    DAOAck: RplCode.DAO_ACK,
}
_CLASS_BY_CODE: dict[RplCode, type[RplMessage]] = {
    RplCode.DIS: DIS,
    RplCode.DIO: DIO,
    RplCode.DAO: DAO,
    RplCode.DAO_ACK: DAOAck,
}


def to_icmpv6(message: RplMessage) -> Icmpv6Message:
    """Wrap an RPL message as an ICMPv6 type-155 message."""
    try:
        code = _CODE_BY_TYPE[type(message)]
    except KeyError:
        raise RplError(f"unsupported message type: {type(message).__name__}") from None
    return Icmpv6Message(RPL_ICMPV6_TYPE, int(code), message.to_bytes())


def from_icmpv6(msg: Icmpv6Message) -> RplMessage:
    """Parse an ICMPv6 type-155 message into the matching RPL message."""
    if msg.type != RPL_ICMPV6_TYPE:
        raise RplError(f"not an RPL message: ICMPv6 type {msg.type}")
    try:
        cls = _CLASS_BY_CODE[RplCode(msg.code)]
    except (ValueError, KeyError) as exc:
        raise RplError(f"unsupported RPL code: {msg.code}") from exc
    return cls.from_bytes(msg.body)
