# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

import threading
import weakref
from dataclasses import dataclass, field
from enum import IntEnum
from ipaddress import IPv6Address

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


# Bit mask for the gateway-centric flag in DIO.flags (LICHEN extension).
# Bit 0 of the flags byte: 1 = gateway centric (suppress announces when joined),
# 0 = normal (standard announce interval).
DIO_FLAG_GATEWAY_CENTRIC = 0x01


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


def _snapshot_dio_options(options: object) -> tuple[tuple[int, bytes], ...]:
    """Copy DIO option primitives once without invoking caller-owned methods."""
    if type(options) is not list:
        raise RplError("DIO options must be an exact list")
    snapshots: list[tuple[int, bytes]] = []
    for option in options.copy():
        if type(option) is not RplOption:
            raise RplError("DIO options must contain exact RplOption values")
        state = object.__getattribute__(option, "__dict__").copy()
        try:
            option_type = state["type"]
            data = state["data"]
        except KeyError as exc:
            raise RplError("DIO option is missing required state") from exc
        if isinstance(option_type, bool) or not isinstance(option_type, int):
            raise RplError(f"option type out of range: {option_type}")
        option_type = int(option_type)
        if not 0 <= option_type <= 0xFF:
            raise RplError(f"option type out of range: {option_type}")
        if type(data) is not bytes:
            raise RplError("option data must be exact bytes")
        if option_type == RplOptionType.PAD1 and data:
            raise RplError("Pad1 option carries no data")
        if len(data) > 0xFF:
            raise RplError(f"option data too long: {len(data)} bytes")
        snapshots.append((option_type, bytes(data)))
    return tuple(snapshots)


def _dio_options_snapshot_to_bytes(options: tuple[tuple[int, bytes], ...]) -> bytes:
    return b"".join(
        b"\x00" if option_type == RplOptionType.PAD1 else bytes((option_type, len(data))) + data
        for option_type, data in options
    )


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
        return cls(flags=data[0], reserved=reserved, options=_parse_options(data[2:]))


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
            self.dodag_id if isinstance(self.dodag_id, IPv6Address) else IPv6Address(self.dodag_id)
        )

    @property
    def gateway_centric(self) -> bool:
        """LICHEN gateway-centric flag (bit 0 of flags byte)."""
        return bool(self.flags & DIO_FLAG_GATEWAY_CENTRIC)

    def to_bytes(self) -> bytes:
        if type(self) is not DIO:
            raise RplError("DIO serializer requires an exact DIO")
        state = object.__getattribute__(self, "__dict__").copy()
        try:
            rpl_instance_id = state["rpl_instance_id"]
            version = state["version"]
            rank = state["rank"]
            dtsn = state["dtsn"]
            dodag_id = state["dodag_id"]
            grounded = state["grounded"]
            mode_of_operation = state["mode_of_operation"]
            preference = state["preference"]
            flags = state["flags"]
            reserved = state["reserved"]
            options = _snapshot_dio_options(state["options"])
        except KeyError as exc:
            raise RplError("DIO is missing required state") from exc

        scalar_ranges = (
            ("rpl_instance_id", rpl_instance_id, 0xFF),
            ("version", version, 0xFF),
            ("rank", rank, 0xFFFF),
            ("dtsn", dtsn, 0xFF),
            ("mode_of_operation", mode_of_operation, 7),
            ("preference", preference, 7),
            ("flags", flags, 0xFF),
            ("reserved", reserved, 0xFF),
        )
        frozen_scalars: dict[str, int] = {}
        for name, value, maximum in scalar_ranges:
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise RplError(f"{name} out of range: {value}")
            frozen_scalars[name] = int(value)
        if type(grounded) is not bool:
            raise RplError("grounded must be a bool")
        if type(dodag_id) is not IPv6Address:
            raise RplError("dodag_id must be an IPv6Address")

        rpl_instance_id = frozen_scalars["rpl_instance_id"]
        version = frozen_scalars["version"]
        rank = frozen_scalars["rank"]
        dtsn = frozen_scalars["dtsn"]
        mode_of_operation = frozen_scalars["mode_of_operation"]
        preference = frozen_scalars["preference"]
        flags = frozen_scalars["flags"]
        reserved = frozen_scalars["reserved"]
        dodag_id_packed = dodag_id.packed
        gmop_prf = (int(grounded) << 7) | (mode_of_operation << 3) | preference
        from lichen.schc.rules import RULE_SET_VERSION, SCHC_RULE_VERSION_TYPE

        version_options = [
            data for option_type, data in options if option_type == SCHC_RULE_VERSION_TYPE
        ]
        if len(version_options) > 1:
            raise RplError("DIO must contain at most one SCHC Rule Version option")
        if version_options and len(version_options[0]) != 1:
            raise RplError("SCHC Rule Version option must contain exactly one version byte")
        if not version_options:
            options = (*options, (SCHC_RULE_VERSION_TYPE, bytes([RULE_SET_VERSION])))
        return (
            bytes([rpl_instance_id, version])
            + rank.to_bytes(2, "big")
            + bytes([gmop_prf, dtsn, flags, reserved])
            + dodag_id_packed
            + _dio_options_snapshot_to_bytes(options)
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> DIO:
        if len(data) < DIO_BASE_LENGTH:
            raise RplError(f"DIO too short: {len(data)} bytes")
        if data[7] != 0:
            raise RplError(f"DIO reserved field must be zero per RFC 6550 §6.3, got {data[7]}")
        gmop_prf = data[4]
        if gmop_prf & 0x40:
            raise RplError("DIO G/MOP/Prf reserved bit must be zero per RFC 6550 §6.3")
        dodag_bytes = data[8:24]
        options_start = 8 + DODAGID_LENGTH
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
            dodag_id=IPv6Address(dodag_bytes),
            options=_parse_options(data[options_start:]),
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
        kd = (int(self.ack_requested) << 7) | (int(d_flag) << 6) | (self.flags & 0x3F)
        out = bytes([self.rpl_instance_id, kd, self.reserved, self.dao_sequence])
        if self.dodag_id is not None:
            out += self.dodag_id.packed
        return out + _options_to_bytes(self.options)

    @classmethod
    def from_bytes(cls, data: bytes) -> DAO:
        data = bytes(data)
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
        parsed = cls(
            rpl_instance_id=data[0],
            ack_requested=bool(kd & 0x80),
            flags=kd & 0x3F,
            reserved=reserved,
            dao_sequence=data[3],
            dodag_id=dodag_id,
            options=_parse_options(data[offset:]),
        )
        _bind_received_dao_wire(parsed, data, offset)
        return parsed


@dataclass(frozen=True)
class _ReceivedDaoWire:
    reference: weakref.ReferenceType[DAO]
    raw: bytes
    structural_state: tuple[object, ...]
    option_spans: tuple[tuple[int, int], ...]


_RECEIVED_DAO_WIRE_LOCK = threading.RLock()
_RECEIVED_DAO_WIRE: dict[int, _ReceivedDaoWire] = {}


def _dao_structural_state(dao: DAO) -> tuple[object, ...]:
    """Snapshot exact parsed DAO primitives without caller-owned methods."""
    if type(dao) is not DAO:
        raise RplError("received DAO must be an exact DAO")
    state = object.__getattribute__(dao, "__dict__").copy()
    try:
        options = state["options"]
        dodag_id = state["dodag_id"]
        scalars = tuple(
            state[name]
            for name in (
                "rpl_instance_id",
                "dao_sequence",
                "ack_requested",
                "flags",
                "reserved",
            )
        )
    except KeyError as exc:
        raise RplError("DAO is missing required parsed state") from exc
    if type(options) is not list:
        raise RplError("DAO options must remain an exact list")
    option_state: list[tuple[int, bytes]] = []
    for option in options.copy():
        if type(option) is not RplOption:
            raise RplError("DAO options must contain exact RplOption values")
        option_fields = object.__getattribute__(option, "__dict__").copy()
        option_type = option_fields.get("type")
        option_data = option_fields.get("data")
        if type(option_type) is not int or type(option_data) is not bytes:
            raise RplError("DAO option primitive types changed after parsing")
        option_state.append((option_type, option_data))
    if (
        type(scalars[0]) is not int
        or type(scalars[1]) is not int
        or type(scalars[2]) is not bool
        or type(scalars[3]) is not int
        or type(scalars[4]) is not int
        or (dodag_id is not None and type(dodag_id) is not IPv6Address)
    ):
        raise RplError("DAO primitive types changed after parsing")
    return (*scalars, None if dodag_id is None else dodag_id.packed, tuple(option_state))


def _bind_received_dao_wire(dao: DAO, raw: bytes, options_offset: int) -> None:
    spans: list[tuple[int, int]] = []
    cursor = options_offset
    while cursor < len(raw):
        start = cursor
        if raw[cursor] == int(RplOptionType.PAD1):
            cursor += 1
        else:
            length = raw[cursor + 1]
            cursor += 2 + length
        spans.append((start, cursor))
    dao_id = id(dao)

    def cleanup(reference: weakref.ReferenceType[DAO]) -> None:
        with _RECEIVED_DAO_WIRE_LOCK:
            current = _RECEIVED_DAO_WIRE.get(dao_id)
            if current is not None and current.reference is reference:
                _RECEIVED_DAO_WIRE.pop(dao_id, None)

    reference = weakref.ref(dao, cleanup)
    provenance = _ReceivedDaoWire(
        reference=reference,
        raw=raw,
        structural_state=_dao_structural_state(dao),
        option_spans=tuple(spans),
    )
    with _RECEIVED_DAO_WIRE_LOCK:
        _RECEIVED_DAO_WIRE[dao_id] = provenance


def _exact_received_dao_wire(
    dao: DAO,
) -> tuple[bytes, tuple[tuple[int, int], ...]] | None:
    """Return immutable raw provenance only while parsed semantics are unchanged."""
    if type(dao) is not DAO:
        return None
    with _RECEIVED_DAO_WIRE_LOCK:
        provenance = _RECEIVED_DAO_WIRE.get(id(dao))
    if provenance is None or provenance.reference() is not dao:
        return None
    try:
        current = _dao_structural_state(dao)
    except RplError:
        return None
    if current != provenance.structural_state:
        return None
    return provenance.raw, provenance.option_spans


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
        out = bytes([self.rpl_instance_id, d_byte, self.dao_sequence, self.status])
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


RplMessage = DIS | DIO | DAO | DAOAck

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
