# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""One-use authenticated DIO elevation and immutable fan-out evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, Literal

from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
from lichen.rpl.messages import DIO, RplCode
from lichen.rpl.root_signature import verify_dodagid_binding
from lichen.schc.headers import decompress_packet
from lichen.schc.rules import RULE_ID_UNCOMPRESSED

if TYPE_CHECKING:
    from lichen.link.link_layer import RxFrame


@dataclass(frozen=True)
class AuthenticatedDioOption:
    """One canonical DIO option and its span in the decompressed IPv6 packet."""

    type: int
    data: bytes
    ipv6_span: tuple[int, int]


@dataclass(frozen=True)
class DetachedAuthenticatedDio:
    """Fresh link-owned primitive snapshot exposed only inside elevation."""

    ipv6: bytes
    dio_bytes: bytes
    options: tuple[AuthenticatedDioOption, ...]
    sender_pubkey: bytes
    sender_iid: bytes
    epoch: int
    seqnum: int
    received_monotonic: float
    rssi_dbm: int
    snr_db: int
    clock_domain_identity: object
    key_generation: object
    receiving_link_identity: object


@dataclass(frozen=True, init=False)
class AuthenticatedDio:
    """Sealed DIO evidence safe to fan out after one receipt consumption."""

    _snapshot: RxFrame = field(repr=False)
    _ipv6: bytes = field(repr=False)
    _dio_bytes: bytes = field(repr=False)
    _options: tuple[AuthenticatedDioOption, ...]
    _expected_rpl_instance_id: int
    _expected_dodag_id: IPv6Address
    _expected_mop: int
    _expected_role: Literal["root", "peer"]

    def __new__(cls) -> AuthenticatedDio:
        raise TypeError("AuthenticatedDio values are issued only by LinkLayer")

    @property
    def ipv6(self) -> bytes:
        return self._ipv6

    @property
    def link_payload(self) -> bytes:
        return self._snapshot.payload

    @property
    def dio(self) -> DIO:
        return DIO.from_bytes(self._dio_bytes)

    @property
    def options(self) -> tuple[AuthenticatedDioOption, ...]:
        return self._options

    @property
    def sender_pubkey(self) -> bytes:
        return self._snapshot.sender_pubkey

    @property
    def sender_iid(self) -> bytes:
        """Authenticated sender IID captured in the sealed receive snapshot."""
        return self._snapshot.sender.iid

    @property
    def epoch(self) -> int:
        return self._snapshot.epoch

    @property
    def seqnum(self) -> int:
        return self._snapshot.seqnum

    @property
    def received_monotonic(self) -> float:
        return self._snapshot.received_monotonic

    @property
    def rssi_dbm(self) -> int:
        return self._snapshot.rssi_dbm

    @property
    def snr_db(self) -> int:
        return self._snapshot.snr_db

    @property
    def clock_domain_identity(self) -> object:
        """Opaque receipt-clock identity; compare only with ``is``."""
        return self._snapshot.clock_domain

    @property
    def key_generation(self) -> object:
        """Opaque peer-key generation identity; compare only with ``is``."""
        return self._snapshot.key_generation

    @property
    def receiving_link_identity(self) -> object:
        """Opaque issuing LinkLayer identity; compare only with ``is``."""
        return self._snapshot.receiving_link_identity


@dataclass(frozen=True)
class _AuthenticatedDioSnapshot:
    """Link-owned deep snapshot used to detect facade/nested mutation."""

    facade: AuthenticatedDio
    rx_snapshot: RxFrame
    structural_state: tuple[object, ...]
    clock_domain_identity: object
    key_generation: object
    receiving_link_identity: object
    sender_pubkey: bytes


def _detach_authenticated_dio(issued: _AuthenticatedDioSnapshot) -> DetachedAuthenticatedDio:
    """Rebuild callback evidence solely from the stored primitive issuance."""
    state = issued.structural_state
    option_state = state[2]
    if type(option_state) is not tuple:
        raise TypeError("stored authenticated DIO option snapshot is invalid")
    options: list[AuthenticatedDioOption] = []
    for item in option_state:
        if type(item) is not tuple or len(item) != 4:
            raise TypeError("stored authenticated DIO option snapshot is invalid")
        option_type, data, start, end = item
        if (
            type(option_type) is not int
            or type(data) is not bytes
            or type(start) is not int
            or type(end) is not int
        ):
            raise TypeError("stored authenticated DIO option snapshot is invalid")
        options.append(AuthenticatedDioOption(option_type, data, (start, end)))
    ipv6, dio_bytes = state[0], state[1]
    if type(ipv6) is not bytes or type(dio_bytes) is not bytes:
        raise TypeError("stored authenticated DIO bytes are invalid")
    snapshot = issued.rx_snapshot
    return DetachedAuthenticatedDio(
        ipv6=ipv6,
        dio_bytes=dio_bytes,
        options=tuple(options),
        sender_pubkey=issued.sender_pubkey,
        sender_iid=snapshot.sender.iid,
        epoch=snapshot.epoch,
        seqnum=snapshot.seqnum,
        received_monotonic=snapshot.received_monotonic,
        rssi_dbm=snapshot.rssi_dbm,
        snr_db=snapshot.snr_db,
        clock_domain_identity=issued.clock_domain_identity,
        key_generation=issued.key_generation,
        receiving_link_identity=issued.receiving_link_identity,
    )


def _capture_authenticated_dio(value: object) -> _AuthenticatedDioSnapshot:
    """Capture and validate every field consumed from sealed DIO evidence."""
    from lichen.crypto.identity import PeerIdentity
    from lichen.link.link_layer import RxFrame

    if type(value) is not AuthenticatedDio:
        raise TypeError("value must be an exact AuthenticatedDio")
    authenticated = value
    snapshot = authenticated._snapshot
    if type(snapshot) is not RxFrame or type(snapshot.sender) is not PeerIdentity:
        raise TypeError("authenticated DIO contains an invalid receive snapshot")
    if type(authenticated._ipv6) is not bytes or type(authenticated._dio_bytes) is not bytes:
        raise TypeError("authenticated DIO byte snapshots must be bytes")
    if type(authenticated._options) is not tuple:
        raise TypeError("authenticated DIO options must be a tuple")
    option_state: list[tuple[int, bytes, int, int]] = []
    for option in authenticated._options:
        if type(option) is not AuthenticatedDioOption:
            raise TypeError("authenticated DIO contains an invalid option")
        if type(option.type) is not int or type(option.data) is not bytes:
            raise TypeError("authenticated DIO option fields have invalid types")
        if (
            type(option.ipv6_span) is not tuple
            or len(option.ipv6_span) != 2
            or any(type(bound) is not int for bound in option.ipv6_span)
        ):
            raise TypeError("authenticated DIO option span is invalid")
        option_state.append(
            (option.type, option.data, option.ipv6_span[0], option.ipv6_span[1])
        )
    if type(authenticated._expected_rpl_instance_id) is not int:
        raise TypeError("authenticated DIO scope is invalid")
    if type(authenticated._expected_dodag_id) is not IPv6Address:
        raise TypeError("authenticated DIO scope is invalid")
    if type(authenticated._expected_mop) is not int:
        raise TypeError("authenticated DIO scope is invalid")
    if authenticated._expected_role not in ("root", "peer"):
        raise TypeError("authenticated DIO scope is invalid")
    if (
        type(snapshot.sender_pubkey) is not bytes
        or type(snapshot.sender.pubkey) is not bytes
        or type(snapshot.sender.iid) is not bytes
        or type(snapshot.local_pubkey) is not bytes
        or type(snapshot.payload) is not bytes
        or type(snapshot.epoch) is not int
        or type(snapshot.seqnum) is not int
        or type(snapshot.received_monotonic) is not float
        or type(snapshot.rssi_dbm) is not int
        or type(snapshot.snr_db) is not int
    ):
        raise TypeError("authenticated DIO receive snapshot has invalid field types")
    structural_state: tuple[object, ...] = (
        authenticated._ipv6,
        authenticated._dio_bytes,
        tuple(option_state),
        authenticated._expected_rpl_instance_id,
        authenticated._expected_dodag_id.packed,
        authenticated._expected_mop,
        authenticated._expected_role,
        snapshot.payload,
        snapshot.sender_pubkey,
        snapshot.sender.pubkey,
        snapshot.sender.iid,
        snapshot.local_pubkey,
        snapshot.epoch,
        snapshot.seqnum,
        snapshot.received_monotonic,
        snapshot.rssi_dbm,
        snapshot.snr_db,
        snapshot.frame.to_bytes(),
    )
    return _AuthenticatedDioSnapshot(
        facade=authenticated,
        rx_snapshot=snapshot,
        structural_state=structural_state,
        clock_domain_identity=snapshot.clock_domain,
        key_generation=snapshot.key_generation,
        receiving_link_identity=snapshot.receiving_link_identity,
        sender_pubkey=snapshot.sender_pubkey,
    )


def _parse_option_spans(dio_bytes: bytes) -> tuple[AuthenticatedDioOption, ...]:
    options: list[AuthenticatedDioOption] = []
    cursor = 24
    while cursor < len(dio_bytes):
        start = cursor
        option_type = dio_bytes[cursor]
        if option_type == 0:
            cursor += 1
            options.append(AuthenticatedDioOption(0, b"", (44 + start, 44 + cursor)))
            continue
        if cursor + 2 > len(dio_bytes):
            raise ValueError("truncated RPL option header")
        data_length = dio_bytes[cursor + 1]
        cursor += 2
        end = cursor + data_length
        if end > len(dio_bytes):
            raise ValueError("RPL option runs past end of DIO")
        options.append(
            AuthenticatedDioOption(
                option_type,
                bytes(dio_bytes[cursor:end]),
                (44 + start, 44 + end),
            )
        )
        cursor = end
    return tuple(options)


def _issue_authenticated_dio(
    snapshot: RxFrame,
    *,
    expected_rpl_instance_id: int,
    expected_dodag_id: IPv6Address,
    expected_mop: int,
    expected_role: Literal["root", "peer"],
) -> AuthenticatedDio:
    """Parse a detached LinkLayer snapshot inside its receipt transaction."""
    from lichen.link.link_layer import RxFrame

    if type(snapshot) is not RxFrame:
        raise TypeError("snapshot must be an exact LinkLayer-issued RxFrame")
    if type(expected_rpl_instance_id) is not int or not 0 <= expected_rpl_instance_id < 0xC0:
        raise ValueError("expected_rpl_instance_id must be a global 0..191 instance")
    if type(expected_dodag_id) is not IPv6Address:
        raise TypeError("expected_dodag_id must be an exact IPv6Address")
    if type(expected_mop) is not int or not 0 <= expected_mop <= 3:
        raise ValueError("expected_mop must be an implemented RPL MOP")
    if expected_role not in ("root", "peer"):
        raise ValueError("expected_role must be 'root' or 'peer'")
    if classify_l2_payload(snapshot.payload) is not L2PayloadKind.SCHC:
        raise ValueError("authenticated DIO must use the SCHC L2 dispatch")
    schc = l2_payload_body(snapshot.payload)
    if not schc or schc[0] != RULE_ID_UNCOMPRESSED:
        raise ValueError("authenticated DIO must use validated SCHC Rule 255")
    ipv6 = decompress_packet(schc)
    return _issue_authenticated_dio_from_ipv6(
        snapshot,
        ipv6,
        schc_rule_id=schc[0],
        expected_rpl_instance_id=expected_rpl_instance_id,
        expected_dodag_id=expected_dodag_id,
        expected_mop=expected_mop,
        expected_role=expected_role,
    )


def _issue_authenticated_dio_from_ipv6(
    snapshot: RxFrame,
    ipv6: bytes,
    *,
    schc_rule_id: int,
    expected_rpl_instance_id: int,
    expected_dodag_id: IPv6Address,
    expected_mop: int,
    expected_role: Literal["root", "peer"],
) -> AuthenticatedDio:
    """Issue DIO evidence from link-authenticated reassembly output."""
    from lichen.link.link_layer import RxFrame

    if type(snapshot) is not RxFrame:
        raise TypeError("snapshot must be an exact LinkLayer-issued RxFrame")
    if type(ipv6) is not bytes:
        raise TypeError("ipv6 must be exact bytes")
    if type(schc_rule_id) is not int or schc_rule_id != RULE_ID_UNCOMPRESSED:
        raise ValueError("authenticated DIO must use validated SCHC Rule 255")
    if type(expected_rpl_instance_id) is not int or not 0 <= expected_rpl_instance_id < 0xC0:
        raise ValueError("expected_rpl_instance_id must be a global 0..191 instance")
    if type(expected_dodag_id) is not IPv6Address:
        raise TypeError("expected_dodag_id must be an exact IPv6Address")
    if type(expected_mop) is not int or not 0 <= expected_mop <= 3:
        raise ValueError("expected_mop must be an implemented RPL MOP")
    if expected_role not in ("root", "peer"):
        raise ValueError("expected_role must be 'root' or 'peer'")
    header = IPv6Header.from_bytes(ipv6)
    expected_source = IPv6Address(b"\xfe\x80" + bytes(6) + snapshot.sender.iid)
    if header.src_addr != expected_source:
        raise ValueError("authenticated DIO source IID does not match signer")
    if header.dst_addr != IPv6Address("ff02::1a"):
        raise ValueError("authenticated DIO destination must be ff02::1a")
    if header.hop_limit != 255:
        raise ValueError("authenticated DIO Hop Limit must be 255")
    if header.next_header != NextHeader.ICMPV6:
        raise ValueError("authenticated DIO must be carried in ICMPv6")
    icmp = ipv6[HEADER_LENGTH:]
    if (
        len(icmp) < 4
        or icmp[0] != 155
        or icmp[1] != RplCode.DIO
        or not Icmpv6Message.verify_checksum(header.src_addr, header.dst_addr, icmp)
    ):
        raise ValueError("authenticated SCHC payload is not a valid RPL DIO")
    dio_bytes = bytes(icmp[4:])
    dio = DIO.from_bytes(dio_bytes)
    if dio.rpl_instance_id != expected_rpl_instance_id:
        raise ValueError("authenticated DIO RPLInstanceID mismatch")
    if dio.dodag_id != expected_dodag_id:
        raise ValueError("authenticated DIO DODAGID mismatch")
    if dio.mode_of_operation != expected_mop:
        raise ValueError("authenticated DIO MOP mismatch")
    is_root = dio.rank == 256
    if is_root != (expected_role == "root"):
        raise ValueError("authenticated DIO role mismatch")
    if expected_role == "root" and not verify_dodagid_binding(
        snapshot.sender_pubkey, dio.dodag_id
    ):
        raise ValueError("authenticated root DODAGID does not match signer key")
    value = object.__new__(AuthenticatedDio)
    object.__setattr__(value, "_snapshot", snapshot)
    object.__setattr__(value, "_ipv6", bytes(ipv6))
    object.__setattr__(value, "_dio_bytes", dio_bytes)
    object.__setattr__(value, "_options", _parse_option_spans(dio_bytes))
    object.__setattr__(value, "_expected_rpl_instance_id", expected_rpl_instance_id)
    object.__setattr__(value, "_expected_dodag_id", expected_dodag_id)
    object.__setattr__(value, "_expected_mop", expected_mop)
    object.__setattr__(value, "_expected_role", expected_role)
    return value
