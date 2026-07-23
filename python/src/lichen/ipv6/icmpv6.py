# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""ICMPv6 messages and handling (RFC 4443, spec section 6.4).

Implements the diagnostic message types — Echo Request/Reply and the error
messages (Destination Unreachable, Packet Too Big, Time Exceeded) — plus the
RFC 4443 checksum over the IPv6 pseudo-header, and a handler that answers echo
requests.

The checksum covers the IPv6 pseudo-header (source, destination, upper-layer
length, and Next Header = 58) followed by the ICMPv6 message, so serialization
requires the enclosing addresses.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from ipaddress import IPv6Address

from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader

ICMPV6_NEXT_HEADER = 58
# Cap the invoking packet quoted in an error message. RFC 4443 allows up to the
# IPv6 minimum MTU; LICHEN frames are far smaller, so a small bound is ample and
# keeps error messages from bloating.
MAX_INVOKING_PACKET = 1232


class Icmpv6Type(IntEnum):
    """ICMPv6 message types (RFC 4443)."""

    DEST_UNREACHABLE = 1
    PACKET_TOO_BIG = 2
    TIME_EXCEEDED = 3
    ECHO_REQUEST = 128
    ECHO_REPLY = 129


class DestUnreachableCode(IntEnum):
    """Codes for Destination Unreachable (RFC 4443 3.1)."""

    NO_ROUTE = 0
    ADMIN_PROHIBITED = 1
    BEYOND_SCOPE = 2
    ADDRESS_UNREACHABLE = 3
    PORT_UNREACHABLE = 4


class TimeExceededCode(IntEnum):
    """Codes for Time Exceeded (RFC 4443 3.3)."""

    HOP_LIMIT_EXCEEDED = 0
    FRAGMENT_REASSEMBLY = 1


class Icmpv6Error(Exception):
    """Raised when an ICMPv6 message is malformed."""


def _internet_checksum(data: bytes) -> int:
    """16-bit ones-complement Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmpv6_checksum(src: IPv6Address, dst: IPv6Address, message: bytes) -> int:
    """Compute the ICMPv6 checksum over the pseudo-header and message."""
    pseudo = (
        src.packed
        + dst.packed
        + len(message).to_bytes(4, "big")
        + bytes(3)
        + bytes([ICMPV6_NEXT_HEADER])
    )
    return _internet_checksum(pseudo + message)


@dataclass
class Icmpv6Message:
    """A generic ICMPv6 message: type, code, and the body after the checksum.

    ``body`` is everything following the 4-byte type/code/checksum prefix.
    """

    type: int
    code: int
    body: bytes = b""

    def to_bytes(self, src: IPv6Address, dst: IPv6Address) -> bytes:
        """Serialize with the checksum computed for the given addresses."""
        if not 0 <= self.type <= 0xFF:
            raise Icmpv6Error(f"type out of range: {self.type}")
        if not 0 <= self.code <= 0xFF:
            raise Icmpv6Error(f"code out of range: {self.code}")
        with_zero_checksum = bytes([self.type, self.code, 0, 0]) + self.body
        checksum = icmpv6_checksum(src, dst, with_zero_checksum)
        return bytes([self.type, self.code]) + checksum.to_bytes(2, "big") + self.body

    @classmethod
    def from_bytes(cls, data: bytes) -> Icmpv6Message:
        """Parse type/code/body (the checksum is not verified here).

        Explicit length check per RFC 4443 §2.3; malformed short messages
        raise Icmpv6Error.
        """
        if len(data) < 4:
            raise Icmpv6Error(f"ICMPv6 message too short: {len(data)} bytes")
        return cls(type=data[0], code=data[1], body=data[4:])

    @staticmethod
    def verify_checksum(src: IPv6Address, dst: IPv6Address, data: bytes) -> bool:
        """Check the checksum of a received ICMPv6 message.

        Per RFC 4443 §2.3, this MUST precede all other processing; returns
        False (silent drop) for too-short or invalid checksum.
        """
        if len(data) < 4:
            return False
        return icmpv6_checksum(src, dst, data) == 0


@dataclass
class EchoRequest:
    """ICMPv6 Echo Request (type 128)."""

    identifier: int
    sequence: int
    data: bytes = b""

    def to_message(self) -> Icmpv6Message:
        if not 0 <= self.identifier <= 0xFFFF:
            raise Icmpv6Error(f"identifier out of range: {self.identifier}")
        if not 0 <= self.sequence <= 0xFFFF:
            raise Icmpv6Error(f"sequence out of range: {self.sequence}")
        body = (
            self.identifier.to_bytes(2, "big")
            + self.sequence.to_bytes(2, "big")
            + self.data
        )
        return Icmpv6Message(Icmpv6Type.ECHO_REQUEST, 0, body)

    @classmethod
    def from_message(cls, msg: Icmpv6Message) -> EchoRequest:
        if msg.type != Icmpv6Type.ECHO_REQUEST:
            raise Icmpv6Error(f"not an echo request: type {msg.type}")
        return cls(*_parse_echo_body(msg.body))


@dataclass
class EchoReply:
    """ICMPv6 Echo Reply (type 129)."""

    identifier: int
    sequence: int
    data: bytes = b""

    def to_message(self) -> Icmpv6Message:
        if not 0 <= self.identifier <= 0xFFFF:
            raise Icmpv6Error(f"identifier out of range: {self.identifier}")
        if not 0 <= self.sequence <= 0xFFFF:
            raise Icmpv6Error(f"sequence out of range: {self.sequence}")
        body = (
            self.identifier.to_bytes(2, "big")
            + self.sequence.to_bytes(2, "big")
            + self.data
        )
        return Icmpv6Message(Icmpv6Type.ECHO_REPLY, 0, body)

    @classmethod
    def from_message(cls, msg: Icmpv6Message) -> EchoReply:
        if msg.type != Icmpv6Type.ECHO_REPLY:
            raise Icmpv6Error(f"not an echo reply: type {msg.type}")
        return cls(*_parse_echo_body(msg.body))


def _parse_echo_body(body: bytes) -> tuple[int, int, bytes]:
    if len(body) < 4:
        raise Icmpv6Error(f"echo body too short: {len(body)} bytes")
    identifier = int.from_bytes(body[0:2], "big")
    sequence = int.from_bytes(body[2:4], "big")
    return identifier, sequence, body[4:]


@dataclass
class Icmpv6ErrorMessage:
    """An ICMPv6 error message quoting the packet that triggered it.

    Used for Destination Unreachable, Packet Too Big, and Time Exceeded. The
    ``mtu`` field is only meaningful for Packet Too Big; the other types carry
    a zeroed 4-byte "rest of header".
    """

    type: int
    code: int
    invoking_packet: bytes
    mtu: int = 0

    def __post_init__(self) -> None:
        if self.type not in (
            Icmpv6Type.DEST_UNREACHABLE,
            Icmpv6Type.PACKET_TOO_BIG,
            Icmpv6Type.TIME_EXCEEDED,
        ):
            raise Icmpv6Error(f"invalid error message type: {self.type}")
        if self.type == Icmpv6Type.DEST_UNREACHABLE and self.code not in range(5):
            raise Icmpv6Error(f"invalid code for DEST_UNREACHABLE: {self.code}")
        if self.type == Icmpv6Type.PACKET_TOO_BIG and self.code != 0:
            raise Icmpv6Error(f"PACKET_TOO_BIG must use code 0, got {self.code}")
        if self.type == Icmpv6Type.TIME_EXCEEDED and self.code not in range(2):
            raise Icmpv6Error(f"invalid code for TIME_EXCEEDED: {self.code}")
        if not isinstance(self.invoking_packet, bytes):
            raise Icmpv6Error("invoking_packet must be bytes")
        if not 0 <= self.mtu <= 0xFFFFFFFF:
            raise Icmpv6Error(f"mtu out of range: {self.mtu}")

    def to_message(self) -> Icmpv6Message:
        rest = (
            self.mtu.to_bytes(4, "big")
            if self.type == Icmpv6Type.PACKET_TOO_BIG
            else bytes(4)
        )
        quoted = self.invoking_packet[:MAX_INVOKING_PACKET]
        return Icmpv6Message(self.type, self.code, rest + quoted)


def make_dest_unreachable(
    invoking_packet: bytes, code: DestUnreachableCode
) -> Icmpv6ErrorMessage:
    """Build a Destination Unreachable error for a packet."""
    return Icmpv6ErrorMessage(
        Icmpv6Type.DEST_UNREACHABLE, int(code), invoking_packet
    )


def make_time_exceeded(
    invoking_packet: bytes, code: TimeExceededCode = TimeExceededCode.HOP_LIMIT_EXCEEDED
) -> Icmpv6ErrorMessage:
    """Build a Time Exceeded error (e.g. hop limit reached during forwarding)."""
    return Icmpv6ErrorMessage(Icmpv6Type.TIME_EXCEEDED, int(code), invoking_packet)


def make_packet_too_big(invoking_packet: bytes, mtu: int) -> Icmpv6ErrorMessage:
    """Build a Packet Too Big error advertising ``mtu``."""
    if not 0 <= mtu <= 0xFFFFFFFF:
        raise Icmpv6Error(f"mtu out of range: {mtu}")
    return Icmpv6ErrorMessage(
        Icmpv6Type.PACKET_TOO_BIG, 0, invoking_packet, mtu=mtu
    )


def handle_icmpv6(
    packet: IPv6Packet, local_addr: IPv6Address | None = None
) -> IPv6Packet | None:
    """Process an inbound ICMPv6 packet, returning a reply if one is due.

    Restores explicit bounds checks for packet length, malformed source
    addresses (no unspecified or multicast sources for Echo Requests per
    RFC 4443 §§2.3, 2.4(e), 4.2), and ensures checksum verification precedes
    all processing. Malformed packets are dropped silently (or with metrics
    in callers).

    Only Echo Requests produce a reply. Replies and error messages are
    consumed without response.
    """
    if packet.header.next_header != ICMPV6_NEXT_HEADER:
        raise Icmpv6Error("packet does not carry ICMPv6")

    # Explicit bounds check for ICMPv6 packet length.
    if len(packet.payload) < 4:
        return None

    # SECURITY: RFC 4443 §2.3 requires checksum verification BEFORE any
    # other processing (type/code parse, source checks, echo parsing).
    # Malformed checksum -> silent drop.
    if not Icmpv6Message.verify_checksum(
        packet.header.src_addr, packet.header.dst_addr, packet.payload
    ):
        return None

    msg = Icmpv6Message.from_bytes(packet.payload)
    if msg.type != Icmpv6Type.ECHO_REQUEST:
        return None

    # SECURITY: RFC 4443 §2.4(e), §4.2: silently drop Echo Requests with
    # unspecified or multicast source address.
    if packet.header.src_addr.is_unspecified or packet.header.src_addr.is_multicast:
        return None

    request = EchoRequest.from_message(msg)
    reply = EchoReply(request.identifier, request.sequence, request.data)

    # Reply from the pinged address back to the requester.
    # RFC 4443 §4.2: If the request was sent to a multicast address,
    # the source of the reply MUST be a unicast address.
    dst_addr = packet.header.dst_addr
    if dst_addr.is_multicast:
        if local_addr is None:
            # Cannot reply to multicast without a unicast source address.
            return None
        reply_src = local_addr
    else:
        reply_src = dst_addr
    reply_dst = packet.header.src_addr
    reply_payload = reply.to_message().to_bytes(reply_src, reply_dst)
    reply_header = IPv6Header(
        src_addr=reply_src,
        dst_addr=reply_dst,
        next_header=NextHeader.ICMPV6,
        hop_limit=64,
    )
    return IPv6Packet(header=reply_header, payload=reply_payload)
