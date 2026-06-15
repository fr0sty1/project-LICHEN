"""Tests for ICMPv6 (RFC 4443, spec 6.4).

The checksum oracle is hand-computed: for a zero-filled Echo Request body
(80 00 0000 0000 0000) with src = dst = ::1, the pseudo-header words sum to
0x44 and the message words sum to 0x8000, giving total 0x8044 and checksum
~0x8044 = 0x7FBB.
"""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.ipv6.icmpv6 import (
    DestUnreachableCode,
    EchoReply,
    EchoRequest,
    Icmpv6Error,
    Icmpv6Message,
    Icmpv6Type,
    TimeExceededCode,
    handle_icmpv6,
    icmpv6_checksum,
    make_dest_unreachable,
    make_packet_too_big,
    make_time_exceeded,
)
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader

LOOPBACK = IPv6Address("::1")


def test_checksum_hand_computed_vector() -> None:
    msg = EchoRequest(identifier=0, sequence=0).to_message()
    raw = msg.to_bytes(LOOPBACK, LOOPBACK)
    assert raw[0] == Icmpv6Type.ECHO_REQUEST
    assert raw[2:4] == bytes([0x7F, 0xBB])


def test_checksum_verifies_to_zero() -> None:
    msg = EchoRequest(identifier=0x1234, sequence=7, data=b"ping").to_message()
    src, dst = IPv6Address("fe80::1"), IPv6Address("fe80::2")
    raw = msg.to_bytes(src, dst)
    # A correct checksum makes the checksum over the received message zero.
    assert icmpv6_checksum(src, dst, raw) == 0
    assert Icmpv6Message.verify_checksum(src, dst, raw)


def test_checksum_detects_corruption() -> None:
    msg = EchoRequest(identifier=1, sequence=1, data=b"x").to_message()
    raw = bytearray(msg.to_bytes(LOOPBACK, LOOPBACK))
    raw[-1] ^= 0xFF
    assert not Icmpv6Message.verify_checksum(LOOPBACK, LOOPBACK, bytes(raw))


def test_echo_request_round_trip() -> None:
    req = EchoRequest(identifier=0xABCD, sequence=42, data=b"hello")
    parsed = EchoRequest.from_message(req.to_message())
    assert parsed == req


def test_echo_reply_round_trip() -> None:
    rep = EchoReply(identifier=0x0001, sequence=2, data=b"")
    parsed = EchoReply.from_message(rep.to_message())
    assert parsed == rep


def test_echo_type_codes() -> None:
    assert EchoRequest(0, 0).to_message().type == 128
    assert EchoReply(0, 0).to_message().type == 129


def test_from_message_rejects_wrong_type() -> None:
    reply_msg = EchoReply(0, 0).to_message()
    with pytest.raises(Icmpv6Error):
        EchoRequest.from_message(reply_msg)


def test_message_from_bytes_rejects_short() -> None:
    with pytest.raises(Icmpv6Error):
        Icmpv6Message.from_bytes(b"\x80\x00")


def test_dest_unreachable_layout() -> None:
    err = make_dest_unreachable(b"INVOKING", DestUnreachableCode.NO_ROUTE)
    msg = err.to_message()
    assert msg.type == Icmpv6Type.DEST_UNREACHABLE
    assert msg.code == DestUnreachableCode.NO_ROUTE
    # 4-byte unused field, then the quoted packet.
    assert msg.body == bytes(4) + b"INVOKING"


def test_packet_too_big_carries_mtu() -> None:
    err = make_packet_too_big(b"PKT", mtu=1280)
    msg = err.to_message()
    assert msg.type == Icmpv6Type.PACKET_TOO_BIG
    assert msg.body[:4] == (1280).to_bytes(4, "big")
    assert msg.body[4:] == b"PKT"


def test_time_exceeded_default_code() -> None:
    err = make_time_exceeded(b"PKT")
    msg = err.to_message()
    assert msg.type == Icmpv6Type.TIME_EXCEEDED
    assert msg.code == TimeExceededCode.HOP_LIMIT_EXCEEDED
    assert msg.body == bytes(4) + b"PKT"


def test_handle_echo_request_produces_reply() -> None:
    src = IPv6Address("fe80::a")
    dst = IPv6Address("fe80::b")
    req = EchoRequest(identifier=0x1111, sequence=5, data=b"payload")
    request_packet = IPv6Packet(
        header=IPv6Header(src, dst, NextHeader.ICMPV6),
        payload=req.to_message().to_bytes(src, dst),
    )

    reply_packet = handle_icmpv6(request_packet)
    assert reply_packet is not None
    # Source and destination are swapped.
    assert reply_packet.header.src_addr == dst
    assert reply_packet.header.dst_addr == src

    reply_msg = Icmpv6Message.from_bytes(reply_packet.payload)
    assert reply_msg.type == Icmpv6Type.ECHO_REPLY
    parsed = EchoReply.from_message(reply_msg)
    assert (parsed.identifier, parsed.sequence, parsed.data) == (
        req.identifier,
        req.sequence,
        req.data,
    )
    # The reply's checksum is valid for the swapped addresses.
    assert Icmpv6Message.verify_checksum(dst, src, reply_packet.payload)


def test_handle_echo_reply_returns_none() -> None:
    src = IPv6Address("fe80::a")
    dst = IPv6Address("fe80::b")
    rep = EchoReply(identifier=1, sequence=1)
    packet = IPv6Packet(
        header=IPv6Header(src, dst, NextHeader.ICMPV6),
        payload=rep.to_message().to_bytes(src, dst),
    )
    assert handle_icmpv6(packet) is None


def test_handle_rejects_non_icmpv6() -> None:
    packet = IPv6Packet(
        header=IPv6Header("fe80::1", "fe80::2", NextHeader.UDP),
        payload=b"\x00\x00\x00\x00",
    )
    with pytest.raises(Icmpv6Error):
        handle_icmpv6(packet)
