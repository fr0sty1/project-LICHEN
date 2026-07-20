# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Packet boundary tests for the node-backed CoAP channel."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from ipaddress import IPv6Address
from typing import cast

import pytest
from aiocoap import GET, Message
from aiocoap.numbers.types import NON

import lichen.coap.node_channel as node_channel_module
from lichen.coap.node_channel import NodeChannel
from lichen.coap.schc_channel import wrap_coap
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.l2_payload import wrap_schc_payload
from lichen.schc.headers import compress_packet


def _coap_request(token: bytes = b"test", mid: int = 1) -> bytes:
    return cast(bytes, Message(code=GET, _mtype=NON, _mid=mid, _token=token).encode())


class _Node:
    def __init__(self) -> None:
        self.on_receive: Callable[[bytes, object], None] | None = None
        self.owner: object | None = None
        self.sent: list[bytes] = []
        self.send_started = asyncio.Event()
        self.send_release: asyncio.Event | None = None

    def register_on_receive(
        self, owner: object, callback: Callable[[bytes, object], None]
    ) -> None:
        if self.on_receive is not None:
            raise RuntimeError("node receive callback already has an owner")
        self.owner = owner
        self.on_receive = callback

    def unregister_on_receive(self, owner: object) -> bool:
        if self.owner is not owner:
            return False
        self.owner = None
        self.on_receive = None
        return True

    async def send(self, packet: bytes) -> None:
        self.send_started.set()
        if self.send_release is not None:
            await self.send_release.wait()
        self.sent.append(packet)


@pytest.mark.asyncio
async def test_node_channel_uses_explicit_ipv6_destination_port() -> None:
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1", dst_port=61615)

    channel.send_datagram(_coap_request(), "[2001:db8::2]:61616")
    await asyncio.sleep(0)

    packet = IPv6Packet.from_bytes(node.sent[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert packet.header.dst_addr == IPv6Address("2001:db8::2")
    assert udp.dst_port == 61616


@pytest.mark.asyncio
async def test_node_channel_scoped_addresses_use_unscoped_wire_bytes() -> None:
    node = _Node()
    channel = NodeChannel(node, "fe80::1%mesh0")

    channel.send_datagram(
        _coap_request(), "[FE80:0:0:0:0:0:0:2]:61616"
    )
    await asyncio.sleep(0)

    packet = IPv6Packet.from_bytes(node.sent[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert packet.header.src_addr == IPv6Address("fe80::1")
    assert packet.header.dst_addr == IPv6Address("fe80::2")
    assert udp.dst_port == 61616
    assert channel.normalize_endpoint("fe80::2") == channel.normalize_endpoint(
        "[fe80::2%mesh0]"
    )
    with pytest.raises(ValueError, match="does not match"):
        channel.send_datagram(_coap_request(), "[fe80::2%other]")

    unscoped = NodeChannel(_Node(), "fe80::3")
    with pytest.raises(ValueError, match="requires a scoped local interface"):
        unscoped.normalize_endpoint("[fe80::2%mesh0]")
    with pytest.raises(ValueError, match="only supported for link-local"):
        NodeChannel(_Node(), "2001:db8::1%mesh0")


def test_node_channel_preserves_inbound_udp_source_port() -> None:
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    packet = wrap_coap(
        IPv6Address("2001:db8::2"),
        IPv6Address("2001:db8::1"),
        _coap_request(),
        src_port=61616,
    )

    assert node.on_receive is not None
    node.on_receive(wrap_schc_payload(compress_packet(packet)), object())

    assert received == [(_coap_request(), "[2001:db8::2]:61616")]


def test_node_channel_scoped_local_accepts_unscoped_wire_destination() -> None:
    node = _Node()
    channel = NodeChannel(node, "fe80::1%mesh0")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    packet = wrap_coap(
        IPv6Address("fe80::2"),
        IPv6Address("fe80::1"),
        _coap_request(),
    )

    assert node.on_receive is not None
    node.on_receive(wrap_schc_payload(compress_packet(packet)), object())

    assert received == [(_coap_request(), "[fe80::2%mesh0]")]


@pytest.mark.parametrize("invalid", ["non-udp", "zero-checksum", "corrupt-checksum"])
def test_node_channel_rejects_invalid_udp_packets(invalid: str, monkeypatch) -> None:
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    if invalid == "non-udp":
        header = IPv6Header(
            src_addr=IPv6Address("2001:db8::2"),
            dst_addr=IPv6Address("2001:db8::1"),
            next_header=NextHeader.ICMPV6,
            payload_length=1,
        )
        packet = header.to_bytes() + b"x"
    else:
        packet_bytes = bytearray(
            wrap_coap(
                IPv6Address("2001:db8::2"),
                IPv6Address("2001:db8::1"),
                _coap_request(),
            )
        )
        if invalid == "zero-checksum":
            packet_bytes[46:48] = b"\x00\x00"
        else:
            packet_bytes[-1] ^= 0xFF
        packet = bytes(packet_bytes)

    assert node.on_receive is not None
    monkeypatch.setattr(node_channel_module, "decompress_packet", lambda _data: packet)
    node.on_receive(wrap_schc_payload(b"compressed"), object())

    assert received == []


def test_node_channel_registration_and_close_are_owner_safe() -> None:
    node = _Node()
    old = NodeChannel(node, "2001:db8::1")
    with pytest.raises(RuntimeError, match="already has an owner"):
        NodeChannel(node, "2001:db8::1")
    assert not node.unregister_on_receive(object())
    assert node.owner is old

    old.close()
    replacement = NodeChannel(node, "2001:db8::1")
    old.close()
    assert node.owner is replacement
    replacement.close()
    replacement.close()
    assert node.owner is None
    with pytest.raises(RuntimeError, match="closed"):
        replacement.set_receiver(lambda _data, _source: None)


@pytest.mark.asyncio
async def test_node_channel_shutdown_cancels_and_drains_pending_sends() -> None:
    node = _Node()
    node.send_release = asyncio.Event()
    channel = NodeChannel(node, "2001:db8::1")
    channel.send_datagram(_coap_request(), "2001:db8::2")
    await node.send_started.wait()

    await channel.shutdown()
    await channel.shutdown()
    channel.close()

    assert channel._tasks == set()
    assert node.sent == []
    assert node.owner is None
    with pytest.raises(RuntimeError, match="closed"):
        channel.send_datagram(_coap_request(), "2001:db8::2")
