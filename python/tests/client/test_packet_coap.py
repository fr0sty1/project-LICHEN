# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for CoAP ResourceTransport over packet LCI links."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from ipaddress import IPv6Address

import pytest

from lichen.client import (
    CoapResult,
    DeliveryState,
    LciClient,
    MessageDraft,
    PacketCoapConfig,
    PacketCoapResourceTransport,
    PacketDatagramChannel,
)
from lichen.client.packet_coap import PacketCoapResourceSubscription
from lichen.coap.resources import MessagesResource, StaticNodeInfo, build_site
from lichen.coap.schc_channel import wrap_coap
from lichen.coap.transport import create_lichen_context


class FakePacketTransport:
    def __init__(self) -> None:
        self.peer: FakePacketTransport | None = None
        self.connected = False
        self.closed = False
        self.sent_packets: list[bytes] = []
        self.fail_send = False
        self._packets: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def connect(self) -> None:
        self.connected = True
        self.closed = False

    async def close(self) -> None:
        self.connected = False
        self.closed = True
        await self._packets.put(None)

    async def send_packet(self, packet: bytes) -> None:
        if self.fail_send:
            raise OSError("packet link down")
        self.sent_packets.append(packet)
        if self.peer is not None:
            await self.peer.inject_packet(packet)

    async def inject_packet(self, packet: bytes) -> None:
        await self._packets.put(packet)

    def packets(self) -> AsyncIterator[bytes]:
        return self._packet_iter()

    async def _packet_iter(self) -> AsyncIterator[bytes]:
        while True:
            packet = await self._packets.get()
            if packet is None:
                return
            yield packet


class FakeResourceSubscription:
    def __init__(self, channel: PacketDatagramChannel | None = None) -> None:
        self.channel = channel
        self.closed = False

    async def close(self) -> None:
        self.closed = True

    def results(self) -> AsyncIterator[CoapResult]:
        return self._results()

    async def _results(self) -> AsyncIterator[CoapResult]:
        if self.channel is not None:
            self.channel.send_datagram(b"coap", "fe80::1")
        await asyncio.Event().wait()
        yield CoapResult(code="2.05")


def _packet_pair() -> tuple[FakePacketTransport, FakePacketTransport]:
    client = FakePacketTransport()
    server = FakePacketTransport()
    client.peer = server
    server.peer = client
    return client, server


async def _setup_packet_lci() -> tuple[
    LciClient,
    FakePacketTransport,
    PacketDatagramChannel,
    object,
    MessagesResource,
]:
    client_packets, server_packets = _packet_pair()
    await server_packets.connect()
    messages = MessagesResource()
    site = build_site(
        StaticNodeInfo(
            status={"uptime_s": 42, "battery_pct": 88},
            config={"name": "node-a"},
        ),
        messages_resource=messages,
    )
    server_channel = PacketDatagramChannel(server_packets, "fe80::1")
    server_channel.start()
    server = await create_lichen_context(server_channel, "fe80::1", site=site)
    transport = PacketCoapResourceTransport(
        client_packets,
        config=PacketCoapConfig(local_host="fe80::2", peer_host="fe80::1", timeout_s=1.0),
    )
    client = LciClient(transport)
    await client.connect()
    return client, client_packets, server_channel, server, messages


async def _cleanup_packet_lci(
    client: LciClient,
    server_channel: PacketDatagramChannel,
    server: object,
) -> None:
    await client.disconnect()
    await server.shutdown()
    await server_channel.aclose()


async def test_lci_client_get_status_over_packet_resource_transport() -> None:
    client, client_packets, server_channel, server, _ = await _setup_packet_lci()
    try:
        status = await client.get_status()

        assert status.uptime_s == 42
        assert status.battery_pct == 88
        assert client_packets.sent_packets
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_lci_client_send_message_over_packet_resource_transport() -> None:
    client, _, server_channel, server, messages = await _setup_packet_lci()
    try:
        result = await client.send_message(MessageDraft(to="fd00::2", body="hello", ack=True))

        assert result.state is DeliveryState.ACCEPTED
        assert result.location_path == ("msg", "sent", "1")
        assert messages.sent_messages()[0]["body"] == "hello"
        assert messages.sent_messages()[0]["ack"] is True
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_lci_client_observe_inbox_over_packet_resource_transport() -> None:
    client, _, server_channel, server, messages = await _setup_packet_lci()
    try:
        subscription = await client.observe_inbox()
        updates = subscription.messages()

        first = await asyncio.wait_for(anext(updates), timeout=1.0)
        messages.deliver({"from": "fd00::9", "to": "fd00::2", "body": "pushed"})
        second = await asyncio.wait_for(anext(updates), timeout=1.0)

        assert first == []
        assert second[0].body == "pushed"
        await subscription.close()
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_packet_resource_transport_close_closes_packet_transport() -> None:
    client, client_packets, server_channel, server, _ = await _setup_packet_lci()

    await _cleanup_packet_lci(client, server_channel, server)

    assert client_packets.closed is True


async def test_packet_send_failure_surfaces_as_lci_transport_error() -> None:
    client_packets, server_packets = _packet_pair()
    await server_packets.connect()
    server_channel = PacketDatagramChannel(server_packets, "fe80::1")
    server_channel.start()
    server = await create_lichen_context(
        server_channel,
        "fe80::1",
        site=build_site(StaticNodeInfo(status={"uptime_s": 42})),
    )
    client_packets.fail_send = True
    transport = PacketCoapResourceTransport(
        client_packets,
        config=PacketCoapConfig(local_host="fe80::2", peer_host="fe80::1", timeout_s=0.1),
    )
    client = LciClient(transport)
    await client.connect()
    try:
        with pytest.raises(Exception, match="packet link down"):
            await client.get_status()
        assert client_packets.closed is True
        client_packets.fail_send = False
        with pytest.raises(Exception, match="not connected"):
            await client.get_status()
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_observe_send_failure_surfaces_before_subscription_is_returned() -> None:
    client_packets, server_packets = _packet_pair()
    await server_packets.connect()
    server_channel = PacketDatagramChannel(server_packets, "fe80::1")
    server_channel.start()
    server = await create_lichen_context(
        server_channel,
        "fe80::1",
        site=build_site(
            StaticNodeInfo(status={"uptime_s": 42}),
            messages_resource=MessagesResource(),
        ),
    )
    client_packets.fail_send = True
    transport = PacketCoapResourceTransport(
        client_packets,
        config=PacketCoapConfig(local_host="fe80::2", peer_host="fe80::1", timeout_s=1.0),
    )
    client = LciClient(transport)
    await client.connect()
    try:
        subscription = await client.observe_inbox()
        with pytest.raises(Exception, match="packet link down"):
            await anext(subscription.messages())
        assert client_packets.closed is True
        client_packets.fail_send = False
        with pytest.raises(Exception, match="not connected"):
            await client.get_status()
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_observe_send_failure_closes_inner_subscription() -> None:
    packet_transport = FakePacketTransport()
    packet_transport.fail_send = True
    channel = PacketDatagramChannel(packet_transport, "fe80::2")
    inner = FakeResourceSubscription(channel)
    subscription = PacketCoapResourceSubscription(inner, channel)

    with pytest.raises(Exception, match="packet link down"):
        await anext(subscription.results())

    assert inner.closed is True


def test_packet_channel_drops_packets_for_other_ipv6_destinations() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(IPv6Address("fe80::1"), IPv6Address("fe80::3"), b"coap")
    )

    assert received == []


def test_packet_channel_drops_packets_for_unexpected_udp_ports() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2", src_port=61616)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(
            IPv6Address("fe80::1"),
            IPv6Address("fe80::2"),
            b"coap",
            src_port=5683,
            dst_port=5683,
        )
    )

    assert received == []


def test_packet_channel_drops_packets_with_bad_udp_checksum() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    packet = bytearray(wrap_coap(IPv6Address("fe80::1"), IPv6Address("fe80::2"), b"coap"))
    packet[-1] ^= 0xFF

    channel._handle_packet(bytes(packet))

    assert received == []


def test_packet_channel_accepts_packets_for_local_coap_port() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(IPv6Address("fe80::1"), IPv6Address("fe80::2"), b"coap")
    )

    assert received == [(b"coap", "fe80::1")]
