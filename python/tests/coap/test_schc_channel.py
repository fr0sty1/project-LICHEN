# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the SCHC-compressing CoAP channel (SCHC<->transport wiring)."""

from __future__ import annotations

import asyncio
from ipaddress import IPv6Address

import aiocoap
import pytest
from aiocoap import GET, Message, resource

import lichen.coap.schc_channel as schc_channel_module
from lichen.coap.schc_channel import SchcChannel, unwrap_coap, wrap_coap
from lichen.coap.transport import (
    DatagramChannel,
    InMemoryNetwork,
    create_lichen_context,
)
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.schc.headers import compress_packet, decompress_packet

SRV = "fe80::2"
CLI = "fe80::1"


class _Capture(DatagramChannel):
    """An inner channel that records what is sent on the wire."""

    def __init__(self) -> None:
        self.sent: list[tuple[bytes, str]] = []
        self._receiver = None

    def set_receiver(self, receiver) -> None:
        self._receiver = receiver

    def send_datagram(self, data: bytes, dest: str) -> None:
        self.sent.append((data, dest))

    def deliver(self, data: bytes, source: str) -> None:
        self._receiver(data, source)


class _RecordingInner(_Capture):
    def __init__(self) -> None:
        super().__init__()
        self.clear_calls = 0
        self.close_calls = 0
        self.shutdown_calls = 0
        self.clear_error = None
        self.close_error = None
        self.shutdown_error = None

    def clear_receiver(self, receiver) -> None:
        self.clear_calls += 1
        if self.clear_error is not None:
            raise self.clear_error
        if self._receiver == receiver:
            self._receiver = None

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error

    async def shutdown(self) -> None:
        self.shutdown_calls += 1
        if self.shutdown_error is not None:
            raise self.shutdown_error


class _BlockingInner(_RecordingInner):
    def __init__(self) -> None:
        super().__init__()
        self.shutdown_started = asyncio.Event()
        self.shutdown_release = asyncio.Event()

    async def shutdown(self) -> None:
        self.shutdown_calls += 1
        self.shutdown_started.set()
        await self.shutdown_release.wait()


def test_wrap_unwrap_round_trip() -> None:
    from ipaddress import IPv6Address

    raw = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"coap-bytes")
    header = IPv6Header.from_bytes(raw)
    assert header.next_header == 17
    assert unwrap_coap(raw) == b"coap-bytes"
    # The framed datagram is a valid UDP datagram to the CoAP port.
    udp = UdpDatagram.from_bytes(raw[40:])
    assert udp.dst_port == 5683


def test_channel_emits_schc_compressed_bytes() -> None:
    cap = _Capture()
    channel = SchcChannel(cap, CLI)
    channel.send_datagram(b"\x40\x01\x12\x34\xffhello", SRV)
    assert len(cap.sent) == 1
    wire, dest = cap.sent[0]
    assert dest == f"[{SRV}]"
    assert wire[0] == 0  # SCHC rule 0 (link-local CoAP) was applied


def test_channel_uses_explicit_ipv6_destination_port() -> None:
    cap = _Capture()
    channel = SchcChannel(cap, CLI, dst_port=61615)
    channel.send_datagram(b"coap", f"[{SRV}]:61616")

    wire, dest = cap.sent[0]
    udp = UdpDatagram.from_bytes(decompress_packet(wire)[40:])
    assert dest == f"[{SRV}]:61616"
    assert udp.dst_port == 61616


def test_channel_preserves_inbound_udp_source_port() -> None:
    channel = SchcChannel(_Capture(), SRV)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    packet = wrap_coap(
        IPv6Address(CLI),
        IPv6Address(SRV),
        b"coap",
        src_port=61616,
    )

    channel._on_inner(compress_packet(packet), f"[{CLI}]:61616")

    assert received == [(b"coap", f"[{CLI}]:61616")]


def test_channel_preserves_scope_and_canonicalizes_source_alias() -> None:
    cap = _Capture()
    sender = SchcChannel(cap, "FE80:0:0:0:0:0:0:1%radio0")
    sender.send_datagram(b"coap", "[FE80:0:0:0:0:0:0:2%radio0]:61616")

    wire, dest = cap.sent[0]
    packet = IPv6Header.from_bytes(decompress_packet(wire))
    assert packet.src_addr == IPv6Address(CLI)
    assert packet.dst_addr == IPv6Address(SRV)
    assert dest == f"[{SRV}%radio0]:61616"

    receiver = SchcChannel(_Capture(), f"{SRV}%radio0", src_port=61616)
    received: list[tuple[bytes, str]] = []
    receiver.set_receiver(lambda data, source: received.append((data, source)))
    receiver._on_inner(wire, "[FE80:0:0:0:0:0:0:1%radio0]")
    assert received == [(b"coap", f"[{CLI}%radio0]")]


@pytest.mark.parametrize("invalid", ["non-udp", "zero-checksum", "corrupt-checksum"])
def test_channel_rejects_invalid_udp_packets(invalid: str, monkeypatch) -> None:
    channel = SchcChannel(_Capture(), SRV)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    if invalid == "non-udp":
        header = IPv6Header(
            src_addr=IPv6Address(CLI),
            dst_addr=IPv6Address(SRV),
            next_header=NextHeader.ICMPV6,
            payload_length=1,
        )
        packet = header.to_bytes() + b"x"
    else:
        packet_bytes = bytearray(
            wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"coap")
        )
        if invalid == "zero-checksum":
            packet_bytes[46:48] = b"\x00\x00"
        else:
            packet_bytes[-1] ^= 0xFF
        packet = bytes(packet_bytes)

    monkeypatch.setattr(schc_channel_module, "decompress_packet", lambda _data: packet)
    channel._on_inner(b"compressed", CLI)

    assert received == []


@pytest.mark.asyncio
async def test_channel_teardown_is_one_shot() -> None:
    closed_inner = _RecordingInner()
    closed = SchcChannel(closed_inner, CLI)
    closed.close()
    closed.close()
    await closed.shutdown()
    assert (closed_inner.clear_calls, closed_inner.close_calls, closed_inner.shutdown_calls) == (
        1,
        1,
        0,
    )
    with pytest.raises(RuntimeError, match="closed"):
        closed.set_receiver(lambda _data, _source: None)
    with pytest.raises(RuntimeError, match="closed"):
        closed.send_datagram(b"data", SRV)

    shutdown_inner = _RecordingInner()
    shutdown = SchcChannel(shutdown_inner, CLI)
    await shutdown.shutdown()
    await shutdown.shutdown()
    shutdown.close()
    assert (
        shutdown_inner.clear_calls,
        shutdown_inner.close_calls,
        shutdown_inner.shutdown_calls,
    ) == (1, 0, 1)


@pytest.mark.asyncio
async def test_concurrent_shutdown_callers_share_completion() -> None:
    inner = _BlockingInner()
    channel = SchcChannel(inner, CLI)
    first = asyncio.create_task(channel.shutdown())
    await inner.shutdown_started.wait()

    second = asyncio.create_task(channel.shutdown())
    await asyncio.sleep(0)
    assert not first.done()
    assert not second.done()
    assert inner.shutdown_calls == 1

    inner.shutdown_release.set()
    await asyncio.gather(first, second)

    assert inner.clear_calls == 1
    assert inner.shutdown_calls == 1


@pytest.mark.asyncio
async def test_close_continues_after_receiver_detach_failure() -> None:
    inner = _RecordingInner()
    inner.clear_error = RuntimeError("clear failed")
    inner.close_error = RuntimeError("close failed")
    channel = SchcChannel(inner, CLI)

    with pytest.raises(RuntimeError) as raised:
        channel.close()
    channel.close()
    shutdown_result = await asyncio.gather(channel.shutdown(), return_exceptions=True)

    assert raised.value is inner.clear_error
    assert shutdown_result == [inner.clear_error]
    assert inner.clear_calls == 1
    assert inner.close_calls == 1
    assert channel._inner is None


@pytest.mark.asyncio
async def test_shutdown_continues_after_receiver_detach_failure_once() -> None:
    inner = _RecordingInner()
    inner.clear_error = RuntimeError("clear failed")
    inner.shutdown_error = RuntimeError("shutdown failed")
    channel = SchcChannel(inner, CLI)

    results = await asyncio.gather(channel.shutdown(), channel.shutdown(), return_exceptions=True)
    repeated = await asyncio.gather(channel.shutdown(), return_exceptions=True)

    assert results == [inner.clear_error, inner.clear_error]
    assert repeated == [inner.clear_error]
    assert inner.clear_calls == 1
    assert inner.shutdown_calls == 1
    assert channel._inner is None

def test_channel_round_trips_through_peer() -> None:
    # Two SchcChannels over a shared capture: what one compresses, the other
    # decompresses back to the original CoAP bytes.
    cap = _Capture()
    sender = SchcChannel(cap, CLI)
    received: list[tuple[bytes, str]] = []
    receiver_channel = SchcChannel(_Capture(), SRV)
    receiver_channel.set_receiver(lambda data, src: received.append((data, src)))

    coap = b"\x40\x01\x12\x34\xffpayload"
    sender.send_datagram(coap, SRV)
    wire, _ = cap.sent[0]
    receiver_channel._on_inner(wire, CLI)
    assert received == [(coap, f"[{CLI}]")]


@pytest.mark.asyncio
async def test_coap_request_over_schc_channel() -> None:
    net = InMemoryNetwork()
    site = resource.Site()

    class _Hello(resource.Resource):
        async def render_get(self, request: Message) -> Message:
            return Message(payload=b"hi", code=aiocoap.CONTENT)

    site.add_resource(["test"], _Hello())

    server = await create_lichen_context(
        SchcChannel(net.channel(SRV), SRV), SRV, site=site
    )
    client = await create_lichen_context(SchcChannel(net.channel(CLI), CLI), CLI)
    try:
        resp = await client.request(
            Message(code=GET, uri=f"coap://[{SRV}]/test")
        ).response
        assert resp.payload == b"hi"
        assert resp.code == aiocoap.CONTENT
    finally:
        await client.shutdown()
        await server.shutdown()
