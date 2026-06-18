"""Tests for the SCHC-compressing CoAP channel (SCHC<->transport wiring)."""

from __future__ import annotations

import aiocoap
import pytest
from aiocoap import GET, Message, resource

from lichen.coap.schc_channel import SchcChannel, unwrap_coap, wrap_coap
from lichen.coap.transport import (
    DatagramChannel,
    InMemoryNetwork,
    create_lichen_context,
)
from lichen.ipv6.packet import IPv6Header
from lichen.ipv6.udp import UdpDatagram

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
    channel.send_datagram(b"\x40\x01\x12\x34hello", SRV)  # minimal CoAP-ish bytes
    assert len(cap.sent) == 1
    wire, dest = cap.sent[0]
    assert dest == SRV
    assert wire[0] == 0  # SCHC rule 0 (link-local CoAP) was applied


def test_channel_round_trips_through_peer() -> None:
    # Two SchcChannels over a shared capture: what one compresses, the other
    # decompresses back to the original CoAP bytes.
    cap = _Capture()
    sender = SchcChannel(cap, CLI)
    received: list[tuple[bytes, str]] = []
    receiver_channel = SchcChannel(_Capture(), SRV)
    receiver_channel.set_receiver(lambda data, src: received.append((data, src)))

    coap = b"\x40\x01\x12\x34payload"
    sender.send_datagram(coap, SRV)
    wire, _ = cap.sent[0]
    receiver_channel._on_inner(wire, CLI)
    assert received == [(coap, CLI)]


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
