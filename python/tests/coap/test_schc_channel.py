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
    Priority,
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
        self.sent_with_opts: list[tuple[bytes, str, dict]] = []
        self._receiver = None

    def set_receiver(self, receiver) -> None:
        self._receiver = receiver

    def send_datagram(
        self, data: bytes, dest: str, *, priority=None, check_congestion=None
    ) -> None:
        self.sent.append((data, dest))
        self.sent_with_opts.append(
            (data, dest, {"priority": priority, "check_congestion": check_congestion})
        )

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


def test_wrap_unwrap_empty_payload() -> None:
    """Verify wrap_coap/unwrap_coap round-trips correctly with empty CoAP payload."""
    from ipaddress import IPv6Address

    raw = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"")
    header = IPv6Header.from_bytes(raw)
    assert header.next_header == 17
    assert unwrap_coap(raw) == b""
    udp = UdpDatagram.from_bytes(raw[40:])
    assert udp.dst_port == 5683
    assert udp.payload == b""


def test_channel_emits_schc_compressed_bytes() -> None:
    cap = _Capture()
    channel = SchcChannel(cap, CLI)
    channel.send_datagram(b"\x40\x01\x12\x34\xffhello", SRV)
    assert len(cap.sent) == 1
    wire, dest = cap.sent[0]
    assert dest == f"[{SRV}]"
    assert wire[0] == 0  # SCHC rule 0 (link-local CoAP) was applied


def test_send_datagram_forwards_priority_and_check_congestion() -> None:
    """Verify send_datagram forwards priority and check_congestion to inner channel."""
    cap = _Capture()
    channel = SchcChannel(cap, CLI)

    # Send with non-default priority and check_congestion=False
    channel.send_datagram(b"coap", SRV, priority=Priority.URGENT, check_congestion=False)

    assert len(cap.sent_with_opts) == 1
    _, _, opts = cap.sent_with_opts[0]
    assert opts["priority"] == Priority.URGENT
    assert opts["check_congestion"] is False


def test_set_receiver_none_raises_type_error() -> None:
    """Verify set_receiver(None) raises TypeError."""
    channel = SchcChannel(_Capture(), CLI)
    with pytest.raises(TypeError, match="receiver must be a callable"):
        channel.set_receiver(None)


def test_constructor_rejects_none_inner() -> None:
    """Verify SchcChannel(None, ...) raises TypeError."""
    with pytest.raises(TypeError, match="inner channel must not be None"):
        SchcChannel(None, CLI)


@pytest.mark.parametrize(
    "invalid_local",
    [
        "not-an-ip",  # Not a valid IPv6 address
        "[fe80::1",  # Mismatched bracket
        "",  # Empty string
    ],
)
def test_constructor_rejects_malformed_local_host(invalid_local: str) -> None:
    """Verify SchcChannel rejects malformed local_host values."""
    with pytest.raises(ValueError):
        SchcChannel(_Capture(), invalid_local)


def test_set_receiver_double_registration_raises_runtime_error() -> None:
    """Verify set_receiver raises RuntimeError when receiver already set."""
    channel = SchcChannel(_Capture(), CLI)
    channel.set_receiver(lambda data, source: None)
    with pytest.raises(RuntimeError, match="channel already has a receiver"):
        channel.set_receiver(lambda data, source: None)


def test_channel_uses_explicit_ipv6_destination_port() -> None:
    cap = _Capture()
    channel = SchcChannel(cap, CLI, dst_port=5684)
    channel.send_datagram(b"coap", f"[{SRV}]:5685")

    wire, dest = cap.sent[0]
    udp = UdpDatagram.from_bytes(decompress_packet(wire)[40:])
    assert dest == f"[{SRV}]:5685"
    assert udp.dst_port == 5685


def test_channel_preserves_inbound_udp_source_port() -> None:
    channel = SchcChannel(_Capture(), SRV)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    packet = wrap_coap(
        IPv6Address(CLI),
        IPv6Address(SRV),
        b"coap",
        src_port=5684,
    )

    channel._on_inner(compress_packet(packet), f"[{CLI}]:5684")

    assert received == [(b"coap", f"[{CLI}]:5684")]


def test_receiver_callback_exception_propagates() -> None:
    """Verify exceptions in receiver callback propagate from _on_inner.

    Receivers must be exception-safe; the channel does not catch callback errors.
    """
    channel = SchcChannel(_Capture(), SRV)

    class _CallbackError(Exception):
        pass

    def raising_receiver(data: bytes, source: str) -> None:
        raise _CallbackError("receiver failed")

    channel.set_receiver(raising_receiver)
    packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"coap")

    with pytest.raises(_CallbackError, match="receiver failed"):
        channel._on_inner(compress_packet(packet), f"[{CLI}]")


def test_channel_preserves_scope_and_canonicalizes_source_alias() -> None:
    cap = _Capture()
    sender = SchcChannel(cap, "FE80:0:0:0:0:0:0:1%radio0")
    sender.send_datagram(b"coap", "[FE80:0:0:0:0:0:0:2%radio0]:5685")

    wire, dest = cap.sent[0]
    packet = IPv6Header.from_bytes(decompress_packet(wire))
    assert packet.src_addr == IPv6Address(CLI)
    assert packet.dst_addr == IPv6Address(SRV)
    assert dest == f"[{SRV}%radio0]:5685"

    receiver = SchcChannel(_Capture(), f"{SRV}%radio0", src_port=5685)
    received: list[tuple[bytes, str]] = []
    receiver.set_receiver(lambda data, source: received.append((data, source)))
    receiver._on_inner(wire, "[FE80:0:0:0:0:0:0:1%radio0]")
    assert received == [(b"coap", f"[{CLI}%radio0]")]


@pytest.mark.parametrize(
    "invalid",
    [
        "empty",
        "non-udp",
        "zero-checksum",
        "corrupt-checksum",
        "dst-mismatch",
        "dst-port-mismatch",
        "src-mismatch",
    ],
)
def test_channel_rejects_invalid_udp_packets(invalid: str, monkeypatch) -> None:
    channel = SchcChannel(_Capture(), SRV)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    if invalid == "empty":
        # Empty compressed data - decompress_packet raises ValueError('empty SCHC packet')
        # which should be silently caught
        channel._on_inner(b"", CLI)
        assert received == []
        return
    if invalid == "non-udp":
        header = IPv6Header(
            src_addr=IPv6Address(CLI),
            dst_addr=IPv6Address(SRV),
            next_header=NextHeader.ICMPV6,
            payload_length=1,
        )
        packet = header.to_bytes() + b"x"
    elif invalid == "dst-mismatch":
        # Packet addressed to different IPv6 address than channel's local address
        wrong_dest = "fe80::dead"
        packet = wrap_coap(IPv6Address(CLI), IPv6Address(wrong_dest), b"coap")
    elif invalid == "dst-port-mismatch":
        # Packet with dst_port different from channel's src_port (5683)
        packet = wrap_coap(
            IPv6Address(CLI), IPv6Address(SRV), b"coap", dst_port=9999
        )
    elif invalid == "src-mismatch":
        # Packet claims to be from CLI but transport reports different source
        packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"coap")
        monkeypatch.setattr(schc_channel_module, "decompress_packet", lambda _data: packet)
        # Deliver from different transport source than packet's src_addr
        channel._on_inner(b"compressed", "[fe80::beef]")
        assert received == []
        return
    else:
        packet_bytes = bytearray(wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"coap"))
        if invalid == "zero-checksum":
            packet_bytes[46:48] = b"\x00\x00"
        else:
            packet_bytes[-1] ^= 0xFF
        packet = bytes(packet_bytes)

    monkeypatch.setattr(schc_channel_module, "decompress_packet", lambda _data: packet)
    channel._on_inner(b"compressed", f"[{CLI}]")

    assert received == []


def test_channel_rejects_oversized_packets(monkeypatch) -> None:
    """Verify packets exceeding MAX_PACKET_SIZE (1280 bytes) are silently dropped."""
    channel = SchcChannel(_Capture(), SRV)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    # Create a valid small packet (52 bytes) - should be accepted
    valid_packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"coap")
    monkeypatch.setattr(schc_channel_module, "decompress_packet", lambda _data: valid_packet)
    channel._on_inner(b"compressed", f"[{CLI}]")
    assert len(received) == 1
    received.clear()

    # Create packet at exactly MAX_PACKET_SIZE (1280 bytes) - should be accepted
    # Payload = 1280 - 40 (IPv6) - 8 (UDP) = 1232 bytes
    boundary_payload = b"x" * 1232
    boundary_packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), boundary_payload)
    assert len(boundary_packet) == 1280  # Verify test setup
    monkeypatch.setattr(schc_channel_module, "decompress_packet", lambda _data: boundary_packet)
    channel._on_inner(b"compressed", f"[{CLI}]")
    assert len(received) == 1
    assert received[0][0] == boundary_payload
    received.clear()

    # Create packet exceeding MAX_PACKET_SIZE (1281 bytes) - should be dropped
    oversized_payload = b"x" * 1233
    oversized_packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), oversized_payload)
    assert len(oversized_packet) == 1281  # Verify test setup
    monkeypatch.setattr(schc_channel_module, "decompress_packet", lambda _data: oversized_packet)
    channel._on_inner(b"compressed", f"[{CLI}]")
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

    # When both clear_receiver and close raise, the second exception is raised
    # with the first preserved in __context__ (exception chaining)
    assert raised.value is inner.close_error
    assert raised.value.__context__ is inner.clear_error
    assert shutdown_result == [inner.close_error]
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

    # When both clear_receiver and shutdown raise, the second exception is raised
    # with the first preserved in __context__ (exception chaining)
    assert results[0] is inner.shutdown_error
    assert results[0].__context__ is inner.clear_error
    assert results[1] is inner.shutdown_error
    assert repeated == [inner.shutdown_error]
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

    server = await create_lichen_context(SchcChannel(net.channel(SRV), SRV), SRV, site=site)
    client = await create_lichen_context(SchcChannel(net.channel(CLI), CLI), CLI)
    try:
        resp = await client.request(Message(code=GET, uri=f"coap://[{SRV}]/test")).response
        assert resp.payload == b"hi"
        assert resp.code == aiocoap.CONTENT
    finally:
        await client.shutdown()
        await server.shutdown()


def test_send_datagram_rejects_oversized_packets() -> None:
    """Verify send_datagram raises ValueError when packet exceeds MAX_PACKET_SIZE."""
    cap = _Capture()
    channel = SchcChannel(cap, CLI)

    # Payload = 1280 - 40 (IPv6) - 8 (UDP) = 1232 bytes - should succeed
    boundary_payload = b"x" * 1232
    channel.send_datagram(boundary_payload, SRV)
    assert len(cap.sent) == 1
    cap.sent.clear()

    # Payload = 1233 bytes -> 1281 byte packet - should fail
    oversized_payload = b"x" * 1233
    with pytest.raises(ValueError, match="too large for SCHC channel"):
        channel.send_datagram(oversized_payload, SRV)


def test_channel_sends_empty_coap_payload() -> None:
    """Verify send_datagram compresses and transmits empty CoAP message body."""
    cap = _Capture()
    channel = SchcChannel(cap, CLI)
    channel.send_datagram(b"", SRV)

    assert len(cap.sent) == 1
    wire, dest = cap.sent[0]
    assert dest == f"[{SRV}]"

    # Decompress and verify empty payload round-trips
    raw = decompress_packet(wire)
    coap_payload = unwrap_coap(raw)
    assert coap_payload == b""


def test_send_datagram_rejects_none_data() -> None:
    """Verify send_datagram rejects None instead of bytes.

    The implementation may raise TypeError, AttributeError, or ValueError
    depending on where None is first used in the call chain. All are acceptable
    since None is never valid input for data.
    """
    channel = SchcChannel(_Capture(), CLI)
    with pytest.raises((TypeError, AttributeError, ValueError)):
        channel.send_datagram(None, SRV)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_send_datagram_during_shutdown_raises_closed() -> None:
    """Verify send_datagram raises RuntimeError if called during shutdown."""
    inner = _BlockingInner()
    channel = SchcChannel(inner, CLI)

    # Start shutdown but don't release it
    shutdown_task = asyncio.create_task(channel.shutdown())
    await inner.shutdown_started.wait()

    # Attempt to send while shutdown is in progress
    with pytest.raises(RuntimeError, match="closed"):
        channel.send_datagram(b"data", SRV)

    # Release shutdown to clean up
    inner.shutdown_release.set()
    await shutdown_task


def test_clear_receiver_none_does_not_clear() -> None:
    """Verify clear_receiver(None) does not clear a non-None receiver."""
    channel = SchcChannel(_Capture(), SRV)
    received: list[tuple[bytes, str]] = []

    def receiver(data: bytes, source: str) -> None:
        received.append((data, source))

    channel.set_receiver(receiver)

    # clear_receiver(None) should be a no-op when receiver is set
    channel.clear_receiver(None)
    assert channel._receiver is receiver

    # clear_receiver with actual receiver should clear
    channel.clear_receiver(receiver)
    assert channel._receiver is None


def test_on_inner_without_receiver_drops_silently() -> None:
    """Verify _on_inner drops packets silently when no receiver is set."""
    channel = SchcChannel(_Capture(), SRV)
    # Do not set a receiver - channel._receiver remains None
    packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"coap")
    compressed = compress_packet(packet)

    # Should not raise any exception
    channel._on_inner(compressed, f"[{CLI}]")


def test_set_receiver_after_clear_receiver() -> None:
    """Verify set_receiver succeeds after clear_receiver."""
    channel = SchcChannel(_Capture(), SRV)
    received_first: list[tuple[bytes, str]] = []
    received_second: list[tuple[bytes, str]] = []

    def first_receiver(data: bytes, source: str) -> None:
        received_first.append((data, source))

    def second_receiver(data: bytes, source: str) -> None:
        received_second.append((data, source))

    # Set and clear first receiver
    channel.set_receiver(first_receiver)
    channel.clear_receiver(first_receiver)

    # Set a new receiver after clearing
    channel.set_receiver(second_receiver)

    # Verify the new receiver works
    packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"hello")
    channel._on_inner(compress_packet(packet), f"[{CLI}]")

    assert received_first == []
    assert received_second == [(b"hello", f"[{CLI}]")]


def test_inbound_packet_after_close_is_dropped() -> None:
    """Verify packets arriving after close() are silently dropped."""
    inner = _RecordingInner()
    channel = SchcChannel(inner, SRV)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    # Verify receiver works before close
    valid_packet = wrap_coap(IPv6Address(CLI), IPv6Address(SRV), b"before")
    channel._on_inner(compress_packet(valid_packet), f"[{CLI}]")
    assert len(received) == 1
    received.clear()

    # Close the channel
    channel.close()

    # Packets after close should be dropped (receiver not invoked)
    channel._on_inner(compress_packet(valid_packet), f"[{CLI}]")
    assert received == []


@pytest.mark.parametrize(
    "invalid_dest,error_pattern",
    [
        ("", "must not be empty"),
        ("not-an-ip", ".*"),  # IPv6Address error message varies by Python version
        ("[fe80::1", "mismatched brackets"),
        ("[fe80::1]:0", "port must be between 1 and 65535"),  # Port 0 rejected
        ("[fe80::1]:65536", "port must be between 1 and 65535"),  # Port overflow
        ("[fe80::1]:-1", "port must be numeric"),  # Negative port rejected
    ],
)
def test_send_datagram_rejects_malformed_destinations(
    invalid_dest: str, error_pattern: str
) -> None:
    """Verify send_datagram raises ValueError for malformed destination strings."""
    channel = SchcChannel(_Capture(), CLI)
    with pytest.raises(ValueError, match=error_pattern):
        channel.send_datagram(b"data", invalid_dest)


def test_send_datagram_rejects_none_destination() -> None:
    """Verify send_datagram rejects None destination."""
    channel = SchcChannel(_Capture(), CLI)
    with pytest.raises((TypeError, AttributeError)):
        channel.send_datagram(b"data", None)  # type: ignore[arg-type]


def test_port_boundary_65535_parses_successfully() -> None:
    """Verify port 65535 (max valid) is accepted by destination parsing.

    This tests the parsing layer directly. The send_datagram path may fail
    later in SCHC compression if the port is not profile-compatible, but
    parsing should succeed for any port in the valid range [1, 65535].
    """
    from lichen.coap.transport import parse_channel_endpoint

    endpoint = parse_channel_endpoint(f"[{SRV}]:65535")
    assert endpoint.port == 65535
    assert endpoint.host == SRV


def test_custom_resolve_callback_failure() -> None:
    """Verify exception from resolve callback propagates from send_datagram."""

    def failing_resolve(host: str) -> IPv6Address:
        # Allow local_host resolution but fail on destination
        if host == CLI:
            return IPv6Address(CLI)
        raise ValueError(f"cannot resolve {host}")

    channel = SchcChannel(_Capture(), CLI, resolve=failing_resolve)

    with pytest.raises(ValueError, match="cannot resolve"):
        channel.send_datagram(b"coap", SRV)
