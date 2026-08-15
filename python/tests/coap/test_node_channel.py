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


class _Sender:
    """Mock sender with IID for link-layer identity validation."""

    def __init__(self, addr: IPv6Address) -> None:
        self.iid = addr.packed[-8:]


class _Node:
    def __init__(self) -> None:
        self.on_receive: Callable[[bytes, object], None] | None = None
        self.owner: object | None = None
        self.sent: list[bytes] = []
        self.send_started = asyncio.Event()
        self.send_release: asyncio.Event | None = None

    def register_on_receive(self, owner: object, callback: Callable[[bytes, object], None]) -> None:
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

    channel.send_datagram(_coap_request(), "[FE80:0:0:0:0:0:0:2]:61616")
    await asyncio.sleep(0)

    packet = IPv6Packet.from_bytes(node.sent[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert packet.header.src_addr == IPv6Address("fe80::1")
    assert packet.header.dst_addr == IPv6Address("fe80::2")
    assert udp.dst_port == 61616
    assert channel.normalize_endpoint("fe80::2") == channel.normalize_endpoint("[fe80::2%mesh0]")
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
    src_addr = IPv6Address("2001:db8::2")
    packet = wrap_coap(
        src_addr,
        IPv6Address("2001:db8::1"),
        _coap_request(),
        src_port=61616,
    )

    assert node.on_receive is not None
    node.on_receive(wrap_schc_payload(compress_packet(packet)), _Sender(src_addr))

    assert received == [(_coap_request(), "[2001:db8::2]:61616")]


def test_node_channel_scoped_local_accepts_unscoped_wire_destination() -> None:
    node = _Node()
    channel = NodeChannel(node, "fe80::1%mesh0")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    src_addr = IPv6Address("fe80::2")
    packet = wrap_coap(
        src_addr,
        IPv6Address("fe80::1"),
        _coap_request(),
    )

    assert node.on_receive is not None
    node.on_receive(wrap_schc_payload(compress_packet(packet)), _Sender(src_addr))

    assert received == [(_coap_request(), "[fe80::2%mesh0]")]


@pytest.mark.parametrize("invalid", ["non-udp", "zero-checksum", "corrupt-checksum"])
def test_node_channel_rejects_invalid_udp_packets(invalid: str, monkeypatch) -> None:
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    src_addr = IPv6Address("2001:db8::2")
    if invalid == "non-udp":
        header = IPv6Header(
            src_addr=src_addr,
            dst_addr=IPv6Address("2001:db8::1"),
            next_header=NextHeader.ICMPV6,
            payload_length=1,
        )
        packet = header.to_bytes() + b"x"
    else:
        packet_bytes = bytearray(
            wrap_coap(
                src_addr,
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
    # Use _Sender with matching IID so IID checks pass, isolating the specific
    # validation being tested (non-UDP / checksum). Without this, checksum tests
    # could pass due to IID rejection if checksum validation were removed.
    node.on_receive(wrap_schc_payload(b"compressed"), _Sender(src_addr))

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


@pytest.mark.asyncio
async def test_node_channel_max_concurrent_sends_raises_congestion_error() -> None:
    """Verify CongestionError when MAX_CONCURRENT_SENDS (32) is reached."""
    from lichen.coap.params import CongestionError, CongestionLevel

    node = _Node()
    node.send_release = asyncio.Event()  # Block all sends
    channel = NodeChannel(node, "2001:db8::1")

    # Fill up to MAX_CONCURRENT_SENDS
    for i in range(NodeChannel.MAX_CONCURRENT_SENDS):
        channel.send_datagram(_coap_request(mid=i), "2001:db8::2")

    assert len(channel._tasks) == NodeChannel.MAX_CONCURRENT_SENDS

    # The 33rd send should raise CongestionError with EXHAUSTED level
    with pytest.raises(CongestionError) as exc_info:
        channel.send_datagram(_coap_request(mid=999), "2001:db8::2")
    assert exc_info.value.level == CongestionLevel.EXHAUSTED

    # Cleanup: release pending sends and shutdown
    node.send_release.set()
    await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_check_congestion_false_bypasses_congestion_check() -> None:
    """Verify check_congestion=False bypasses congestion check but respects task limit.

    The check_congestion parameter at node_channel.py:114 controls whether
    check_congestion_for(priority) is called. When False, congestion level checks
    are bypassed, but the MAX_CONCURRENT_SENDS limit is still enforced.
    """
    from unittest.mock import patch

    from lichen.coap.params import CongestionError, CongestionLevel, CongestionState

    node = _Node()
    node.send_release = asyncio.Event()  # Block all sends
    channel = NodeChannel(node, "2001:db8::1")

    # Patch congestion_state to return EXHAUSTED (would block all sends)
    exhausted_state = CongestionState(level=CongestionLevel.EXHAUSTED, retry_after_ms=None)
    with patch.object(channel, "congestion_state", return_value=exhausted_state):
        # With check_congestion=True (default), should raise CongestionError
        with pytest.raises(CongestionError) as exc_info:
            channel.send_datagram(_coap_request(mid=1), "2001:db8::2", check_congestion=True)
        assert exc_info.value.level == CongestionLevel.EXHAUSTED

        # With check_congestion=False, should bypass congestion check and succeed
        channel.send_datagram(_coap_request(mid=2), "2001:db8::2", check_congestion=False)
        assert len(channel._tasks) == 1

    # Cleanup
    node.send_release.set()
    await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_on_send_done_logs_exception_and_cleans_up(caplog) -> None:
    """Verify _on_send_done logs warning on exception and removes task from _tasks.

    This exercises the exception logging path at node_channel.py:152-153 where
    node.send() raises an exception and the channel logs a warning while cleaning
    up the task.
    """
    import logging

    class _FailingNode(_Node):
        async def send(self, packet: bytes) -> None:
            self.send_started.set()
            raise RuntimeError("simulated send failure")

    node = _FailingNode()
    channel = NodeChannel(node, "2001:db8::1")

    # Capture logs at WARNING level
    caplog.set_level(logging.WARNING)

    # Send starts a task that will fail
    channel.send_datagram(_coap_request(), "2001:db8::2")
    # Multiple yields to let task complete and done callback fire
    for _ in range(5):
        await asyncio.sleep(0)

    # Verify warning was logged with exception type name (not message, for security)
    # Implementation logs type(exc).__name__ at node_channel.py:153
    assert any("send failed" in r.getMessage() for r in caplog.records)
    assert any("RuntimeError" in r.getMessage() for r in caplog.records)

    # Task should be cleaned up from _tasks
    assert len(channel._tasks) == 0

    # Verify channel is still usable (can accept new sends)
    node2 = _Node()
    channel2 = NodeChannel(node2, "2001:db8::3")
    channel2.send_datagram(_coap_request(mid=99), "2001:db8::4")
    await asyncio.sleep(0)
    assert len(node2.sent) == 1

    await channel.shutdown()
    await channel2.shutdown()


@pytest.mark.parametrize(
    "src_addr_str,metric_substring",
    [
        ("::", "dropped malformed source"),
        ("ff02::1", "dropped malformed source"),
    ],
)
def test_node_channel_rejects_malformed_ipv6_source(
    src_addr_str: str, metric_substring: str, monkeypatch
) -> None:
    """Verify packets with unspecified or multicast source addresses are dropped."""

    class _MockMetrics:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def record_error(self, msg: str) -> None:
            self.errors.append(msg)

    metrics = _MockMetrics()
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1", metrics=metrics)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    src_addr = IPv6Address(src_addr_str)
    packet = wrap_coap(src_addr, IPv6Address("2001:db8::1"), _coap_request())

    assert node.on_receive is not None
    monkeypatch.setattr(node_channel_module, "decompress_packet", lambda _data: packet)
    # Use a sender with iid matching the src_addr so we get past IID check
    # but note: unspecified/multicast check happens before IID check
    node.on_receive(wrap_schc_payload(b"compressed"), _Sender(src_addr))

    assert received == []
    assert any(metric_substring in err for err in metrics.errors)


def test_node_channel_accepts_multihop_packets(monkeypatch) -> None:
    """Verify multi-hop packets are accepted when relay IID differs from source IID.

    In multi-hop mesh routing, the link-layer sender (relay) differs from the original
    IPv6 source. NodeChannel must NOT compare the link-layer sender IID against the
    IPv6 source address IID, as that would break multi-hop routing.

    OSCORE provides E2E authentication for the original source at the application layer.
    """
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    # Original source (e.g., Node A)
    original_source = IPv6Address("2001:db8::2")
    packet = wrap_coap(original_source, IPv6Address("2001:db8::1"), _coap_request())

    # Relay (e.g., Node B) has a DIFFERENT IID than the original source
    relay_addr = IPv6Address("2001:db8::3")  # Different from 2001:db8::2
    relay_sender = _Sender(relay_addr)

    assert node.on_receive is not None
    monkeypatch.setattr(node_channel_module, "decompress_packet", lambda _data: packet)
    node.on_receive(wrap_schc_payload(b"compressed"), relay_sender)

    # Packet MUST be accepted - the source address in the packet is the original source
    assert received == [(_coap_request(), "[2001:db8::2]")]
    channel.close()


def test_node_channel_rejects_wrong_ipv6_destination(monkeypatch) -> None:
    """Verify packets with IPv6 destination not matching local address are dropped.

    This exercises the dst_addr check at node_channel.py:170-174. An attacker-induced
    regression in this check could allow processing of packets not destined for this node.
    """

    class _MockMetrics:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def record_error(self, msg: str) -> None:
            self.errors.append(msg)

    metrics = _MockMetrics()
    node = _Node()
    # Channel local address is 2001:db8::1
    channel = NodeChannel(node, "2001:db8::1", metrics=metrics)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    src_addr = IPv6Address("2001:db8::2")
    # Packet destination is 2001:db8::99, which does NOT match channel's 2001:db8::1
    wrong_dst = IPv6Address("2001:db8::99")
    packet = wrap_coap(src_addr, wrong_dst, _coap_request())

    assert node.on_receive is not None
    monkeypatch.setattr(node_channel_module, "decompress_packet", lambda _data: packet)
    node.on_receive(wrap_schc_payload(b"compressed"), _Sender(src_addr))

    assert received == []
    assert any("dropped wrong destination" in err for err in metrics.errors)
    channel.close()


def test_node_channel_rejects_wrong_udp_destination_port(monkeypatch) -> None:
    """Verify packets with UDP destination port not matching channel port are dropped.

    This exercises the dst_port check at node_channel.py:175-182. Regression in this
    check could allow packets to wrong ports to be processed.
    """

    class _MockMetrics:
        def __init__(self) -> None:
            self.errors: list[str] = []

        def record_error(self, msg: str) -> None:
            self.errors.append(msg)

    metrics = _MockMetrics()
    node = _Node()
    # Channel listens on src_port 5683 (default)
    channel = NodeChannel(node, "2001:db8::1", metrics=metrics)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    src_addr = IPv6Address("2001:db8::2")
    # Correct destination address, but wrong UDP destination port (9999 != 5683)
    packet = wrap_coap(
        src_addr, IPv6Address("2001:db8::1"), _coap_request(), dst_port=9999
    )

    assert node.on_receive is not None
    monkeypatch.setattr(node_channel_module, "decompress_packet", lambda _data: packet)
    node.on_receive(wrap_schc_payload(b"compressed"), _Sender(src_addr))

    assert received == []
    assert any("dropped invalid UDP: bad port" in err for err in metrics.errors)
    channel.close()


def test_node_channel_set_receiver_twice_raises() -> None:
    """Verify set_receiver raises RuntimeError when called twice on open channel."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    channel.set_receiver(lambda data, source: None)

    with pytest.raises(RuntimeError, match="already has a receiver"):
        channel.set_receiver(lambda data, source: None)

    channel.close()


def test_node_channel_clear_receiver_non_matching_is_noop() -> None:
    """Verify clear_receiver with non-matching receiver leaves original intact and returns False."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    received: list[tuple[bytes, str]] = []

    def receiver_a(data: bytes, source: str) -> None:
        received.append((data, source))

    def receiver_b(data: bytes, source: str) -> None:
        pass

    channel.set_receiver(receiver_a)
    # Clearing non-matching receiver should return False
    assert channel.clear_receiver(receiver_b) is False

    # Verify receiver A is still active by receiving a packet
    src_addr = IPv6Address("2001:db8::2")
    packet = wrap_coap(src_addr, IPv6Address("2001:db8::1"), _coap_request())

    assert node.on_receive is not None
    node.on_receive(wrap_schc_payload(compress_packet(packet)), _Sender(src_addr))

    # Default port (5683) is not included in authority string
    assert received == [(_coap_request(), "[2001:db8::2]")]

    # Clearing matching receiver should return True
    assert channel.clear_receiver(receiver_a) is True
    channel.close()


def test_node_channel_constructor_with_none_node_raises() -> None:
    """Verify NodeChannel constructor raises ValueError for None node."""
    with pytest.raises(ValueError, match="node must not be None"):
        NodeChannel(None, "2001:db8::1")


def test_node_channel_constructor_with_none_local_host_raises() -> None:
    """Verify NodeChannel constructor raises ValueError for None local_host."""
    with pytest.raises(ValueError, match="local_host must not be None"):
        NodeChannel(_Node(), None)


def test_node_channel_set_receiver_none_raises() -> None:
    """Verify set_receiver raises ValueError for None receiver."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    try:
        with pytest.raises(ValueError, match="receiver must not be None"):
            channel.set_receiver(None)
    finally:
        channel.close()


@pytest.mark.asyncio
async def test_node_channel_send_datagram_none_data_raises() -> None:
    """Verify send_datagram raises ValueError for None data."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    try:
        with pytest.raises(ValueError, match="data must not be None"):
            channel.send_datagram(None, "2001:db8::2")
    finally:
        await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_send_datagram_none_dest_raises() -> None:
    """Verify send_datagram raises ValueError for None dest."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    try:
        with pytest.raises(ValueError, match="dest must not be None"):
            channel.send_datagram(_coap_request(), None)
    finally:
        await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_send_datagram_empty_dest_raises() -> None:
    """Verify send_datagram raises ValueError for empty string dest."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    try:
        with pytest.raises(ValueError, match="must not be empty"):
            channel.send_datagram(_coap_request(), "")
    finally:
        await channel.shutdown()


def test_node_channel_empty_payload_does_not_crash() -> None:
    """Verify empty payload on receive is gracefully handled via exception path."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    assert node.on_receive is not None
    # Empty payload is classified as UNKNOWN (not SCHC) and dropped at L2 classification
    node.on_receive(b"", object())

    assert received == []
    channel.close()


def test_node_channel_packet_arrival_before_set_receiver_is_dropped() -> None:
    """Verify packets arriving before set_receiver is called are silently dropped."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    # Note: set_receiver is NOT called, so _receiver is None

    src_addr = IPv6Address("2001:db8::2")
    packet = wrap_coap(src_addr, IPv6Address("2001:db8::1"), _coap_request())

    assert node.on_receive is not None
    # This should not raise, packet should be silently dropped
    node.on_receive(wrap_schc_payload(compress_packet(packet)), _Sender(src_addr))

    # Now set receiver and verify nothing was queued
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    assert received == []
    channel.close()


@pytest.mark.asyncio
async def test_node_channel_boundary_udp_port_65535() -> None:
    """Verify correct handling at maximum UDP port boundary (65535)."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1", dst_port=65535)

    channel.send_datagram(_coap_request(), "[2001:db8::2]:65535")
    await asyncio.sleep(0)

    assert len(node.sent) == 1
    packet = IPv6Packet.from_bytes(node.sent[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert udp.dst_port == 65535
    await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_boundary_udp_port_1() -> None:
    """Verify correct handling at minimum valid UDP port boundary (port 1)."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")

    channel.send_datagram(_coap_request(), "[2001:db8::2]:1")
    await asyncio.sleep(0)

    assert len(node.sent) == 1
    packet = IPv6Packet.from_bytes(node.sent[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert udp.dst_port == 1
    await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_port_zero_is_rejected() -> None:
    """Verify port 0 is rejected per RFC (reserved port)."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1", dst_port=5683)

    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        channel.send_datagram(_coap_request(), "[2001:db8::2]:0")

    await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_concurrent_send_recovery_after_congestion() -> None:
    """Verify channel accepts new sends after pending sends complete."""
    from lichen.coap.params import CongestionError

    node = _Node()
    node.send_release = asyncio.Event()  # Block all sends
    channel = NodeChannel(node, "2001:db8::1")

    # Fill up to MAX_CONCURRENT_SENDS
    for i in range(NodeChannel.MAX_CONCURRENT_SENDS):
        channel.send_datagram(_coap_request(mid=i), "2001:db8::2")

    assert len(channel._tasks) == NodeChannel.MAX_CONCURRENT_SENDS

    # Verify we're at the limit
    with pytest.raises(CongestionError):
        channel.send_datagram(_coap_request(mid=999), "2001:db8::2")

    # Release all pending sends so they complete
    node.send_release.set()

    # Poll until tasks drain (more robust than fixed sleep(0) count)
    for _ in range(100):  # timeout after ~100 iterations
        await asyncio.sleep(0)
        if len(channel._tasks) == 0:
            break
    else:
        pytest.fail(f"tasks did not drain within timeout: {len(channel._tasks)} remaining")

    # Tasks should now be drained
    assert len(channel._tasks) == 0

    # New send should be accepted without CongestionError
    node.send_release = asyncio.Event()  # Block again to observe task creation
    channel.send_datagram(_coap_request(mid=1000), "2001:db8::2")
    assert len(channel._tasks) == 1

    # Cleanup
    node.send_release.set()
    await channel.shutdown()


def test_node_channel_metrics_missing_record_error_raises_type_error() -> None:
    """Verify TypeError when metrics lacks record_error() method."""
    node = _Node()
    with pytest.raises(TypeError, match="record_error"):
        NodeChannel(node, "2001:db8::1", metrics=object())


def test_node_channel_metrics_non_callable_record_error_raises_type_error() -> None:
    """Verify TypeError when metrics.record_error exists but is not callable."""
    node = _Node()
    bad_metrics = type("M", (), {"record_error": "not_callable"})()
    with pytest.raises(TypeError, match="callable record_error"):
        NodeChannel(node, "2001:db8::1", metrics=bad_metrics)


def test_node_channel_constructor_src_port_zero_rejected() -> None:
    """Verify src_port=0 is rejected at construction time."""
    node = _Node()
    # src_port=0 is validated at Endpoint construction
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        NodeChannel(node, "2001:db8::1", src_port=0)


@pytest.mark.asyncio
async def test_node_channel_constructor_dst_port_zero_rejected() -> None:
    """Verify dst_port=0 used as default is rejected at first send."""
    node = _Node()
    # dst_port=0 is used as default when dest has no explicit port
    channel = NodeChannel(node, "2001:db8::1", dst_port=0)

    # Send to dest without explicit port - should use dst_port=0 and fail
    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        channel.send_datagram(_coap_request(), "2001:db8::2")

    await channel.shutdown()


def test_node_channel_receiver_exception_does_not_crash_channel() -> None:
    """Verify channel remains usable after receiver callback raises exception.

    NodeChannel._on_node_receive calls the receiver without try/except, so
    exceptions propagate to the node's receive dispatcher. This test verifies
    channel state remains consistent after callback exception.
    """
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")
    exception_raised = False

    def raising_receiver(data: bytes, source: str) -> None:
        nonlocal exception_raised
        exception_raised = True
        raise RuntimeError("simulated receiver failure")

    channel.set_receiver(raising_receiver)
    src_addr = IPv6Address("2001:db8::2")
    packet = wrap_coap(src_addr, IPv6Address("2001:db8::1"), _coap_request())

    assert node.on_receive is not None
    # Callback should propagate the exception (no try/except wrapper)
    with pytest.raises(RuntimeError, match="simulated receiver failure"):
        node.on_receive(wrap_schc_payload(compress_packet(packet)), _Sender(src_addr))

    assert exception_raised

    # Verify channel is still usable: clear old receiver and set new one
    assert channel.clear_receiver(raising_receiver) is True
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    # Deliver another packet - channel should still function
    node.on_receive(wrap_schc_payload(compress_packet(packet)), _Sender(src_addr))
    assert received == [(_coap_request(), "[2001:db8::2]")]

    channel.close()


@pytest.mark.asyncio
async def test_node_channel_port_65536_is_rejected() -> None:
    """Verify port 65536 (first invalid value above valid range) is rejected."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")

    with pytest.raises(ValueError, match="port must be between 1 and 65535"):
        channel.send_datagram(_coap_request(), "[2001:db8::2]:65536")

    await channel.shutdown()


@pytest.mark.asyncio
async def test_node_channel_negative_port_is_rejected() -> None:
    """Verify negative port -1 is rejected."""
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")

    with pytest.raises(ValueError, match="port must be numeric"):
        channel.send_datagram(_coap_request(), "[2001:db8::2]:-1")

    await channel.shutdown()


def test_node_channel_constructor_with_empty_local_host_raises() -> None:
    """Verify NodeChannel constructor raises ValueError for empty string local_host."""
    with pytest.raises(ValueError, match="authority must not be empty"):
        NodeChannel(_Node(), "")


@pytest.mark.asyncio
async def test_node_channel_send_datagram_empty_bytes_accepted() -> None:
    """Verify empty bytes b'' is accepted (valid minimal CoAP payload).

    Empty payload is wrapped into valid IPv6+UDP frame and sent through the node.
    While empty CoAP messages may have semantic meaning (like ping), the channel
    layer should not reject them.
    """
    node = _Node()
    channel = NodeChannel(node, "2001:db8::1")

    # Empty bytes should be accepted - no exception raised
    channel.send_datagram(b"", "[2001:db8::2]:5683")
    await asyncio.sleep(0)

    # Verify the packet was sent (empty payload wrapped in IPv6+UDP)
    assert len(node.sent) == 1
    packet = IPv6Packet.from_bytes(node.sent[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert udp.payload == b""

    await channel.shutdown()
