"""Tests for KISS-LICHEN bridge."""

import asyncio
from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from lichen.interface.kiss import (
    KissHandler,
    ax25_decode,
    ax25_encode,
    kiss_decode,
)
from lichen.interface.kiss.bridge import (
    PORT_AX25,
    PORT_RAW,
    KissBridge,
)
from lichen.interface.kiss.callsign import iid_to_callsign
from lichen.l2_payload import L2_DISPATCH_ROUTING


@dataclass
class MockIdentity:
    """Mock identity for testing."""

    iid: bytes = field(
        default_factory=lambda: bytes(
            [0xFE, 0x80, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33]
        )
    )
    pubkey: bytes = field(default_factory=lambda: b"x" * 32)
    privkey: bytes = field(default_factory=lambda: b"p" * 32)


@dataclass
class MockPeerIdentity:
    """Mock peer identity."""

    iid: bytes
    pubkey: bytes = field(default_factory=lambda: b"y" * 32)


@dataclass
class MockLichenFrame:
    """Mock LICHEN frame."""

    payload: bytes
    dst_addr: bytes = b""


@dataclass
class MockRxFrame:
    """Mock received frame."""

    frame: MockLichenFrame
    sender: MockPeerIdentity
    rssi_dbm: int = -50
    snr_db: int = 10


@dataclass
class MockLinkLayer:
    """Mock LinkLayer for testing."""

    sent_frames: list = field(default_factory=list)
    rx_queue: asyncio.Queue = field(default_factory=asyncio.Queue)

    async def send(self, payload: bytes, dst_addr: bytes = b"", **kwargs) -> bool:
        self.sent_frames.append((payload, dst_addr))
        return True

    async def receive(self, timeout_ms: int) -> MockRxFrame | None:
        try:
            return await asyncio.wait_for(self.rx_queue.get(), timeout=timeout_ms / 1000)
        except TimeoutError:
            return None


@pytest.fixture
def mock_identity():
    return MockIdentity()


@pytest.fixture
def mock_link_layer():
    return MockLinkLayer()


@pytest.fixture
def mock_peer():
    return MockPeerIdentity(iid=bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC]))


@pytest.fixture
def bridge(mock_identity, mock_link_layer):
    handler = KissHandler()
    return KissBridge(
        link_layer=mock_link_layer,
        identity=mock_identity,
        handler=handler,
        peer_lookup=lambda iid: None,
    )


class TestBridgeInit:
    def test_creates_with_handler(self, bridge):
        assert bridge.handler is not None

    def test_wires_tx_callback(self, bridge):
        assert bridge.handler.on_tx_frame is not None

    def test_own_callsign_from_iid(self, bridge, mock_identity):
        expected = iid_to_callsign(mock_identity.iid)
        assert bridge.own_callsign == expected

    def test_adds_own_iid_to_peer_table(self, bridge, mock_identity):
        suffix = (mock_identity.iid[5] << 16) | (mock_identity.iid[6] << 8) | mock_identity.iid[7]
        assert bridge._peer_table.lookup_by_suffix(suffix) == mock_identity.iid


class TestBridgeTxAx25:
    @pytest.mark.asyncio
    async def test_ax25_tx_sends_payload(self, bridge, mock_link_layer, mock_peer):
        # Add peer so we can resolve callsign
        bridge.add_peer(mock_peer)

        # Build AX.25 frame
        dst_call = iid_to_callsign(mock_peer.iid)
        ax25_frame = ax25_encode("LTEST", dst_call, b"hello")

        # Trigger TX via handler
        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)

        # Wait for async send
        await asyncio.sleep(0.01)

        assert len(mock_link_layer.sent_frames) == 1
        payload, dst = mock_link_layer.sent_frames[0]
        assert payload == b"hello"
        assert dst == mock_peer.iid

    @pytest.mark.asyncio
    async def test_ax25_tx_broadcast(self, bridge, mock_link_layer):
        # Build AX.25 frame to CQ (broadcast)
        ax25_frame = ax25_encode("LTEST", "CQ", b"broadcast")

        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)
        await asyncio.sleep(0.01)

        assert len(mock_link_layer.sent_frames) == 1
        payload, dst = mock_link_layer.sent_frames[0]
        assert payload == b"broadcast"
        assert dst == b""  # broadcast

    @pytest.mark.asyncio
    async def test_ax25_tx_unknown_dest_dropped(self, bridge, mock_link_layer):
        # Build AX.25 frame to unknown callsign
        ax25_frame = ax25_encode("LTEST", "LUNKNOWN", b"dropped")

        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)
        await asyncio.sleep(0.01)

        # Should not send (unknown destination)
        assert len(mock_link_layer.sent_frames) == 0

    @pytest.mark.asyncio
    async def test_ax25_tx_invalid_frame_dropped(self, bridge, mock_link_layer):
        # Invalid AX.25 frame
        bridge.handler.on_tx_frame(PORT_AX25, b"garbage")
        await asyncio.sleep(0.01)

        assert len(mock_link_layer.sent_frames) == 0


class TestBridgeTxRaw:
    @pytest.mark.asyncio
    async def test_raw_tx_sends_directly(self, bridge, mock_link_layer):
        raw_payload = b"raw lichen frame"

        bridge.handler.on_tx_frame(PORT_RAW, raw_payload)
        await asyncio.sleep(0.01)

        assert len(mock_link_layer.sent_frames) == 1
        payload, dst = mock_link_layer.sent_frames[0]
        assert payload == raw_payload
        assert dst == b""


class TestBridgeTxUnsupportedPort:
    @pytest.mark.asyncio
    async def test_unsupported_port_ignored(self, bridge, mock_link_layer):
        bridge.handler.on_tx_frame(5, b"ignored")
        await asyncio.sleep(0.01)

        assert len(mock_link_layer.sent_frames) == 0


class TestBridgeRx:
    def test_encode_rx_frames_returns_both_ports(self, bridge, mock_peer):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"test"),
            sender=mock_peer,
        )

        ax25_kiss, raw_kiss = bridge.encode_rx_frames(rx)

        # Both should be valid KISS frames
        assert len(ax25_kiss) > 0
        assert len(raw_kiss) > 0

    def test_encode_rx_ax25_has_aprs_format(self, bridge, mock_peer):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"Hello world"),
            sender=mock_peer,
        )

        ax25_kiss, _ = bridge.encode_rx_frames(rx)

        # Decode KISS frame
        kiss = kiss_decode(ax25_kiss)
        assert kiss.port == PORT_AX25

        # Decode AX.25 inside
        ax25 = ax25_decode(kiss.data)
        assert ax25.src == iid_to_callsign(mock_peer.iid)
        assert ax25.dst == bridge.own_callsign

        # AX.25 payload should be APRS message format
        # :ADDRESSEE:text{id
        payload = ax25.payload.decode("utf-8")
        assert payload.startswith(":")
        assert "Hello world" in payload
        assert "{" in payload  # Message ID present

    def test_encode_rx_raw_has_payload(self, bridge, mock_peer):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"raw data"),
            sender=mock_peer,
        )

        _, raw_kiss = bridge.encode_rx_frames(rx)

        kiss = kiss_decode(raw_kiss)
        assert kiss.port == PORT_RAW
        assert kiss.data == b"raw data"

    def test_encode_rx_adds_sender_to_peer_table(self, bridge, mock_peer):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"test"),
            sender=mock_peer,
        )

        bridge.encode_rx_frames(rx)

        # Sender should now be in peer table
        suffix = (mock_peer.iid[5] << 16) | (mock_peer.iid[6] << 8) | mock_peer.iid[7]
        assert bridge._peer_table.lookup_by_suffix(suffix) == mock_peer.iid

    @pytest.mark.asyncio
    async def test_routing_dispatch_is_not_treated_as_rej(self, bridge, mock_peer):
        sent = []
        bridge.on_send_kiss = sent.append
        bridge._msg_tracker.handle_rej = MagicMock()
        rx = MockRxFrame(
            frame=MockLichenFrame(
                payload=bytes([L2_DISPATCH_ROUTING, 0x01, 0x00, 0x00])
            ),
            sender=mock_peer,
        )

        await bridge._on_link_rx(rx)

        bridge._msg_tracker.handle_rej.assert_not_called()
        assert sent

    @pytest.mark.asyncio
    async def test_private_aprs_rej_payload_handles_rej(self, bridge, mock_peer):
        bridge.on_send_kiss = MagicMock()
        bridge._msg_tracker.handle_rej = MagicMock()
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"\x7f\x15123"),
            sender=mock_peer,
        )

        await bridge._on_link_rx(rx)

        bridge._msg_tracker.handle_rej.assert_called_once_with("123")
        bridge.on_send_kiss.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_announce_routing_dispatch_is_not_rej(self, bridge, mock_peer):
        sent = []
        bridge.on_send_kiss = sent.append
        bridge._msg_tracker.handle_rej = MagicMock()
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=bytes([L2_DISPATCH_ROUTING, 0x02, 0x00])),
            sender=mock_peer,
        )

        await bridge._on_link_rx(rx)

        bridge._msg_tracker.handle_rej.assert_not_called()
        assert sent

    def test_encode_rx_routing_dispatch_is_not_rej(self, bridge, mock_peer):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=bytes([L2_DISPATCH_ROUTING, 0x01, 0])),
            sender=mock_peer,
        )

        ax25_kiss, _ = bridge.encode_rx_frames(rx)
        kiss = kiss_decode(ax25_kiss)
        ax25 = ax25_decode(kiss.data)

        assert b":rej" not in ax25.payload

    def test_encode_rx_non_announce_routing_dispatch_is_not_rej(
        self, bridge, mock_peer
    ):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=bytes([L2_DISPATCH_ROUTING, 0x02, 0])),
            sender=mock_peer,
        )

        ax25_kiss, _ = bridge.encode_rx_frames(rx)
        kiss = kiss_decode(ax25_kiss)
        ax25 = ax25_decode(kiss.data)

        assert b":rej" not in ax25.payload


class TestBridgeAddPeer:
    def test_add_peer_enables_lookup(self, bridge, mock_peer):
        bridge.add_peer(mock_peer)

        suffix = (mock_peer.iid[5] << 16) | (mock_peer.iid[6] << 8) | mock_peer.iid[7]
        assert bridge._peer_table.lookup_by_suffix(suffix) == mock_peer.iid


class TestBridgeStartStop:
    @pytest.mark.asyncio
    async def test_start_creates_task(self, bridge):
        await bridge.start()
        assert bridge._running
        assert bridge._rx_task is not None
        await bridge.stop()

    @pytest.mark.asyncio
    async def test_stop_cancels_task(self, bridge):
        await bridge.start()
        await bridge.stop()
        assert not bridge._running
        assert bridge._rx_task is None

    @pytest.mark.asyncio
    async def test_start_twice_no_error(self, bridge):
        await bridge.start()
        await bridge.start()  # Should be no-op
        assert bridge._running
        await bridge.stop()

    @pytest.mark.asyncio
    async def test_stop_without_start_no_error(self, bridge):
        await bridge.stop()  # Should be no-op


class TestBridgeRxLoop:
    @pytest.mark.asyncio
    async def test_rx_loop_processes_frame(self, bridge, mock_link_layer, mock_peer):
        # Start bridge
        await bridge.start(rx_timeout_ms=100)

        # Inject a frame
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"looped"),
            sender=mock_peer,
        )
        await mock_link_layer.rx_queue.put(rx)

        # Wait for processing
        await asyncio.sleep(0.05)

        # Peer should be added to table
        suffix = (mock_peer.iid[5] << 16) | (mock_peer.iid[6] << 8) | mock_peer.iid[7]
        assert bridge._peer_table.lookup_by_suffix(suffix) == mock_peer.iid

        await bridge.stop()


class TestBridgeAprsTx:
    """Test APRS message transmission from app."""

    @pytest.mark.asyncio
    async def test_aprs_message_sends_text_only(self, bridge, mock_link_layer, mock_peer):
        # Add peer so we can resolve callsign
        bridge.add_peer(mock_peer)
        dst_call = iid_to_callsign(mock_peer.iid)

        # Build APRS message inside AX.25
        from lichen.interface.kiss.aprs import create_message
        aprs_msg = create_message(dst_call, "Hello from app", "42")
        ax25_frame = ax25_encode("LSRC", dst_call, aprs_msg.encode())

        # Trigger TX via handler
        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)
        await asyncio.sleep(0.01)

        # Should send the TEXT only, not the APRS wrapper
        assert len(mock_link_layer.sent_frames) == 1
        payload, dst = mock_link_layer.sent_frames[0]
        assert payload == b"Hello from app"
        assert dst == mock_peer.iid

    @pytest.mark.asyncio
    async def test_aprs_message_tracked_for_ack(self, bridge, mock_link_layer, mock_peer):
        bridge.add_peer(mock_peer)
        dst_call = iid_to_callsign(mock_peer.iid)

        from lichen.interface.kiss.aprs import create_message
        aprs_msg = create_message(dst_call, "Track me", "99")
        ax25_frame = ax25_encode("LSRC", dst_call, aprs_msg.encode())

        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)
        await asyncio.sleep(0.01)

        # Message should be tracked
        assert bridge._msg_tracker.pending_count() == 1

    @pytest.mark.asyncio
    async def test_aprs_broadcast_to_cq(self, bridge, mock_link_layer):
        from lichen.interface.kiss.aprs import create_message
        aprs_msg = create_message("CQ", "Broadcast message")
        ax25_frame = ax25_encode("LSRC", "CQ", aprs_msg.encode())

        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)
        await asyncio.sleep(0.01)

        assert len(mock_link_layer.sent_frames) == 1
        payload, dst = mock_link_layer.sent_frames[0]
        assert payload == b"Broadcast message"
        assert dst == b""  # Broadcast

    @pytest.mark.asyncio
    async def test_aprs_rej_uses_private_kiss_control_prefix(
        self, bridge, mock_link_layer, mock_peer
    ):
        bridge.add_peer(mock_peer)
        dst_call = iid_to_callsign(mock_peer.iid)

        from lichen.interface.kiss.aprs import AprsRej

        ax25_frame = ax25_encode("LSRC", dst_call, AprsRej(dst_call, "123").encode())
        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)
        await asyncio.sleep(0.01)

        assert len(mock_link_layer.sent_frames) == 1
        payload, dst = mock_link_layer.sent_frames[0]
        assert payload == b"\x7f\x15123"
        assert dst == mock_peer.iid


class TestBridgeAprsRx:
    """Test APRS message reception to app."""

    def test_rx_formats_as_aprs_message(self, bridge, mock_peer):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"Incoming message"),
            sender=mock_peer,
        )

        ax25_kiss, _ = bridge.encode_rx_frames(rx)

        # Decode and verify APRS format
        kiss = kiss_decode(ax25_kiss)
        ax25 = ax25_decode(kiss.data)
        payload = ax25.payload.decode("utf-8")

        # Should be APRS message format: :ADDRESSEE:text{id
        assert payload.startswith(":")
        assert "Incoming message" in payload
        assert "{" in payload  # Has message ID

    def test_rx_ack_formats_correctly(self, bridge, mock_peer):
        # Receive an ack (0x06 prefix)
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"\x06123"),
            sender=mock_peer,
        )

        ax25_kiss, _ = bridge.encode_rx_frames(rx)

        kiss = kiss_decode(ax25_kiss)
        ax25 = ax25_decode(kiss.data)
        payload = ax25.payload.decode("utf-8")

        # Should be APRS ack format
        assert "ack123" in payload

    def test_rx_private_rej_formats_correctly(self, bridge, mock_peer):
        rx = MockRxFrame(
            frame=MockLichenFrame(payload=b"\x7f\x15123"),
            sender=mock_peer,
        )

        ax25_kiss, _ = bridge.encode_rx_frames(rx)

        kiss = kiss_decode(ax25_kiss)
        ax25 = ax25_decode(kiss.data)
        payload = ax25.payload.decode("utf-8")

        assert "rej123" in payload


class TestBridgeAprsAckFlow:
    """Test full ack flow between apps."""

    @pytest.mark.asyncio
    async def test_outgoing_ack_tracked_and_confirmed(self, bridge, mock_link_layer, mock_peer):
        bridge.add_peer(mock_peer)
        dst_call = iid_to_callsign(mock_peer.iid)

        # Send message with ID
        from lichen.interface.kiss.aprs import create_message
        aprs_msg = create_message(dst_call, "Ack me", "77")
        ax25_frame = ax25_encode("LSRC", dst_call, aprs_msg.encode())
        bridge.handler.on_tx_frame(PORT_AX25, ax25_frame)
        await asyncio.sleep(0.01)

        assert bridge._msg_tracker.pending_count() == 1

        # Simulate receiving ack
        bridge._msg_tracker.handle_ack("77")

        assert bridge._msg_tracker.pending_count() == 0
