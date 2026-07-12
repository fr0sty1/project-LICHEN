# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for Meshtastic config sync state machine."""

from unittest.mock import MagicMock

import pytest

from lichen.interface.meshtastic.config_sync import (
    FIRMWARE_VERSION,
    HW_MODEL_PRIVATE,
    LEGACY_NONCE_A,
    LEGACY_NONCE_B,
    MIN_APP_VERSION,
    AckTracker,
    ConfigSync,
    ConfigSyncState,
    build_queue_status,
    build_routing_ack,
    build_routing_nak,
)


@pytest.fixture
def mock_adapter():
    """Create a mock adapter with minimal node."""
    adapter = MagicMock()
    adapter.node.identity.iid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    return adapter


@pytest.fixture
def config_sync(mock_adapter):
    """Create config sync with mock adapter."""
    return ConfigSync(adapter=mock_adapter)


class TestConfigSyncState:
    """Test config sync state machine."""

    def test_initial_state(self, config_sync):
        assert config_sync.state == ConfigSyncState.IDLE
        assert config_sync.config_id is None
        assert not config_sync.is_active()

    def test_start_sets_state(self, config_sync):
        config_sync.start(69420)
        assert config_sync.config_id == 69420
        assert config_sync.state == ConfigSyncState.SENDING_MY_INFO
        assert config_sync.is_active()

    def test_start_with_legacy_nonce_a(self, config_sync):
        config_sync.start(LEGACY_NONCE_A)
        assert config_sync.config_id == LEGACY_NONCE_A

    def test_start_with_legacy_nonce_b(self, config_sync):
        config_sync.start(LEGACY_NONCE_B)
        assert config_sync.config_id == LEGACY_NONCE_B

    def test_cancel(self, config_sync):
        config_sync.start(69420)
        config_sync.cancel()
        assert config_sync.config_id is None
        assert config_sync.state == ConfigSyncState.IDLE
        assert not config_sync.is_active()

    def test_next_message_when_idle(self, config_sync):
        assert config_sync.next_message() is None

    def test_full_sync_sequence(self, config_sync):
        """Test complete config sync message sequence."""
        config_sync.start(69420)

        # 1. MyNodeInfo
        msg1 = config_sync.next_message()
        assert msg1 is not None
        assert msg1.my_info is not None
        assert msg1.my_info.my_node_num == 0x05060708  # Low 32 bits of IID
        assert msg1.my_info.min_app_version == MIN_APP_VERSION

        # 2. DeviceMetadata
        msg2 = config_sync.next_message()
        assert msg2 is not None
        assert msg2.metadata is not None
        assert msg2.metadata.firmware_version == FIRMWARE_VERSION
        assert msg2.metadata.hw_model == HW_MODEL_PRIVATE
        assert msg2.metadata.has_bluetooth is True

        # 3. NodeInfo (our own)
        msg3 = config_sync.next_message()
        assert msg3 is not None
        assert msg3.node_info is not None

        # 4. ConfigCompleteId
        msg4 = config_sync.next_message()
        assert msg4 is not None
        assert msg4.config_complete_id == 69420

        # 5. Done
        assert config_sync.state == ConfigSyncState.DONE
        assert config_sync.next_message() is None


class TestAckTracker:
    """Test ACK request tracking."""

    def test_track_and_complete(self):
        tracker = AckTracker()
        tracker.track(123)
        assert 123 in tracker.pending
        assert tracker.complete(123) is True
        assert 123 not in tracker.pending

    def test_complete_unknown(self):
        tracker = AckTracker()
        assert tracker.complete(999) is False

    def test_expired(self):
        tracker = AckTracker(timeout_secs=0)  # Immediate expiry
        tracker.track(123)
        expired = tracker.get_expired()
        assert 123 in expired
        assert 123 not in tracker.pending


class TestBuildHelpers:
    """Test message building helpers."""

    def test_build_queue_status(self):
        msg = build_queue_status(packet_id=42, free=6, maxlen=8, result=0)
        assert msg.queue_status is not None
        assert msg.queue_status.mesh_packet_id == 42
        assert msg.queue_status.free == 6
        assert msg.queue_status.maxlen == 8
        assert msg.queue_status.res == 0

    def test_build_routing_ack(self):
        msg = build_routing_ack(request_id=42, from_=0x11111111, to=0x22222222)
        assert msg.packet is not None
        assert msg.packet.from_ == 0x11111111
        assert msg.packet.to == 0x22222222
        assert msg.packet.id == 42
        assert msg.packet.decoded is not None
        assert msg.packet.decoded.portnum == 5  # ROUTING_APP
        assert msg.packet.decoded.request_id == 42

    def test_build_routing_nak(self):
        msg = build_routing_nak(request_id=42, from_=0x11111111, to=0x22222222, error=3)
        assert msg.packet is not None
        assert msg.packet.decoded is not None
        assert msg.packet.decoded.portnum == 5  # ROUTING_APP

        # Verify error is encoded in payload
        from lichen.interface.meshtastic.proto import Routing

        routing = Routing.from_bytes(msg.packet.decoded.payload)
        assert routing.error_reason == 3  # TIMEOUT
