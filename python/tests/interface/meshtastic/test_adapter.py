# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for Meshtastic adapter state machine."""

import threading
from unittest.mock import MagicMock

import pytest

from lichen.interface.meshtastic.adapter import MeshtasticAdapter, create_adapter


@pytest.fixture
def mock_node():
    """Create a mock LICHEN node."""
    node = MagicMock()
    node.identity.iid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    node._on_receive = None
    return node


@pytest.fixture
def adapter(mock_node):
    """Create an adapter with mock node."""
    return MeshtasticAdapter(node=mock_node)


class TestStateTransitions:
    """Test adapter state machine transitions."""

    def test_initial_state(self, adapter):
        """Adapter starts disconnected with empty queue."""
        assert adapter.connected is False
        assert adapter.config_sync_pending is None
        assert len(adapter.from_radio_queue) == 0
        assert adapter.from_num == 0

    def test_connect(self, adapter):
        """Connect sets connected flag and clears state."""
        adapter.on_connect()
        assert adapter.connected is True
        assert adapter.config_sync_pending is None
        assert adapter.from_num == 0

    def test_disconnect(self, adapter):
        """Disconnect clears connected flag and queue."""
        adapter.on_connect()
        adapter.queue_from_radio(b"\x01\x02\x03")
        adapter.on_disconnect()
        assert adapter.connected is False
        assert len(adapter.from_radio_queue) == 0

    def test_connect_clears_pending_config(self, adapter):
        """New connection clears any pending config sync."""
        adapter.config_sync_pending = 42
        adapter.on_connect()
        assert adapter.config_sync_pending is None


class TestQueueBehavior:
    """Test FromRadio queue behavior."""

    def test_queue_when_connected(self, adapter):
        """Messages queue when connected."""
        adapter.on_connect()
        adapter.queue_from_radio(b"\x01\x02\x03")
        assert len(adapter.from_radio_queue) == 1
        assert adapter.from_num == 1

    def test_queue_when_disconnected(self, adapter):
        """Messages dropped when disconnected."""
        adapter.queue_from_radio(b"\x01\x02\x03")
        assert len(adapter.from_radio_queue) == 0
        assert adapter.from_num == 0

    def test_read_from_radio(self, adapter):
        """Read returns oldest message and removes it."""
        adapter.on_connect()
        adapter.queue_from_radio(b"\x01")
        adapter.queue_from_radio(b"\x02")

        msg = adapter.read_from_radio()
        assert msg == b"\x01"
        assert len(adapter.from_radio_queue) == 1

        msg = adapter.read_from_radio()
        assert msg == b"\x02"

        msg = adapter.read_from_radio()
        assert msg is None

    def test_from_num_increments(self, adapter):
        """FromNum increments on each queued message."""
        adapter.on_connect()
        for i in range(5):
            adapter.queue_from_radio(bytes([i]))
        assert adapter.from_num == 5

    def test_from_num_wraps(self, adapter):
        """FromNum wraps at 32-bit boundary."""
        adapter.on_connect()
        adapter.from_num = 0xFFFFFFFF
        adapter.queue_from_radio(b"\x01")
        assert adapter.from_num == 0

    def test_notify_callback(self, adapter):
        """Notify callback invoked on queue."""
        notified = []
        adapter.set_on_from_num_changed(lambda: notified.append(True))
        adapter.on_connect()
        adapter.queue_from_radio(b"\x01")
        assert len(notified) == 1


class TestConcurrency:
    """Test thread-safe behavior."""

    def test_concurrent_queue_read(self, adapter):
        """Concurrent queue and read operations are safe."""
        adapter.on_connect()
        errors = []

        def writer():
            try:
                for i in range(100):
                    adapter.queue_from_radio(bytes([i % 256]))
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(100):
                    adapter.read_from_radio()
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestCreateAdapter:
    """Test adapter factory function."""

    def test_create_wires_node(self, mock_node):
        """create_adapter wires up node callbacks."""
        adapter = create_adapter(mock_node)
        assert adapter.node is mock_node
        # Verify callback was set
        mock_node.set_on_receive.assert_called_once()

    def test_create_preserves_original_callback(self, mock_node):
        """create_adapter preserves existing on_receive callback."""
        original = MagicMock()
        mock_node._on_receive = original

        create_adapter(mock_node)

        # Get the callback that was set
        callback = mock_node.set_on_receive.call_args[0][0]

        # Simulate message receipt
        sender = MagicMock()
        sender.iid = b"\x01" * 8
        callback(b"test", sender)

        # Original callback should have been called
        original.assert_called_once_with(b"test", sender)
