# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the WebSocket interface.

Tests the WebSocketManager, WebSocketObserver, and API integration.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from lichen.sim.websocket import (
    WebSocketClient,
    WebSocketManager,
    WebSocketObserver,
)


class TestWebSocketClient:
    """Tests for WebSocketClient dataclass."""

    def test_default_subscriptions_empty(self) -> None:
        """New client has empty subscriptions (subscribes to all)."""
        ws = MagicMock()
        client = WebSocketClient(id="c1", websocket=ws, sim_id="s1")
        assert client.subscriptions == set()

    def test_is_subscribed_empty_means_all(self) -> None:
        """Empty subscription set means subscribed to all events."""
        ws = MagicMock()
        client = WebSocketClient(id="c1", websocket=ws, sim_id="s1")
        assert client.is_subscribed("tx_start") is True
        assert client.is_subscribed("collision") is True
        assert client.is_subscribed("anything") is True

    def test_is_subscribed_with_filter(self) -> None:
        """With subscriptions set, only those events match."""
        ws = MagicMock()
        client = WebSocketClient(
            id="c1",
            websocket=ws,
            sim_id="s1",
            subscriptions={"tx_start", "tx_end"},
        )
        assert client.is_subscribed("tx_start") is True
        assert client.is_subscribed("tx_end") is True
        assert client.is_subscribed("collision") is False


class TestWebSocketManager:
    """Tests for WebSocketManager."""

    @pytest.fixture
    def manager(self) -> WebSocketManager:
        return WebSocketManager()

    @pytest.fixture
    def mock_websocket(self) -> AsyncMock:
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        ws.send_json = AsyncMock()
        # Provide scope for subprotocol handling
        ws.scope = {"subprotocols": []}
        return ws

    async def test_connect_accepts_websocket(
        self, manager: WebSocketManager, mock_websocket: AsyncMock
    ) -> None:
        """connect() calls accept on the websocket."""
        await manager.connect(mock_websocket, "sim1")
        mock_websocket.accept.assert_called_once()

    async def test_connect_returns_client(
        self, manager: WebSocketManager, mock_websocket: AsyncMock
    ) -> None:
        """connect() returns a WebSocketClient."""
        client = await manager.connect(mock_websocket, "sim1")
        assert isinstance(client, WebSocketClient)
        assert client.sim_id == "sim1"
        assert client.websocket is mock_websocket

    async def test_connect_with_custom_id(
        self, manager: WebSocketManager, mock_websocket: AsyncMock
    ) -> None:
        """connect() uses provided client_id."""
        client = await manager.connect(mock_websocket, "sim1", client_id="myclient")
        assert client.id == "myclient"

    async def test_disconnect_removes_client(
        self, manager: WebSocketManager, mock_websocket: AsyncMock
    ) -> None:
        """disconnect() removes client from manager."""
        client = await manager.connect(mock_websocket, "sim1")
        assert manager.get_client_count() == 1

        await manager.disconnect(client.id)
        assert manager.get_client_count() == 0

    async def test_disconnect_nonexistent_is_safe(
        self, manager: WebSocketManager
    ) -> None:
        """disconnect() on unknown client is no-op."""
        await manager.disconnect("nonexistent")  # Should not raise

    async def test_broadcast_to_sim_sends_to_subscribed(
        self, manager: WebSocketManager
    ) -> None:
        """broadcast_to_sim sends to clients subscribed to that sim."""
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_text = AsyncMock()
        ws1.scope = {"subprotocols": []}

        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.send_text = AsyncMock()
        ws2.scope = {"subprotocols": []}

        await manager.connect(ws1, "sim1", client_id="c1")
        await manager.connect(ws2, "sim2", client_id="c2")

        await manager.broadcast_to_sim("sim1", "tx_start", {"node_id": "n1"})

        # ws1 should receive, ws2 should not
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_not_called()

        # Check message content
        sent_msg = ws1.send_text.call_args[0][0]
        data = json.loads(sent_msg)
        assert data["event"] == "tx_start"
        assert data["node_id"] == "n1"

    async def test_broadcast_respects_subscriptions(
        self, manager: WebSocketManager
    ) -> None:
        """broadcast only sends to clients subscribed to that event type."""
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.send_text = AsyncMock()
        ws1.scope = {"subprotocols": []}

        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.send_text = AsyncMock()
        ws2.scope = {"subprotocols": []}

        c1 = await manager.connect(ws1, "sim1", client_id="c1")
        _c2 = await manager.connect(ws2, "sim1", client_id="c2")

        # c1 subscribes only to tx_start
        c1.subscriptions.add("tx_start")
        # c2 has no filter (gets everything)

        await manager.broadcast_to_sim("sim1", "collision", {"node_id": "n1"})

        # Only c2 should receive (c1 filtered it out)
        ws1.send_text.assert_not_called()
        ws2.send_text.assert_called_once()

    async def test_broadcast_removes_dead_clients(
        self, manager: WebSocketManager
    ) -> None:
        """broadcast removes clients that fail to receive."""
        ws_good = AsyncMock()
        ws_good.accept = AsyncMock()
        ws_good.send_text = AsyncMock()
        ws_good.scope = {"subprotocols": []}

        ws_bad = AsyncMock()
        ws_bad.accept = AsyncMock()
        ws_bad.send_text = AsyncMock(side_effect=Exception("Connection closed"))
        ws_bad.scope = {"subprotocols": []}

        await manager.connect(ws_good, "sim1", client_id="good")
        await manager.connect(ws_bad, "sim1", client_id="bad")

        assert manager.get_client_count() == 2

        await manager.broadcast_to_sim("sim1", "tx_start", {})

        # Bad client should be removed
        assert manager.get_client_count() == 1

    async def test_send_to_client(
        self, manager: WebSocketManager, mock_websocket: AsyncMock
    ) -> None:
        """send_to_client sends to specific client."""
        _client = await manager.connect(mock_websocket, "sim1", client_id="c1")

        result = await manager.send_to_client("c1", {"msg": "hello"})

        assert result is True
        mock_websocket.send_json.assert_called_once_with({"msg": "hello"})

    async def test_send_to_client_unknown_returns_false(
        self, manager: WebSocketManager
    ) -> None:
        """send_to_client returns False for unknown client."""
        result = await manager.send_to_client("unknown", {"msg": "hello"})
        assert result is False

    async def test_get_client_count(
        self, manager: WebSocketManager
    ) -> None:
        """get_client_count returns correct counts."""
        ws1 = AsyncMock()
        ws1.accept = AsyncMock()
        ws1.scope = {"subprotocols": []}
        ws2 = AsyncMock()
        ws2.accept = AsyncMock()
        ws2.scope = {"subprotocols": []}

        assert manager.get_client_count() == 0

        await manager.connect(ws1, "sim1", client_id="c1")
        assert manager.get_client_count() == 1
        assert manager.get_client_count("sim1") == 1
        assert manager.get_client_count("sim2") == 0

        await manager.connect(ws2, "sim2", client_id="c2")
        assert manager.get_client_count() == 2
        assert manager.get_client_count("sim1") == 1
        assert manager.get_client_count("sim2") == 1


class TestWebSocketObserver:
    """Tests for WebSocketObserver."""

    @pytest.fixture
    def manager(self) -> WebSocketManager:
        return WebSocketManager()

    def test_observer_has_all_event_methods(
        self, manager: WebSocketManager
    ) -> None:
        """Observer implements all expected event methods."""
        observer = WebSocketObserver(manager, "sim1")

        # All these should exist and be callable
        assert callable(observer.on_tx_start)
        assert callable(observer.on_tx_end)
        assert callable(observer.on_rx_success)
        assert callable(observer.on_rx_timeout)
        assert callable(observer.on_collision)
        assert callable(observer.on_node_added)
        assert callable(observer.on_node_removed)

    async def test_observer_broadcasts_via_manager(
        self, manager: WebSocketManager
    ) -> None:
        """Observer broadcasts events through the manager."""
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        ws.scope = {"subprotocols": []}

        await manager.connect(ws, "sim1", client_id="c1")

        observer = WebSocketObserver(manager, "sim1")

        # Call observer method
        observer.on_tx_start(
            sim_id="sim1",
            node_id="n1",
            tx_id="t1",
            payload_len=10,
            time_us=1000,
        )

        # Give the async task time to run
        await asyncio.sleep(0.01)

        # Check broadcast was called
        ws.send_text.assert_called_once()
        sent = json.loads(ws.send_text.call_args[0][0])
        assert sent["event"] == "tx_start"
        assert sent["node_id"] == "n1"
        assert sent["tx_id"] == "t1"

    def test_observer_handles_no_event_loop(
        self, manager: WebSocketManager
    ) -> None:
        """Observer handles case where no event loop is running."""
        observer = WebSocketObserver(manager, "sim1")

        # This should not raise even without event loop
        # (it will fail silently which is the expected behavior)
        observer.on_tx_start(
            sim_id="sim1",
            node_id="n1",
            tx_id="t1",
            payload_len=10,
            time_us=1000,
        )
