# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""WebSocket interface for real-time simulation events.

Provides WebSocket endpoints for streaming simulation events to connected
clients. Uses the SimulationObserver protocol to receive events from the
simulation engine and broadcast them to subscribers.

Defensive design:
- Client disconnections are handled gracefully
- Broadcast failures don't crash the server
- Invalid messages are logged and ignored
- Connection cleanup is guaranteed via finally blocks
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from starlette.websockets import WebSocket, WebSocketDisconnect

from lichen.sim.auth import WEBSOCKET_AUTH_SUBPROTOCOL

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class WebSocketClient:
    """Represents a connected WebSocket client.

    Tracks client identity, subscriptions, and the WebSocket connection.
    """

    id: str
    websocket: WebSocket
    sim_id: str
    subscriptions: set[str] = field(default_factory=set)

    def is_subscribed(self, event_type: str) -> bool:
        """Check if client is subscribed to an event type.

        Empty subscription set means subscribed to all events.
        """
        if not self.subscriptions:
            return True  # No filter = all events
        return event_type in self.subscriptions


class WebSocketManager:
    """Manages WebSocket connections and broadcasts.

    Thread-safe management of client connections with automatic cleanup
    on disconnect. Integrates with SimulationObserver to receive events.

    Defensive design:
    - Failed sends remove the client automatically
    - Iteration uses snapshot to allow concurrent modification
    - All exceptions are caught and logged
    """

    def __init__(self) -> None:
        """Initialize empty manager."""
        self._clients: dict[str, WebSocketClient] = {}
        self._lock = asyncio.Lock()

    async def connect(
        self,
        websocket: WebSocket,
        sim_id: str,
        client_id: str | None = None,
    ) -> WebSocketClient:
        """Accept a new WebSocket connection.

        Args:
            websocket: The WebSocket to accept.
            sim_id: Simulation this client is observing.
            client_id: Optional client ID. Generated if not provided.

        Returns:
            The WebSocketClient object.
        """
        # SECURITY: If client used subprotocol auth (bearer.<token>), echo back
        # the "bearer" subprotocol to complete the handshake. This confirms we
        # accepted the auth mechanism without echoing the token itself.
        subprotocols = websocket.scope.get("subprotocols", [])
        accepted_subprotocol = None
        for proto in subprotocols:
            if proto.startswith(f"{WEBSOCKET_AUTH_SUBPROTOCOL}."):
                accepted_subprotocol = WEBSOCKET_AUTH_SUBPROTOCOL
                break

        await websocket.accept(subprotocol=accepted_subprotocol)

        if client_id is None:
            client_id = str(uuid.uuid4())[:8]

        client = WebSocketClient(
            id=client_id,
            websocket=websocket,
            sim_id=sim_id,
        )

        async with self._lock:
            self._clients[client_id] = client

        logger.info(
            "WebSocket client connected: %s for sim %s",
            client_id,
            sim_id,
        )
        return client

    async def disconnect(self, client_id: str) -> None:
        """Remove a client from the manager.

        Safe to call even if client doesn't exist.

        Args:
            client_id: ID of client to remove.
        """
        async with self._lock:
            client = self._clients.pop(client_id, None)

        if client is not None:
            logger.info("WebSocket client disconnected: %s", client_id)

    async def broadcast_to_sim(
        self,
        sim_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """Broadcast an event to all clients subscribed to a simulation.

        Args:
            sim_id: Simulation ID to broadcast to.
            event_type: Type of event (for subscription filtering).
            data: Event data to send as JSON.
        """
        # Snapshot clients to allow concurrent modification
        async with self._lock:
            clients = [
                c for c in self._clients.values()
                if c.sim_id == sim_id and c.is_subscribed(event_type)
            ]

        if not clients:
            return

        message = json.dumps({"event": event_type, **data})
        disconnected: list[str] = []

        for client in clients:
            try:
                await client.websocket.send_text(message)
            except Exception:
                # Client is dead, mark for removal
                disconnected.append(client.id)
                logger.debug("Client %s send failed, marking for disconnect", client.id)

        # Clean up dead connections
        for client_id in disconnected:
            await self.disconnect(client_id)

    async def send_to_client(
        self,
        client_id: str,
        data: dict[str, Any],
    ) -> bool:
        """Send a message to a specific client.

        Args:
            client_id: Target client ID.
            data: Data to send as JSON.

        Returns:
            True if sent successfully, False if client not found or send failed.
        """
        async with self._lock:
            client = self._clients.get(client_id)

        if client is None:
            return False

        try:
            await client.websocket.send_json(data)
            return True
        except Exception:
            await self.disconnect(client_id)
            return False

    def get_client_count(self, sim_id: str | None = None) -> int:
        """Get number of connected clients.

        Args:
            sim_id: If provided, count only clients for this simulation.

        Returns:
            Number of connected clients.
        """
        if sim_id is None:
            return len(self._clients)
        return sum(1 for c in self._clients.values() if c.sim_id == sim_id)


class WebSocketObserver:
    """SimulationObserver that broadcasts events to WebSocket clients.

    Bridges the simulation's observer system to WebSocket broadcasting.
    Each simulation gets its own observer instance.

    Note: Observer methods are synchronous, but we need to broadcast
    asynchronously. We use asyncio.create_task to schedule broadcasts
    without blocking the simulation.
    """

    def __init__(self, manager: WebSocketManager, sim_id: str) -> None:
        """Initialize observer for a simulation.

        Args:
            manager: The WebSocketManager to broadcast through.
            sim_id: ID of the simulation being observed.
        """
        self._manager = manager
        self._sim_id = sim_id

    def _broadcast(self, event_type: str, **data: Any) -> None:
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(
                self._manager.broadcast_to_sim(self._sim_id, event_type, data)
            )
            task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        except RuntimeError:
            pass

    def on_tx_start(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        payload_len: int,
        time_us: int,
    ) -> None:
        """Broadcast transmission start."""
        self._broadcast(
            "tx_start",
            node_id=node_id,
            tx_id=tx_id,
            payload_len=payload_len,
            time_us=time_us,
        )

    def on_tx_end(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        time_us: int,
    ) -> None:
        """Broadcast transmission end."""
        self._broadcast(
            "tx_end",
            node_id=node_id,
            tx_id=tx_id,
            time_us=time_us,
        )

    def on_rx_success(
        self,
        sim_id: str,
        node_id: str,
        tx_id: str,
        from_node_id: str,
        payload_len: int,
        rssi: int,
        snr: int,
        time_us: int,
    ) -> None:
        """Broadcast successful reception."""
        self._broadcast(
            "rx_success",
            node_id=node_id,
            tx_id=tx_id,
            from_node_id=from_node_id,
            payload_len=payload_len,
            rssi=rssi,
            snr=snr,
            time_us=time_us,
        )

    def on_rx_timeout(
        self,
        sim_id: str,
        node_id: str,
        time_us: int,
    ) -> None:
        """Broadcast receive timeout."""
        self._broadcast(
            "rx_timeout",
            node_id=node_id,
            time_us=time_us,
        )

    def on_collision(
        self,
        sim_id: str,
        node_id: str,
        tx_ids: list[str],
        time_us: int,
    ) -> None:
        """Broadcast collision."""
        self._broadcast(
            "collision",
            node_id=node_id,
            tx_ids=tx_ids,
            time_us=time_us,
        )

    def on_node_added(
        self,
        sim_id: str,
        node_id: str,
        x: float,
        y: float,
        z: float,
    ) -> None:
        """Broadcast node addition."""
        self._broadcast(
            "node_added",
            node_id=node_id,
            x=x,
            y=y,
            z=z,
        )

    def on_node_removed(
        self,
        sim_id: str,
        node_id: str,
    ) -> None:
        """Broadcast node removal."""
        self._broadcast(
            "node_removed",
            node_id=node_id,
        )


async def handle_websocket(
    websocket: WebSocket,
    manager: WebSocketManager,
    sim_id: str,
) -> None:
    """Handle a WebSocket connection for simulation events.

    Protocol:
    - Client connects to /sim/{sim_id}/ws
    - Server accepts and starts streaming events
    - Client can send JSON commands:
      - {"cmd": "subscribe", "events": ["tx_start", "rx_success"]}
      - {"cmd": "unsubscribe", "events": ["collision"]}
      - {"cmd": "ping"} -> server responds {"event": "pong"}
    - Server broadcasts events as {"event": "tx_start", ...data}

    Args:
        websocket: The WebSocket connection.
        manager: The WebSocketManager for this API.
        sim_id: ID of the simulation to observe.
    """
    client = await manager.connect(websocket, sim_id)

    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "event": "connected",
            "client_id": client.id,
            "sim_id": sim_id,
        })

        # Process incoming commands
        while True:
            try:
                data = await websocket.receive_json()
            except json.JSONDecodeError:
                await websocket.send_json({
                    "event": "error",
                    "message": "Invalid JSON",
                })
                continue

            cmd = data.get("cmd")

            if cmd == "ping":
                await websocket.send_json({"event": "pong"})

            elif cmd == "subscribe":
                events = data.get("events", [])
                if isinstance(events, list):
                    if not all(isinstance(e, str) for e in events):
                        await websocket.send_json({
                            "event": "error",
                            "message": "events must be a list of strings",
                        })
                        continue
                    client.subscriptions.update(events)
                    await websocket.send_json({
                        "event": "subscribed",
                        "events": list(client.subscriptions),
                    })

            elif cmd == "unsubscribe":
                events = data.get("events", [])
                if isinstance(events, list):
                    if not all(isinstance(e, str) for e in events):
                        await websocket.send_json({
                            "event": "error",
                            "message": "events must be a list of strings",
                        })
                        continue
                    client.subscriptions.difference_update(events)
                    await websocket.send_json({
                        "event": "unsubscribed",
                        "events": list(client.subscriptions),
                    })

            elif cmd == "clear_subscriptions":
                client.subscriptions.clear()
                await websocket.send_json({
                    "event": "subscriptions_cleared",
                })

            else:
                await websocket.send_json({
                    "event": "error",
                    "message": f"Unknown command: {cmd}",
                })

    except WebSocketDisconnect:
        pass  # Normal disconnection
    except Exception:
        logger.exception("WebSocket error for client %s", client.id)
    finally:
        await manager.disconnect(client.id)
