"""
Legacy LICHEN Native CBOR protocol handler for Node class.

Wires up Node methods to historical spec/lichen-native protocol messages.
Current LCI sessions use IPv6 + CoAP from spec/11-lci.md.

DEPRECATED: This module is deprecated. Set LICHEN_LEGACY_CBOR=1 to suppress warnings.
"""

from __future__ import annotations

import asyncio
import logging
import os
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lichen.interface.messages import (
    ConfigGet,
    ConfigKey,
    ConfigResult,
    ConfigSet,
    GradientEntry,
    Hello,
    LogSubscribe,
    MeshState,
    Message,
    MessageType,
    NeighborEntry,
    NodeInfo,
    ResultCode,
    SendMessage,
)
from lichen.interface.tcp import TcpConnection, TcpServer, serve

_LEGACY_ENABLED = bool(os.environ.get("LICHEN_LEGACY_CBOR"))

if TYPE_CHECKING:
    from lichen.node import Node

log = logging.getLogger(__name__)


@dataclass
class NodeHandler:
    """
    Handles legacy LICHEN Native CBOR protocol messages for a Node.

    Usage:
        handler = NodeHandler(node)
        server = await handler.serve("localhost", 5684)
    """

    node: Node
    connections: list[TcpConnection] = field(default_factory=list)
    _server: TcpServer | None = None
    _log_subscribers: set[TcpConnection] = field(default_factory=set)

    async def handle(self, msg: Message) -> Message | None:
        """Handle an incoming message, return response if any."""
        if isinstance(msg, Hello):
            return self._handle_hello(msg)
        elif isinstance(msg, ConfigGet):
            return self._handle_config_get(msg)
        elif isinstance(msg, ConfigSet):
            return self._handle_config_set(msg)
        elif isinstance(msg, SendMessage):
            return await self._handle_send_message(msg)
        elif isinstance(msg, LogSubscribe):
            return self._handle_log_subscribe(msg)
        else:
            log.warning("unhandled message type: %s", type(msg).__name__)
            return None

    def _handle_hello(self, msg: Hello) -> Hello:
        """Respond to hello with node info."""
        status = self.node.get_status()
        return Hello(
            version=1,
            supported=[
                MessageType.HELLO,
                MessageType.CONFIG_GET,
                MessageType.CONFIG_SET,
                MessageType.CONFIG_RESULT,
                MessageType.SEND_MESSAGE,
                MessageType.MESSAGE_RECEIVED,
                MessageType.MESH_STATE,
                MessageType.NODE_INFO,
                MessageType.LOG_ENTRY,
                MessageType.LOG_SUBSCRIBE,
            ],
            firmware=status.get("firmware", "lichen-py"),
            iid=self.node.identity.iid,
            name=None,  # ponytail: no name support yet
            features={3: True},  # supports log streaming
        )

    def _handle_config_get(self, msg: ConfigGet) -> ConfigResult:
        """Return node configuration."""
        config = self.node.get_config()

        # Map to protocol config keys
        values = {
            ConfigKey.RECEIVE_TIMEOUT: config.get("receive_timeout_ms", 1000),
            ConfigKey.ANNOUNCE_INTERVAL: config.get("announce_interval_ms", 300000),
        }

        # Filter to requested keys if specified
        if msg.keys:
            values = {k: v for k, v in values.items() if k in msg.keys}

        return ConfigResult(result=ResultCode.OK, values=values)

    def _handle_config_set(self, msg: ConfigSet) -> ConfigResult:
        """Update node configuration."""
        updates = {}

        # Map protocol keys to node config keys
        key_map = {
            ConfigKey.RECEIVE_TIMEOUT: "receive_timeout_ms",
            ConfigKey.ANNOUNCE_INTERVAL: "announce_interval_ms",
        }

        for key, value in msg.values.items():
            if key in key_map:
                updates[key_map[key]] = value

        if updates:
            self.node.set_config(updates)

        return ConfigResult(result=ResultCode.OK)

    async def _handle_send_message(self, msg: SendMessage) -> Message | None:
        """Send a message through the mesh."""
        # ponytail: for now, just wrap in minimal IPv6/UDP and send
        # Full implementation would build proper packet with routing
        try:
            # Build minimal IPv6 packet
            # This is a simplified version - real impl uses full IPv6 builder
            dest_iid = msg.dest[:8] if len(msg.dest) == 8 else msg.dest[8:16]

            # For now, log and acknowledge
            log.info("send_message to %s: %d bytes", dest_iid.hex(), len(msg.payload))

            # ponytail: actual send requires building IPv6/UDP packet
            # await self.node.send(ipv6_packet)

            return None  # No immediate response, ACK comes later if requested
        except Exception as e:
            log.error("send_message failed: %s", e)
            return None

    def _handle_log_subscribe(self, msg: LogSubscribe) -> None:
        """Handle log subscription (connection tracked separately)."""
        # ponytail: subscription state managed per-connection elsewhere
        log.info("log subscribe: enable=%s level=%s", msg.enable, msg.level)
        return None

    def get_mesh_state(self) -> MeshState:
        """Build current mesh state message."""
        gradients = []
        for entry in self.node.gradient_table.entries():  # uses public entries() API
            # Extract IID from IPv6 destination (last 8 bytes)
            dest_iid = entry.destination.packed[8:16]
            next_hop_iid = entry.next_hop.packed[8:16]
            now_ms = int(asyncio.get_running_loop().time() * 1000)
            gradients.append(
                GradientEntry(
                    dest=dest_iid,
                    next_hop=next_hop_iid,
                    hops=entry.hop_count,
                    seq=entry.sequence,
                    expires_ms=max(0, entry.expires_at - now_ms),
                )
            )

        neighbors = []
        for n in self.node.get_neighbors():
            # Extract IID from IPv6 address
            addr = n.get("addr", "")
            if addr:
                # Link-local: fe80::XXXX -> extract last 8 bytes
                try:
                    from ipaddress import IPv6Address
                    iid = IPv6Address(addr).packed[8:16]
                except Exception:
                    iid = bytes(8)
            else:
                iid = bytes(8)

            neighbors.append(
                NeighborEntry(
                    iid=iid,
                    rssi=n.get("rssi", -100),
                )
            )

        return MeshState(gradients=gradients, neighbors=neighbors)

    def get_node_info(self) -> NodeInfo:
        """Build node info message."""
        status = self.node.get_status()
        return NodeInfo(
            iid=self.node.identity.iid,
            name=None,
            firmware=status.get("firmware", "lichen-py"),
            hardware="python-sim",
            uptime_ms=status.get("uptime", 0) * 1000,
        )

    async def serve(self, host: str, port: int) -> TcpServer:
        """Start TCP server for this node."""
        self._server = await serve(host, port, self.handle)
        return self._server

    async def close(self) -> None:
        """Close server and all connections."""
        if self._server:
            await self._server.close()
            self._server = None


async def bind_native(
    node: Node,
    port: int = 5684,
    host: str = "127.0.0.1",
) -> NodeHandler:
    """
    Bind a Node to a LICHEN Native TCP port.

    Args:
        node: The Node to expose
        port: TCP port (default 5684, one above CoAP)
        host: Bind address

    Returns:
        NodeHandler with running server

    .. deprecated::
        Legacy CBOR protocol. Use IPv6 + CoAP from spec/11-lci.md.
        Set LICHEN_LEGACY_CBOR=1 to suppress warning.
    """
    if not _LEGACY_ENABLED:
        warnings.warn(
            "bind_native() is deprecated (legacy CBOR protocol). "
            "Use IPv6 + CoAP interface instead. Set LICHEN_LEGACY_CBOR=1 to suppress.",
            DeprecationWarning,
            stacklevel=2,
        )
    handler = NodeHandler(node=node)
    await handler.serve(host, port)
    return handler
