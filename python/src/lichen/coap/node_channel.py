"""NodeChannel: routes CoAP datagrams through a LICHEN Node for multi-hop delivery.

Wraps a :class:`~lichen.node.Node` as a :class:`~lichen.coap.transport.DatagramChannel`
so that aiocoap traffic travels through the full SCHC-compress → route → link-layer
stack rather than the in-memory loopback used in single-node tests.

Host addresses are ULA IPv6 address strings (``"fd00::1"``).  Outbound CoAP bytes
are framed as IPv6 + UDP, compressed with SCHC, routed by the Node's Router, and
transmitted via the signed link layer.  Inbound SCHC packets are decompressed and
the CoAP payload is extracted before delivery to aiocoap.
"""

from __future__ import annotations

import asyncio
import logging
from ipaddress import IPv6Address
from typing import Any

from lichen.coap.schc_channel import DEFAULT_COAP_PORT, wrap_coap
from lichen.coap.transport import (
    DatagramChannel,
    Endpoint,
    EndpointPolicy,
    ReceiveCallback,
    parse_channel_endpoint,
    unscoped_ipv6,
)
from lichen.ipv6.packet import IPv6Packet, NextHeader
from lichen.ipv6.udp import UdpDatagram, udp_checksum
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body
from lichen.schc.headers import decompress_packet

logger = logging.getLogger(__name__)


class NodeChannel(DatagramChannel):
    """Routes CoAP datagrams through a Node for multi-hop mesh delivery.

    The ``local_host`` and destination strings must be valid IPv6 address
    strings (e.g. ``"fd00::1"``).  The Node must have its gradient table
    pre-populated so that ``node.send()`` can find a next-hop.

    Why NodeChannel vs SchcChannel: SchcChannel wraps an InMemoryChannel for
    single-process loopback; NodeChannel wraps the full Node (link layer +
    router + SCHC) for real multi-hop delivery.
    """

    def __init__(
        self,
        node: Any,
        local_host: str,
        *,
        src_port: int = DEFAULT_COAP_PORT,
        dst_port: int = DEFAULT_COAP_PORT,
        metrics: Any | None = None,
    ) -> None:
        self._node: Any | None = node
        self._metrics: Any | None = metrics
        local = parse_channel_endpoint(local_host, default_port=src_port)
        local_address = IPv6Address(local.host)
        if local_address.scope_id is not None and not local_address.is_link_local:
            raise ValueError("IPv6 scope is only supported for link-local endpoints")
        self._local_endpoint = local
        self._local = unscoped_ipv6(local.host)
        self._endpoint_policy = EndpointPolicy.owning_link_local(local.host)
        self._src_port = local.port
        self._dst_port = dst_port
        self._receiver: ReceiveCallback | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self._closed = False
        node.register_on_receive(self, self._on_node_receive)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        if self._closed:
            raise RuntimeError("channel is closed")
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver == receiver:
            self._receiver = None

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._endpoint_policy

    def send_datagram(self, data: bytes, dest: str) -> None:
        if self._closed or self._node is None:
            raise RuntimeError("channel is closed")
        endpoint = self.normalize_endpoint(
            parse_channel_endpoint(dest, default_port=self._dst_port)
        )
        destination = IPv6Address(endpoint.host)
        dst = unscoped_ipv6(destination)
        ipv6_bytes = wrap_coap(
            self._local, dst, data, src_port=self._src_port, dst_port=endpoint.port
        )
        task = asyncio.get_running_loop().create_task(self._node.send(ipv6_bytes))
        self._tasks.add(task)
        task.add_done_callback(self._on_send_done)

    def _on_send_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.warning("NodeChannel: send failed: %s", exc)

    def _on_node_receive(self, payload: bytes, sender: object) -> None:
        if self._closed:
            return
        try:
            if classify_l2_payload(payload) is not L2PayloadKind.SCHC:
                logger.info(
                    "NodeChannel: dropped non-SCHC L2 payload from %s", sender
                )
                if self._metrics is not None:
                    self._metrics.record_error("dropped non-SCHC L2 payload")
                return
            ipv6_bytes = decompress_packet(l2_payload_body(payload))
            packet = IPv6Packet.from_bytes(ipv6_bytes)
            if (
                packet.header.src_addr.is_unspecified
                or packet.header.src_addr.is_multicast
            ):
                logger.warning(
                    "NodeChannel: dropped malformed source from %s", sender
                )
                if self._metrics is not None:
                    self._metrics.record_error("dropped malformed source")
                return
            if packet.header.next_header != NextHeader.UDP:
                logger.info(
                    "NodeChannel: dropped non-UDP IPv6 from %s", sender
                )
                if self._metrics is not None:
                    self._metrics.record_error("dropped non-UDP IPv6")
                return
            udp = UdpDatagram.from_bytes(packet.payload)
            if packet.header.dst_addr.packed != self._local.packed:
                logger.info(
                    "NodeChannel: dropped IPv6 for wrong dst from %s", sender
                )
                if self._metrics is not None:
                    self._metrics.record_error("dropped wrong destination")
                return
            if udp.dst_port != self._src_port or udp.checksum == 0:
                logger.info(
                    "NodeChannel: dropped invalid UDP: bad port or checksum from %s",
                    sender,
                )
                if self._metrics is not None:
                    self._metrics.record_error("dropped invalid UDP: bad port or checksum")
                return
            if (
                udp_checksum(
                    packet.header.src_addr,
                    packet.header.dst_addr,
                    packet.payload,
                )
                != 0
            ):
                logger.warning("NodeChannel: dropped invalid UDP: bad checksum from %s", sender)
                if self._metrics is not None:
                    self._metrics.record_error("dropped invalid UDP: bad checksum")
                return
            coap = udp.payload
            src = self.normalize_endpoint(
                Endpoint(str(packet.header.src_addr), udp.src_port)
            ).authority
        except Exception as exc:
            logger.warning("NodeChannel: failed to unwrap received packet: %s", exc)
            if self._metrics is not None:
                self._metrics.record_error(f"unwrap failed: {type(exc).__name__}")
            return
        if self._receiver is not None:
            self._receiver(coap, src)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        node = self._node
        self._node = None
        self._receiver = None
        if node is not None:
            node.unregister_on_receive(self)
        for task in tuple(self._tasks):
            task.cancel()

    async def shutdown(self) -> None:
        """Release callback ownership and drain pending sends."""
        self.close()
        tasks = tuple(self._tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
