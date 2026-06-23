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

from lichen.coap.schc_channel import DEFAULT_COAP_PORT, unwrap_coap, wrap_coap
from lichen.coap.transport import DatagramChannel, ReceiveCallback
from lichen.ipv6.packet import IPv6Packet
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
        node,
        local_host: str,
        *,
        src_port: int = DEFAULT_COAP_PORT,
        dst_port: int = DEFAULT_COAP_PORT,
    ) -> None:
        self._node = node
        self._local = IPv6Address(local_host)
        self._src_port = src_port
        self._dst_port = dst_port
        self._receiver: ReceiveCallback | None = None
        node.set_on_receive(self._on_node_receive)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        self._receiver = receiver

    def send_datagram(self, data: bytes, dest: str) -> None:
        dst = IPv6Address(dest)
        ipv6_bytes = wrap_coap(
            self._local, dst, data, src_port=self._src_port, dst_port=self._dst_port
        )
        asyncio.get_event_loop().create_task(self._node.send(ipv6_bytes))

    def _on_node_receive(self, schc_bytes: bytes, _sender: object) -> None:
        try:
            ipv6_bytes = decompress_packet(schc_bytes)
            coap = unwrap_coap(ipv6_bytes)
            src = str(IPv6Packet.from_bytes(ipv6_bytes).header.src_addr)
        except Exception as exc:
            logger.debug("NodeChannel: failed to unwrap received packet: %s", exc)
            return
        if self._receiver is not None:
            self._receiver(coap, src)

    def close(self) -> None:
        pass
