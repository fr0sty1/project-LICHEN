"""A SCHC-compressing datagram channel for the CoAP transport (spec sections 3, 7).

Wraps an inner :class:`~lichen.coap.transport.DatagramChannel`: outbound CoAP
message bytes are framed as an IPv6 + UDP datagram and run through
:func:`~lichen.schc.headers.compress_packet`; inbound datagrams are
decompressed and unwrapped back to CoAP bytes. This lets the aiocoap
:class:`~lichen.coap.transport.LichenTransport` exchange SCHC-compressed packets
instead of raw CoAP.

Endpoints are identified by link-local IPv6 address strings (e.g. ``"fe80::1"``)
so the link-local CoAP rule (rule 0) applies; non-link-local packets fall back
to the uncompressed rule. The signed link layer is still future work — this
covers the SCHC portion of the on-air path.
"""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import IPv6Address

from lichen.coap.transport import DatagramChannel, ReceiveCallback
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.ipv6.udp import UDP_NEXT_HEADER, UdpDatagram
from lichen.schc.headers import compress_packet, decompress_packet

DEFAULT_COAP_PORT = 5683
HostResolver = Callable[[str], IPv6Address]


def wrap_coap(
    src: IPv6Address,
    dst: IPv6Address,
    coap: bytes,
    *,
    src_port: int = DEFAULT_COAP_PORT,
    dst_port: int = DEFAULT_COAP_PORT,
) -> bytes:
    """Frame CoAP bytes as an IPv6 + UDP datagram."""
    udp = UdpDatagram(src_port, dst_port, coap).to_bytes(src, dst)
    header = IPv6Header(
        src_addr=src,
        dst_addr=dst,
        next_header=UDP_NEXT_HEADER,
        payload_length=len(udp),
    )
    return header.to_bytes() + udp


def unwrap_coap(raw: bytes) -> bytes:
    """Extract the CoAP (UDP payload) bytes from an IPv6 + UDP datagram."""
    header = IPv6Header.from_bytes(raw)
    if header.next_header != NextHeader.UDP:
        raise ValueError("not a UDP datagram")
    udp = UdpDatagram.from_bytes(
        raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
    )
    return udp.payload


class SchcChannel(DatagramChannel):
    """Compresses CoAP datagrams with SCHC over an inner channel."""

    def __init__(
        self,
        inner: DatagramChannel,
        local_host: str,
        *,
        resolve: HostResolver = IPv6Address,
        src_port: int = DEFAULT_COAP_PORT,
        dst_port: int = DEFAULT_COAP_PORT,
    ) -> None:
        self._inner = inner
        self._resolve = resolve
        self._local = resolve(local_host)
        self._src_port = src_port
        self._dst_port = dst_port
        self._receiver: ReceiveCallback | None = None
        inner.set_receiver(self._on_inner)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        self._receiver = receiver

    def send_datagram(self, data: bytes, dest: str) -> None:
        raw = wrap_coap(
            self._local,
            self._resolve(dest),
            data,
            src_port=self._src_port,
            dst_port=self._dst_port,
        )
        self._inner.send_datagram(compress_packet(raw), dest)

    def _on_inner(self, data: bytes, source: str) -> None:
        coap = unwrap_coap(decompress_packet(data))
        if self._receiver is not None:
            self._receiver(coap, source)

    def close(self) -> None:
        self._inner.close()
