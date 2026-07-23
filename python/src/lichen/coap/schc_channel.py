# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
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

import asyncio
import logging
from collections.abc import Callable
from ipaddress import IPv6Address
from typing import Any

from lichen.coap.transport import (
    DatagramChannel,
    Endpoint,
    EndpointPolicy,
    ReceiveCallback,
    parse_channel_endpoint,
    unscoped_ipv6,
)
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, IPv6Packet, NextHeader
from lichen.ipv6.udp import UDP_NEXT_HEADER, UdpDatagram, udp_checksum
from lichen.schc.headers import compress_packet, decompress_packet

logger = logging.getLogger(__name__)

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
    if len(udp) > 0xFFFF:
        raise ValueError(f"UDP datagram too large for IPv6: {len(udp)} > 65535 bytes")
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
        metrics: Any | None = None,
    ) -> None:
        self._inner: DatagramChannel | None = inner
        self._endpoint_policy = inner.endpoint_policy
        self._resolve = resolve
        local = parse_channel_endpoint(local_host, default_port=src_port)
        self._local_endpoint = local
        self._local = unscoped_ipv6(resolve(local.host))
        self._src_port = local.port
        self._dst_port = dst_port
        self._metrics: Any | None = metrics
        self._receiver: ReceiveCallback | None = None
        self._closed = False
        self._teardown_started = False
        self._teardown_error: BaseException | None = None
        self._shutdown_task: asyncio.Task[None] | None = None
        inner.set_receiver(self._on_inner)

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
        if self._closed or self._inner is None:
            raise RuntimeError("channel is closed")
        endpoint = self.normalize_endpoint(
            parse_channel_endpoint(dest, default_port=self._dst_port)
        )
        destination = unscoped_ipv6(self._resolve(endpoint.host))
        raw = wrap_coap(
            self._local,
            destination,
            data,
            src_port=self._src_port,
            dst_port=endpoint.port,
        )
        self._inner.send_datagram(compress_packet(raw), endpoint.authority)

    def _on_inner(self, data: bytes, source: str) -> None:
        if self._closed:
            return
        try:
            raw = decompress_packet(data)
            packet = IPv6Packet.from_bytes(raw)
            if packet.header.next_header != NextHeader.UDP:
                logger.info(
                    "SchcChannel: dropped non-UDP IPv6 from %s", source
                )
                if self._metrics is not None:
                    self._metrics.record_error("dropped non-UDP IPv6")
                return
            udp = UdpDatagram.from_bytes(packet.payload)
            if packet.header.dst_addr.packed != self._local.packed:
                logger.info(
                    "SchcChannel: dropped IPv6 for wrong dst from %s", source
                )
                if self._metrics is not None:
                    self._metrics.record_error("dropped wrong destination")
                return
            if udp.dst_port != self._src_port or udp.checksum == 0:
                logger.info(
                    "SchcChannel: dropped invalid UDP: bad port/checksum from %s", source
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
                logger.warning("SchcChannel: dropped invalid UDP: bad checksum from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("dropped invalid UDP: bad checksum")
                return
            coap = udp.payload
            source_endpoint = parse_channel_endpoint(source)
            if unscoped_ipv6(self._resolve(source_endpoint.host)) != packet.header.src_addr:
                logger.warning("SchcChannel: dropped mismatched source address from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("dropped mismatched source")
                return
            source = Endpoint(source_endpoint.host, udp.src_port).authority
        except Exception as exc:
            logger.warning("SchcChannel: failed to decompress/unwrap packet: %s", exc)
            if self._metrics is not None:
                self._metrics.record_error(f"decompress unwrap failed: {type(exc).__name__}")
            return
        if self._receiver is not None:
            self._receiver(coap, source)

    def close(self) -> None:
        inner = self._claim_teardown()
        if inner is None:
            return
        error: BaseException | None = None
        try:
            inner.clear_receiver(self._on_inner)
        except BaseException as exc:
            error = exc
        try:
            inner.close()
        except BaseException as exc:
            if error is None:
                error = exc
        self._inner = None
        if error is not None:
            self._teardown_error = error
            raise error

    async def shutdown(self) -> None:
        """Release receiver ownership and shut down the inner channel once."""
        if self._shutdown_task is None:
            inner = self._claim_teardown()
            self._shutdown_task = asyncio.create_task(self._shutdown_inner(inner))
        await asyncio.shield(self._shutdown_task)

    async def _shutdown_inner(self, inner: DatagramChannel | None) -> None:
        if inner is None:
            if self._teardown_error is not None:
                raise self._teardown_error
            return
        error: BaseException | None = None
        try:
            inner.clear_receiver(self._on_inner)
        except BaseException as exc:
            error = exc
        try:
            await inner.shutdown()
        except BaseException as exc:
            if error is None:
                error = exc
        self._inner = None
        if error is not None:
            self._teardown_error = error
            raise error

    def _claim_teardown(self) -> DatagramChannel | None:
        if self._teardown_started:
            return None
        self._teardown_started = True
        self._closed = True
        inner = self._inner
        self._receiver = None
        return inner
