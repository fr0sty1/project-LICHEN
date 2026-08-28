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
import threading
from collections.abc import Callable
from ipaddress import IPv6Address
from typing import Any

from lichen.coap.params import CongestionLevel, CongestionState
from lichen.coap.transport import (
    DatagramChannel,
    Endpoint,
    EndpointPolicy,
    Priority,
    ReceiveCallback,
    parse_channel_endpoint,
    unscoped_ipv6,
)
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, IPv6Packet, NextHeader, PacketError
from lichen.ipv6.udp import UDP_NEXT_HEADER, UdpDatagram, UdpError, udp_checksum
from lichen.schc.codec import SchcError
from lichen.schc.headers import compress_packet, decompress_packet

logger = logging.getLogger(__name__)

DEFAULT_COAP_PORT = 5683
MAX_PACKET_SIZE = 1280  # IPv6 minimum MTU
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
    if HEADER_LENGTH + header.payload_length > len(raw):
        avail = len(raw) - HEADER_LENGTH
        raise ValueError(f"payload_length {header.payload_length} exceeds available bytes {avail}")
    udp = UdpDatagram.from_bytes(raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length])
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
        if inner is None:
            raise TypeError("inner channel must not be None")
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
        self._teardown_lock = threading.Lock()
        self._shutdown_task: asyncio.Task[None] | None = None
        inner.set_receiver(self._on_inner)

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        if receiver is None:
            raise TypeError("receiver must be a callable")
        if self._closed:
            raise RuntimeError("channel is closed")
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> bool:
        if self._receiver == receiver:
            self._receiver = None
            return True
        return False

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        return self._endpoint_policy

    @property
    def congestion_level(self) -> CongestionLevel:
        """Delegate congestion level to inner channel."""
        inner = self._inner
        if self._closed or inner is None:
            return CongestionLevel.EXHAUSTED
        return inner.congestion_level

    @property
    def retry_after_ms(self) -> int | None:
        """Delegate retry delay to inner channel."""
        inner = self._inner
        if self._closed or inner is None:
            return None
        return inner.retry_after_ms

    def congestion_state(self) -> CongestionState:
        """Delegate atomic congestion snapshot to inner channel."""
        inner = self._inner
        if self._closed or inner is None:
            return CongestionState(level=CongestionLevel.EXHAUSTED, retry_after_ms=None)
        return inner.congestion_state()

    def send_datagram(
        self,
        data: bytes,
        dest: str,
        *,
        priority: Priority = Priority.NORMAL,
        check_congestion: bool = True,
    ) -> None:
        inner = self._inner
        if self._closed or inner is None:
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
        if len(raw) > MAX_PACKET_SIZE:
            raise ValueError(
                f"CoAP message too large for SCHC channel: {len(raw)} > {MAX_PACKET_SIZE} bytes"
            )
        inner.send_datagram(
            compress_packet(raw),
            endpoint.authority,
            priority=priority,
            check_congestion=check_congestion,
        )

    def _on_inner(self, data: bytes, source: str) -> None:
        if self._closed:
            return
        # SECURITY: Sequential validation checks below have varying execution time.
        # Timing side-channels are acceptable here: the values being checked (packet
        # size, next_header, dst_addr, port, checksum, source match) are not secrets.
        # An attacker inferring which validation failed gains no cryptographic advantage.
        try:
            raw = decompress_packet(data)
            if len(raw) > MAX_PACKET_SIZE:
                logger.debug("SchcChannel: dropped invalid packet from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("invalid_packet")
                return
            packet = IPv6Packet.from_bytes(raw)
            if packet.header.next_header != NextHeader.UDP:
                logger.debug("SchcChannel: dropped invalid packet from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("invalid_packet")
                return
            udp = UdpDatagram.from_bytes(packet.payload)
            # SECURITY: Non-constant-time comparison is acceptable here since IP
            # addresses are not secrets. Constant-time comparison would be overkill.
            if packet.header.dst_addr.packed != self._local.packed:
                logger.debug("SchcChannel: dropped invalid packet from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("invalid_packet")
                return
            if udp.dst_port != self._src_port:
                logger.debug("SchcChannel: dropped invalid packet from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("invalid_packet")
                return
            if (
                udp_checksum(
                    packet.header.src_addr,
                    packet.header.dst_addr,
                    packet.payload,
                )
                != 0
            ):
                logger.debug("SchcChannel: dropped invalid packet from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("invalid_packet")
                return
            coap = udp.payload
            source_endpoint = parse_channel_endpoint(source)
            if unscoped_ipv6(self._resolve(source_endpoint.host)) != packet.header.src_addr:
                logger.debug("SchcChannel: dropped invalid packet from %s", source)
                if self._metrics is not None:
                    self._metrics.record_error("invalid_packet")
                return
            source = Endpoint(source_endpoint.host, udp.src_port).authority
        except (SchcError, PacketError, UdpError, ValueError):
            logger.debug("SchcChannel: dropped invalid packet from %s", source)
            if self._metrics is not None:
                self._metrics.record_error("invalid_packet")
            return
        receiver = self._receiver
        if receiver is not None:
            receiver(coap, source)

    def close(self) -> None:
        """Synchronously close the channel.

        Thread safety: Must only be called from the asyncio event loop thread.
        """
        inner = self._claim_teardown()
        if inner is None:
            return
        error: BaseException | None = None
        try:
            if not inner.clear_receiver(self._on_inner):
                logger.warning("clear_receiver returned False during close - possible double-close")
        except BaseException as exc:
            error = exc
        try:
            inner.close()
        except BaseException as exc:
            if error is None:
                error = exc
            else:
                exc.__context__ = error
                error = exc
        self._inner = None
        if error is not None:
            self._teardown_error = error
            raise error

    async def shutdown(self) -> None:
        """Release receiver ownership and shut down the inner channel once.

        Thread safety: Must only be called from the asyncio event loop thread.
        """
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
            if not inner.clear_receiver(self._on_inner):
                logger.warning(
                    "clear_receiver returned False during shutdown - possible double-close"
                )
        except BaseException as exc:
            error = exc
        try:
            await inner.shutdown()
        except BaseException as exc:
            if error is None:
                error = exc
            else:
                exc.__context__ = error
                error = exc
        self._inner = None
        if error is not None:
            self._teardown_error = error
            raise error

    def _claim_teardown(self) -> DatagramChannel | None:
        """Atomically claim the teardown, returning the inner channel or None if already claimed.

        Thread safety: Uses explicit lock for synchronization, safe with threaded event loops.
        """
        with self._teardown_lock:
            if self._teardown_started:
                return None
            self._teardown_started = True
            self._closed = True
            inner = self._inner
            self._receiver = None
            return inner
