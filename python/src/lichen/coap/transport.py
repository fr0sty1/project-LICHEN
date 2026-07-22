# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""aiocoap transport binding for the LICHEN stack (spec section 7).

Implements a custom aiocoap :class:`~aiocoap.interfaces.MessageInterface` so
CoAP requests/responses travel over the LICHEN network instead of real UDP.

This is the *thin* variant (see issue 3dl): CoAP datagrams are carried over a
pluggable :class:`DatagramChannel` — an in-memory loopback fabric for tests and
single-process simulations. SCHC compression and the signed link layer are not
yet inserted here; they slot in once the link TX/RX path (9a9/muq) and the SCHC
packet<->field extraction layer exist, by replacing the channel with one that
runs the full pipeline.

aiocoap handles CoAP message serialization, retransmission, and blockwise; this
module only moves opaque datagrams between endpoints addressed by host string.
"""

from __future__ import annotations

import asyncio
import struct
from abc import ABC, abstractmethod
from collections.abc import Callable

import aiocoap
from aiocoap import Message, error, interfaces, util
from aiocoap.numbers import constants

ReceiveCallback = Callable[[bytes, str], None]


class DatagramChannel(ABC):
    """A bidirectional, host-addressed datagram link for CoAP messages."""

    @abstractmethod
    def send_datagram(self, data: bytes, dest: str) -> None:
        """Send ``data`` to the endpoint identified by ``dest``."""

    @abstractmethod
    def set_receiver(self, receiver: ReceiveCallback) -> None:
        """Register ``receiver(data, source)`` for inbound datagrams."""

    def close(self) -> None:  # noqa: B027 - optional hook, default no-op
        """Release the channel (subclasses override as needed)."""


class InMemoryNetwork:
    """An in-process datagram fabric connecting endpoints by host string."""

    def __init__(self) -> None:
        self._receivers: dict[str, ReceiveCallback] = {}

    def channel(self, host: str) -> InMemoryChannel:
        """Return a channel bound to ``host`` on this fabric."""
        return InMemoryChannel(self, host)

    def _register(self, host: str, receiver: ReceiveCallback) -> None:
        self._receivers[host] = receiver

    def _unregister(self, host: str) -> None:
        self._receivers.pop(host, None)

    def _deliver(self, source: str, dest: str, data: bytes) -> None:
        receiver = self._receivers.get(dest)
        if receiver is not None:
            receiver(data, source)


class InMemoryChannel(DatagramChannel):
    """A :class:`DatagramChannel` over an :class:`InMemoryNetwork`.

    Delivery is deferred to the next event-loop iteration (``call_soon``) so a
    synchronous send never re-enters the receiver within the sender's stack.
    """

    def __init__(self, network: InMemoryNetwork, host: str) -> None:
        self._network = network
        self._host = host

    @property
    def host(self) -> str:
        return self._host

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        self._network._register(self._host, receiver)

    def send_datagram(self, data: bytes, dest: str) -> None:
        loop = asyncio.get_running_loop()
        loop.call_soon(self._network._deliver, self._host, dest, data)

    def close(self) -> None:
        self._network._unregister(self._host)


class LichenRemote(interfaces.EndpointAddress):
    """An aiocoap endpoint address identified by a LICHEN host string."""

    scheme = "coap"
    is_multicast = False
    is_multicast_locally = False
    maximum_block_size_exp = constants.MAX_REGULAR_BLOCK_SIZE_EXP

    def __init__(self, host: str) -> None:
        self._host = host

    @property
    def hostinfo(self) -> str:
        return self._host

    @property
    def hostinfo_local(self) -> str:
        return self._host

    @property
    def uri_base(self) -> str:
        if ":" in self._host:  # IPv6
            return f"coap://[{self._host}]"
        return f"coap://{self._host}"

    @property
    def uri_base_local(self) -> str:
        if ":" in self._host:  # IPv6
            return f"coap://[{self._host}]"
        return f"coap://{self._host}"

    @property
    def blockwise_key(self) -> str:
        return self._host

    def __eq__(self, other: object) -> bool:
        return isinstance(other, LichenRemote) and other._host == self._host

    def __hash__(self) -> int:
        return hash(self._host)

    def __repr__(self) -> str:
        return f"<LichenRemote {self._host}>"


class LichenTransport(interfaces.MessageInterface):
    """A CoAP MessageInterface that carries datagrams over a DatagramChannel."""

    def __init__(
        self,
        message_manager: interfaces.MessageManager,
        channel: DatagramChannel,
        local_host: str,
    ) -> None:
        self._mm = message_manager
        self._channel = channel
        self._local_host = local_host
        channel.set_receiver(self._on_datagram)

    @classmethod
    async def create(
        cls,
        message_manager: interfaces.MessageManager,
        channel: DatagramChannel,
        local_host: str,
    ) -> LichenTransport:
        return cls(message_manager, channel, local_host)

    def _on_datagram(self, data: bytes, source: str) -> None:
        try:
            message = Message.decode(data, LichenRemote(source))
        except (error.UnparsableMessage, IndexError, struct.error, TypeError, ValueError):
            return  # drop malformed datagrams
        self._mm.dispatch_message(message)

    def send(self, message: Message) -> None:
        self._channel.send_datagram(message.encode(), message.remote.hostinfo)

    async def recognize_remote(self, remote: object) -> bool:
        return isinstance(remote, LichenRemote)

    async def determine_remote(self, message: Message) -> LichenRemote | None:
        if message.requested_scheme not in (None, "coap"):
            return None
        if message.unresolved_remote is not None:
            host, _port = util.hostportsplit(message.unresolved_remote)
        elif message.opt.uri_host:
            host = message.opt.uri_host
        else:
            return None
        return LichenRemote(host)

    async def shutdown(self) -> None:
        self._channel.close()


async def create_lichen_context(
    channel: DatagramChannel,
    local_host: str,
    *,
    site: aiocoap.resource.Site | None = None,
) -> aiocoap.Context:
    """Build an aiocoap Context whose only transport is the LICHEN channel.

    Pass ``site`` to serve resources; omit it for a client-only context.
    """
    context = aiocoap.Context(serversite=site)
    await context._append_tokenmanaged_messagemanaged_transport(
        lambda mm: LichenTransport.create(mm, channel, local_host)
    )
    return context
