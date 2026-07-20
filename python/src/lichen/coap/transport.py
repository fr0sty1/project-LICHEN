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
import importlib.metadata
import inspect
from abc import ABC, abstractmethod
from collections.abc import Callable
from functools import partial
from typing import Any

import aiocoap
from aiocoap import Message, error, interfaces, util
from aiocoap.numbers import constants
from aiocoap.numbers.codes import EMPTY
from aiocoap.numbers.types import ACK, RST

ReceiveCallback = Callable[[bytes, str], None]


class DatagramChannel(ABC):
    """A bidirectional, host-addressed datagram link for CoAP messages."""

    @abstractmethod
    def send_datagram(self, data: bytes, dest: str) -> None:
        """Send ``data`` to the endpoint identified by ``dest``."""

    def send_message(self, message: Message, dest: str) -> None:
        """Send a message, preserving lifecycle metadata where supported."""
        self.send_datagram(message.encode(), dest)

    @abstractmethod
    def set_receiver(self, receiver: ReceiveCallback) -> None:
        """Register ``receiver(data, source)`` for inbound datagrams."""

    def close(self) -> None:  # noqa: B027 - optional hook, default no-op
        """Release the channel (subclasses override as needed)."""

    async def shutdown(self) -> None:
        """Drain asynchronous work and release the channel."""
        self.close()

    def request_started(
        self, peer: str, token: bytes, *, locally_originated: bool
    ) -> object | None:
        """Return the current request lifecycle identity, if stateful."""
        return None

    def message_admitted(self, message: Message, peer: str) -> object | None:
        """Reserve lifecycle ownership before aiocoap may backlog a message."""
        return None

    def message_abandoned(self, message: Message) -> None:
        """Release lifecycle ownership for a message that will not be sent."""
        return None

    def request_interest_ended(
        self,
        peer: str,
        token: bytes,
        lifecycle_id: object | None,
        *,
        locally_originated: bool,
    ) -> None:
        """Notify stateful wrappers that request interest ended."""
        return None

    def observation_cancelled(
        self,
        peer: str,
        token: bytes,
        lifecycle_id: object | None,
        exchange_lifetime: float,
    ) -> None:
        """Retain a canceled Observe ID for its exchange lifetime."""
        return None

    def response_completed(
        self, peer: str, token: bytes, lifecycle_id: object | None
    ) -> None:
        """Notify stateful wrappers that a terminal response was dispatched."""
        return None

    def exchange_ended(self, peer: str, mid: int, *, reset: bool) -> None:
        """Notify stateful wrappers that a CON exchange was ACKed or reset."""
        return None

    def exchange_expired(self, peer: str, mid: int) -> None:
        """Notify stateful wrappers that a CON exchange exhausted retries."""
        return None


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
        return f"coap://{self._host}"

    @property
    def uri_base_local(self) -> str:
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
        self._lifecycle = _AiocoapLifecycleAdapter(message_manager, channel)
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
        except error.UnparsableMessage:
            return  # drop malformed datagrams
        exchange_key = (message.remote, message.mid)
        active_exchanges = self._mm._active_exchanges
        matched_exchange = (
            active_exchanges.get(exchange_key)
            if message.mtype in (ACK, RST) and active_exchanges is not None
            else None
        )
        self._mm.dispatch_message(message)
        if matched_exchange is not None:
            current = self._mm._active_exchanges
            if current is None or current.get(exchange_key) is not matched_exchange:
                self._channel.exchange_ended(
                    source, message.mid, reset=message.mtype == RST
                )

    def send(self, message: Message) -> None:
        self._channel.send_message(message, message.remote.hostinfo)

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
        self._lifecycle.close()
        await self._channel.shutdown()


class _AiocoapLifecycleAdapter:
    """Isolate the private aiocoap 0.4.17 hooks needed by secure channels."""

    _SUPPORTED_VERSION = "0.4.17"

    def __init__(
        self, message_manager: interfaces.MessageManager, channel: DatagramChannel
    ) -> None:
        version = importlib.metadata.version("aiocoap")
        manager_type = type(message_manager)
        token_manager = getattr(message_manager, "token_manager", None)
        if (
            version != self._SUPPORTED_VERSION
            or manager_type.__module__ != "aiocoap.messagemanager"
            or manager_type.__name__ != "MessageManager"
            or token_manager is None
            or type(token_manager).__module__ != "aiocoap.tokenmanager"
            or type(token_manager).__name__ != "TokenManager"
            or not isinstance(getattr(message_manager, "_active_exchanges", None), dict)
            or not isinstance(getattr(message_manager, "_backlogs", None), dict)
            or not self._has_expected_signature(manager_type._retransmit, 4)
            or not self._has_expected_signature(manager_type.send_message, 3)
            or not self._has_expected_signature(type(token_manager).request, 2)
            or not self._has_expected_signature(type(token_manager).process_request, 2)
        ):
            raise RuntimeError(
                "LICHEN's CoAP lifecycle adapter requires aiocoap 0.4.17 "
                "MessageManager/TokenManager private APIs"
            )

        self._channel = channel
        self._message_manager = message_manager
        self._token_manager = token_manager
        self._original_retransmit = message_manager._retransmit
        self._original_send_message = message_manager.send_message
        self._original_request = token_manager.request
        self._original_process_request = token_manager.process_request
        self._context: aiocoap.Context | None = None
        self._original_context_request: Callable[..., Any] | None = None

        message_manager._retransmit = self._retransmit
        message_manager.send_message = self._send_message
        token_manager.request = self._request
        token_manager.process_request = self._process_request

    @staticmethod
    def _has_expected_signature(method: Callable[..., Any], parameters: int) -> bool:
        try:
            return len(inspect.signature(method).parameters) == parameters
        except (TypeError, ValueError):
            return False

    def _retransmit(self, message: Message, timeout: float, counter: int) -> None:
        dropped = (
            tuple(self._message_manager._backlogs.get(message.remote, ()))
            if counter >= message.transport_tuning.MAX_RETRANSMIT
            else ()
        )
        self._original_retransmit(message, timeout, counter)
        if counter >= message.transport_tuning.MAX_RETRANSMIT:
            for queued, _monitor in dropped:
                self._channel.message_abandoned(queued)
                self._complete_terminal_response(queued)
            self._channel.exchange_expired(message.remote.hostinfo, message.mid)

    def _request(self, pipe: Any) -> None:
        self._original_request(pipe)
        request = pipe.request
        if request.remote is not None:
            lifecycle_id = getattr(request, "_lichen_lifecycle_id", None)
            if lifecycle_id is None:
                lifecycle_id = self._channel.request_started(
                    request.remote.hostinfo,
                    request.token,
                    locally_originated=True,
                )
            request._lichen_lifecycle_id = lifecycle_id

            def interest_ended() -> None:
                self._channel.request_interest_ended(
                    request.remote.hostinfo,
                    request.token,
                    lifecycle_id,
                    locally_originated=True,
                )
                self._drop_backlogged(request)
                self._channel.message_abandoned(request)

            pipe.on_interest_end(interest_ended)

    def _drop_backlogged(self, message: Message) -> None:
        backlogs = self._message_manager._backlogs
        if backlogs is None or message.remote not in backlogs:
            return
        backlogs[message.remote] = [
            (queued, monitor)
            for queued, monitor in backlogs[message.remote]
            if queued is not message
        ]

    def _is_backlogged(self, message: Message) -> bool:
        backlogs = self._message_manager._backlogs
        return backlogs is not None and any(
            queued is message for queued, _monitor in backlogs.get(message.remote, ())
        )

    def _cancel_established_observation(
        self, message: Message, lifecycle_id: object | None
    ) -> None:
        remote = message.remote
        self._channel.observation_cancelled(
            remote.hostinfo,
            message.token,
            lifecycle_id,
            float(
                getattr(
                    message.transport_tuning,
                    "EXCHANGE_LIFETIME",
                    constants.TransportTuning().EXCHANGE_LIFETIME,
                )
            ),
        )
        exchange_key = (remote, message.mid)
        active = self._message_manager._active_exchanges
        matched = active.get(exchange_key) if active is not None else None
        if matched is not None:
            cancellation = Message(code=EMPTY, _mtype=ACK, _mid=message.mid)
            cancellation.remote = remote
            self._message_manager._remove_exchange(cancellation)
            current = self._message_manager._active_exchanges
            if current is None or current.get(exchange_key) is not matched:
                self._channel.exchange_ended(
                    remote.hostinfo, message.mid, reset=False
                )
        outgoing = self._token_manager.outgoing_requests
        if outgoing is not None:
            pipe = outgoing.get((message.token, remote))
            if pipe is not None:
                pipe.add_exception(error.ObservationCancelled())
                outgoing.pop((message.token, remote), None)
        self._drop_backlogged(message)
        self._channel.message_abandoned(message)

    def _process_request(self, request: Message) -> None:
        lifecycle_id = self._channel.request_started(
            request.remote.hostinfo,
            request.token,
            locally_originated=False,
        )
        request._lichen_lifecycle_id = lifecycle_id
        self._original_process_request(request)
        incoming = self._token_manager.incoming_requests
        if incoming is None:
            return
        entry = incoming.get((request.token, request.remote))
        if entry is not None:
            pipe, _stop = entry
            pipe.on_interest_end(
                partial(
                    self._channel.request_interest_ended,
                    request.remote.hostinfo,
                    request.token,
                    lifecycle_id,
                    locally_originated=False,
                )
            )

    def _send_message(self, message: Message, messageerror_monitor: Any) -> Any:
        lifecycle_id = self._channel.message_admitted(
            message, message.remote.hostinfo
        )
        if lifecycle_id is not None:
            message._lichen_lifecycle_id = lifecycle_id
        try:
            result = self._original_send_message(message, messageerror_monitor)
        except BaseException:
            self._channel.message_abandoned(message)
            self._complete_terminal_response(message)
            raise
        if not self._is_backlogged(message):
            self._channel.message_abandoned(message)
        self._complete_terminal_response(message)
        return result

    def _complete_terminal_response(self, message: Message) -> None:
        if message.code.is_response() and message.opt.observe is None:
            request = message.request
            if request is not None:
                self._channel.response_completed(
                    request.remote.hostinfo,
                    request.token,
                    getattr(request, "_lichen_lifecycle_id", None),
                )

    def attach_context(self, context: aiocoap.Context) -> None:
        """Bridge immediate ClientObservation cancellation to channel cleanup."""
        if self._context is not None:
            raise RuntimeError("aiocoap lifecycle adapter context attached twice")
        original = context.request

        def request(message: Message, handle_blockwise: bool = True) -> Any:
            result = original(message, handle_blockwise=handle_blockwise)
            observation = result.observation
            if observation is not None:

                def cancelled() -> None:
                    if message.remote is not None:
                        lifecycle_id = getattr(
                            message, "_lichen_lifecycle_id", None
                        )
                        established = (
                            result.response.done()
                            and not result.response.cancelled()
                            and result.response.exception() is None
                        )
                        if established:
                            self._cancel_established_observation(
                                message, lifecycle_id
                            )
                        else:
                            self._channel.request_interest_ended(
                                message.remote.hostinfo,
                                message.token,
                                lifecycle_id,
                                locally_originated=True,
                            )
                            self._drop_backlogged(message)
                            self._channel.message_abandoned(message)

                observation.on_cancel(cancelled)
            return result

        self._context = context
        self._original_context_request = original
        context.request = request

    def close(self) -> None:
        self._message_manager._retransmit = self._original_retransmit
        self._message_manager.send_message = self._original_send_message
        self._token_manager.request = self._original_request
        self._token_manager.process_request = self._original_process_request
        if self._context is not None and self._original_context_request is not None:
            self._context.request = self._original_context_request
        self._context = None
        self._original_context_request = None


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
    transports: list[LichenTransport] = []

    async def create_transport(mm: interfaces.MessageManager) -> LichenTransport:
        transport = await LichenTransport.create(mm, channel, local_host)
        transports.append(transport)
        return transport

    await context._append_tokenmanaged_messagemanaged_transport(create_transport)
    transports[0]._lifecycle.attach_context(context)
    return context
