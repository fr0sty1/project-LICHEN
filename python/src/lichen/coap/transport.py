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
import json
import re
import struct
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from ipaddress import IPv6Address, ip_address
from typing import Any
from urllib.parse import quote, unquote

import aiocoap
from aiocoap import Message, error, interfaces
from aiocoap.numbers import constants
from aiocoap.numbers.codes import EMPTY
from aiocoap.numbers.types import ACK

ReceiveCallback = Callable[[bytes, str], None]
DEFAULT_COAP_PORT = 5683
_REG_NAME = re.compile(r"[A-Za-z0-9._-]+\Z")


def _validate_ipv6_scope(scope: object) -> str:
    """Validate an internal IPv6 scope that can round-trip through a URI."""
    if not isinstance(scope, str) or not scope:
        raise ValueError("IPv6 scope must be a nonempty string")
    if any(
        character.isspace()
        or ord(character) < 32
        or ord(character) == 127
        or character in "%[]@/?#"
        for character in scope
    ):
        raise ValueError("IPv6 scope contains invalid characters")
    try:
        IPv6Address(f"fe80::1%{scope}")
        encoded = quote(scope, safe="-._~")
        decoded = unquote(encoded)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("IPv6 scope is not authority-representable") from exc
    if decoded != scope:
        raise ValueError("IPv6 scope is not authority-representable")
    return scope


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A transport endpoint independent of IP literal spelling.

    IPv4 and IPv6 literals are canonicalized. ASCII DNS/reg-names are
    canonicalized to lowercase and reject URI delimiters or ambiguous syntax.
    """

    host: str
    port: int = DEFAULT_COAP_PORT

    def __post_init__(self) -> None:
        if not self.host:
            raise ValueError("endpoint host must not be empty")
        address_text, separator, scope = self.host.partition("%")
        if separator:
            _validate_ipv6_scope(scope)
            try:
                canonical_host = f"{IPv6Address(address_text)}%{scope}"
            except ValueError as exc:
                raise ValueError("scoped endpoint host must be an IPv6 literal") from exc
        else:
            canonical_host = self.host
        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            or character in "[]@/?#"
            for character in address_text
        ):
            raise ValueError("endpoint host contains invalid characters")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise ValueError("endpoint port must be an integer")
        if not 1 <= self.port <= 65535:
            raise ValueError("endpoint port must be between 1 and 65535")
        if not separator:
            try:
                parsed_address = ip_address(self.host)
            except ValueError:
                parsed_address = None
            if parsed_address is not None:
                canonical_host = str(parsed_address)
            else:
                if ":" in self.host:
                    raise ValueError(
                        "endpoint host with a colon must be a valid IPv6 literal"
                    )
                if _REG_NAME.fullmatch(self.host) is None:
                    raise ValueError("endpoint reg-name contains invalid characters")
                canonical_host = self.host.lower()
        object.__setattr__(self, "host", canonical_host)

    @property
    def authority(self) -> str:
        """Return canonical internal authority text with a raw IPv6 scope."""
        host = f"[{self.host}]" if _is_ipv6(self.host) else self.host
        if self.port == DEFAULT_COAP_PORT:
            return host
        return f"{host}:{self.port}"

    @property
    def uri_authority(self) -> str:
        """Return a URI-safe authority, encoding an IPv6 zone delimiter."""
        if not _is_ipv6(self.host):
            return self.authority
        address, separator, scope = self.host.partition("%")
        host = address
        if separator:
            host += f"%25{quote(scope, safe='-._~')}"
        authority = f"[{host}]"
        if self.port != DEFAULT_COAP_PORT:
            authority += f":{self.port}"
        return authority

    @property
    def uri(self) -> str:
        return f"coap://{self.uri_authority}"


@dataclass(frozen=True, slots=True)
class EndpointPolicy:
    """Serializable rules defining one endpoint-identity namespace."""

    version: int = 1
    scope_mode: str = "preserve"
    link_local_scope: str | None = None
    ipv6_only: bool = False

    def __post_init__(self) -> None:
        if self.version != 1:
            raise ValueError(f"unsupported endpoint policy version: {self.version}")
        if self.scope_mode not in {"preserve", "owning"}:
            raise ValueError("unsupported endpoint scope mode")
        if self.scope_mode == "preserve" and self.link_local_scope is not None:
            raise ValueError("preserving endpoint policy cannot own a scope")
        if self.link_local_scope is not None:
            _validate_ipv6_scope(self.link_local_scope)

    @classmethod
    def owning_link_local(cls, local_host: str) -> EndpointPolicy:
        """Create the IPv6 policy owned by a local packet interface."""
        address = IPv6Address(local_host)
        if address.scope_id is not None and not address.is_link_local:
            raise ValueError("IPv6 scope is only supported for link-local endpoints")
        return cls(
            scope_mode="owning",
            link_local_scope=address.scope_id,
            ipv6_only=True,
        )

    def normalize(self, endpoint: str | Endpoint) -> Endpoint:
        """Normalize an endpoint according to this namespace policy."""
        value = (
            Endpoint(endpoint.host, endpoint.port)
            if isinstance(endpoint, Endpoint)
            else parse_channel_endpoint(endpoint)
        )
        try:
            address = IPv6Address(value.host)
        except ValueError:
            if self.ipv6_only:
                raise ValueError("endpoint must be an IPv6 address") from None
            return value
        scope = address.scope_id
        if scope is not None and not address.is_link_local:
            raise ValueError("IPv6 scope is only supported for link-local endpoints")
        if self.scope_mode == "preserve" or not address.is_link_local:
            return value
        if self.link_local_scope is None:
            if scope is not None:
                raise ValueError("scoped peer requires a scoped local interface")
            return value
        if scope is not None and scope != self.link_local_scope:
            raise ValueError("peer scope does not match the local interface")
        return Endpoint(
            f"{unscoped_ipv6(address)}%{self.link_local_scope}",
            value.port,
        )

    def serialize(self) -> str:
        """Return the stable SQLite representation of this policy."""
        return json.dumps(
            {
                "ipv6_only": self.ipv6_only,
                "link_local_scope": self.link_local_scope,
                "scope_mode": self.scope_mode,
                "version": self.version,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def deserialize(cls, value: str) -> EndpointPolicy:
        """Load a policy, rejecting unknown or malformed representations."""
        try:
            payload = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid endpoint policy metadata") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "ipv6_only",
            "link_local_scope",
            "scope_mode",
            "version",
        }:
            raise ValueError("invalid endpoint policy metadata")
        if not isinstance(payload["ipv6_only"], bool):
            raise ValueError("invalid endpoint policy metadata")
        if payload["link_local_scope"] is not None and not isinstance(
            payload["link_local_scope"], str
        ):
            raise ValueError("invalid endpoint policy metadata")
        if (
            not isinstance(payload["scope_mode"], str)
            or isinstance(payload["version"], bool)
            or not isinstance(payload["version"], int)
        ):
            raise ValueError("invalid endpoint policy metadata")
        return cls(
            version=payload["version"],
            scope_mode=payload["scope_mode"],
            link_local_scope=payload["link_local_scope"],
            ipv6_only=payload["ipv6_only"],
        )


def _is_ipv6(host: str) -> bool:
    try:
        IPv6Address(host)
    except ValueError:
        return False
    return True


def unscoped_ipv6(value: str | IPv6Address) -> IPv6Address:
    """Return the wire address, dropping link-local scope metadata."""
    return IPv6Address(IPv6Address(value).packed)


def _decode_uri_ipv6_host(host: str) -> str:
    if "%" not in host:
        return host
    marker = host.lower().find("%25")
    if marker < 0:
        raise ValueError("IPv6 scope delimiter in a URI must be encoded as %25")
    address = host[:marker]
    scope = unquote(host[marker + 3 :])
    _validate_ipv6_scope(scope)
    return f"{address}%{scope}"


def _parse_port(text: str) -> int:
    if not text or not text.isascii() or not text.isdecimal():
        raise ValueError("endpoint port must be numeric")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError("endpoint port must be between 1 and 65535")
    return port


def parse_uri_authority(authority: str, *, default_port: int = DEFAULT_COAP_PORT) -> Endpoint:
    """Parse a strict URI authority, requiring brackets around IPv6 literals."""
    if not authority:
        raise ValueError("URI authority must not be empty")
    if any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in authority
    ):
        raise ValueError("URI authority must not contain whitespace or control characters")
    if any(character in authority for character in "@/?#"):
        raise ValueError("URI authority must contain only a host and optional port")

    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0 or authority.count("[") != 1 or authority.count("]") != 1:
            raise ValueError("mismatched brackets in URI authority")
        host = _decode_uri_ipv6_host(authority[1:closing])
        try:
            IPv6Address(host)
        except ValueError as exc:
            raise ValueError("bracketed URI host must be an IPv6 literal") from exc
        suffix = authority[closing + 1 :]
        if not suffix:
            port = default_port
        elif suffix.startswith(":"):
            port = _parse_port(suffix[1:])
        else:
            raise ValueError("invalid text after bracketed URI host")
        return Endpoint(host, port)

    if "[" in authority or "]" in authority:
        raise ValueError("mismatched brackets in URI authority")
    if authority.count(":") > 1:
        raise ValueError("IPv6 literals in URI authorities must be bracketed")
    if ":" in authority:
        host, port_text = authority.rsplit(":", 1)
        port = _parse_port(port_text)
    else:
        host, port = authority, default_port
    if not host:
        raise ValueError("URI authority host must not be empty")
    return Endpoint(host, port)


def parse_channel_endpoint(value: str, *, default_port: int = DEFAULT_COAP_PORT) -> Endpoint:
    """Parse an internal endpoint, additionally accepting a bare IPv6 host."""
    if value.count(":") > 1 and not value.startswith("["):
        if any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in value
        ):
            raise ValueError("endpoint must not contain whitespace or control characters")
        try:
            IPv6Address(value)
        except ValueError as exc:
            raise ValueError("invalid bare IPv6 endpoint") from exc
        return Endpoint(value, default_port)
    if value.startswith("["):
        closing = value.find("]")
        if closing > 0:
            host = value[1:closing]
            address, separator, scope = host.partition("%")
            if separator:
                encoded = f"{address}%25{quote(scope, safe='-._~')}"
                value = f"[{encoded}]{value[closing + 1:]}"
    return parse_uri_authority(value, default_port=default_port)


class DatagramChannel(ABC):
    """A bidirectional, host-addressed datagram link for CoAP messages."""

    @abstractmethod
    def send_datagram(self, data: bytes, dest: str) -> None:
        """Send ``data`` to the endpoint identified by ``dest``."""

    def send_message(self, message: Message, dest: str) -> None:
        """Send a message, preserving lifecycle metadata where supported."""
        self.send_datagram(message.encode(), dest)

    @property
    def endpoint_policy(self) -> EndpointPolicy:
        """Return the deterministic endpoint namespace used by this channel."""
        return EndpointPolicy()

    def normalize_endpoint(self, endpoint: str | Endpoint) -> Endpoint:
        """Return this channel's canonical endpoint identity."""
        return self.endpoint_policy.normalize(endpoint)

    @abstractmethod
    def set_receiver(self, receiver: ReceiveCallback) -> None:
        """Register ``receiver(data, source)`` for inbound datagrams."""

    def clear_receiver(self, receiver: ReceiveCallback) -> None:  # noqa: B027
        """Release ``receiver`` if it is still registered by this owner."""

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
        self._receivers: dict[Endpoint, tuple[object, ReceiveCallback]] = {}

    def channel(self, host: str) -> InMemoryChannel:
        """Return a channel bound to ``host`` on this fabric."""
        return InMemoryChannel(self, host)

    def _register(
        self, endpoint: Endpoint, owner: object, receiver: ReceiveCallback
    ) -> None:
        if endpoint in self._receivers:
            raise RuntimeError(f"endpoint {endpoint.authority} already has a receiver")
        self._receivers[endpoint] = (owner, receiver)

    def _unregister(self, endpoint: Endpoint, owner: object) -> None:
        registered = self._receivers.get(endpoint)
        if registered is not None and registered[0] is owner:
            self._receivers.pop(endpoint)

    def _deliver(self, source: str, dest: str, data: bytes) -> None:
        registered = self._receivers.get(parse_channel_endpoint(dest))
        if registered is not None:
            registered[1](data, source)


class InMemoryChannel(DatagramChannel):
    """A :class:`DatagramChannel` over an :class:`InMemoryNetwork`.

    Delivery is deferred to the next event-loop iteration (``call_soon``) so a
    synchronous send never re-enters the receiver within the sender's stack.
    """

    def __init__(self, network: InMemoryNetwork, host: str) -> None:
        self._network = network
        self._endpoint = parse_channel_endpoint(host)
        self._receiver: ReceiveCallback | None = None
        self._closed = False

    @property
    def host(self) -> str:
        return self._endpoint.authority

    def set_receiver(self, receiver: ReceiveCallback) -> None:
        if self._closed:
            raise RuntimeError("channel is closed")
        if self._receiver is not None:
            raise RuntimeError("channel already has a receiver")
        self._network._register(self._endpoint, self, receiver)
        self._receiver = receiver

    def clear_receiver(self, receiver: ReceiveCallback) -> None:
        if self._receiver == receiver:
            self._network._unregister(self._endpoint, self)
            self._receiver = None

    def send_datagram(self, data: bytes, dest: str) -> None:
        if self._closed:
            raise RuntimeError("channel is closed")
        endpoint = parse_channel_endpoint(dest)
        loop = asyncio.get_running_loop()
        loop.call_soon(
            self._network._deliver,
            self._endpoint.authority,
            endpoint.authority,
            data,
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._network._unregister(self._endpoint, self)
        self._receiver = None


class LichenRemote(interfaces.EndpointAddress):
    """An aiocoap endpoint address identified by a LICHEN host string."""

    scheme = "coap"
    is_multicast = False
    is_multicast_locally = False
    maximum_block_size_exp = constants.MAX_REGULAR_BLOCK_SIZE_EXP

    def __init__(
        self,
        peer: str | Endpoint,
        local: str | Endpoint | None = None,
        *,
        owner: object | None = None,
    ) -> None:
        self._peer = peer if isinstance(peer, Endpoint) else parse_channel_endpoint(peer)
        self._local = (
            self._peer
            if local is None
            else local if isinstance(local, Endpoint) else parse_channel_endpoint(local)
        )
        self._owner = owner

    @property
    def hostinfo(self) -> str:
        return self._peer.authority

    @property
    def hostinfo_local(self) -> str:
        return self._local.authority

    @property
    def uri_base(self) -> str:
        return f"coap://{self._peer.uri_authority}"

    @property
    def uri_base_local(self) -> str:
        return f"coap://{self._local.uri_authority}"

    @property
    def blockwise_key(self) -> tuple[int, Endpoint]:
        return (id(self._owner), self._peer)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, LichenRemote)
            and other._peer == self._peer
            and other._owner is self._owner
        )

    def __hash__(self) -> int:
        return hash((id(self._owner), self._peer))

    def __repr__(self) -> str:
        return f"<LichenRemote {self.hostinfo}>"


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
        self._local = channel.normalize_endpoint(local_host)
        self._shutdown = False
        self._shutdown_task: asyncio.Task[None] | None = None
        self._lifecycle = _AiocoapLifecycleAdapter(message_manager, channel)
        try:
            channel.set_receiver(self._on_datagram)
        except BaseException:
            self._lifecycle.close()
            raise

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
            message = Message.decode(data, LichenRemote(source, self._local))
        except (error.UnparsableMessage, IndexError, struct.error, TypeError, ValueError):
            return
        self._mm.dispatch_message(message)

    def send(self, message: Message) -> None:
        if not isinstance(message.remote, LichenRemote) or message.remote._owner is not self:
            raise ValueError("remote does not belong to this transport")
        endpoint = self._channel.normalize_endpoint(message.remote.hostinfo)
        if endpoint != message.remote._peer:
            raise ValueError("remote is not canonical for this transport")
        self._channel.send_message(message, endpoint.authority)

    async def recognize_remote(self, remote: object) -> bool:
        return isinstance(remote, LichenRemote) and remote._owner is self

    async def determine_remote(self, message: Message) -> LichenRemote | None:
        try:
            requested_scheme = message.requested_scheme
        except AttributeError:
            requested_scheme = None
        if requested_scheme not in (None, "coap"):
            return None
        try:
            if message.unresolved_remote is not None:
                peer = parse_uri_authority(message.unresolved_remote)
            elif message.opt.uri_host is not None:
                host = message.opt.uri_host
                port = (
                    DEFAULT_COAP_PORT
                    if message.opt.uri_port is None
                    else message.opt.uri_port
                )
                if any(character in host for character in "[]@/?#") or ":" in host:
                    if _is_ipv6(host):
                        peer = Endpoint(host, port)
                    else:
                        raise ValueError("invalid Uri-Host option")
                else:
                    peer = parse_uri_authority(
                        f"{host}:{port}" if port != DEFAULT_COAP_PORT else host
                    )
            else:
                return None
            peer = self._channel.normalize_endpoint(peer)
        except ValueError as exc:
            raise error.MalformedUrlError(str(exc)) from exc
        return LichenRemote(peer, self._local, owner=self)

    async def shutdown(self) -> None:
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.create_task(self._shutdown_once())
        await asyncio.shield(self._shutdown_task)

    async def _shutdown_once(self) -> None:
        self._shutdown = True
        error: BaseException | None = None
        try:
            self._channel.clear_receiver(self._on_datagram)
        except BaseException as exc:
            error = exc
        try:
            self._lifecycle.close()
        except BaseException as exc:
            if error is None:
                error = exc
        try:
            await self._channel.shutdown()
        except BaseException as exc:
            if error is None:
                error = exc
        if error is not None:
            raise error


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
        self._installed_context_request: Callable[..., Any] | None = None

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
        self._installed_context_request = request
        context.request = request

    def close(self) -> None:
        if self._message_manager._retransmit == self._retransmit:
            self._message_manager._retransmit = self._original_retransmit
        if self._message_manager.send_message == self._send_message:
            self._message_manager.send_message = self._original_send_message
        if self._token_manager.request == self._request:
            self._token_manager.request = self._original_request
        if self._token_manager.process_request == self._process_request:
            self._token_manager.process_request = self._original_process_request
        if (
            self._context is not None
            and self._original_context_request is not None
            and self._context.request == self._installed_context_request
        ):
            self._context.request = self._original_context_request
        self._context = None
        self._original_context_request = None
        self._installed_context_request = None


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
