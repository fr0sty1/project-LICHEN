# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the aiocoap LICHEN transport binding (3dl)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import aiocoap
import pytest
from aiocoap import GET, Message, error, resource

from lichen.coap.transport import (
    DatagramChannel,
    Endpoint,
    EndpointPolicy,
    InMemoryNetwork,
    LichenRemote,
    LichenTransport,
    create_lichen_context,
    parse_channel_endpoint,
    parse_uri_authority,
)


class _Hello(resource.Resource):
    async def render_get(self, request: Message) -> Message:
        return Message(payload=b"hello", code=aiocoap.CONTENT)


class _Echo(resource.Resource):
    async def render_post(self, request: Message) -> Message:
        return Message(payload=request.payload, code=aiocoap.CHANGED)


class _InspectRemote(resource.Resource):
    def __init__(self) -> None:
        super().__init__()
        self.peer: str | None = None
        self.local: str | None = None
        self.request_uri: str | None = None

    async def render_get(self, request: Message) -> Message:
        self.peer = request.remote.hostinfo
        self.local = request.remote.hostinfo_local
        self.request_uri = request.get_request_uri()
        return Message(payload=b"ok", code=aiocoap.CONTENT)


def _transport(context: aiocoap.Context) -> LichenTransport:
    token_manager = context.request_interfaces[0]
    return token_manager.token_interface.message_interface


def test_remote_identity_and_uri() -> None:
    r = LichenRemote("node-b")
    assert r.hostinfo == "node-b"
    assert r.uri_base == "coap://node-b"
    assert r == LichenRemote("node-b")
    assert r != LichenRemote("node-c")
    assert hash(r) == hash(LichenRemote("node-b"))
    assert hash(r) == 3597868155


@pytest.mark.parametrize(
    ("host", "port", "authority", "uri"),
    [
        ("example.test", 5683, "example.test", "coap://example.test"),
        ("example.test", 61616, "example.test:61616", "coap://example.test:61616"),
        ("192.0.2.1", 5683, "192.0.2.1", "coap://192.0.2.1"),
        ("192.0.2.1", 61616, "192.0.2.1:61616", "coap://192.0.2.1:61616"),
        ("2001:db8::1", 5683, "[2001:db8::1]", "coap://[2001:db8::1]"),
        ("2001:db8::1", 61616, "[2001:db8::1]:61616", "coap://[2001:db8::1]:61616"),
    ],
)
def test_endpoint_canonical_formatting(
    host: str, port: int, authority: str, uri: str
) -> None:
    endpoint = Endpoint(host, port)
    assert endpoint.authority == authority
    assert endpoint.uri == uri
    assert parse_uri_authority(authority) == endpoint


def test_explicit_default_port_is_canonicalized() -> None:
    assert parse_uri_authority("example.test:5683").authority == "example.test"
    assert parse_uri_authority("[2001:db8::1]:5683").authority == "[2001:db8::1]"
    assert parse_channel_endpoint("2001:db8::1").authority == "[2001:db8::1]"


def test_ip_literal_spellings_have_one_structural_identity() -> None:
    expanded = Endpoint("2001:0DB8:0:0:0:0:0:1", 61616)
    compressed = Endpoint("2001:db8::1", 61616)
    ipv4 = Endpoint("192.0.2.1")

    assert expanded == compressed
    assert hash(expanded) == hash(compressed)
    assert expanded.authority == "[2001:db8::1]:61616"
    assert ipv4.host == "192.0.2.1"
    assert Endpoint("Node.Example") == Endpoint("node.example")


def test_endpoint_rejects_embedded_port_but_structural_port_remains_valid() -> None:
    with pytest.raises(ValueError, match="colon"):
        Endpoint("peer:61616")
    assert Endpoint("peer", 61616).authority == "peer:61616"


@pytest.mark.parametrize(
    "host",
    ["bad%name", r"bad\name", "bad:name", "bad name", "bad@name", "bad/name"],
)
def test_endpoint_rejects_malformed_reg_names(host: str) -> None:
    with pytest.raises(ValueError):
        Endpoint(host)


@pytest.mark.parametrize(
    ("host", "canonical"),
    [("Peer", "peer"), ("node.example", "node.example"), ("mesh_node-1", "mesh_node-1")],
)
def test_endpoint_accepts_project_reg_names(host: str, canonical: str) -> None:
    assert Endpoint(host).host == canonical


def test_endpoint_policy_revalidates_structural_endpoint() -> None:
    endpoint = object.__new__(Endpoint)
    object.__setattr__(endpoint, "host", "peer:61616")
    object.__setattr__(endpoint, "port", 5683)

    with pytest.raises(ValueError, match="colon"):
        EndpointPolicy().normalize(endpoint)


def test_scoped_ipv6_has_raw_internal_and_encoded_uri_authority() -> None:
    endpoint = Endpoint("FE80:0:0:0:0:0:0:1%radio0", 61616)

    assert endpoint.host == "fe80::1%radio0"
    assert endpoint.authority == "[fe80::1%radio0]:61616"
    assert endpoint.uri == "coap://[fe80::1%25radio0]:61616"
    assert parse_uri_authority("[FE80:0:0:0:0:0:0:1%25radio0]:61616") == endpoint


def test_endpoint_policy_round_trips_and_enforces_owning_scope() -> None:
    policy = EndpointPolicy.owning_link_local("fe80::2%ble0")

    assert EndpointPolicy.deserialize(policy.serialize()) == policy
    assert policy.normalize("fe80::1").authority == "[fe80::1%ble0]"
    assert policy.normalize("[fe80::1%ble0]:61616").authority == (
        "[fe80::1%ble0]:61616"
    )
    assert policy.normalize("2001:db8::1").authority == "[2001:db8::1]"
    with pytest.raises(ValueError, match="does not match"):
        policy.normalize("fe80::1%other")
    with pytest.raises(ValueError, match="IPv6"):
        policy.normalize("peer.example")


@pytest.mark.parametrize("scope", ["ble0", "eth0.100", "interface_name", "interface-name"])
def test_endpoint_policy_valid_scopes_round_trip(scope: str) -> None:
    endpoint = Endpoint(f"fe80::1%{scope}", 61616)
    policy = EndpointPolicy.owning_link_local(f"fe80::2%{scope}")

    assert parse_uri_authority(endpoint.uri_authority) == endpoint
    assert EndpointPolicy.deserialize(policy.serialize()) == policy
    assert policy.normalize(Endpoint("fe80::1", 61616)) == endpoint


@pytest.mark.parametrize(
    "scope",
    ["", "bad@scope", "bad?scope", "bad#scope", "bad[scope", "bad]scope", "bad/scope",
     "bad scope", "bad\x00scope", "bad%scope", chr(0xD800)],
)
def test_endpoint_and_policy_reject_same_malformed_scopes(scope: str) -> None:
    with pytest.raises(ValueError, match="scope"):
        Endpoint(f"fe80::1%{scope}")
    with pytest.raises(ValueError, match="scope"):
        EndpointPolicy(
            scope_mode="owning",
            link_local_scope=scope,
            ipv6_only=True,
        )


def test_endpoint_policy_rejects_unknown_serialized_format() -> None:
    with pytest.raises(ValueError, match="metadata"):
        EndpointPolicy.deserialize('{"version":2}')


@pytest.mark.parametrize(
    "authority",
    [
        "",
        ":5683",
        "host:",
        "host:not-a-port",
        "host:0",
        "host:65536",
        "user@host",
        "host/path",
        "host?query",
        "host#fragment",
        "host name",
        "host\x00name",
        "[example.test]",
        "[2001:db8::1",
        "2001:db8::1]",
        "[2001:db8::1]]",
        "[2001:db8::1]:",
        "[fe80::1%radio0]",
        "2001:db8::1",
    ],
)
def test_strict_uri_authority_rejects_malformed_input(authority: str) -> None:
    with pytest.raises(ValueError):
        parse_uri_authority(authority)


def test_remote_identity_includes_port_and_owner() -> None:
    owner_a = object()
    owner_b = object()
    default = LichenRemote("peer:5683", owner=owner_a)
    same = LichenRemote("peer", owner=owner_a)
    other_port = LichenRemote("peer:61616", owner=owner_a)
    other_owner = LichenRemote("peer", owner=owner_b)

    assert default == same
    assert hash(default) == hash(same)
    assert default.blockwise_key == same.blockwise_key
    assert default != other_port
    assert default.blockwise_key != other_port.blockwise_key
    assert default != other_owner
    assert default.blockwise_key != other_owner.blockwise_key


@pytest.mark.asyncio
async def test_determine_remote_preserves_authority_and_uri_options() -> None:
    context = await create_lichen_context(InMemoryNetwork().channel("local:61617"), "local:61617")
    transport = _transport(context)
    try:
        unresolved = Message(code=GET)
        unresolved.unresolved_remote = "example.test:61616"
        remote = await transport.determine_remote(unresolved)
        assert remote is not None
        assert remote.hostinfo == "example.test:61616"
        assert remote.hostinfo_local == "local:61617"
        assert remote.uri_base == "coap://example.test:61616"
        assert remote.uri_base_local == "coap://local:61617"

        options = SimpleNamespace(
            requested_scheme="coap",
            unresolved_remote=None,
            opt=SimpleNamespace(uri_host="192.0.2.1", uri_port=61616),
        )
        remote = await transport.determine_remote(options)
        assert remote is not None
        assert remote.hostinfo == "192.0.2.1:61616"

        ipv6 = SimpleNamespace(
            requested_scheme="coap",
            unresolved_remote=None,
            opt=SimpleNamespace(uri_host="2001:db8::1", uri_port=61616),
        )
        remote = await transport.determine_remote(ipv6)
        assert remote is not None
        assert remote.hostinfo == "[2001:db8::1]:61616"

        scoped = Message(
            code=GET,
            uri="coap://[FE80:0:0:0:0:0:0:1%25radio0]:61616/resource",
        )
        remote = await transport.determine_remote(scoped)
        assert remote is not None
        assert remote.hostinfo == "[fe80::1%radio0]:61616"
        assert remote.uri_base == "coap://[fe80::1%25radio0]:61616"
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_determine_remote_errors_and_transport_ownership() -> None:
    net = InMemoryNetwork()
    first_context = await create_lichen_context(net.channel("first"), "first")
    second_context = await create_lichen_context(net.channel("second"), "second")
    first = _transport(first_context)
    second = _transport(second_context)
    try:
        malformed = Message(code=GET)
        malformed.unresolved_remote = "2001:db8::1"
        with pytest.raises(error.MalformedUrlError):
            await first.determine_remote(malformed)

        empty_uri_host = SimpleNamespace(
            requested_scheme="coap",
            unresolved_remote=None,
            opt=SimpleNamespace(uri_host="", uri_port=None),
        )
        with pytest.raises(error.MalformedUrlError):
            await first.determine_remote(empty_uri_host)

        unsupported = Message(code=GET, uri="coaps://peer/test")
        assert await first.determine_remote(unsupported) is None

        valid = Message(code=GET)
        valid.unresolved_remote = "peer"
        remote = await first.determine_remote(valid)
        assert remote is not None
        assert await first.recognize_remote(remote)
        assert not await second.recognize_remote(remote)
        wrong_transport = Message(code=GET)
        wrong_transport.remote = remote
        with pytest.raises(ValueError, match="does not belong"):
            second.send(wrong_transport)
    finally:
        await second_context.shutdown()
        await first_context.shutdown()


def test_in_memory_registration_is_owner_safe_and_close_is_idempotent() -> None:
    net = InMemoryNetwork()
    old = net.channel("endpoint")
    duplicate = net.channel("endpoint:5683")

    def receiver(_data: bytes, _source: str) -> None:
        pass

    old.set_receiver(receiver)
    with pytest.raises(RuntimeError, match="already has a receiver"):
        duplicate.set_receiver(receiver)

    old.close()
    replacement = net.channel("endpoint")
    replacement.set_receiver(receiver)
    old.close()
    assert net._receivers[Endpoint("endpoint")][0] is replacement
    replacement.close()
    replacement.close()
    with pytest.raises(RuntimeError, match="closed"):
        replacement.set_receiver(receiver)
    with pytest.raises(RuntimeError, match="closed"):
        replacement.send_datagram(b"data", "peer")


def test_in_memory_ip_alias_registration_does_not_overwrite() -> None:
    net = InMemoryNetwork()
    expanded = net.channel("2001:0DB8:0:0:0:0:0:1")
    compressed = net.channel("[2001:db8::1]:5683")

    expanded.set_receiver(lambda _data, _source: None)
    with pytest.raises(RuntimeError, match="already has a receiver"):
        compressed.set_receiver(lambda _data, _source: None)


@pytest.mark.asyncio
async def test_in_memory_routes_default_and_nondefault_ports_separately() -> None:
    net = InMemoryNetwork()
    default = net.channel("server")
    alternate = net.channel("server:61616")
    sender = net.channel("client")
    received: list[tuple[str, bytes, str]] = []
    default.set_receiver(lambda data, source: received.append(("default", data, source)))
    alternate.set_receiver(lambda data, source: received.append(("alternate", data, source)))

    sender.send_datagram(b"a", "server")
    sender.send_datagram(b"b", "server:61616")
    await asyncio.sleep(0)

    assert received == [
        ("default", b"a", "client"),
        ("alternate", b"b", "client"),
    ]


class _RejectingChannel(DatagramChannel):
    def send_datagram(self, data: bytes, dest: str) -> None:
        raise AssertionError("not used")

    def set_receiver(self, receiver) -> None:
        raise RuntimeError("registration failed")


class _FailingShutdownChannel(DatagramChannel):
    def __init__(self) -> None:
        self.receiver = None
        self.clear_calls = 0
        self.shutdown_calls = 0
        self.shutdown_started = asyncio.Event()
        self.shutdown_release = asyncio.Event()
        self.clear_error = RuntimeError("clear failed")
        self.shutdown_error = RuntimeError("shutdown failed")

    def send_datagram(self, data: bytes, dest: str) -> None:
        raise AssertionError("not used")

    def set_receiver(self, receiver) -> None:
        self.receiver = receiver

    def clear_receiver(self, receiver) -> None:
        self.clear_calls += 1
        raise self.clear_error

    async def shutdown(self) -> None:
        self.shutdown_calls += 1
        self.shutdown_started.set()
        await self.shutdown_release.wait()
        raise self.shutdown_error


@pytest.mark.asyncio
async def test_transport_construction_rolls_back_lifecycle_hooks() -> None:
    context = await create_lichen_context(InMemoryNetwork().channel("local"), "local")
    message_manager = context.request_interfaces[0].token_interface
    original_send = message_manager.send_message
    original_request = message_manager.token_manager.request
    try:
        with pytest.raises(RuntimeError, match="registration failed"):
            LichenTransport(message_manager, _RejectingChannel(), "other")
        assert message_manager.send_message == original_send
        assert message_manager.token_manager.request == original_request
    finally:
        await context.shutdown()


@pytest.mark.asyncio
async def test_transport_concurrent_shutdown_shares_cleanup_and_primary_error() -> None:
    channel = _FailingShutdownChannel()
    context = await create_lichen_context(channel, "local")
    transport = _transport(context)
    original_send = transport._lifecycle._original_send_message
    first = asyncio.create_task(transport.shutdown())
    await channel.shutdown_started.wait()
    second = asyncio.create_task(transport.shutdown())
    channel.shutdown_release.set()

    results = await asyncio.gather(first, second, return_exceptions=True)
    repeated = await asyncio.gather(transport.shutdown(), return_exceptions=True)

    assert results == [channel.clear_error, channel.clear_error]
    assert repeated == [channel.clear_error]
    assert channel.clear_calls == 1
    assert channel.shutdown_calls == 1
    assert transport._mm.send_message == original_send


@pytest.mark.asyncio
async def test_get_request_over_loopback() -> None:
    net = InMemoryNetwork()
    site = resource.Site()
    site.add_resource(["test"], _Hello())

    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        response = await client.request(
            Message(code=GET, uri="coap://server/test")
        ).response
        assert response.payload == b"hello"
        assert response.code == aiocoap.CONTENT
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_server_remote_has_peer_local_identity_and_request_uri() -> None:
    net = InMemoryNetwork()
    inspect_remote = _InspectRemote()
    site = resource.Site()
    site.add_resource(["inspect"], inspect_remote)
    server = await create_lichen_context(
        net.channel("server:61616"), "server:61616", site=site
    )
    client = await create_lichen_context(net.channel("client:61617"), "client:61617")
    try:
        response = await client.request(
            Message(code=GET, uri="coap://server:61616/inspect")
        ).response

        assert response.payload == b"ok"
        assert inspect_remote.peer == "client:61617"
        assert inspect_remote.local == "server:61616"
        assert inspect_remote.request_uri == "coap://server:61616/inspect"
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_post_round_trips_payload() -> None:
    net = InMemoryNetwork()
    site = resource.Site()
    site.add_resource(["echo"], _Echo())

    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        response = await client.request(
            Message(code=aiocoap.POST, uri="coap://server/echo", payload=b"ping")
        ).response
        assert response.payload == b"ping"
        assert response.code == aiocoap.CHANGED
    finally:
        await client.shutdown()
        await server.shutdown()


@pytest.mark.asyncio
async def test_request_to_unknown_resource_returns_not_found() -> None:
    net = InMemoryNetwork()
    site = resource.Site()
    site.add_resource(["test"], _Hello())

    server = await create_lichen_context(net.channel("server"), "server", site=site)
    client = await create_lichen_context(net.channel("client"), "client")
    try:
        response = await client.request(
            Message(code=GET, uri="coap://server/nope")
        ).response
        assert response.code == aiocoap.NOT_FOUND
    finally:
        await client.shutdown()
        await server.shutdown()
