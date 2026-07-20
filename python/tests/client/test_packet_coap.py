# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for CoAP ResourceTransport over packet LCI links."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from ipaddress import IPv6Address
from typing import Any, cast

import aiocoap
import pytest
from aiocoap import GET, Message, resource
from aiocoap.numbers.types import NON

import lichen.client.packet_coap as packet_coap_module
from lichen.client import (
    CoapResult,
    DeliveryState,
    LciClient,
    MessageDraft,
    PacketCoapConfig,
    PacketCoapResourceTransport,
    PacketDatagramChannel,
)
from lichen.client.packet_coap import PacketCoapResourceSubscription
from lichen.coap.resources import MessagesResource, StaticNodeInfo, build_site
from lichen.coap.schc_channel import wrap_coap
from lichen.coap.secure import (
    OscoreContextStore,
    PeerKeyConflictError,
    SecureDatagramChannel,
    TofuPeerResolver,
)
from lichen.coap.transport import create_lichen_context
from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext
from lichen.ipv6.packet import IPv6Packet
from lichen.ipv6.udp import UdpDatagram


class FakePacketTransport:
    def __init__(self) -> None:
        self.peer: FakePacketTransport | None = None
        self.connected = False
        self.closed = False
        self.close_calls = 0
        self.sent_packets: list[bytes] = []
        self.fail_send = False
        self._packets: asyncio.Queue[bytes | None] = asyncio.Queue()

    async def connect(self) -> None:
        self.connected = True
        self.closed = False

    async def close(self) -> None:
        self.close_calls += 1
        self.connected = False
        self.closed = True
        await self._packets.put(None)

    async def send_packet(self, packet: bytes) -> None:
        if self.fail_send:
            raise OSError("packet link down")
        self.sent_packets.append(packet)
        if self.peer is not None:
            await self.peer.inject_packet(packet)

    async def inject_packet(self, packet: bytes) -> None:
        await self._packets.put(packet)

    def packets(self) -> AsyncIterator[bytes]:
        return self._packet_iter()

    async def _packet_iter(self) -> AsyncIterator[bytes]:
        while True:
            packet = await self._packets.get()
            if packet is None:
                return
            yield packet


class FakeResourceSubscription:
    def __init__(self, channel: PacketDatagramChannel | None = None) -> None:
        self.channel = channel
        self.closed = False

    async def close(self) -> None:
        self.closed = True

    def results(self) -> AsyncIterator[CoapResult]:
        return self._results()

    async def _results(self) -> AsyncIterator[CoapResult]:
        if self.channel is not None:
            self.channel.send_datagram(_coap_request(), "fe80::1")
        await asyncio.Event().wait()
        yield CoapResult(code="2.05")


def _packet_pair() -> tuple[FakePacketTransport, FakePacketTransport]:
    client = FakePacketTransport()
    server = FakePacketTransport()
    client.peer = server
    server.peer = client
    return client, server


def _coap_request(token: bytes = b"test", mid: int = 1) -> bytes:
    return cast(bytes, Message(code=GET, _mtype=NON, _mid=mid, _token=token).encode())


def _oscore_pair(
    alice: Identity, bob: Identity
) -> tuple[MemorySecurityContext, MemorySecurityContext]:
    initiator = EdhocInitiator.create(alice, c_i=b"\x00")
    responder = EdhocResponder.create(bob, c_r=b"\x01")
    message_1 = initiator.create_message_1()
    message_2 = responder.process_message_1(message_1, alice.pubkey)
    message_3 = initiator.process_message_2(message_2, bob.pubkey)
    responder.process_message_3(message_3, alice.pubkey)
    return (
        MemorySecurityContext.from_edhoc(initiator.export_oscore()),
        MemorySecurityContext.from_edhoc(responder.export_oscore()),
    )


class _Hello(resource.Resource):
    def __init__(self) -> None:
        super().__init__()
        self.peer: str | None = None

    async def render_get(self, request: Message) -> Message:
        self.peer = request.remote.hostinfo
        return Message(code=aiocoap.CONTENT, payload=b"hello")


class _Observable(resource.ObservableResource):
    def __init__(self) -> None:
        super().__init__()
        self.value = 0

    async def render_get(self, _request: Message) -> Message:
        return Message(code=aiocoap.CONTENT, payload=str(self.value).encode())

    def update(self, value: int) -> None:
        self.value = value
        self.updated_state()


def test_packet_config_formats_peer_and_local_endpoints() -> None:
    default = PacketCoapConfig(peer_host="2001:db8::1")
    alternate = PacketCoapConfig(
        local_host="2001:db8::2",
        peer_host="2001:db8::1",
        src_port=61617,
        dst_port=61616,
    )

    assert default.base_uri == "coap://[2001:db8::1]"
    assert PacketCoapConfig(peer_host="node.example").base_uri == "coap://node.example"
    assert PacketCoapConfig(peer_host="192.0.2.1").base_uri == "coap://192.0.2.1"
    assert (
        PacketCoapConfig(peer_host="192.0.2.1", dst_port=61616).base_uri
        == "coap://192.0.2.1:61616"
    )
    assert alternate.base_uri == "coap://[2001:db8::1]:61616"
    assert alternate.local_endpoint == "[2001:db8::2]:61617"
    scoped = PacketCoapConfig(
        local_host="FE80:0:0:0:0:0:0:2%ble0",
        peer_host="FE80:0:0:0:0:0:0:1%ble0",
    )
    assert scoped.base_uri == "coap://[fe80::1%25ble0]"
    assert scoped.local_endpoint == "[fe80::2%ble0]"


async def _setup_packet_lci() -> tuple[
    LciClient,
    FakePacketTransport,
    PacketDatagramChannel,
    object,
    MessagesResource,
]:
    client_packets, server_packets = _packet_pair()
    await server_packets.connect()
    messages = MessagesResource()
    site = build_site(
        StaticNodeInfo(
            status={"uptime_s": 42, "battery_pct": 88},
            config={"name": "node-a"},
        ),
        messages_resource=messages,
    )
    server_channel = PacketDatagramChannel(server_packets, "fe80::1")
    server_channel.start()
    server = await create_lichen_context(server_channel, "fe80::1", site=site)
    transport = PacketCoapResourceTransport(
        client_packets,
        config=PacketCoapConfig(local_host="fe80::2", peer_host="fe80::1", timeout_s=1.0),
    )
    client = LciClient(transport)
    await client.connect()
    return client, client_packets, server_channel, server, messages


async def _cleanup_packet_lci(
    client: LciClient,
    server_channel: PacketDatagramChannel,
    server: object,
) -> None:
    await client.disconnect()
    await server.shutdown()
    await server_channel.aclose()


async def test_lci_client_get_status_over_packet_resource_transport() -> None:
    client, client_packets, server_channel, server, _ = await _setup_packet_lci()
    try:
        status = await client.get_status()

        assert status.uptime_s == 42
        assert status.battery_pct == 88
        assert client_packets.sent_packets
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


@pytest.mark.asyncio
async def test_plain_aiocoap_request_matches_over_scoped_packet_channels() -> None:
    client_packets, server_packets = _packet_pair()
    await client_packets.connect()
    await server_packets.connect()
    client_channel = PacketDatagramChannel(client_packets, "fe80::2%ble0")
    server_channel = PacketDatagramChannel(server_packets, "fe80::1%ble0")
    client_channel.start()
    server_channel.start()
    hello = _Hello()
    site = resource.Site()
    site.add_resource(["hello"], hello)
    server = await create_lichen_context(
        server_channel, "[fe80::1%ble0]", site=site
    )
    client = await create_lichen_context(client_channel, "[fe80::2%ble0]")
    try:
        response = await client.request(
            Message(code=GET, uri="coap://[fe80::1%25ble0]/hello")
        ).response

        assert response.payload == b"hello"
        assert hello.peer == "[fe80::2%ble0]"

        response = await client.request(
            Message(code=GET, uri="coap://[fe80::1]/hello")
        ).response
        assert response.payload == b"hello"
    finally:
        await client.shutdown()
        await server.shutdown()
        await client_channel.aclose()
        await server_channel.aclose()


@pytest.mark.asyncio
async def test_interface_scope_normalization_and_mismatch_rejection() -> None:
    packet_transport = FakePacketTransport()
    channel = PacketDatagramChannel(packet_transport, "fe80::2%ble0")

    assert channel.normalize_endpoint("fe80::1") == channel.normalize_endpoint(
        "[fe80::1%ble0]"
    )
    assert channel.normalize_endpoint("[fe80::1]:61616").authority == (
        "[fe80::1%ble0]:61616"
    )
    assert channel.normalize_endpoint("fe80::1") != channel.normalize_endpoint(
        "[fe80::1]:61616"
    )
    with pytest.raises(ValueError, match="does not match"):
        channel.send_datagram(_coap_request(), "[fe80::1%ble1]")
    assert packet_transport.sent_packets == []

    unscoped = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    with pytest.raises(ValueError, match="requires a scoped local interface"):
        unscoped.normalize_endpoint("[fe80::1%ble0]")
    with pytest.raises(ValueError, match="only supported for link-local"):
        PacketDatagramChannel(FakePacketTransport(), "2001:db8::2%ble0")


@pytest.mark.asyncio
async def test_separate_interface_owners_canonicalize_peer_independently() -> None:
    blue_channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2%blue")
    green_channel = PacketDatagramChannel(FakePacketTransport(), "fe80::3%green")
    blue = await create_lichen_context(blue_channel, "fe80::2")
    green = await create_lichen_context(green_channel, "fe80::3")
    try:
        blue_transport = blue.request_interfaces[0].token_interface.message_interface
        green_transport = green.request_interfaces[0].token_interface.message_interface
        blue_message = Message(code=GET, uri="coap://[fe80::1]/hello")
        green_message = Message(code=GET, uri="coap://[fe80::1]/hello")
        blue_remote = await blue_transport.determine_remote(blue_message)
        green_remote = await green_transport.determine_remote(green_message)

        assert blue_remote.hostinfo == "[fe80::1%blue]"
        assert green_remote.hostinfo == "[fe80::1%green]"
        assert blue_remote != green_remote
    finally:
        await blue.shutdown()
        await green.shutdown()


@pytest.mark.asyncio
async def test_real_oscore_roundtrip_matches_scoped_packet_sources() -> None:
    alice_packets, bob_packets = _packet_pair()
    await alice_packets.connect()
    await bob_packets.connect()
    alice_channel = PacketDatagramChannel(alice_packets, "fe80::2%ble0")
    bob_channel = PacketDatagramChannel(bob_packets, "fe80::1%ble0")
    alice_channel.start()
    bob_channel.start()
    alice_identity = Identity.generate()
    bob_identity = Identity.generate()
    alice_oscore, bob_oscore = _oscore_pair(alice_identity, bob_identity)
    alice_secure = SecureDatagramChannel(alice_channel, alice_identity)
    bob_secure = SecureDatagramChannel(bob_channel, bob_identity)
    alice_secure.add_context_sync("fe80::1", alice_oscore, bob_identity.pubkey)
    bob_secure.add_context_sync("fe80::2", bob_oscore, alice_identity.pubkey)
    assert alice_secure.has_context_sync("[fe80::1%ble0]")
    assert bob_secure.has_context_sync("[fe80::2%ble0]")
    hello = _Hello()
    observable = _Observable()
    site = resource.Site()
    site.add_resource(["hello"], hello)
    site.add_resource(["observe"], observable)
    bob = await create_lichen_context(bob_secure, "[fe80::1%ble0]", site=site)
    alice = await create_lichen_context(alice_secure, "[fe80::2%ble0]")
    try:
        response = await alice.request(
            Message(code=GET, uri="coap://[fe80::1%25ble0]/hello")
        ).response

        assert response.payload == b"hello"
        assert hello.peer == "[fe80::2%ble0]"

        request = alice.request(
            Message(
                code=GET,
                observe=0,
                uri="coap://[fe80::1%25ble0]/observe",
            )
        )
        assert (await request.response).payload == b"0"
        notifications = request.observation.__aiter__()
        observable.update(1)
        assert (await asyncio.wait_for(anext(notifications), 1.0)).payload == b"1"
        observable.update(2)
        assert (await asyncio.wait_for(anext(notifications), 1.0)).payload == b"2"
    finally:
        await alice.shutdown()
        await bob.shutdown()
        await alice_channel.aclose()
        await bob_channel.aclose()


@pytest.mark.asyncio
async def test_scoped_packet_source_matches_secure_context_key() -> None:
    packet_transport = FakePacketTransport()
    packet_channel = PacketDatagramChannel(packet_transport, "fe80::2%ble0")
    secure = SecureDatagramChannel(packet_channel, Identity.generate())
    oscore = MemorySecurityContext(
        master_secret=b"s" * 16,
        master_salt=b"t" * 8,
        sender_id=b"\x01",
        recipient_id=b"\x02",
    )
    secure.add_context_sync("[FE80:0:0:0:0:0:0:1%ble0]", oscore, b"peer-key")
    seen: list[tuple[str, object | None]] = []

    async def process(_data: bytes, source: str) -> None:
        seen.append((source, await secure._get_peer_context(source)))

    secure._process_incoming = cast(Any, process)
    secure.set_receiver(lambda _data, _source: None)
    packet_channel._handle_packet(
        wrap_coap(
            IPv6Address("fe80::1"),
            IPv6Address("fe80::2"),
            _coap_request(),
        )
    )
    await asyncio.gather(*tuple(secure._tasks))

    assert seen[0][0] == "[fe80::1%ble0]"
    assert seen[0][1] is secure._active_peer_contexts["[fe80::1%ble0]"]
    await secure.shutdown()


@pytest.mark.asyncio
async def test_prebound_tofu_pins_migrate_to_packet_scope() -> None:
    resolver = TofuPeerResolver()
    await resolver.pin_peer("fe80::1", b"default-key")
    await resolver.pin_peer("[fe80::1%ble0]", b"default-key")
    await resolver.pin_peer("[fe80::1]:61616", b"port-key")
    store = OscoreContextStore()
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2%ble0")

    SecureDatagramChannel(
        channel,
        Identity.generate(),
        context_store=store,
        peer_resolver=resolver,
    )

    assert await resolver.get_peer_pubkey("[fe80::1%ble0]") == b"default-key"
    assert await resolver.get_peer_pubkey("fe80::1") == b"default-key"
    assert await resolver.get_peer_pubkey("[fe80::1%ble0]:61616") == b"port-key"
    assert await store.get_peer_pubkey("[fe80::1%ble0]") == b"default-key"
    assert await store.get_peer_pubkey("[fe80::1%ble0]:61616") == b"port-key"

    await resolver.pin_peer("fe80::3", b"new-key")
    assert await resolver.get_peer_pubkey("[fe80::3%ble0]") == b"new-key"


@pytest.mark.asyncio
async def test_store_bound_tofu_context_migrates_before_scope_binding() -> None:
    store = OscoreContextStore()
    context = MemorySecurityContext(
        master_secret=b"c" * 16,
        master_salt=b"s" * 8,
        sender_id=b"\x01",
        recipient_id=b"\x02",
    )
    published = await store.put("fe80::1", context, b"peer-key")
    resolver = TofuPeerResolver(store)
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2%ble0")

    secure = SecureDatagramChannel(
        channel,
        Identity.generate(),
        context_store=store,
        peer_resolver=resolver,
    )
    resolver.bind_authority(store, channel.endpoint_policy)

    assert await store.get("fe80::1") is published
    assert await store.get("[fe80::1%ble0]") is published
    assert set(store._records) == {"[fe80::1%ble0]"}
    assert await resolver.get_peer_pubkey("fe80::1") == b"peer-key"
    assert secure.has_context_sync("[fe80::1%ble0]")


@pytest.mark.asyncio
async def test_tofu_alias_conflict_binding_is_atomic() -> None:
    resolver = TofuPeerResolver()
    await resolver.pin_peer("fe80::1", b"unscoped-key")
    await resolver.pin_peer("[fe80::1%ble0]", b"scoped-key")
    original_pins = dict(resolver._pinned)
    store = OscoreContextStore()
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2%ble0")

    with pytest.raises(PeerKeyConflictError, match="aliases normalize"):
        SecureDatagramChannel(
            channel,
            Identity.generate(),
            context_store=store,
            peer_resolver=resolver,
        )

    assert resolver._pinned == original_pins
    assert resolver._endpoint_policy is None
    assert resolver._context_store is None
    assert resolver._pending_context_store is None
    assert await store.get_peer_pubkey("fe80::1") is None
    assert await store.get_peer_pubkey("[fe80::1%ble0]") is None
    assert channel._receiver is None


async def test_lci_client_send_message_over_packet_resource_transport() -> None:
    client, _, server_channel, server, messages = await _setup_packet_lci()
    try:
        result = await client.send_message(MessageDraft(to="fd00::2", body="hello", ack=True))

        assert result.state is DeliveryState.ACCEPTED
        assert result.location_path == ("msg", "sent", "1")
        assert messages.sent_messages()[0]["body"] == "hello"
        assert messages.sent_messages()[0]["ack"] is True
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_lci_client_observe_inbox_over_packet_resource_transport() -> None:
    client, _, server_channel, server, messages = await _setup_packet_lci()
    try:
        subscription = await client.observe_inbox()
        updates = subscription.messages()

        first = await asyncio.wait_for(anext(updates), timeout=1.0)
        messages.deliver({"from": "fd00::9", "to": "fd00::2", "body": "pushed"})
        second = await asyncio.wait_for(anext(updates), timeout=1.0)

        assert first == []
        assert second[0].body == "pushed"
        await subscription.close()
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_packet_resource_transport_close_closes_packet_transport() -> None:
    client, client_packets, server_channel, server, _ = await _setup_packet_lci()

    await _cleanup_packet_lci(client, server_channel, server)

    assert client_packets.closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["connect", "local", "base_uri", "context", "reader"])
async def test_packet_connect_failure_rolls_back_from_every_stage(
    stage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FailingPacketTransport(FakePacketTransport):
        async def connect(self) -> None:
            if stage == "connect":
                raise RuntimeError("connect failed")
            await super().connect()

        def packets(self) -> AsyncIterator[bytes]:
            if stage != "reader":
                return super().packets()

            async def fail_reader() -> AsyncIterator[bytes]:
                raise RuntimeError("reader failed")
                yield b""  # pragma: no cover

            return fail_reader()

    async def fail_context(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("context failed")

    if stage == "context":
        monkeypatch.setattr(packet_coap_module, "create_lichen_context", fail_context)
    config = PacketCoapConfig(
        local_host=r"bad\local" if stage == "local" else "fe80::2",
        peer_host=r"bad\peer" if stage == "base_uri" else "fe80::1",
    )
    packet = FailingPacketTransport()
    transport = PacketCoapResourceTransport(packet, config=config)

    with pytest.raises(Exception, match=f"{stage}|reg-name"):
        await transport.connect()
    await transport.close()

    assert packet.close_calls == 1
    assert transport._channel is None
    assert transport._resource_transport is None
    assert not any(
        "PacketDatagramChannel._read_packets" in repr(task.get_coro())
        and not task.done()
        for task in asyncio.all_tasks()
    )


@pytest.mark.asyncio
async def test_packet_connect_rollback_preserves_primary_close_error() -> None:
    primary = RuntimeError("connect failed")

    class FailingPacketTransport(FakePacketTransport):
        async def connect(self) -> None:
            raise primary

        async def close(self) -> None:
            self.close_calls += 1
            raise RuntimeError("close failed")

    packet = FailingPacketTransport()
    transport = PacketCoapResourceTransport(packet)

    with pytest.raises(RuntimeError) as raised:
        await transport.connect()

    assert raised.value is primary
    assert packet.close_calls == 1


@pytest.mark.asyncio
async def test_packet_resource_concurrent_close_is_shared_and_preserves_error() -> None:
    class BlockingPacketTransport(FakePacketTransport):
        def __init__(self) -> None:
            super().__init__()
            self.close_started = asyncio.Event()
            self.close_release = asyncio.Event()

        async def close(self) -> None:
            self.close_calls += 1
            if self.close_calls != 1:
                raise RuntimeError("packet transport closed twice")
            self.close_started.set()
            await self.close_release.wait()
            self.closed = True

    resource_error = RuntimeError("resource close failed")

    class FailingResourceTransport:
        close_calls = 0

        async def close(self) -> None:
            self.close_calls += 1
            raise resource_error

    packet = BlockingPacketTransport()
    channel = PacketDatagramChannel(packet, "fe80::2")
    channel.start()
    failing_resource = FailingResourceTransport()
    transport = PacketCoapResourceTransport(packet)
    transport._channel = channel
    transport._resource_transport = cast(Any, failing_resource)
    first = asyncio.create_task(transport.close())
    await packet.close_started.wait()
    second = asyncio.create_task(transport.close())
    packet.close_release.set()

    results = await asyncio.gather(first, second, return_exceptions=True)
    repeated = await asyncio.gather(transport.close(), return_exceptions=True)

    assert results == [resource_error, resource_error]
    assert repeated == [resource_error]
    assert failing_resource.close_calls == 1
    assert packet.close_calls == 1


@pytest.mark.asyncio
async def test_packet_channel_aclose_is_exception_safe_and_idempotent() -> None:
    packet_transport = FakePacketTransport()
    channel = PacketDatagramChannel(packet_transport, "fe80::2")
    reader_error = RuntimeError("reader failed")

    async def fail(error: BaseException) -> None:
        raise error

    reader = asyncio.create_task(fail(reader_error))
    send = asyncio.create_task(fail(OSError("send failed")))
    await asyncio.sleep(0)
    channel._reader_task = reader
    channel._send_tasks.add(send)

    results = await asyncio.gather(channel.aclose(), channel.aclose(), return_exceptions=True)
    repeated = await asyncio.gather(channel.aclose(), return_exceptions=True)

    assert results == [reader_error, reader_error]
    assert repeated == [reader_error]
    assert packet_transport.close_calls == 1
    assert packet_transport.closed


async def test_packet_send_failure_surfaces_as_lci_transport_error() -> None:
    client_packets, server_packets = _packet_pair()
    await server_packets.connect()
    server_channel = PacketDatagramChannel(server_packets, "fe80::1")
    server_channel.start()
    server = await create_lichen_context(
        server_channel,
        "fe80::1",
        site=build_site(StaticNodeInfo(status={"uptime_s": 42})),
    )
    client_packets.fail_send = True
    transport = PacketCoapResourceTransport(
        client_packets,
        config=PacketCoapConfig(local_host="fe80::2", peer_host="fe80::1", timeout_s=0.1),
    )
    client = LciClient(transport)
    await client.connect()
    try:
        with pytest.raises(Exception, match="packet link down"):
            await client.get_status()
        assert client_packets.closed is True
        client_packets.fail_send = False
        with pytest.raises(Exception, match="not connected"):
            await client.get_status()
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_observe_send_failure_surfaces_before_subscription_is_returned() -> None:
    client_packets, server_packets = _packet_pair()
    await server_packets.connect()
    server_channel = PacketDatagramChannel(server_packets, "fe80::1")
    server_channel.start()
    server = await create_lichen_context(
        server_channel,
        "fe80::1",
        site=build_site(
            StaticNodeInfo(status={"uptime_s": 42}),
            messages_resource=MessagesResource(),
        ),
    )
    client_packets.fail_send = True
    transport = PacketCoapResourceTransport(
        client_packets,
        config=PacketCoapConfig(local_host="fe80::2", peer_host="fe80::1", timeout_s=1.0),
    )
    client = LciClient(transport)
    await client.connect()
    try:
        subscription = await client.observe_inbox()
        with pytest.raises(Exception, match="packet link down"):
            await anext(subscription.messages())
        assert client_packets.closed is True
        client_packets.fail_send = False
        with pytest.raises(Exception, match="not connected"):
            await client.get_status()
    finally:
        await _cleanup_packet_lci(client, server_channel, server)


async def test_observe_send_failure_closes_inner_subscription() -> None:
    packet_transport = FakePacketTransport()
    packet_transport.fail_send = True
    channel = PacketDatagramChannel(packet_transport, "fe80::2")
    inner = FakeResourceSubscription(channel)
    subscription = PacketCoapResourceSubscription(inner, channel)

    with pytest.raises(Exception, match="packet link down"):
        await anext(subscription.results())

    assert inner.closed is True


def test_packet_channel_drops_packets_for_other_ipv6_destinations() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(
            IPv6Address("fe80::1"), IPv6Address("fe80::3"), _coap_request()
        )
    )

    assert received == []


def test_packet_channel_drops_packets_for_unexpected_udp_ports() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2", src_port=61616)
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(
            IPv6Address("fe80::1"),
            IPv6Address("fe80::2"),
            _coap_request(),
            src_port=5683,
            dst_port=5683,
        )
    )

    assert received == []


def test_packet_channel_drops_packets_with_bad_udp_checksum() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))
    packet = bytearray(
        wrap_coap(
            IPv6Address("fe80::1"), IPv6Address("fe80::2"), _coap_request()
        )
    )
    packet[-1] ^= 0xFF

    channel._handle_packet(bytes(packet))

    assert received == []


def test_packet_channel_accepts_packets_for_local_coap_port() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(
            IPv6Address("fe80::1"), IPv6Address("fe80::2"), _coap_request()
        )
    )

    assert received == [(_coap_request(), "[fe80::1]")]


@pytest.mark.asyncio
async def test_packet_channel_uses_explicit_destination_port() -> None:
    packet_transport = FakePacketTransport()
    channel = PacketDatagramChannel(packet_transport, "fe80::2", dst_port=61615)

    channel.send_datagram(_coap_request(), "[fe80::1]:61616")
    await asyncio.gather(*tuple(channel._send_tasks))

    packet = IPv6Packet.from_bytes(packet_transport.sent_packets[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert packet.header.dst_addr == IPv6Address("fe80::1")
    assert udp.dst_port == 61616


@pytest.mark.asyncio
async def test_packet_channel_scoped_addresses_use_unscoped_wire_bytes() -> None:
    packet_transport = FakePacketTransport()
    channel = PacketDatagramChannel(packet_transport, "fe80::2%ble0")

    channel.send_datagram(
        _coap_request(), "[FE80:0:0:0:0:0:0:1%ble0]:61616"
    )
    await asyncio.gather(*tuple(channel._send_tasks))

    packet = IPv6Packet.from_bytes(packet_transport.sent_packets[0])
    udp = UdpDatagram.from_bytes(packet.payload)
    assert packet.header.src_addr == IPv6Address("fe80::2")
    assert packet.header.dst_addr == IPv6Address("fe80::1")
    assert udp.dst_port == 61616


def test_packet_channel_preserves_inbound_udp_source_port() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(
            IPv6Address("fe80::1"),
            IPv6Address("fe80::2"),
            _coap_request(),
            src_port=61616,
        )
    )

    assert received == [(_coap_request(), "[fe80::1]:61616")]


def test_packet_channel_scoped_local_accepts_unscoped_wire_destination() -> None:
    channel = PacketDatagramChannel(FakePacketTransport(), "fe80::2%ble0")
    received: list[tuple[bytes, str]] = []
    channel.set_receiver(lambda data, source: received.append((data, source)))

    channel._handle_packet(
        wrap_coap(
            IPv6Address("fe80::1"), IPv6Address("fe80::2"), _coap_request()
        )
    )

    assert received == [(_coap_request(), "[fe80::1%ble0]")]
