# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for EDHOC CoAP transport integration (spec section 8.8)."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any, cast

import aiocoap
import pytest

from lichen.client.packet_coap import PacketDatagramChannel
from lichen.coap.resources import EdhocResource, StaticNodeInfo, build_site
from lichen.coap.secure import (
    OscoreContextStore,
    PeerContext,
    SecureDatagramChannel,
    SqliteOscoreContextStore,
    TofuPeerResolver,
    TransactionalOscoreContextStore,
)
from lichen.coap.transport import (
    EndpointPolicy,
    InMemoryNetwork,
    LichenRemote,
    create_lichen_context,
)
from lichen.crypto.edhoc import EdhocInitiator
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext


class _CapturedRequest:
    def __init__(self, response: aiocoap.Message) -> None:
        loop = asyncio.get_running_loop()
        self.response: asyncio.Future[aiocoap.Message] = loop.create_future()
        self.response.set_result(response)


class _CapturingContext:
    def __init__(self) -> None:
        self.message: aiocoap.Message | None = None

    def request(self, message: aiocoap.Message) -> _CapturedRequest:
        self.message = message
        return _CapturedRequest(aiocoap.Message(code=aiocoap.CHANGED, payload=b"response"))


class _FailingPutStore(OscoreContextStore):
    async def put(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext:
        raise RuntimeError("injected context publication failure")


class _BlockingPutStore(OscoreContextStore):
    def __init__(self, *, fail: bool = False) -> None:
        super().__init__()
        self.fail = fail
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def put(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext:
        self.started.set()
        await self.release.wait()
        if self.fail:
            raise RuntimeError("injected blocked publication failure")
        return await super().put(
            host,
            oscore_ctx,
            peer_pubkey,
            expected_generation=expected_generation,
        )


class _CancellationDefinitiveStore(OscoreContextStore):
    def __init__(self, *, commit_after_cancel: bool) -> None:
        super().__init__()
        self.commit_after_cancel = commit_after_cancel
        self.started = asyncio.Event()

    async def put(
        self,
        host: str,
        oscore_ctx: MemorySecurityContext,
        peer_pubkey: bytes,
        *,
        expected_generation: int | None = None,
    ) -> PeerContext:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            if not self.commit_after_cancel:
                raise RuntimeError("publication rolled back after cancellation") from None
        return await super().put(
            host,
            oscore_ctx,
            peer_pubkey,
            expected_generation=expected_generation,
        )


class _ScheduledCall:
    def __init__(self, when: float, callback: Any) -> None:
        self.when = when
        self.callback = callback
        self.cancelled = False
        self.fired = False

    def cancel(self) -> None:
        self.cancelled = True


class _FakeScheduler:
    def __init__(self, now: list[float]) -> None:
        self.now = now
        self.calls: list[_ScheduledCall] = []

    def call_later(self, delay: float, callback: Any) -> _ScheduledCall:
        call = _ScheduledCall(self.now[0] + delay, callback)
        self.calls.append(call)
        return call

    def advance(self, when: float) -> None:
        self.now[0] = when
        while True:
            ready = [
                call
                for call in self.calls
                if not call.cancelled and not call.fired and call.when <= when
            ]
            if not ready:
                return
            call = min(ready, key=lambda item: item.when)
            call.fired = True
            call.callback()


def _edhoc_request(payload: bytes, host: str = "alice") -> aiocoap.Message:
    request = aiocoap.Message(code=aiocoap.POST, payload=payload)
    request.remote = LichenRemote(host)
    return request


@pytest.mark.asyncio
async def test_scoped_responder_normalizes_session_lookup_and_publication() -> None:
    alice = Identity.generate()
    bob = Identity.generate()
    store = OscoreContextStore()
    resolver = TofuPeerResolver()
    await resolver.pin_peer("fe80::2", alice.pubkey)
    channel = PacketDatagramChannel(cast(Any, object()), "fe80::1%ble0")
    edhoc = EdhocResource(bob, store, resolver)
    build_site(
        StaticNodeInfo(),
        edhoc_resource=edhoc,
        endpoint_policy=channel.endpoint_policy,
    )
    initiator = EdhocInitiator.create(alice, c_i=b"\x00")

    request_1 = aiocoap.Message(
        code=aiocoap.POST,
        payload=initiator.create_message_1(),
    )
    request_1.remote = LichenRemote("fe80::2")
    response_2 = await edhoc.render_post(request_1)

    assert response_2.code.is_successful()
    assert {host for host, _c_i in edhoc._sessions} == {"[fe80::2%ble0]"}
    request_3 = aiocoap.Message(
        code=aiocoap.POST,
        payload=initiator.process_message_2(response_2.payload, bob.pubkey),
    )
    request_3.remote = LichenRemote("fe80::2")
    response_3 = await edhoc.render_post(request_3)

    assert response_3.code.is_successful()
    assert edhoc._sessions == {}
    published = await store.get("[fe80::2%ble0]")
    assert published is not None
    assert await store.get("fe80::2") is published
    assert set(store._records) == {"[fe80::2%ble0]"}


@pytest.mark.asyncio
async def test_default_edhoc_resource_installs_legacy_sqlite_policy(tmp_path: Path) -> None:
    store = SqliteOscoreContextStore(tmp_path / "legacy-edhoc.sqlite3")
    with sqlite3.connect(store._path) as connection:
        connection.executemany(
            "INSERT INTO oscore_hosts (host, peer_pubkey) VALUES (?, ?)",
            [("Peer", b"peer-key"), ("peer", b"peer-key")],
        )
    resolver = TofuPeerResolver(store)
    resource = EdhocResource(Identity.generate(), store, resolver)

    assert await resource._peer_resolver.get_peer_pubkey("PEER") == b"peer-key"
    with sqlite3.connect(store._path) as connection:
        hosts = {str(row[0]) for row in connection.execute("SELECT host FROM oscore_hosts")}
        metadata = connection.execute(
            "SELECT value FROM oscore_metadata WHERE key = 'endpoint_policy'"
        ).fetchone()
    assert hosts == {"peer"}
    assert metadata == (EndpointPolicy().serialize(),)


@pytest.mark.asyncio
async def test_secure_edhoc_uses_canonical_ipv6_endpoint_uri(monkeypatch) -> None:
    channel = SecureDatagramChannel(
        InMemoryNetwork().channel("[2001:db8::2]:61617"),
        Identity.generate(),
        local_host="[2001:db8::2]:61617",
    )
    context = _CapturingContext()

    async def get_context() -> _CapturingContext:
        return context

    monkeypatch.setattr(channel, "_get_edhoc_context", get_context)

    response = await channel._edhoc_exchange("[2001:db8::1]:61616", b"message-1")

    assert response == b"response"
    assert context.message is not None
    assert context.message.get_request_uri() == (
        "coap://[2001:db8::1]:61616/.well-known/edhoc"
    )


class TestEdhocResource:
    """Tests for EdhocResource at /.well-known/edhoc."""

    @pytest.fixture
    def alice_identity(self) -> Identity:
        return Identity.generate()

    @pytest.fixture
    def bob_identity(self) -> Identity:
        return Identity.generate()

    @pytest.fixture
    def context_store(self) -> TransactionalOscoreContextStore:
        return OscoreContextStore()

    @pytest.fixture
    def peer_resolver(self) -> TofuPeerResolver:
        return TofuPeerResolver()

    @pytest.mark.asyncio
    async def test_edhoc_resource_creation(
        self,
        bob_identity: Identity,
        context_store: TransactionalOscoreContextStore,
        peer_resolver: TofuPeerResolver,
    ) -> None:
        """EdhocResource can be created and added to a site."""
        edhoc = EdhocResource(bob_identity, context_store, peer_resolver)
        info = StaticNodeInfo()
        site = build_site(info, edhoc_resource=edhoc)

        # Check resource is mounted at /.well-known/edhoc
        resources = list(site.get_resources_as_linkheader().links)
        paths = [r.href for r in resources]
        assert "/.well-known/edhoc" in paths

    @pytest.mark.asyncio
    async def test_edhoc_handshake_via_coap(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
        context_store: TransactionalOscoreContextStore,
        peer_resolver: TofuPeerResolver,
    ) -> None:
        """Complete EDHOC handshake via CoAP POST to /.well-known/edhoc."""
        # Set up in-memory network
        net = InMemoryNetwork()
        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        # Pin Alice's public key so Bob can authenticate her
        await peer_resolver.pin_peer("alice", alice_identity.pubkey)

        # Create EDHOC responder resource for Bob
        edhoc = EdhocResource(bob_identity, context_store, peer_resolver)
        info = StaticNodeInfo()
        site = build_site(info, edhoc_resource=edhoc)

        # Create CoAP contexts
        alice_ctx = await create_lichen_context(alice_channel, "alice")
        bob_ctx = await create_lichen_context(bob_channel, "bob", site=site)

        # Run EDHOC as initiator (Alice)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")

        # Step 1: Send Message 1
        msg1 = initiator.create_message_1()
        request1 = aiocoap.Message(
            code=aiocoap.POST,
            uri="coap://bob/.well-known/edhoc",
            payload=msg1,
        )
        response1 = await asyncio.wait_for(
            alice_ctx.request(request1).response,
            timeout=5.0,
        )
        assert response1.code.is_successful()
        msg2 = response1.payload

        # Step 2: Process Message 2 and send Message 3
        msg3 = initiator.process_message_2(msg2, bob_identity.pubkey)
        request3 = aiocoap.Message(
            code=aiocoap.POST,
            uri="coap://bob/.well-known/edhoc",
            payload=msg3,
        )
        response3 = await asyncio.wait_for(
            alice_ctx.request(request3).response,
            timeout=5.0,
        )
        assert response3.code.is_successful()

        # Step 3: Export OSCORE contexts
        alice_oscore = initiator.export_oscore()

        # Bob's context should be stored by the EdhocResource
        bob_peer_ctx = context_store.get_sync("alice")
        assert bob_peer_ctx is not None

        # Verify contexts match
        alice_sec = MemorySecurityContext.from_edhoc(alice_oscore)
        bob_sec = bob_peer_ctx.oscore

        # Sender/recipient keys should be swapped
        assert alice_sec.sender_key == bob_sec.recipient_key
        assert alice_sec.recipient_key == bob_sec.sender_key

        # Clean up
        await alice_ctx.shutdown()
        await bob_ctx.shutdown()

    @pytest.mark.asyncio
    async def test_edhoc_resource_rejects_empty_payload(
        self,
        bob_identity: Identity,
        context_store: TransactionalOscoreContextStore,
        peer_resolver: TofuPeerResolver,
    ) -> None:
        """EdhocResource rejects POST with empty payload."""
        net = InMemoryNetwork()
        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        edhoc = EdhocResource(bob_identity, context_store, peer_resolver)
        info = StaticNodeInfo()
        site = build_site(info, edhoc_resource=edhoc)

        alice_ctx = await create_lichen_context(alice_channel, "alice")
        bob_ctx = await create_lichen_context(bob_channel, "bob", site=site)

        # Send POST with no payload
        request = aiocoap.Message(
            code=aiocoap.POST,
            uri="coap://bob/.well-known/edhoc",
            payload=b"",
        )
        response = await asyncio.wait_for(
            alice_ctx.request(request).response,
            timeout=5.0,
        )
        assert response.code == aiocoap.BAD_REQUEST

        await alice_ctx.shutdown()
        await bob_ctx.shutdown()

    @pytest.mark.asyncio
    async def test_edhoc_resource_rejects_unknown_peer(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
        context_store: TransactionalOscoreContextStore,
        peer_resolver: TofuPeerResolver,
    ) -> None:
        """EdhocResource rejects Message 1 from unknown peer with UNAUTHORIZED.

        SECURITY: Unknown peers must be rejected early in Message 1 processing,
        not deferred to Message 3. This prevents wasted resources and ensures
        no crypto operations are performed with dummy keys.
        """
        net = InMemoryNetwork()
        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        # Note: We do NOT pin Alice's public key, so she is unknown to Bob
        edhoc = EdhocResource(bob_identity, context_store, peer_resolver)
        info = StaticNodeInfo()
        site = build_site(info, edhoc_resource=edhoc)

        alice_ctx = await create_lichen_context(alice_channel, "alice")
        bob_ctx = await create_lichen_context(bob_channel, "bob", site=site)

        # Alice initiates EDHOC
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        msg1 = initiator.create_message_1()

        # Send Message 1 - should be rejected immediately
        request = aiocoap.Message(
            code=aiocoap.POST,
            uri="coap://bob/.well-known/edhoc",
            payload=msg1,
        )
        response = await asyncio.wait_for(
            alice_ctx.request(request).response,
            timeout=5.0,
        )

        # Must reject with UNAUTHORIZED (4.01), not proceed to Message 2
        assert response.code == aiocoap.UNAUTHORIZED

        # Verify no session was created
        assert len(edhoc._sessions) == 0

        await alice_ctx.shutdown()
        await bob_ctx.shutdown()

    @pytest.mark.asyncio
    async def test_responder_restart_resolves_durable_store_pin(
        self,
        tmp_path: Path,
        alice_identity: Identity,
        bob_identity: Identity,
    ) -> None:
        path = tmp_path / "contexts.sqlite3"
        initial_store = SqliteOscoreContextStore(path)
        await initial_store.pin_peer("alice", alice_identity.pubkey)

        restarted_store = SqliteOscoreContextStore(path)
        fresh_resolver = TofuPeerResolver()
        edhoc = EdhocResource(bob_identity, restarted_store, fresh_resolver)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")

        response = await edhoc._handle_message_1("alice", initiator.create_message_1())

        assert response.code.is_successful()
        assert await fresh_resolver.get_peer_pubkey("alice") == alice_identity.pubkey
        assert fresh_resolver._context_store is restarted_store
        assert fresh_resolver._pinned == {}

    def test_responder_rejects_resolver_bound_to_different_store(
        self, bob_identity: Identity
    ) -> None:
        resolver = TofuPeerResolver(OscoreContextStore())

        with pytest.raises(ValueError, match="different context store"):
            EdhocResource(bob_identity, OscoreContextStore(), resolver)

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"max_sessions": 0},
            {"max_sessions": -1},
            {"max_sessions": True},
            {"session_lifetime": 0},
            {"session_lifetime": -1},
            {"session_lifetime": float("nan")},
            {"session_lifetime": float("inf")},
            {"session_lifetime": True},
        ],
    )
    def test_constructor_rejects_invalid_limits(
        self, bob_identity: Identity, kwargs: dict[str, object]
    ) -> None:
        with pytest.raises(ValueError):
            EdhocResource(
                bob_identity,
                OscoreContextStore(),
                TofuPeerResolver(),
                **kwargs,  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_capacity_rejects_new_session_without_disturbing_live_session(
        self, bob_identity: Identity
    ) -> None:
        alice = Identity.generate()
        carol = Identity.generate()
        store = OscoreContextStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice.pubkey)
        await resolver.pin_peer("carol", carol.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver, max_sessions=1)
        alice_init = EdhocInitiator.create(alice, c_i=b"\x00")
        carol_init = EdhocInitiator.create(carol, c_i=b"\x01")

        accepted = await edhoc._handle_message_1("alice", alice_init.create_message_1())
        live_session = next(iter(edhoc._sessions.values()))
        overloaded = await edhoc._handle_message_1("carol", carol_init.create_message_1())

        assert accepted.code == aiocoap.CHANGED
        assert overloaded.code == aiocoap.SERVICE_UNAVAILABLE
        assert list(edhoc._sessions.values()) == [live_session]
        assert live_session["responder"]._state.name == "WAIT_MESSAGE_3"

    @pytest.mark.asyncio
    async def test_concurrent_admission_never_exceeds_capacity(
        self, bob_identity: Identity
    ) -> None:
        alice = Identity.generate()
        carol = Identity.generate()
        store = OscoreContextStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice.pubkey)
        await resolver.pin_peer("carol", carol.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver, max_sessions=1)

        responses = await asyncio.gather(
            edhoc._handle_message_1(
                "alice", EdhocInitiator.create(alice, c_i=b"\x00").create_message_1()
            ),
            edhoc._handle_message_1(
                "carol", EdhocInitiator.create(carol, c_i=b"\x01").create_message_1()
            ),
        )

        assert {response.code for response in responses} == {
            aiocoap.CHANGED,
            aiocoap.SERVICE_UNAVAILABLE,
        }
        assert len(edhoc._sessions) == 1

    @pytest.mark.asyncio
    async def test_idle_session_expires_without_further_traffic(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        now = [100.0]
        scheduler = _FakeScheduler(now)
        store = OscoreContextStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(
            bob_identity,
            store,
            resolver,
            session_lifetime=5.0,
            monotonic=lambda: now[0],
            call_later=scheduler.call_later,
        )
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")

        response = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))
        session = next(iter(edhoc._sessions.values()))
        responder = session["responder"]
        assert response.code == aiocoap.CHANGED
        assert scheduler.calls[0].when == 105.0

        scheduler.advance(105.0)

        assert edhoc._sessions == {}
        assert responder._state.name == "FAILED"
        assert responder._eph_sk == b""
        assert responder._prk_2e == b""
        assert responder._msg1 == b""

    @pytest.mark.asyncio
    async def test_exact_m1_retransmission_returns_cached_m2_and_timer(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        now = [10.0]
        scheduler = _FakeScheduler(now)
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(
            bob_identity,
            OscoreContextStore(),
            resolver,
            monotonic=lambda: now[0],
            call_later=scheduler.call_later,
        )
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_1 = initiator.create_message_1()

        first = await edhoc.render_post(_edhoc_request(message_1))
        session = next(iter(edhoc._sessions.values()))
        retry = await edhoc.render_post(_edhoc_request(message_1))

        assert retry.code == aiocoap.CHANGED
        assert retry.payload == first.payload
        assert list(edhoc._sessions.values()) == [session]
        assert len([call for call in scheduler.calls if not call.cancelled]) == 1

    @pytest.mark.asyncio
    async def test_restart_m1_is_rejected_and_original_can_complete(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        resolver = TofuPeerResolver()
        store = OscoreContextStore()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver)
        original = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        restart = EdhocInitiator.create(alice_identity, c_i=b"\x01")

        message_2 = await edhoc.render_post(_edhoc_request(original.create_message_1()))
        live_session = next(iter(edhoc._sessions.values()))
        rejected = await edhoc.render_post(_edhoc_request(restart.create_message_1()))

        assert rejected.code == aiocoap.BAD_REQUEST
        assert list(edhoc._sessions.values()) == [live_session]

        message_3 = original.process_message_2(message_2.payload, bob_identity.pubkey)
        completed = await edhoc.render_post(_edhoc_request(message_3))
        assert completed.code == aiocoap.CHANGED
        assert edhoc._sessions == {}
        assert store.get_sync("alice") is not None

    @pytest.mark.asyncio
    async def test_malformed_m3_aborts_only_selected_session(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, OscoreContextStore(), resolver)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        await edhoc.render_post(_edhoc_request(initiator.create_message_1()))
        responder = next(iter(edhoc._sessions.values()))["responder"]

        response = await edhoc.render_post(_edhoc_request(b"malformed-message-3"))

        assert response.code == aiocoap.BAD_REQUEST
        assert edhoc._sessions == {}
        assert responder._state.name == "FAILED"

    @pytest.mark.asyncio
    async def test_expiry_before_m3_never_reaches_blocked_put(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        now = [20.0]
        scheduler = _FakeScheduler(now)
        store = _BlockingPutStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(
            bob_identity,
            store,
            resolver,
            session_lifetime=2.0,
            monotonic=lambda: now[0],
            call_later=scheduler.call_later,
        )
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_2 = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))
        message_3 = initiator.process_message_2(message_2.payload, bob_identity.pubkey)

        scheduler.advance(22.0)
        response = await edhoc.render_post(_edhoc_request(message_3))

        assert response.code == aiocoap.BAD_REQUEST
        assert not store.started.is_set()
        assert store.get_sync("alice") is None

    @pytest.mark.asyncio
    async def test_completed_m3_can_publish_after_deadline(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        now = [30.0]
        scheduler = _FakeScheduler(now)
        store = _BlockingPutStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(
            bob_identity,
            store,
            resolver,
            session_lifetime=5.0,
            monotonic=lambda: now[0],
            call_later=scheduler.call_later,
        )
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_2 = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))
        message_3 = initiator.process_message_2(message_2.payload, bob_identity.pubkey)

        completion = asyncio.create_task(edhoc.render_post(_edhoc_request(message_3)))
        await store.started.wait()
        assert edhoc._sessions == {}
        assert scheduler.calls[0].cancelled

        scheduler.advance(35.0)
        store.release.set()
        response = await completion

        assert response.code == aiocoap.CHANGED
        assert store.get_sync("alice") is not None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("failure_stage", ["ensure", "get"])
    async def test_resolver_failures_are_service_unavailable(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
        monkeypatch: pytest.MonkeyPatch,
        failure_stage: str,
    ) -> None:
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, OscoreContextStore(), resolver)

        async def fail(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("private injected resolver detail")

        if failure_stage == "ensure":
            monkeypatch.setattr(resolver, "ensure_bound", fail)
        else:
            monkeypatch.setattr(resolver, "get_peer_pubkey", fail)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")

        response = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))

        assert response.code == aiocoap.SERVICE_UNAVAILABLE
        assert response.payload == b""
        assert edhoc._sessions == {}

    @pytest.mark.asyncio
    async def test_publication_failure_is_service_unavailable(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        store = _FailingPutStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_2 = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))
        message_3 = initiator.process_message_2(message_2.payload, bob_identity.pubkey)

        response = await edhoc.render_post(_edhoc_request(message_3))

        assert response.code == aiocoap.SERVICE_UNAVAILABLE
        assert response.payload == b""
        assert edhoc._sessions == {}
        assert store.get_sync("alice") is None

    @pytest.mark.asyncio
    async def test_unexpected_internal_failure_maps_to_internal_server_error(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, OscoreContextStore(), resolver)

        async def fail(_peer: str, _payload: bytes) -> aiocoap.Message:
            raise AssertionError("private injected internal detail")

        monkeypatch.setattr(edhoc, "_handle_message_1", fail)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")

        response = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))

        assert response.code == aiocoap.INTERNAL_SERVER_ERROR
        assert response.payload == b""

    @pytest.mark.asyncio
    async def test_stale_timer_is_identity_safe(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        now = [40.0]
        scheduler = _FakeScheduler(now)
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(
            bob_identity,
            OscoreContextStore(),
            resolver,
            monotonic=lambda: now[0],
            call_later=scheduler.call_later,
        )
        first = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        await edhoc.render_post(_edhoc_request(first.create_message_1()))
        first_session = next(iter(edhoc._sessions.values()))
        first_key = next(iter(edhoc._sessions))
        stale_call = scheduler.calls[0]

        edhoc._remove_session(first_key, first_session, abort=True)
        assert stale_call.cancelled
        assert first_session["responder"]._state.name == "FAILED"

        second = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        await edhoc.render_post(_edhoc_request(second.create_message_1()))
        second_session = next(iter(edhoc._sessions.values()))
        stale_call.callback()

        assert list(edhoc._sessions.values()) == [second_session]
        assert second_session["responder"]._state.name == "WAIT_MESSAGE_3"

    @pytest.mark.asyncio
    async def test_close_is_terminal_and_idempotent(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, OscoreContextStore(), resolver)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_1 = initiator.create_message_1()
        await edhoc.render_post(_edhoc_request(message_1))
        session = next(iter(edhoc._sessions.values()))

        await asyncio.gather(edhoc.close(), edhoc.close())
        retry = await edhoc.render_post(_edhoc_request(message_1))

        assert retry.code == aiocoap.SERVICE_UNAVAILABLE
        assert edhoc._sessions == {}
        assert edhoc._completing == {}
        assert session["responder"]._state.name == "FAILED"

    @pytest.mark.asyncio
    @pytest.mark.parametrize("publication_fails", [False, True])
    async def test_completing_session_holds_capacity_until_finalized(
        self,
        bob_identity: Identity,
        publication_fails: bool,
    ) -> None:
        alice = Identity.generate()
        carol = Identity.generate()
        store = _BlockingPutStore(fail=publication_fails)
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice.pubkey)
        await resolver.pin_peer("carol", carol.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver, max_sessions=1)
        first = EdhocInitiator.create(alice, c_i=b"\x00")
        second = EdhocInitiator.create(carol, c_i=b"\x01")
        second_message_1 = second.create_message_1()
        message_2 = await edhoc.render_post(
            _edhoc_request(first.create_message_1(), "alice")
        )
        message_3 = first.process_message_2(message_2.payload, bob_identity.pubkey)

        completion = asyncio.create_task(
            edhoc.render_post(_edhoc_request(message_3, "alice"))
        )
        await store.started.wait()
        assert edhoc._sessions == {}
        assert len(edhoc._completing) == 1

        overloaded = await edhoc.render_post(
            _edhoc_request(second_message_1, "carol")
        )
        assert overloaded.code == aiocoap.SERVICE_UNAVAILABLE

        store.release.set()
        first_result = await completion
        expected = aiocoap.SERVICE_UNAVAILABLE if publication_fails else aiocoap.CHANGED
        assert first_result.code == expected
        assert edhoc._completing == {}

        recovered = await edhoc.render_post(
            _edhoc_request(second_message_1, "carol")
        )
        assert recovered.code == aiocoap.CHANGED

    @pytest.mark.asyncio
    async def test_close_during_completion_cancels_publication_without_success(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        store = _BlockingPutStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver, max_sessions=1)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_2 = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))
        message_3 = initiator.process_message_2(message_2.payload, bob_identity.pubkey)
        completion = asyncio.create_task(edhoc.render_post(_edhoc_request(message_3)))
        await store.started.wait()
        session = next(iter(edhoc._completing.values()))
        publication_task = session["publication_task"]

        await edhoc.close()
        response = await completion

        assert response.code == aiocoap.SERVICE_UNAVAILABLE
        assert edhoc._sessions == {}
        assert edhoc._completing == {}
        assert publication_task.done()
        assert session["publication_task"] is None
        assert session["responder"]._state.name == "FAILED"
        assert store.get_sync("alice") is None

    @pytest.mark.asyncio
    @pytest.mark.parametrize("commit_after_cancel", [True, False])
    async def test_close_uses_definitive_publication_result(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
        commit_after_cancel: bool,
    ) -> None:
        store = _CancellationDefinitiveStore(
            commit_after_cancel=commit_after_cancel
        )
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver, max_sessions=1)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_2 = await edhoc.render_post(_edhoc_request(initiator.create_message_1()))
        message_3 = initiator.process_message_2(message_2.payload, bob_identity.pubkey)
        completion = asyncio.create_task(edhoc.render_post(_edhoc_request(message_3)))
        await store.started.wait()
        session = next(iter(edhoc._completing.values()))
        publication_task = session["publication_task"]

        first_close = asyncio.create_task(edhoc.close())
        second_close = asyncio.create_task(edhoc.close())
        response, _, _ = await asyncio.gather(completion, first_close, second_close)

        expected = aiocoap.CHANGED if commit_after_cancel else aiocoap.SERVICE_UNAVAILABLE
        assert response.code == expected
        assert (store.get_sync("alice") is not None) is commit_after_cancel
        assert edhoc._sessions == {}
        assert edhoc._completing == {}
        assert publication_task.done()
        assert session["publication_task"] is None

    @pytest.mark.asyncio
    async def test_duplicate_session_key_does_not_replace_live_session(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        store = OscoreContextStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, store, resolver, max_sessions=2)
        first = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        second = EdhocInitiator.create(alice_identity, c_i=b"\x00")

        accepted = await edhoc._handle_message_1("alice", first.create_message_1())
        live_session = next(iter(edhoc._sessions.values()))
        duplicate = await edhoc._handle_message_1("alice", second.create_message_1())

        assert accepted.code == aiocoap.CHANGED
        assert duplicate.code == aiocoap.BAD_REQUEST
        assert list(edhoc._sessions.values()) == [live_session]
        assert live_session["responder"]._state.name == "WAIT_MESSAGE_3"

    @pytest.mark.asyncio
    async def test_exact_deadline_expires_and_aborts_before_admission(
        self, bob_identity: Identity
    ) -> None:
        now = [10.0]
        alice = Identity.generate()
        carol = Identity.generate()
        store = OscoreContextStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice.pubkey)
        await resolver.pin_peer("carol", carol.pubkey)
        edhoc = EdhocResource(
            bob_identity,
            store,
            resolver,
            max_sessions=1,
            session_lifetime=5.0,
            monotonic=lambda: now[0],
        )
        first = EdhocInitiator.create(alice, c_i=b"\x00")
        await edhoc._handle_message_1("alice", first.create_message_1())
        expired_responder = next(iter(edhoc._sessions.values()))["responder"]

        now[0] = 15.0
        second = EdhocInitiator.create(carol, c_i=b"\x01")
        response = await edhoc._handle_message_1("carol", second.create_message_1())

        assert response.code == aiocoap.CHANGED
        assert {host for host, _c_i in edhoc._sessions} == {"carol"}
        assert expired_responder._state.name == "FAILED"
        expired_responder.abort()
        assert expired_responder._state.name == "FAILED"

    @pytest.mark.asyncio
    async def test_expired_message_3_is_rejected_without_publication(
        self, alice_identity: Identity, bob_identity: Identity
    ) -> None:
        now = [20.0]
        store = OscoreContextStore()
        resolver = TofuPeerResolver()
        await resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(
            bob_identity,
            store,
            resolver,
            session_lifetime=2.0,
            monotonic=lambda: now[0],
        )
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        message_2 = await edhoc._handle_message_1("alice", initiator.create_message_1())
        message_3 = initiator.process_message_2(message_2.payload, bob_identity.pubkey)
        session_key, session = next(iter(edhoc._sessions.items()))

        now[0] = 22.0
        response = await edhoc._handle_message_3(
            "alice", message_3, session_key, session
        )

        assert response.code == aiocoap.BAD_REQUEST
        assert edhoc._sessions == {}
        assert store.get_sync("alice") is None
        assert session["responder"]._state.name == "FAILED"

    @pytest.mark.asyncio
    async def test_malformed_message_1_publishes_nothing(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
        context_store: TransactionalOscoreContextStore,
        peer_resolver: TofuPeerResolver,
    ) -> None:
        await peer_resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, context_store, peer_resolver)

        with pytest.raises(ValueError):
            await edhoc._handle_message_1("alice", b"\x58")

        assert edhoc._sessions == {}
        assert context_store.get_sync("alice") is None

    @pytest.mark.asyncio
    async def test_failed_message_3_is_removed_and_fresh_handshake_succeeds(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
        context_store: TransactionalOscoreContextStore,
        peer_resolver: TofuPeerResolver,
    ) -> None:
        await peer_resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, context_store, peer_resolver)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        response2 = await edhoc._handle_message_1("alice", initiator.create_message_1())
        msg3 = initiator.process_message_2(response2.payload, bob_identity.pubkey)
        session_key, session = next(iter(edhoc._sessions.items()))
        corrupted_msg3 = bytes([msg3[0] ^ 1]) + msg3[1:]

        with pytest.raises(ValueError):
            await edhoc._handle_message_3(
                "alice", corrupted_msg3, session_key, session
            )

        assert edhoc._sessions == {}
        assert context_store.get_sync("alice") is None

        fresh = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        fresh_response2 = await edhoc._handle_message_1(
            "alice", fresh.create_message_1()
        )
        fresh_msg3 = fresh.process_message_2(fresh_response2.payload, bob_identity.pubkey)
        fresh_key, fresh_session = next(iter(edhoc._sessions.items()))
        response3 = await edhoc._handle_message_3(
            "alice", fresh_msg3, fresh_key, fresh_session
        )

        assert response3.code.is_successful()
        assert edhoc._sessions == {}
        assert context_store.get_sync("alice") is not None

    @pytest.mark.asyncio
    async def test_publication_failure_cleans_session_without_publishing(
        self,
        alice_identity: Identity,
        bob_identity: Identity,
    ) -> None:
        context_store = _FailingPutStore()
        peer_resolver = TofuPeerResolver()
        await peer_resolver.pin_peer("alice", alice_identity.pubkey)
        edhoc = EdhocResource(bob_identity, context_store, peer_resolver)
        initiator = EdhocInitiator.create(alice_identity, c_i=b"\x00")
        response2 = await edhoc._handle_message_1("alice", initiator.create_message_1())
        msg3 = initiator.process_message_2(response2.payload, bob_identity.pubkey)
        session_key, session = next(iter(edhoc._sessions.items()))
        responder = session["responder"]

        with pytest.raises(RuntimeError):
            await edhoc._handle_message_3("alice", msg3, session_key, session)

        assert responder._state.name == "FAILED"
        assert edhoc._sessions == {}
        assert context_store.get_sync("alice") is None


class TestEdhocContextDerivation:
    """Tests for OSCORE context derivation from EDHOC."""

    @pytest.mark.asyncio
    async def test_derived_contexts_have_matching_keys(self) -> None:
        """Initiator and responder derive matching OSCORE keys."""
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        context_store = OscoreContextStore()
        peer_resolver = TofuPeerResolver()
        await peer_resolver.pin_peer("alice", alice_id.pubkey)

        # Set up in-memory network
        net = InMemoryNetwork()
        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        edhoc = EdhocResource(bob_id, context_store, peer_resolver)
        info = StaticNodeInfo()
        site = build_site(info, edhoc_resource=edhoc)

        alice_ctx = await create_lichen_context(alice_channel, "alice")
        bob_ctx = await create_lichen_context(bob_channel, "bob", site=site)

        # Complete EDHOC handshake
        initiator = EdhocInitiator.create(alice_id, c_i=b"\x00")

        msg1 = initiator.create_message_1()
        req1 = aiocoap.Message(
            code=aiocoap.POST,
            uri="coap://bob/.well-known/edhoc",
            payload=msg1,
        )
        resp1 = await asyncio.wait_for(alice_ctx.request(req1).response, timeout=5.0)
        msg2 = resp1.payload

        msg3 = initiator.process_message_2(msg2, bob_id.pubkey)
        req3 = aiocoap.Message(
            code=aiocoap.POST,
            uri="coap://bob/.well-known/edhoc",
            payload=msg3,
        )
        await asyncio.wait_for(alice_ctx.request(req3).response, timeout=5.0)

        # Verify derived contexts
        alice_oscore = MemorySecurityContext.from_edhoc(initiator.export_oscore())
        bob_peer_ctx = context_store.get_sync("alice")
        assert bob_peer_ctx is not None
        bob_oscore = bob_peer_ctx.oscore

        # Common IV must match
        assert alice_oscore.common_iv == bob_oscore.common_iv

        # Sender/recipient IDs are swapped
        assert alice_oscore.sender_id == bob_oscore.recipient_id
        assert alice_oscore.recipient_id == bob_oscore.sender_id

        await alice_ctx.shutdown()
        await bob_ctx.shutdown()
