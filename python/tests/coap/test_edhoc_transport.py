# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for EDHOC CoAP transport integration (spec section 8.8)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import aiocoap
import pytest

from lichen.coap.resources import EdhocResource, StaticNodeInfo, build_site
from lichen.coap.secure import (
    OscoreContextStore,
    SqliteOscoreContextStore,
    TofuPeerResolver,
    TransactionalOscoreContextStore,
)
from lichen.coap.transport import InMemoryNetwork, create_lichen_context
from lichen.crypto.edhoc import EdhocInitiator
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext


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
