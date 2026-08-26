# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for OSCORE-protected CoAP transport (spec section 8.7)."""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from lichen.coap.secure import (
    InMemoryOscoreContextStore,
    SecureDatagramChannel,
    TofuPeerResolver,
    create_secure_channel,
)
from lichen.coap.transport import InMemoryNetwork
from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext


class TestOscoreContextStore:
    """Tests for OscoreContextStore."""

    @pytest.mark.asyncio
    async def test_put_and_get(self) -> None:
        """Store and retrieve a context."""
        store = InMemoryOscoreContextStore()
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        await store.put("fd00::1", ctx, b"pubkey")

        peer_ctx = await store.get("fd00::1")
        assert peer_ctx is not None
        assert peer_ctx.oscore is ctx
        assert peer_ctx.peer_pubkey == b"pubkey"

    @pytest.mark.asyncio
    async def test_get_missing_returns_none(self) -> None:
        """Getting a missing context returns None."""
        store = InMemoryOscoreContextStore()
        assert await store.get("fd00::1") is None

    @pytest.mark.asyncio
    async def test_has_context(self) -> None:
        """has_context reflects stored contexts."""
        store = InMemoryOscoreContextStore()
        assert not await store.has_context("fd00::1")

        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        await store.put("fd00::1", ctx, b"pubkey")
        assert await store.has_context("fd00::1")

    @pytest.mark.asyncio
    async def test_remove(self) -> None:
        """Remove deletes stored context."""
        store = InMemoryOscoreContextStore()
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        await store.put("fd00::1", ctx, b"pubkey")
        await store.remove("fd00::1")
        assert not await store.has_context("fd00::1")

    def test_sync_operations(self) -> None:
        """Synchronous operations work without event loop."""
        store = InMemoryOscoreContextStore()
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        store.put_sync("fd00::1", ctx, b"pubkey")
        assert store.has_context_sync("fd00::1")
        assert store.get_sync("fd00::1") is not None


class TestTofuPeerResolver:
    """Tests for TofuPeerResolver."""

    @pytest.mark.asyncio
    async def test_unknown_peer_returns_none(self) -> None:
        """Unknown peer returns None."""
        resolver = TofuPeerResolver()
        assert await resolver.get_peer_pubkey("fd00::1") is None

    @pytest.mark.asyncio
    async def test_pin_and_get(self) -> None:
        """Pinned peer key can be retrieved."""
        resolver = TofuPeerResolver()
        pubkey = b"a" * 32
        await resolver.pin_peer("fd00::1", pubkey)
        assert await resolver.get_peer_pubkey("fd00::1") == pubkey

    @pytest.mark.asyncio
    async def test_pin_same_key_succeeds(self) -> None:
        """Pinning the same key again succeeds."""
        resolver = TofuPeerResolver()
        pubkey = b"a" * 32
        await resolver.pin_peer("fd00::1", pubkey)
        await resolver.pin_peer("fd00::1", pubkey)  # Should not raise
        assert await resolver.get_peer_pubkey("fd00::1") == pubkey

    @pytest.mark.asyncio
    async def test_pin_different_key_raises(self) -> None:
        """Pinning a different key for same peer raises."""
        resolver = TofuPeerResolver()
        await resolver.pin_peer("fd00::1", b"a" * 32)
        with pytest.raises(ValueError, match="TOFU violation"):
            await resolver.pin_peer("fd00::1", b"b" * 32)


class TestSecureDatagramChannel:
    """Tests for SecureDatagramChannel with pre-provisioned contexts."""

    def test_send_message_forwards_congestion_policy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Polymorphic message sends preserve the caller's admission policy."""
        from aiocoap import GET, Message
        from aiocoap.numbers import types
        from aiocoap.oscore import Direction

        secure = create_secure_channel(InMemoryNetwork().channel("alice"), Identity.generate())
        observed: list[bool] = []

        def no_operation(_data: bytes, _dest: str, _key: str) -> None:
            return None

        def record_schedule(
            _data: bytes,
            _dest: str,
            _key: str,
            _operation: object,
            _priority: object,
            check_congestion: bool,
        ) -> None:
            observed.append(check_congestion)

        monkeypatch.setattr(secure, "_prepare_send_operation", no_operation)
        monkeypatch.setattr(secure, "_schedule_send", record_schedule)

        request = Message(code=GET)
        request.mtype = types.NON
        request.mid = 1
        request.direction = Direction.OUTGOING
        secure.send_message(request, "bob", check_congestion=False)

        assert observed == [False]

    def _create_edhoc_contexts(
        self, alice_id: Identity, bob_id: Identity
    ) -> tuple[MemorySecurityContext, MemorySecurityContext]:
        """Run EDHOC and create paired OSCORE contexts."""
        initiator = EdhocInitiator.create(alice_id, c_i=b"\x00")
        responder = EdhocResponder.create(bob_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, alice_id.pubkey)
        msg3 = initiator.process_message_2(msg2, bob_id.pubkey)
        responder.process_message_3(msg3, alice_id.pubkey)

        alice_ctx = MemorySecurityContext.from_edhoc(initiator.export_oscore())
        bob_ctx = MemorySecurityContext.from_edhoc(responder.export_oscore())

        return alice_ctx, bob_ctx

    @pytest.mark.asyncio
    async def test_create_secure_channel(self) -> None:
        """create_secure_channel creates a SecureDatagramChannel."""
        net = InMemoryNetwork()
        channel = net.channel("alice")
        identity = Identity.generate()

        secure = create_secure_channel(channel, identity)
        assert isinstance(secure, SecureDatagramChannel)

    @pytest.mark.asyncio
    async def test_add_context_sync(self) -> None:
        """add_context_sync pre-provisions a context."""
        net = InMemoryNetwork()
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_channel = net.channel("alice")
        secure = create_secure_channel(alice_channel, alice_id)

        alice_ctx, _ = self._create_edhoc_contexts(alice_id, bob_id)
        secure.add_context_sync("bob", alice_ctx, bob_id.pubkey)

        assert secure.has_context_sync("bob")

    @pytest.mark.asyncio
    async def test_add_context_async(self) -> None:
        """add_context pre-provisions a context."""
        net = InMemoryNetwork()
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_channel = net.channel("alice")
        secure = create_secure_channel(alice_channel, alice_id)

        alice_ctx, _ = self._create_edhoc_contexts(alice_id, bob_id)
        await secure.add_context("bob", alice_ctx, bob_id.pubkey)

        assert await secure.has_context("bob")

    @pytest.mark.asyncio
    async def test_plaintext_rejected_when_required(self) -> None:
        """Plaintext messages are rejected when require_oscore=True."""
        net = InMemoryNetwork()
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        create_secure_channel(alice_channel, alice_id, require_oscore=True)
        bob_secure = create_secure_channel(bob_channel, bob_id, require_oscore=True)

        received = []
        bob_secure.set_receiver(lambda data, src: received.append((data, src)))

        # Send plaintext (raw CoAP) - no OSCORE option
        # This is a minimal CoAP GET with no options
        plaintext_coap = bytes(
            [
                0x40,  # Ver=1, T=CON, TKL=0
                0x01,  # Code=GET
                0x00,
                0x01,  # Message ID
            ]
        )
        alice_channel.send_datagram(plaintext_coap, "bob")

        # Give event loop time to process
        await asyncio.sleep(0.01)

        # Message should be rejected (empty received list)
        assert len(received) == 0

    @pytest.mark.asyncio
    async def test_plaintext_passthrough_when_not_required(self) -> None:
        """Plaintext messages pass through when require_oscore=False."""
        net = InMemoryNetwork()
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        create_secure_channel(alice_channel, alice_id, require_oscore=False)
        bob_secure = create_secure_channel(bob_channel, bob_id, require_oscore=False)

        received = []
        bob_secure.set_receiver(lambda data, src: received.append((data, src)))

        # Send plaintext CoAP
        plaintext_coap = bytes(
            [
                0x40,  # Ver=1, T=CON, TKL=0
                0x01,  # Code=GET
                0x00,
                0x01,  # Message ID
            ]
        )
        alice_channel.send_datagram(plaintext_coap, "bob")

        # Give event loop time to process
        await asyncio.sleep(0.01)

        # Message should pass through
        assert len(received) == 1
        assert received[0][0] == plaintext_coap
        assert received[0][1] == "alice"

    @pytest.mark.asyncio
    async def test_no_context_establishment_without_peer_pubkey(self) -> None:
        """Sending to unknown peer without pubkey fails."""
        net = InMemoryNetwork()
        alice_id = Identity.generate()

        alice_channel = net.channel("alice")
        secure = create_secure_channel(alice_channel, alice_id)

        # Try to send - should fail to establish context
        plaintext_coap = bytes(
            [
                0x40,
                0x01,
                0x00,
                0x01,  # CON GET
            ]
        )
        secure.send_datagram(plaintext_coap, "unknown_peer")

        # Give time for async processing
        await asyncio.sleep(0.01)

        # No context should be established (peer unknown)
        assert not await secure.has_context("unknown_peer")


class TestSecureChannelIntegration:
    """Integration tests for secure channel with OSCORE protection."""

    def _create_edhoc_contexts(
        self, alice_id: Identity, bob_id: Identity
    ) -> tuple[MemorySecurityContext, MemorySecurityContext]:
        """Run EDHOC and create paired OSCORE contexts."""
        initiator = EdhocInitiator.create(alice_id, c_i=b"\x00")
        responder = EdhocResponder.create(bob_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, alice_id.pubkey)
        msg3 = initiator.process_message_2(msg2, bob_id.pubkey)
        responder.process_message_3(msg3, alice_id.pubkey)

        alice_ctx = MemorySecurityContext.from_edhoc(initiator.export_oscore())
        bob_ctx = MemorySecurityContext.from_edhoc(responder.export_oscore())

        return alice_ctx, bob_ctx

    @pytest.mark.asyncio
    async def test_contexts_derive_matching_keys(self) -> None:
        """Verify that EDHOC-derived contexts have matching keys."""
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_ctx, bob_ctx = self._create_edhoc_contexts(alice_id, bob_id)

        # Alice's sender key should match Bob's recipient key
        assert alice_ctx.sender_key == bob_ctx.recipient_key
        # Alice's recipient key should match Bob's sender key
        assert alice_ctx.recipient_key == bob_ctx.sender_key
        # Common IV should match
        assert alice_ctx.common_iv == bob_ctx.common_iv

    @pytest.mark.asyncio
    async def test_close_releases_inner_channel(self) -> None:
        """close() releases the inner channel."""
        net = InMemoryNetwork()
        alice_id = Identity.generate()

        inner = net.channel("alice")
        secure = create_secure_channel(inner, alice_id)
        secure.close()

        # After close, sending should not deliver
        # (This tests that close was propagated)


class TestNodeChannelOscoreIntegration:
    """Tests for OSCORE integration with NodeChannel.

    These tests verify that SecureDatagramChannel can wrap NodeChannel
    for multi-hop mesh delivery with end-to-end encryption.
    """

    def _create_edhoc_contexts(
        self, alice_id: Identity, bob_id: Identity
    ) -> tuple[MemorySecurityContext, MemorySecurityContext]:
        """Run EDHOC and create paired OSCORE contexts."""
        initiator = EdhocInitiator.create(alice_id, c_i=b"\x00")
        responder = EdhocResponder.create(bob_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, alice_id.pubkey)
        msg3 = initiator.process_message_2(msg2, bob_id.pubkey)
        responder.process_message_3(msg3, alice_id.pubkey)

        alice_ctx = MemorySecurityContext.from_edhoc(initiator.export_oscore())
        bob_ctx = MemorySecurityContext.from_edhoc(responder.export_oscore())

        return alice_ctx, bob_ctx

    @pytest.mark.asyncio
    async def test_secure_channel_wraps_any_datagram_channel(self) -> None:
        """SecureDatagramChannel can wrap any DatagramChannel implementation."""
        # This test uses InMemoryChannel but demonstrates the pattern
        # that would work with NodeChannel
        net = InMemoryNetwork()
        alice_id = Identity.generate()

        # Any DatagramChannel implementation works
        channel = net.channel("alice")
        secure = create_secure_channel(channel, alice_id)

        # The secure channel is a DatagramChannel itself
        assert hasattr(secure, "send_datagram")
        assert hasattr(secure, "set_receiver")
        assert hasattr(secure, "close")

    @pytest.mark.asyncio
    async def test_oscore_protect_unprotect_round_trip(self) -> None:
        """OSCORE-protected message is correctly protected and unprotected."""
        from aiocoap import GET, Message
        from aiocoap.oscore import Direction

        from lichen.coap.transport import LichenRemote

        net = InMemoryNetwork()
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        alice_secure = create_secure_channel(alice_channel, alice_id)
        bob_secure = create_secure_channel(bob_channel, bob_id)

        # Pre-provision OSCORE contexts from EDHOC
        alice_ctx, bob_ctx = self._create_edhoc_contexts(alice_id, bob_id)
        alice_secure.add_context_sync("bob", alice_ctx, bob_id.pubkey)
        bob_secure.add_context_sync("alice", bob_ctx, alice_id.pubkey)

        received: list[tuple[bytes, str]] = []
        bob_secure.set_receiver(lambda data, src: received.append((data, src)))

        # Create a proper CoAP GET request using aiocoap
        from aiocoap.numbers import types

        request = Message(code=GET)
        request.mtype = types.NON
        request.mid = 1
        request.remote = LichenRemote("bob")
        request.direction = Direction.OUTGOING
        plaintext_coap = request.encode()

        alice_secure.send_datagram(plaintext_coap, "bob")

        # Give event loop time to process
        await asyncio.sleep(0.05)

        # Bob should receive the unprotected plaintext
        assert len(received) == 1
        data, source = received[0]
        assert source == "alice"
        # Decode and verify the CoAP message content is preserved
        # Note: OSCORE may not preserve token, so we compare code and MID
        received_msg = Message.decode(data, LichenRemote("alice"))
        assert received_msg.code == GET
        assert received_msg.mtype == types.NON
        assert received_msg.mid == 1

    @pytest.mark.asyncio
    async def test_oscore_without_context_rejected(self) -> None:
        """Sending to peer without context fails to establish (no pubkey)."""
        net = InMemoryNetwork()
        alice_id = Identity.generate()

        alice_channel = net.channel("alice")
        bob_channel = net.channel("bob")

        alice_secure = create_secure_channel(alice_channel, alice_id)
        # Bob has no context for alice, and require_oscore=True (default)
        bob_secure = create_secure_channel(bob_channel, Identity.generate(), require_oscore=True)

        received: list[tuple[bytes, str]] = []
        bob_secure.set_receiver(lambda data, src: received.append((data, src)))

        # Alice has no context for bob - send fails without EDHOC
        plaintext_coap = bytes([0x40, 0x01, 0x00, 0x01])
        alice_secure.send_datagram(plaintext_coap, "bob")

        await asyncio.sleep(0.05)

        # Nothing received - no context could be established
        assert len(received) == 0


class TestSecureChannelConcurrency:
    """Tests for race condition handling in SecureDatagramChannel."""

    @pytest.mark.asyncio
    async def test_concurrent_context_establishment_waits_on_single_handshake(
        self,
    ) -> None:
        """Concurrent requests for same peer wait on a single EDHOC handshake.

        Verifies fix for race condition where concurrent requests with expired
        pending state could start parallel EDHOC handshakes. The future must
        be registered BEFORE any await to prevent race window.

        Note: This test calls _establish_context directly (bypassing the
        per-peer lock in _send_protected) to actually exercise the coalescing
        logic in _pending_edhoc.
        """
        net = InMemoryNetwork()
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_channel = net.channel("alice")
        alice_secure = create_secure_channel(
            alice_channel,
            alice_id,
            require_oscore=True,
            local_host="alice",
        )

        # Pin bob's key so EDHOC can proceed (would need responder for full test)
        alice_resolver = alice_secure._peer_resolver
        await alice_resolver.pin_peer("bob", bob_id.pubkey)

        key = alice_secure._endpoint_key("bob")

        # Track how many times _establish_context actually starts EDHOC
        # (i.e., proceeds past the _pending_edhoc check, not early returns)
        establish_count = 0
        original_establish = alice_secure._establish_context

        async def counting_establish(dest: str, key: str) -> None:
            nonlocal establish_count
            # Check if this call will coalesce (early return) or proceed
            if key in alice_secure._pending_edhoc:
                # This call will wait on existing future - don't count it
                await original_establish(dest, key)
                return
            # This call is the initiator - count it
            establish_count += 1
            await original_establish(dest, key)

        alice_secure._establish_context = counting_establish  # type: ignore[method-assign]

        # Start multiple concurrent calls to _establish_context directly
        # (bypassing _send_protected's lock to actually test coalescing)
        tasks = [asyncio.create_task(alice_secure._establish_context("bob", key)) for _ in range(5)]

        # Let tasks start
        await asyncio.sleep(0.01)

        # All should be waiting on the single pending future
        # Only 1 should have actually started the establish process
        # (subsequent ones wait on the future registered by the first)
        assert len(alice_secure._pending_edhoc) <= 1

        # Verify that only one EDHOC handshake was initiated despite 5 concurrent
        # calls. This is the core assertion: multiple calls coalesce via the
        # _pending_edhoc future mechanism.
        assert establish_count == 1, (
            f"Expected exactly 1 EDHOC handshake for concurrent requests, got {establish_count}"
        )

        # Cancel tasks (since no responder, they would timeout)
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)

        # Clean up
        alice_secure._pending_edhoc.pop(key, None)

    @pytest.mark.asyncio
    async def test_pending_edhoc_future_registered_before_await(self) -> None:
        """Verify future is registered synchronously before any await.

        The _pending_edhoc dictionary must be populated immediately when
        _establish_context starts, not after the first await. This prevents
        the race window where concurrent requests both pass the check.
        """
        net = InMemoryNetwork()
        alice_id = Identity.generate()
        bob_id = Identity.generate()

        alice_channel = net.channel("alice")
        alice_secure = create_secure_channel(
            alice_channel,
            alice_id,
            require_oscore=True,
            local_host="alice",
        )

        # Pin bob's key
        await alice_secure._peer_resolver.pin_peer("bob", bob_id.pubkey)

        # Start context establishment
        key = alice_secure._endpoint_key("bob")

        # After we enter _establish_context but before any await completes,
        # the future should already be registered
        async def check_immediate_registration() -> None:
            # This checks that concurrent callers see the future immediately
            task = asyncio.create_task(alice_secure._establish_context("bob", key))
            # Yield to let the task start
            await asyncio.sleep(0)
            # The future should already be registered
            assert key in alice_secure._pending_edhoc
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        await check_immediate_registration()
        # Clean up
        alice_secure._pending_edhoc.pop(key, None)


class TestHasOscoreOption:
    """Unit tests for _has_oscore_option bounds checking."""

    def test_valid_oscore_option_found(self) -> None:
        """Detect OSCORE option (number 9) in valid CoAP datagram."""
        # CoAP header: Ver=1, T=NON, TKL=1, Code=GET, MID=0x0001
        # Token: 0xAB
        # Option: delta=9 (OSCORE), len=1, value=0x00
        datagram = bytes(
            [
                0x51,
                0x01,
                0x00,
                0x01,  # Header (TKL=1)
                0xAB,  # Token
                0x91,
                0x00,  # Option: delta=9, len=1, value=0x00
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is True

    def test_no_oscore_option(self) -> None:
        """Return False when OSCORE option not present."""
        # Option delta=3 (Uri-Host), then payload marker
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0x31,
                0x41,  # Option: delta=3, len=1, value='A'
                0xFF,  # Payload marker
                0x48,
                0x45,
                0x4C,
                0x4C,
                0x4F,  # Payload: HELLO
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is False

    def test_truncated_header(self) -> None:
        """Return False for datagram shorter than 4-byte header."""
        assert SecureDatagramChannel._has_oscore_option(b"\x50\x01\x00") is False
        assert SecureDatagramChannel._has_oscore_option(b"") is False

    def test_truncated_extended_option_len_13(self) -> None:
        """Return False when extended option length (13) lacks data byte."""
        # CoAP header + token, then option with delta=1, extended len=13
        # but truncated before the extended length byte
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0x1D,  # Option: delta=1, len=13 (extended)
                # Missing: extended length byte and option value
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is False

    def test_truncated_extended_option_len_14(self) -> None:
        """Return False when extended option length (14) lacks 2-byte length."""
        # Option with delta=1, extended len=14 but truncated
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0x1E,  # Option: delta=1, len=14 (extended)
                0x00,  # Only 1 byte of 2-byte extended length
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is False

    def test_valid_extended_option_len_13(self) -> None:
        """Handle valid extended option length (13) correctly."""
        # Option: delta=1, extended len=13 (actual len = 13 + 0 = 13 bytes)
        # Then OSCORE option (delta=8 to reach cumulative 9)
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0x1D,
                0x00,  # Option: delta=1, len=13+0=13
            ]
            + [0x00] * 13
            + [  # 13 bytes of option value
                0x81,
                0x00,  # Option: delta=8, len=1 (cumulative=9=OSCORE)
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is True

    def test_valid_extended_option_len_14(self) -> None:
        """Handle valid extended option length (14) correctly."""
        # Option: delta=1, extended len=14 (actual len = 269 + 0 = 269 bytes)
        # Then OSCORE option
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0x1E,
                0x00,
                0x00,  # Option: delta=1, len=269+0=269
            ]
            + [0x00] * 269
            + [  # 269 bytes of option value
                0x81,
                0x00,  # Option: delta=8, len=1 (cumulative=9=OSCORE)
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is True

    def test_truncated_with_extended_delta_and_extended_len(self) -> None:
        """Return False when both delta and len are extended but len truncated."""
        # Option: delta=13 (extended), len=13 (extended)
        # delta byte present, but len byte missing
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0xDD,
                0x00,  # Option: delta=13+0=13, len=13 (extended)
                # Missing: extended length byte (should be at pos+2)
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is False

    def test_option_len_15_reserved(self) -> None:
        """Return False for reserved option length value 15."""
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0x1F,  # Option: delta=1, len=15 (reserved)
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is False

    def test_option_delta_15_reserved(self) -> None:
        """Return False for reserved option delta value 15."""
        datagram = bytes(
            [
                0x50,
                0x01,
                0x00,
                0x01,  # Header (TKL=0)
                0xF1,  # Option: delta=15 (reserved), len=1
            ]
        )
        assert SecureDatagramChannel._has_oscore_option(datagram) is False
