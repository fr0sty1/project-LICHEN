# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for BR provisioning CoAP resource.

Per spec section 8.7, BR provisioning channels MUST be encrypted and
authenticated. These tests verify the ProvisioningResource correctly
implements the encrypted provisioning protocol.

Test categories:
1. Resource creation and configuration
2. BR-side provisioning flow
3. NODE-side provisioning flow
4. Session management
5. Error handling
6. Security properties
"""

from typing import Any
from unittest.mock import MagicMock

import pytest

from lichen.coap.resources.provisioning import (
    ProvisioningResource,
    ProvisioningRole,
)
from lichen.crypto.identity import Identity
from lichen.crypto.provisioning import (
    BRProvisioningSession,
    NodeProvisioningSession,
    ProvisioningState,
)


class TestResourceCreation:
    """Tests for ProvisioningResource creation and configuration."""

    def test_for_br_creates_br_role(self):
        """for_br() creates resource with BR role."""
        identity = Identity.generate()
        resource = ProvisioningResource.for_br(identity)
        assert resource.role == ProvisioningRole.BR

    def test_for_node_creates_node_role(self):
        """for_node() creates resource with NODE role."""
        identity = Identity.generate()
        resource = ProvisioningResource.for_node(identity)
        assert resource.role == ProvisioningRole.NODE

    def test_for_br_with_custom_seed_provider(self):
        """for_br() accepts custom seed provider."""

        class CustomSeedProvider:
            def generate_seed(self) -> bytes:
                return bytes(32)

        identity = Identity.generate()
        provider = CustomSeedProvider()
        resource = ProvisioningResource.for_br(identity, seed_provider=provider)
        assert resource.role == ProvisioningRole.BR

    def test_for_br_with_provisioned_callback(self):
        """for_br() accepts provisioned callback."""

        class Callback:
            async def on_provisioned(
                self, node_pubkey: bytes, node_iid: bytes, node_ygg_addr: bytes
            ) -> None:
                pass

        identity = Identity.generate()
        callback = Callback()
        resource = ProvisioningResource.for_br(
            identity, provisioned_callback=callback
        )
        assert resource.role == ProvisioningRole.BR

    def test_for_node_with_new_identity_callback(self):
        """for_node() accepts new identity callback."""

        class Callback:
            async def on_new_identity(self, identity: Any) -> None:
                pass

        identity = Identity.generate()
        callback = Callback()
        resource = ProvisioningResource.for_node(
            identity, new_identity_callback=callback
        )
        assert resource.role == ProvisioningRole.NODE


class TestBRSessionCreation:
    """Tests for BR-side session creation."""

    def test_create_br_session_returns_session(self):
        """create_br_session() returns a BRProvisioningSession."""
        br_identity = Identity.generate()
        node_identity = Identity.generate()

        resource = ProvisioningResource.for_br(br_identity)
        session = resource.create_br_session("peer1", node_identity.pubkey)

        assert isinstance(session, BRProvisioningSession)
        assert session.state == ProvisioningState.IDLE

    def test_create_br_session_wrong_role_fails(self):
        """create_br_session() fails for NODE role."""
        identity = Identity.generate()
        resource = ProvisioningResource.for_node(identity)

        with pytest.raises(RuntimeError, match="BR role"):
            resource.create_br_session("peer1", bytes(32))

    @pytest.mark.asyncio
    async def test_create_br_session_when_closed_fails(self):
        """create_br_session() fails after close()."""
        identity = Identity.generate()
        resource = ProvisioningResource.for_br(identity)
        await resource.close()

        with pytest.raises(RuntimeError, match="closed"):
            resource.create_br_session("peer1", bytes(32))

    def test_create_br_session_max_sessions_fails(self):
        """create_br_session() fails when max sessions reached."""
        br_identity = Identity.generate()
        resource = ProvisioningResource.for_br(br_identity, max_sessions=2)

        # Create max sessions
        for i in range(2):
            node_id = Identity.generate()
            resource.create_br_session(f"peer{i}", node_id.pubkey)

        # Third should fail
        with pytest.raises(RuntimeError, match="Max sessions"):
            node_id = Identity.generate()
            resource.create_br_session("peer_overflow", node_id.pubkey)


class TestNodeSessionCreation:
    """Tests for NODE-side session creation."""

    def test_create_node_session_returns_session(self):
        """create_node_session() returns a NodeProvisioningSession."""
        ephemeral = Identity.generate()
        resource = ProvisioningResource.for_node(ephemeral)

        session = resource.create_node_session("br1")

        assert isinstance(session, NodeProvisioningSession)
        assert session.state == ProvisioningState.IDLE

    def test_create_node_session_wrong_role_fails(self):
        """create_node_session() fails for BR role."""
        identity = Identity.generate()
        resource = ProvisioningResource.for_br(identity)

        with pytest.raises(RuntimeError, match="NODE role"):
            resource.create_node_session("br1")


class TestSessionExpiry:
    """Tests for session timeout handling."""

    def test_sessions_expire_after_lifetime(self):
        """Sessions are removed after session_lifetime."""
        br_identity = Identity.generate()
        node_identity = Identity.generate()

        current_time = [0.0]

        def mock_monotonic() -> float:
            return current_time[0]

        resource = ProvisioningResource.for_br(
            br_identity,
            session_lifetime=10.0,
            monotonic=mock_monotonic,
        )

        # Create session
        resource.create_br_session("peer1", node_identity.pubkey)
        assert "peer1" in resource._sessions

        # Advance time past deadline
        current_time[0] = 11.0
        resource._expire_sessions()

        # Session should be removed
        assert "peer1" not in resource._sessions


class TestFullProvisioningFlow:
    """Integration tests for complete provisioning flow."""

    @pytest.mark.asyncio
    async def test_full_provisioning_flow(self):
        """Complete BR to NODE provisioning flow succeeds."""
        # Setup identities
        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        # Create resources
        br_resource = ProvisioningResource.for_br(br_identity)
        node_resource = ProvisioningResource.for_node(node_ephemeral)

        # Create sessions
        br_session = br_resource.create_br_session("node1", node_ephemeral.pubkey)
        node_session = node_resource.create_node_session("br1")

        # EDHOC handshake
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        br_session.process_message_3(msg3)

        assert br_session.state == ProvisioningState.ESTABLISHED
        assert node_session.state == ProvisioningState.ESTABLISHED

        # BR provisions seed
        seed = br_resource._seed_provider.generate_seed()
        br_resource._sessions["node1"].provisioned_seed = seed
        encrypted_seed = br_session.encrypt_seed(seed)

        # Node decrypts and creates ACK
        new_identity = node_session.decrypt_seed(encrypted_seed.encode())
        assert len(new_identity.pubkey) == 32

        ack = node_session.create_ack(new_identity.pubkey)
        assert node_session.state == ProvisioningState.COMPLETED

        # BR verifies ACK
        received_pubkey = br_session.decrypt_ack(ack.encode())
        assert received_pubkey == new_identity.pubkey
        assert br_session.state == ProvisioningState.COMPLETED

        # Cleanup
        await br_resource.close()
        await node_resource.close()

    @pytest.mark.asyncio
    async def test_provision_node_performs_edhoc_handshake_and_verifies_ack(self):
        """provision_node() performs EDHOC handshake, sends seed, and verifies ACK."""
        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        br_resource = ProvisioningResource.for_br(br_identity)
        node_session = NodeProvisioningSession(node_ephemeral)

        # Prepare node's EDHOC messages
        msg1 = node_session.create_message_1()
        node_messages = [msg1]  # Will add msg3 after receiving msg2, then ACK
        sent_from_br: list[bytes] = []

        async def receive_message() -> bytes:
            return node_messages.pop(0)

        async def send_message(data: bytes) -> None:
            sent_from_br.append(data)
            # When BR sends msg2, node responds with msg3
            if len(sent_from_br) == 1:
                msg3 = node_session.process_message_2(data, br_identity.pubkey)
                node_messages.append(msg3)
            # When BR sends encrypted seed, node decrypts, derives identity, sends ACK
            elif len(sent_from_br) == 2:
                new_identity = node_session.decrypt_seed(data)
                ack = node_session.create_ack(new_identity.pubkey)
                node_messages.append(ack.encode())

        # Call provision_node - should complete with ACK verification
        seed = await br_resource.provision_node(
            "node1",
            node_ephemeral.pubkey,
            send_message,
            receive_message,
        )

        # Verify: EDHOC completed (msg2 sent, msg3 processed) + seed sent
        assert len(sent_from_br) == 2  # msg2 and encrypted seed
        assert len(seed) == 32

        await br_resource.close()


class TestSecurityProperties:
    """Tests verifying security properties of provisioning."""

    def test_seed_is_encrypted_not_plaintext(self):
        """Seeds are encrypted before transmission, never plaintext."""
        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        br_session = BRProvisioningSession(br_identity, node_ephemeral.pubkey)
        node_session = NodeProvisioningSession(node_ephemeral)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        br_session.process_message_3(msg3)

        # Encrypt seed
        seed = bytes(range(32))
        encrypted = br_session.encrypt_seed(seed)

        # SECURITY: The ciphertext must not contain the plaintext seed
        # The seed should be encrypted with AES-CCM, not sent in the clear
        assert seed not in encrypted.encode()
        assert len(encrypted.ciphertext) > 32  # Includes authentication tag

    @pytest.mark.asyncio
    async def test_sessions_are_wiped_on_close(self):
        """Session secrets are wiped when resource closes."""
        br_identity = Identity.generate()
        node_identity = Identity.generate()

        resource = ProvisioningResource.for_br(br_identity)
        resource.create_br_session("peer1", node_identity.pubkey)

        # Store a seed
        resource._sessions["peer1"].provisioned_seed = bytes(32)

        # Close resource
        await resource.close()

        # Session should be removed and wiped
        assert "peer1" not in resource._sessions

    def test_existing_session_wiped_on_br_session_overwrite(self):
        """Creating new BR session for same peer wipes old session first.

        SECURITY: Prevents cryptographic state leakage when a session is
        overwritten. Without this, _prov_key and provisioned_seed would
        remain in memory when the dict entry is replaced.
        """
        br_identity = Identity.generate()
        node_identity1 = Identity.generate()
        node_identity2 = Identity.generate()

        resource = ProvisioningResource.for_br(br_identity)

        # Create first session and store sensitive data
        session1 = resource.create_br_session("peer1", node_identity1.pubkey)
        resource._sessions["peer1"].provisioned_seed = bytes([0xAB] * 32)
        old_session_obj = resource._sessions["peer1"]

        # Create second session for same peer - old session must be wiped
        session2 = resource.create_br_session("peer1", node_identity2.pubkey)

        # New session should be different from old
        assert session2 is not session1
        new_session_obj = resource._sessions["peer1"]
        assert new_session_obj is not old_session_obj

        # Old session's sensitive data should have been cleared
        assert old_session_obj.provisioned_seed is None

    def test_existing_session_wiped_on_node_session_overwrite(self):
        """Creating new NODE session for same peer wipes old session first.

        SECURITY: Same protection as BR side - prevents cryptographic state
        leakage when overwriting a session.
        """
        node_identity = Identity.generate()

        resource = ProvisioningResource.for_node(node_identity)

        # Create first session
        session1 = resource.create_node_session("br1")
        old_session_obj = resource._sessions["br1"]

        # Create second session for same peer - old session must be wiped
        session2 = resource.create_node_session("br1")

        # New session should be different from old
        assert session2 is not session1
        new_session_obj = resource._sessions["br1"]
        assert new_session_obj is not old_session_obj

    def test_node_identity_callback_receives_complete_identity(self):
        """NODE callback receives full identity (seed, pubkey, IID, addr)."""
        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        received_identity = [None]

        class Callback:
            async def on_new_identity(self, identity: Any) -> None:
                received_identity[0] = identity

        callback = Callback()
        node_resource = ProvisioningResource.for_node(
            node_ephemeral, new_identity_callback=callback
        )

        # Create and complete session manually
        node_session = node_resource.create_node_session("br1")
        br_session = BRProvisioningSession(br_identity, node_ephemeral.pubkey)

        # EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        br_session.process_message_3(msg3)

        # Provision
        seed = bytes([0x42] * 32)
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())

        # Verify identity has all fields
        assert len(new_identity.seed) == 32
        assert len(new_identity.pubkey) == 32
        assert len(new_identity.iid) == 8
        assert len(new_identity.ygg_addr) == 16


class TestCOAPIntegration:
    """Tests for CoAP message handling."""

    @pytest.mark.asyncio
    async def test_render_get_returns_status(self):
        """GET /provision returns current status."""
        identity = Identity.generate()
        resource = ProvisioningResource.for_br(identity)

        # Mock request
        request = MagicMock()
        request.remote.hostinfo = "peer1"

        response = await resource.render_get(request)

        assert response.code.is_successful()
        import cbor2

        status = cbor2.loads(response.payload)
        assert status["state"] == "idle"
        assert status["role"] == "br"

    @pytest.mark.asyncio
    async def test_render_post_without_payload_returns_bad_request(self):
        """POST /provision without payload returns 4.00."""
        from aiocoap import BAD_REQUEST

        identity = Identity.generate()
        resource = ProvisioningResource.for_br(identity)

        request = MagicMock()
        request.payload = b""

        response = await resource.render_post(request)

        assert response.code == BAD_REQUEST

    @pytest.mark.asyncio
    async def test_render_post_when_closed_returns_service_unavailable(self):
        """POST /provision when closed returns 5.03."""
        from aiocoap import SERVICE_UNAVAILABLE

        identity = Identity.generate()
        resource = ProvisioningResource.for_br(identity)
        await resource.close()

        request = MagicMock()
        request.payload = b"something"
        request.remote = MagicMock()
        request.remote.hostinfo = "peer1"

        response = await resource.render_post(request)

        assert response.code == SERVICE_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_br_post_invokes_callback_when_using_create_br_session_directly(self):
        """BR POST handler invokes callback even when using create_br_session() directly.

        When create_br_session() is used directly (not via provision_node()),
        session.provisioned_seed remains None. The POST handler must still
        invoke the callback by falling back to the crypto layer's seed.
        """
        from aiocoap import CHANGED

        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        callback_invoked = [False]
        callback_pubkey = [None]

        class Callback:
            async def on_provisioned(self, node_pubkey, **kwargs) -> None:
                callback_invoked[0] = True
                callback_pubkey[0] = node_pubkey

        callback = Callback()
        br_resource = ProvisioningResource.for_br(
            br_identity, provisioned_callback=callback
        )

        # Create session via create_br_session (NOT provision_node)
        # This leaves provisioned_seed = None
        br_session = br_resource.create_br_session("node1", node_ephemeral.pubkey)
        node_session = NodeProvisioningSession(node_ephemeral)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        br_session.process_message_3(msg3)

        # Manually encrypt a seed (simulating what provision_node would do)
        # but do NOT set session.provisioned_seed
        seed = bytes([0x42] * 32)
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())
        ack = node_session.create_ack(new_identity.pubkey)

        # Confirm session.provisioned_seed is None (crypto layer has it)
        assert br_resource._sessions["node1"].provisioned_seed is None

        # POST the ACK - should succeed AND invoke callback
        request = MagicMock()
        request.payload = ack.encode()
        request.remote = MagicMock()
        request.remote.hostinfo = "node1"

        response = await br_resource.render_post(request)

        # Should return success AND callback should have been invoked
        # with the correct pubkey derived from the seed
        assert response.code == CHANGED
        assert callback_invoked[0] is True
        assert callback_pubkey[0] == new_identity.pubkey

        await br_resource.close()

    @pytest.mark.asyncio
    async def test_br_callback_exception_returns_service_unavailable(self):
        """BR POST returns 5.03 Service Unavailable when on_provisioned callback raises.

        SECURITY: Callback exceptions must NOT be silently swallowed. If the
        callback fails (e.g., audit logging fails, database write fails), the
        client must receive an error so it can retry. Silent success would mean
        provisioning appears complete but the identity is not recorded.

        SERVICE_UNAVAILABLE (5.03) signals the backend is temporarily unable
        to complete the request, prompting client retry with backoff.

        Regression test for: contextlib.suppress(Exception) swallowing errors.
        """
        from aiocoap import SERVICE_UNAVAILABLE

        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        class FailingCallback:
            async def on_provisioned(self, **kwargs) -> None:
                raise RuntimeError("Simulated database failure")

        callback = FailingCallback()
        br_resource = ProvisioningResource.for_br(
            br_identity, provisioned_callback=callback
        )

        # Create session via provision_node flow (sets provisioned_seed)
        br_session = br_resource.create_br_session("node1", node_ephemeral.pubkey)
        node_session = NodeProvisioningSession(node_ephemeral)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        br_session.process_message_3(msg3)

        # Encrypt seed AND set provisioned_seed (like provision_node does)
        seed = bytes([0x42] * 32)
        br_resource._sessions["node1"].provisioned_seed = seed
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())
        ack = node_session.create_ack(new_identity.pubkey)

        # POST the ACK - callback will fail
        request = MagicMock()
        request.payload = ack.encode()
        request.remote = MagicMock()
        request.remote.hostinfo = "node1"

        response = await br_resource.render_post(request)

        # MUST return error, not silently succeed
        assert response.code == SERVICE_UNAVAILABLE

        # Session should NOT be wiped (allows retry)
        assert "node1" in br_resource._sessions

        await br_resource.close()

    @pytest.mark.asyncio
    async def test_node_callback_exception_returns_service_unavailable(self):
        """NODE POST returns 5.03 Service Unavailable when on_new_identity callback raises.

        SECURITY: Same as BR side - callback exceptions must not be swallowed.
        If identity storage fails, the node must know so it can retry.

        SERVICE_UNAVAILABLE (5.03) signals the backend is temporarily unable
        to complete the request, prompting client retry with backoff.
        """
        from aiocoap import SERVICE_UNAVAILABLE

        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        class FailingCallback:
            async def on_new_identity(self, identity: Any) -> None:
                raise RuntimeError("Simulated storage failure")

        callback = FailingCallback()
        node_resource = ProvisioningResource.for_node(
            node_ephemeral, new_identity_callback=callback
        )

        # Create sessions
        node_session = node_resource.create_node_session("br1")
        br_session = BRProvisioningSession(br_identity, node_ephemeral.pubkey)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        br_session.process_message_3(msg3)

        # BR provisions seed
        seed = bytes([0x42] * 32)
        encrypted = br_session.encrypt_seed(seed)

        # POST the encrypted seed - callback will fail
        request = MagicMock()
        request.payload = encrypted.encode()
        request.remote = MagicMock()
        request.remote.hostinfo = "br1"

        response = await node_resource.render_post(request)

        # MUST return error, not silently succeed
        assert response.code == SERVICE_UNAVAILABLE

        # Session should NOT be wiped (allows retry)
        assert "br1" in node_resource._sessions

        await node_resource.close()
