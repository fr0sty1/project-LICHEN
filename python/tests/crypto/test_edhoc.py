# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for EDHOC Suite 0 implementation."""

import pytest

from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder, OscoreContext
from lichen.crypto.identity import Identity


class TestEdhocHandshake:
    """Test EDHOC handshake between initiator and responder."""

    def test_full_handshake(self) -> None:
        """Complete EDHOC handshake derives matching OSCORE contexts."""
        # Create identities
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        # Create EDHOC roles
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        # Message 1: Initiator -> Responder
        msg1 = initiator.create_message_1()
        assert len(msg1) > 0

        # Message 2: Responder -> Initiator
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        assert len(msg2) > 0

        # Message 3: Initiator -> Responder
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        assert len(msg3) > 0

        # Responder processes Message 3
        responder.process_message_3(msg3, initiator_id.pubkey)

        # Export OSCORE contexts
        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()

        # Master secret and salt must match
        assert ctx_i.master_secret == ctx_r.master_secret
        assert ctx_i.master_salt == ctx_r.master_salt

        # Sender/recipient IDs are swapped
        assert ctx_i.sender_id == ctx_r.recipient_id
        assert ctx_i.recipient_id == ctx_r.sender_id

    def test_different_connection_ids(self) -> None:
        """Handshake works with various connection ID sizes."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        # Longer connection IDs
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\xde\xad")
        responder = EdhocResponder.create(responder_id, c_r=b"\xbe\xef")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()

        assert ctx_i.master_secret == ctx_r.master_secret
        assert ctx_i.sender_id == b"\xde\xad"
        assert ctx_r.sender_id == b"\xbe\xef"

    def test_export_before_complete_fails(self) -> None:
        """Exporting OSCORE context before handshake complete raises."""
        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id)

        with pytest.raises(ValueError, match="not complete"):
            initiator.export_oscore()


class TestOscoreContext:
    """Test OSCORE context properties."""

    def test_key_lengths(self) -> None:
        """Exported keys have correct lengths."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx = initiator.export_oscore()

        assert len(ctx.master_secret) == 16  # AES-128
        assert len(ctx.master_salt) == 8

    def test_custom_key_lengths(self) -> None:
        """Can export with custom key/salt lengths."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx = initiator.export_oscore(oscore_salt_len=16, oscore_key_len=32)

        assert len(ctx.master_secret) == 32
        assert len(ctx.master_salt) == 16
