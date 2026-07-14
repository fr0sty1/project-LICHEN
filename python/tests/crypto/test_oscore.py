# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for OSCORE security context integration with aiocoap."""

import pytest

from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder
from lichen.crypto.identity import Identity
from lichen.crypto.oscore import MemorySecurityContext


class TestMemorySecurityContext:
    """Test MemorySecurityContext creation and basic operations."""

    def test_from_edhoc_creates_context(self) -> None:
        """MemorySecurityContext.from_edhoc creates a usable context."""
        # Run EDHOC handshake
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        # Export OSCORE contexts
        edhoc_ctx_i = initiator.export_oscore()
        edhoc_ctx_r = responder.export_oscore()

        # Create MemorySecurityContexts
        ctx_i = MemorySecurityContext.from_edhoc(edhoc_ctx_i)
        ctx_r = MemorySecurityContext.from_edhoc(edhoc_ctx_r)

        # Verify derived keys match (initiator sender = responder recipient)
        assert ctx_i.sender_key == ctx_r.recipient_key
        assert ctx_i.recipient_key == ctx_r.sender_key
        assert ctx_i.common_iv == ctx_r.common_iv

    def test_derived_keys_compatible(self) -> None:
        """Initiator and responder derive compatible keys for protect/unprotect."""
        # Setup contexts
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx_i = MemorySecurityContext.from_edhoc(initiator.export_oscore())
        ctx_r = MemorySecurityContext.from_edhoc(responder.export_oscore())

        # Keys are derived correctly for bidirectional communication:
        # - Initiator's sender_key == Responder's recipient_key
        # - Initiator's recipient_key == Responder's sender_key
        assert ctx_i.sender_key == ctx_r.recipient_key
        assert ctx_i.recipient_key == ctx_r.sender_key
        assert ctx_i.common_iv == ctx_r.common_iv

        # IDs are correctly swapped
        assert ctx_i.sender_id == ctx_r.recipient_id
        assert ctx_i.recipient_id == ctx_r.sender_id

        # Replay window is initialized
        assert ctx_i.recipient_replay_window is not None
        assert ctx_r.recipient_replay_window is not None

    def test_sequence_number_increments(self) -> None:
        """Each protect() call increments sequence number."""
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )

        assert ctx.sender_sequence_number == 0
        ctx.new_sequence_number()
        assert ctx.sender_sequence_number == 1
        ctx.new_sequence_number()
        assert ctx.sender_sequence_number == 2

    def test_id_too_long_raises(self) -> None:
        """IDs longer than algorithm allows raise ValueError."""
        # AES-CCM-16-64-128 has 13-byte IV, so max ID is 7 bytes
        with pytest.raises(ValueError, match="ID too long"):
            MemorySecurityContext(
                master_secret=b"0" * 16,
                master_salt=b"1" * 8,
                sender_id=b"\x00" * 8,  # Too long
                recipient_id=b"\x01",
            )

    def test_sequence_number_overflow_raises(self) -> None:
        """Sequence number overflow raises OverflowError to prevent nonce reuse."""
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )

        # Set sequence number to max (2^40 - 1)
        ctx.sender_sequence_number = (1 << 40) - 1

        # Last valid sequence number should succeed
        seqno = ctx.new_sequence_number()
        assert seqno == (1 << 40) - 1

        # Next call should raise (would exceed 5-byte limit)
        with pytest.raises(OverflowError, match="sequence number exhausted"):
            ctx.new_sequence_number()

    def test_starting_sequence_number_parameter(self) -> None:
        """starting_sequence_number allows state recovery to prevent nonce reuse."""
        # Simulate state recovery: context recreated with persisted sequence number
        starting_seq = 1000
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
            starting_sequence_number=starting_seq,
        )

        # Sequence number starts at the provided value, not 0
        assert ctx.sender_sequence_number == starting_seq

        # Next sequence number continues from there
        seqno = ctx.new_sequence_number()
        assert seqno == starting_seq
        assert ctx.sender_sequence_number == starting_seq + 1

    def test_starting_sequence_number_negative_raises(self) -> None:
        """Negative starting_sequence_number raises ValueError."""
        with pytest.raises(ValueError, match="non-negative"):
            MemorySecurityContext(
                master_secret=b"0" * 16,
                master_salt=b"1" * 8,
                sender_id=b"\x00",
                recipient_id=b"\x01",
                starting_sequence_number=-1,
            )

    def test_starting_sequence_number_exceeds_max_raises(self) -> None:
        """starting_sequence_number exceeding RFC 8613 limit raises ValueError."""
        max_seq = (1 << 40) - 1
        # Value at max should succeed
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
            starting_sequence_number=max_seq,
        )
        assert ctx.sender_sequence_number == max_seq

        # Value exceeding max should fail
        with pytest.raises(ValueError, match="exceeds RFC 8613 limit"):
            MemorySecurityContext(
                master_secret=b"0" * 16,
                master_salt=b"1" * 8,
                sender_id=b"\x00",
                recipient_id=b"\x01",
                starting_sequence_number=max_seq + 1,
            )

    def test_get_persisted_sequence_number(self) -> None:
        """get_persisted_sequence_number returns current value for persistence."""
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
            starting_sequence_number=500,
        )

        assert ctx.get_persisted_sequence_number() == 500

        ctx.new_sequence_number()
        ctx.new_sequence_number()
        assert ctx.get_persisted_sequence_number() == 502

    def test_from_edhoc_with_starting_sequence_number(self) -> None:
        """from_edhoc accepts starting_sequence_number for state recovery."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        edhoc_ctx = initiator.export_oscore()

        # Create context with recovered sequence number
        ctx = MemorySecurityContext.from_edhoc(edhoc_ctx, starting_sequence_number=42)
        assert ctx.sender_sequence_number == 42
