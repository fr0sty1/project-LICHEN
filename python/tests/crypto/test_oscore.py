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

        ctx = MemorySecurityContext.from_edhoc(edhoc_ctx, starting_sequence_number=42)
        assert ctx.sender_sequence_number == 42

    def test_no_nonce_reuse_after_simulated_nvm_failure(self) -> None:
        """After simulated NVM failure, restored context produces distinct nonces.

        Simulates: context created, used at seq=20..99, crashes, then restored
        at starting_sequence_number=1000. Verifies the restored context
        produces a nonce different from the crash-period context's nonces.
        """
        master_secret = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        master_salt = bytes.fromhex("9e7ca92223786340")

        # Phase 1: Pre-crash context, used up through seq=99
        pre_crash = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=b"",
            recipient_id=b"\x01",
        )
        pre_crash.sender_sequence_number = 99
        pre_crash._sender_sequence_reservation_end = (1 << 40)

        # Compute nonce for pre-crash seq=99
        alg = pre_crash.alg_aead
        fresh_seq0 = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=b"",
            recipient_id=b"\x01",
        )
        pre_crash_nonce = fresh_seq0._construct_nonce(
            b"\x63", fresh_seq0.sender_id, alg
        )

        # Phase 2: Simulate crash — destroy pre_crash context, restore at seq=1000
        restored = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=b"",
            recipient_id=b"\x01",
            starting_sequence_number=1000,
        )

        # Compute nonce for restored seq=1000
        restored_nonce = fresh_seq0._construct_nonce(
            b"\x03\xe8", restored.sender_id, alg
        )

        # Phase 3: Verify nonces are distinct (no nonce reuse)
        assert pre_crash_nonce != restored_nonce, (
            f"Nonce reuse detected: seq=99 and seq=1000 produce same nonce "
            f"{pre_crash_nonce.hex()}"
        )

        # Verify restored nonce matches independently computed value
        expected_nonce = "4622d4dd6d944168eefb549b94"
        assert restored_nonce.hex() == expected_nonce, (
            f"Restored nonce mismatch: got {restored_nonce.hex()}, "
            f"expected {expected_nonce}"
        )

        # Verify restored context can protect successfully
        assert restored.has_reserved_sender_sequence
        seqno = restored.new_sequence_number()
        assert seqno == 1000
        assert restored.sender_sequence_number == 1001
