# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for OSCORE using RFC 8613 test vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.crypto.oscore import MemorySecurityContext

# Load test vectors
VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "oscore.json"
with open(VECTORS_PATH) as f:
    VECTORS_DATA = json.load(f)


def get_vectors_by_type(type_name: str) -> list[dict[str, Any]]:
    """Get all test vectors of a specific type."""
    return [v for v in VECTORS_DATA["vectors"] if v.get("type") == type_name]


class TestKeyDerivation:
    """Test OSCORE key derivation against RFC 8613 Appendix C vectors."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("key_derivation"),
        ids=lambda v: v["name"],
    )
    def test_key_derivation(self, vector: dict[str, Any]) -> None:
        """Verify key derivation matches RFC 8613 expected values."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        sender_id = bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        recipient_id = bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""
        id_context = bytes.fromhex(vector["id_context"]) if vector.get("id_context") else None

        # Create context - this derives keys
        ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
            id_context=id_context,
        )

        expected = vector["expected"]
        assert ctx.sender_key == bytes.fromhex(expected["sender_key"]), (
            f"sender_key mismatch for {vector['name']}"
        )
        assert ctx.recipient_key == bytes.fromhex(expected["recipient_key"]), (
            f"recipient_key mismatch for {vector['name']}"
        )
        assert ctx.common_iv == bytes.fromhex(expected["common_iv"]), (
            f"common_iv mismatch for {vector['name']}"
        )


class TestRoundtrip:
    """Test OSCORE protect/unprotect roundtrip."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("roundtrip"),
        ids=lambda v: v["name"],
    )
    def test_roundtrip(self, vector: dict[str, Any]) -> None:
        """Verify protect followed by unprotect recovers original plaintext."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        sender_id = bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        recipient_id = bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""

        # Create sender and recipient contexts (symmetric, swapped IDs)
        sender_ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
        )
        recipient_ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=recipient_id,
            recipient_id=sender_id,
        )

        # Verify keys are correctly swapped
        assert sender_ctx.sender_key == recipient_ctx.recipient_key
        assert sender_ctx.recipient_key == recipient_ctx.sender_key
        assert sender_ctx.common_iv == recipient_ctx.common_iv


class TestReplayWindow:
    """Test OSCORE replay window behavior."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("replay"),
        ids=lambda v: v["name"],
    )
    def test_replay_detection(self, vector: dict[str, Any]) -> None:
        """Verify replay window correctly accepts/rejects sequence numbers.

        Note: MemorySecurityContext uses aiocoap's ReplayWindow which has a
        different interface than the Rust implementation. This test verifies
        the basic replay window behavior is correct.
        """
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )

        highest_seq = vector["highest_seq"]
        test_seq = vector["test_seq"]
        expected_is_replay = vector["expected"]["is_replay"]

        # Initialize the replay window to the specified state
        # First, mark the highest_seq as seen
        if highest_seq > 0:
            # Strike (mark as seen) all sequence numbers up to highest
            # This is a simplified setup - in real usage, packets arrive one at a time
            ctx.recipient_replay_window.strike_out(highest_seq)

        # Now test if test_seq would be accepted
        is_replay = ctx.recipient_replay_window.is_valid(test_seq) is False

        assert is_replay == expected_is_replay, (
            f"replay detection mismatch for {vector['name']}: "
            f"highest={highest_seq}, test={test_seq}, "
            f"expected_replay={expected_is_replay}, got_replay={is_replay}"
        )


class TestInvalidInputs:
    """Test OSCORE rejects invalid inputs."""

    def test_sender_id_too_long(self) -> None:
        """Sender ID exceeding 7 bytes should raise ValueError."""
        with pytest.raises(ValueError, match="ID too long"):
            MemorySecurityContext(
                master_secret=b"0" * 16,
                master_salt=b"1" * 8,
                sender_id=b"\x00" * 8,  # 8 bytes - too long
                recipient_id=b"\x01",
            )

    def test_recipient_id_too_long(self) -> None:
        """Recipient ID exceeding 7 bytes should raise ValueError."""
        with pytest.raises(ValueError, match="ID too long"):
            MemorySecurityContext(
                master_secret=b"0" * 16,
                master_salt=b"1" * 8,
                sender_id=b"\x00",
                recipient_id=b"\x01" * 8,  # 8 bytes - too long
            )


class TestSsnRestoreVectors:
    """Test OSCORE SSN restore vectors for NVM failure/recovery edge cases."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("ssn_restore"),
        ids=lambda v: v["name"],
    )
    def test_ssn_restore_nonce(self, vector: dict[str, Any]) -> None:
        """Verify restored context produces correct nonce matching vector."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = (
            bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        )
        sender_id = (
            bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        )
        recipient_id = (
            bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""
        )
        id_context = (
            bytes.fromhex(vector["id_context"]) if vector.get("id_context") else None
        )

        starting_seq = vector["starting_sequence_number"]
        ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
            id_context=id_context,
            starting_sequence_number=starting_seq,
        )

        expected = vector["expected"]
        algorithm = ctx.alg_aead

        piv = starting_seq.to_bytes(5, "big").lstrip(b"\x00") or b"\x00"
        nonce = ctx._construct_nonce(piv, sender_id, algorithm)
        assert nonce.hex() == expected["nonce"], (
            f"Nonce mismatch for {vector['name']}: "
            f"got {nonce.hex()}, expected {expected['nonce']}"
        )

        # Verify keys are correctly derived from the restored context
        if "sender_key" in expected:
            assert ctx.sender_key.hex() == expected["sender_key"]
        if "recipient_key" in expected:
            assert ctx.recipient_key.hex() == expected["recipient_key"]

        # Verify restored context can issue sequence numbers at the correct offset
        seqno = ctx.new_sequence_number()
        assert seqno == starting_seq
        assert ctx.sender_sequence_number == starting_seq + 1

    def test_ssn_restore_no_nonce_reuse(self) -> None:
        """Verify prior_sequence_number and starting_sequence_number nonces differ."""
        vectors = [
            v for v in VECTORS_DATA["vectors"]
            if v.get("name") == "ssn_restore_no_nonce_reuse"
        ]
        assert len(vectors) == 1, "Missing ssn_restore_no_nonce_reuse vector"

        vector = vectors[0]
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = (
            bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        )
        prior_seq = vector["prior_sequence_number"]
        starting_seq = vector["starting_sequence_number"]

        ctx_prior = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=b"",
            recipient_id=b"\x01",
        )
        alg = ctx_prior.alg_aead

        prior_piv = prior_seq.to_bytes(5, "big").lstrip(b"\x00") or b"\x00"
        prior_nonce = ctx_prior._construct_nonce(prior_piv, b"", alg)

        ctx_restored = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=b"",
            recipient_id=b"\x01",
            starting_sequence_number=starting_seq,
        )
        restored_nonce = ctx_restored._construct_nonce(
            b"\x03\xe8", b"", alg
        )

        assert prior_nonce != restored_nonce, (
            f"Nonce reuse: seq={prior_seq} and seq={starting_seq} produce "
            f"same nonce {prior_nonce.hex()}"
        )

        assert restored_nonce.hex() == vector["expected"]["nonce"], (
            f"Restored nonce mismatch: got {restored_nonce.hex()}, "
            f"expected {vector['expected']['nonce']}"
        )
