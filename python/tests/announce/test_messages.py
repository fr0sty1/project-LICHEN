# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for announce message codec.

Why these tests: Announce messages are the primary routing mechanism for active
nodes. Bugs here mean:
- Malformed messages rejected by receivers (routing failure)
- Wrong signed_data() = signature verification fails
- Hop count not incremented = infinite flooding
- seq_num wrong = stale announces accepted or fresh ones rejected

Test categories:
1. Construction and validation
2. Serialization round-trip
3. signed_data() correctness
4. Hop count management
5. Error cases
"""

import pytest

from lichen.announce.messages import (
    ANNOUNCE_TYPE,
    MAX_ANNOUNCE_HOPS,
    SIGNATURE_LENGTH,
    AnnounceError,
    AnnounceMessage,
)


class TestAnnounceConstruction:
    """Tests for AnnounceMessage construction and validation."""

    def test_valid_minimal_announce(self):
        """A valid announce with minimum required fields."""
        # Why test: Baseline - a properly constructed message should work.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=0,
            signature=bytes(SIGNATURE_LENGTH),
        )
        assert msg.originator_iid == bytes(8)
        assert msg.pubkey == bytes(32)
        assert msg.seq_num == 0
        assert msg.hop_count == 0
        assert len(msg.signature) == SIGNATURE_LENGTH
        assert msg.app_data == b""
        assert msg.flags == 0

    def test_valid_announce_with_app_data(self):
        """Announce with optional app_data field."""
        # Why test: app_data is optional but must be handled correctly.
        app_data = b"node-name:alice"
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=42,
            hop_count=3,
            signature=bytes(SIGNATURE_LENGTH),
            app_data=app_data,
        )
        assert msg.app_data == app_data

    def test_rejects_wrong_iid_length(self):
        """IID must be exactly 8 bytes."""
        # Why test: IID is a fixed-size field. Wrong length = parsing failure.
        with pytest.raises(AnnounceError, match="originator_iid must be 8 bytes"):
            AnnounceMessage(
                originator_iid=bytes(7),  # Too short
                pubkey=bytes(32),
                seq_num=0,
            )

        with pytest.raises(AnnounceError, match="originator_iid must be 8 bytes"):
            AnnounceMessage(
                originator_iid=bytes(9),  # Too long
                pubkey=bytes(32),
                seq_num=0,
            )

    def test_rejects_wrong_pubkey_length(self):
        """Pubkey must be exactly 32 bytes."""
        # Why test: Ed25519 pubkeys are 32 bytes. Wrong length = crypto failure.
        with pytest.raises(AnnounceError, match="pubkey must be 32 bytes"):
            AnnounceMessage(
                originator_iid=bytes(8),
                pubkey=bytes(31),
                seq_num=0,
            )

    def test_rejects_seq_num_out_of_range(self):
        """seq_num must fit in 16 bits."""
        # Why test: Wire format uses 2 bytes. Overflow = wrong seq on wire.
        with pytest.raises(AnnounceError, match="seq_num out of range"):
            AnnounceMessage(
                originator_iid=bytes(8),
                pubkey=bytes(32),
                seq_num=0x10000,  # Too large
            )

        with pytest.raises(AnnounceError, match="seq_num out of range"):
            AnnounceMessage(
                originator_iid=bytes(8),
                pubkey=bytes(32),
                seq_num=-1,  # Negative
            )

    def test_rejects_hop_count_out_of_range(self):
        """hop_count must fit in 8 bits."""
        # Why test: Wire format uses 1 byte. Overflow = wrong hop on wire.
        with pytest.raises(AnnounceError, match="hop_count out of range"):
            AnnounceMessage(
                originator_iid=bytes(8),
                pubkey=bytes(32),
                seq_num=0,
                hop_count=256,
            )

    def test_rejects_wrong_signature_length(self):
        """Signature must be 0 (unsigned) or 48 bytes (signed)."""
        # Why test: Schnorr48 signatures are exactly 48 bytes.
        with pytest.raises(AnnounceError, match="signature must be 0 or 48"):
            AnnounceMessage(
                originator_iid=bytes(8),
                pubkey=bytes(32),
                seq_num=0,
                signature=bytes(47),  # Wrong length
            )

    def test_allows_empty_signature_for_construction(self):
        """Empty signature allowed during construction (before signing)."""
        # Why test: Caller builds message, computes signed_data(), then signs.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            signature=b"",  # Empty = not yet signed
        )
        assert msg.signature == b""


class TestSignedData:
    """Tests for signed_data() method."""

    def test_signed_data_includes_iid(self):
        """signed_data() includes originator_iid."""
        # Why test: IID in signed data prevents announce forgery for others.
        iid = bytes([1, 2, 3, 4, 5, 6, 7, 8])
        msg = AnnounceMessage(
            originator_iid=iid,
            pubkey=bytes(32),
            seq_num=0,
        )
        assert msg.signed_data().startswith(iid)

    def test_signed_data_includes_pubkey(self):
        """signed_data() includes pubkey."""
        # Why test: Pubkey binding is part of TOFU security model.
        pubkey = bytes([0xAB] * 32)
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=pubkey,
            seq_num=0,
        )
        assert pubkey in msg.signed_data()

    def test_signed_data_includes_seq_num(self):
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0x1234,
        )
        signed = msg.signed_data()
        assert signed[40:42] == bytes([0x12, 0x34])

    def test_signed_data_includes_current_channel_at_offset(self):
        msg = AnnounceMessage(
            originator_iid=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            pubkey=b"\x00" * 32,
            seq_num=0x1234,
            current_channel=5,
        )
        signed = msg.signed_data()
        expected = (
            b"\x01\x02\x03\x04\x05\x06\x07\x08"
            + b"\x00" * 32
            + b"\x12\x34"
            + b"\x05"
        )
        assert signed == expected
        assert signed[42] == 5

    def test_signed_data_includes_app_data(self):
        app_data = b"capabilities:sensor,relay"
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            app_data=app_data,
        )
        assert msg.signed_data().endswith(app_data)

    def test_signed_data_excludes_hop_count(self):
        """signed_data() does NOT include hop_count."""
        # Why test: Relays must increment hop_count without breaking signature.
        msg1 = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=0,
        )
        msg2 = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=10,
        )
        # Same signed_data despite different hop_count
        assert msg1.signed_data() == msg2.signed_data()

    def test_signed_data_is_deterministic(self):
        msg1 = AnnounceMessage(
            originator_iid=bytes([1] * 8),
            pubkey=bytes([2] * 32),
            seq_num=100,
            app_data=b"test",
        )
        msg2 = AnnounceMessage(
            originator_iid=bytes([1] * 8),
            pubkey=bytes([2] * 32),
            seq_num=100,
            app_data=b"test",
        )
        assert msg1.signed_data() == msg2.signed_data()

    def test_signed_data_includes_current_channel(self):
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            current_channel=5,
        )
        signed = msg.signed_data()
        assert signed[42:43] == bytes([5])


class TestSerialization:
    """Tests for to_bytes() and from_bytes() round-trip."""

    def test_round_trip_minimal(self):
        """Minimal announce survives serialization round-trip."""
        # Why test: Basic codec correctness.
        original = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=0,
            signature=bytes(SIGNATURE_LENGTH),
        )
        wire = original.to_bytes()
        parsed = AnnounceMessage.from_bytes(wire)

        assert parsed.originator_iid == original.originator_iid
        assert parsed.pubkey == original.pubkey
        assert parsed.seq_num == original.seq_num
        assert parsed.hop_count == original.hop_count
        assert parsed.signature == original.signature
        assert parsed.app_data == original.app_data
        assert parsed.flags == original.flags

    def test_round_trip_with_app_data(self):
        """Announce with app_data survives round-trip."""
        # Why test: Variable-length app_data must be preserved.
        original = AnnounceMessage(
            originator_iid=bytes([0x11] * 8),
            pubkey=bytes([0x22] * 32),
            seq_num=12345,
            hop_count=5,
            signature=bytes([0x33] * SIGNATURE_LENGTH),
            app_data=b"node-name:bob;caps:relay,sensor",
        )
        parsed = AnnounceMessage.from_bytes(original.to_bytes())

        assert parsed.app_data == original.app_data

    def test_wire_format_type_byte(self):
        """Wire format starts with ANNOUNCE_TYPE."""
        # Why test: Type byte identifies the message type on the wire.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            signature=bytes(SIGNATURE_LENGTH),
        )
        wire = msg.to_bytes()
        assert wire[0] == ANNOUNCE_TYPE

    def test_wire_format_hop_count_position(self):
        """Hop count is at byte offset 2."""
        # Why test: Relays may want to read hop_count before full parse.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=7,
            signature=bytes(SIGNATURE_LENGTH),
        )
        wire = msg.to_bytes()
        assert wire[2] == 7

    def test_wire_format_seq_num_big_endian(self):
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0xABCD,
            signature=bytes(SIGNATURE_LENGTH),
            current_channel=0,
        )
        wire = msg.to_bytes()
        assert wire[3:5] == bytes([0xAB, 0xCD])

    def test_to_bytes_rejects_unsigned(self):
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            signature=b"",
            current_channel=0,
        )
        with pytest.raises(AnnounceError, match="cannot serialize unsigned"):
            msg.to_bytes()

    def test_from_bytes_rejects_truncated(self):
        """Rejects data shorter than fixed portion."""
        with pytest.raises(AnnounceError, match="too short"):
            AnnounceMessage.from_bytes(bytes(50))

    def test_from_bytes_rejects_wrong_type(self):
        """Rejects messages with wrong type byte."""
        wire = bytes([0xFF]) + bytes(92)
        with pytest.raises(AnnounceError, match="wrong message type"):
            AnnounceMessage.from_bytes(wire)


class TestHopCount:
    """Tests for hop count management."""

    def test_with_incremented_hop_count(self):
        """with_incremented_hop_count() returns new message with hop+1."""
        # Why test: Relays must increment hop count before forwarding.
        original = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=5,
            signature=bytes(SIGNATURE_LENGTH),
        )
        incremented = original.with_incremented_hop_count()

        assert incremented.hop_count == 6
        # Original unchanged
        assert original.hop_count == 5
        # Other fields preserved
        assert incremented.originator_iid == original.originator_iid
        assert incremented.signature == original.signature

    def test_with_incremented_rejects_at_max(self):
        """Cannot increment beyond MAX_ANNOUNCE_HOPS."""
        # Why test: Prevents infinite flooding in the mesh.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=MAX_ANNOUNCE_HOPS,
            signature=bytes(SIGNATURE_LENGTH),
        )
        with pytest.raises(AnnounceError, match="would exceed MAX_ANNOUNCE_HOPS"):
            msg.with_incremented_hop_count()

    def test_should_relay_true_below_max(self):
        """should_relay() returns True when hop_count < MAX."""
        # Why test: Messages below limit should propagate.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=MAX_ANNOUNCE_HOPS - 1,
            signature=bytes(SIGNATURE_LENGTH),
        )
        assert msg.should_relay() is True

    def test_should_relay_false_at_max(self):
        """should_relay() returns False when hop_count == MAX."""
        # Why test: Messages at limit should not be forwarded.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=MAX_ANNOUNCE_HOPS,
            signature=bytes(SIGNATURE_LENGTH),
        )
        assert msg.should_relay() is False

    def test_should_relay_false_above_max(self):
        """should_relay() returns False when hop_count > MAX."""
        # Why test: Messages somehow above limit should definitely not relay.
        # This shouldn't happen in practice but defensive check is good.
        msg = AnnounceMessage(
            originator_iid=bytes(8),
            pubkey=bytes(32),
            seq_num=0,
            hop_count=MAX_ANNOUNCE_HOPS + 1,
            signature=bytes(SIGNATURE_LENGTH),
        )
        assert msg.should_relay() is False


class TestKnownVectors:
    def test_known_wire_format(self):
        msg = AnnounceMessage(
            originator_iid=bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            pubkey=bytes([0xAA] * 32),
            seq_num=0x1234,
            hop_count=3,
            flags=7,
            signature=bytes([0xBB] * SIGNATURE_LENGTH),
            app_data=b"",
            current_channel=7,
        )
        wire = msg.to_bytes()

        assert wire[0] == ANNOUNCE_TYPE
        assert wire[1] == 7
        assert wire[2] == 3
        assert wire[3:5] == bytes([0x12, 0x34])
        assert wire[5:13] == bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        assert wire[13:45] == bytes([0xAA] * 32)
        assert wire[45:93] == bytes([0xBB] * SIGNATURE_LENGTH)
        assert len(wire) == 93
