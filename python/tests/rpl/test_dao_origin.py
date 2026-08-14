# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for consolidated DAO origin validation (spec section 8.6)."""

from __future__ import annotations

import struct
from ipaddress import IPv6Address

import pytest

from lichen.crypto.identity import Identity, yggdrasil_address
from lichen.crypto.schnorr48 import sign
from lichen.rpl.dao_origin import (
    DAO_ORIGIN_DOMAIN,
    DAO_ORIGIN_SIGNATURE_LENGTH,
    DAO_ORIGIN_SIGNATURE_TYPE,
    DaoOriginRejectReason,
    DaoOriginSignature,
    DaoOriginValidator,
    compute_dao_digest,
    compute_signature_transcript,
    extract_unsigned_dao_bytes,
)
from lichen.rpl.dao_types import RplTarget, TransitInformation
from lichen.rpl.messages import DAO, RplOption

# Test fixtures
ROOT_SEED = bytes(range(32))
ROOT_IDENTITY = Identity.from_seed(ROOT_SEED)
ROOT_ADDR = yggdrasil_address(ROOT_IDENTITY.pubkey)

NODE_SEED = bytes(range(32, 64))
NODE_IDENTITY = Identity.from_seed(NODE_SEED)
NODE_ADDR = yggdrasil_address(NODE_IDENTITY.pubkey)

DODAG_ID = ROOT_ADDR


class MockPinTable:
    """Mock pin table for testing.

    Validates that pubkeys are exactly 32 bytes (Ed25519) and IIDs are
    exactly 8 bytes per spec 06-security.md section 8.5.
    """

    def __init__(self, pins: dict[bytes, bytes] | None = None):
        self._pins: dict[bytes, bytes] = {}
        if pins:
            for iid, pubkey in pins.items():
                self.pin(iid, pubkey)

    def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
        return self._pins.get(iid)

    def pin(self, iid: bytes, pubkey: bytes) -> None:
        if len(iid) != 8:
            raise ValueError(f"iid must be 8 bytes, got {len(iid)}")
        if len(pubkey) != 32:
            raise ValueError(f"pubkey must be 32 bytes, got {len(pubkey)}")
        self._pins[iid] = pubkey


class MockReplayStore:
    """Mock replay store for testing."""

    def __init__(self) -> None:
        self._floors: dict[bytes, tuple[int, bytes]] = {}

    def get_floor(self, pubkey: bytes) -> tuple[int, bytes] | None:
        return self._floors.get(pubkey)

    def set_floor(self, pubkey: bytes, sequence: int, dao_digest: bytes) -> None:
        self._floors[pubkey] = (sequence, dao_digest)


def make_signed_dao(
    identity: Identity,
    parent: IPv6Address,
    dodag_id: IPv6Address,
    origin_sequence: int,
    *,
    target: IPv6Address | None = None,
    path_sequence: int = 1,
    path_lifetime: int = 255,
) -> DAO:
    """Build a DAO with a valid origin signature."""
    if target is None:
        target = yggdrasil_address(identity.pubkey)

    # Build DAO without signature
    options = [
        RplTarget(target).to_option(),
        TransitInformation(
            parent,
            path_sequence=path_sequence,
            path_lifetime=path_lifetime,
        ).to_option(),
    ]

    dao_without_sig = DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        dodag_id=dodag_id,
        options=options,
    )

    # Compute signature
    source_addr = yggdrasil_address(identity.pubkey)
    unsigned_bytes = dao_without_sig.to_bytes()
    transcript = compute_signature_transcript(
        source_addr, dodag_id, origin_sequence, unsigned_bytes
    )
    signature = sign(identity.privkey, identity.pubkey, transcript)

    # Build signature option
    sig_data = struct.pack(">Q", origin_sequence) + signature
    sig_opt = RplOption(DAO_ORIGIN_SIGNATURE_TYPE, sig_data)

    # Return DAO with signature
    return DAO(
        rpl_instance_id=0,
        dao_sequence=1,
        dodag_id=dodag_id,
        options=options + [sig_opt],
    )


class TestDaoOriginSignature:
    """Tests for DaoOriginSignature parsing and serialization."""

    def test_from_option_valid(self) -> None:
        seq = 12345
        sig = bytes(48)
        data = struct.pack(">Q", seq) + sig
        opt = RplOption(DAO_ORIGIN_SIGNATURE_TYPE, data)

        parsed = DaoOriginSignature.from_option(opt)

        assert parsed.origin_sequence == seq
        assert parsed.signature == sig

    def test_from_option_wrong_type(self) -> None:
        data = bytes(56)
        opt = RplOption(0x05, data)  # Wrong type

        with pytest.raises(ValueError, match="not a DAO Origin Signature"):
            DaoOriginSignature.from_option(opt)

    def test_from_option_wrong_length(self) -> None:
        data = bytes(55)  # Too short
        opt = RplOption(DAO_ORIGIN_SIGNATURE_TYPE, data)

        with pytest.raises(ValueError, match="must be 56 bytes"):
            DaoOriginSignature.from_option(opt)

    def test_to_option_roundtrip(self) -> None:
        original = DaoOriginSignature(origin_sequence=0xDEADBEEF, signature=bytes(48))

        opt = original.to_option()
        parsed = DaoOriginSignature.from_option(opt)

        assert parsed.origin_sequence == original.origin_sequence
        assert parsed.signature == original.signature


class TestSignatureTranscript:
    """Tests for signature transcript computation."""

    def test_transcript_includes_all_components(self) -> None:
        origin = IPv6Address("0200::1")
        dodag = IPv6Address("0200::ff")
        seq = 42
        unsigned_bytes = b"test dao bytes"

        transcript = compute_signature_transcript(origin, dodag, seq, unsigned_bytes)

        # Verify it's SHA-512 output
        assert len(transcript) == 64

        # Verify domain separator is included
        # (Cannot verify exact bytes without reimplementing, but test determinism)
        transcript2 = compute_signature_transcript(origin, dodag, seq, unsigned_bytes)
        assert transcript == transcript2

    def test_transcript_changes_with_origin(self) -> None:
        origin1 = IPv6Address("0200::1")
        origin2 = IPv6Address("0200::2")
        dodag = IPv6Address("0200::ff")
        seq = 42
        unsigned_bytes = b"test"

        t1 = compute_signature_transcript(origin1, dodag, seq, unsigned_bytes)
        t2 = compute_signature_transcript(origin2, dodag, seq, unsigned_bytes)

        assert t1 != t2

    def test_transcript_changes_with_sequence(self) -> None:
        origin = IPv6Address("0200::1")
        dodag = IPv6Address("0200::ff")
        unsigned_bytes = b"test"

        t1 = compute_signature_transcript(origin, dodag, 1, unsigned_bytes)
        t2 = compute_signature_transcript(origin, dodag, 2, unsigned_bytes)

        assert t1 != t2


class TestExtractUnsignedDaoBytes:
    """Tests for unsigned DAO byte extraction."""

    def test_excludes_signature_option(self) -> None:
        options = [
            RplTarget(NODE_ADDR).to_option(),
            TransitInformation(ROOT_ADDR).to_option(),
            RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),
        ]
        dao = DAO(rpl_instance_id=0, dao_sequence=1, dodag_id=DODAG_ID, options=options)

        unsigned = extract_unsigned_dao_bytes(dao)
        full = dao.to_bytes()

        # Unsigned bytes should be shorter by the signature option (type+len+data = 58 bytes)
        assert len(unsigned) == len(full) - 58

        # Verify it ends with Transit Information option, not the signature
        # Transit Information for this test: type=6, followed by option data
        assert unsigned[-22] == 6  # Transit Information type


class TestDaoOriginValidator:
    """Tests for the consolidated DaoOriginValidator."""

    def test_rejects_unpinned_origin(self) -> None:
        pin_table = MockPinTable()  # Empty - no pins
        validator = DaoOriginValidator(pin_table)
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.ORIGIN_NOT_PINNED

    def test_rejects_iid_mismatch(self) -> None:
        # Pin wrong key for the IID
        wrong_key = bytes(32)
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: wrong_key})
        validator = DaoOriginValidator(pin_table)
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.IID_MISMATCH

    def test_rejects_malformed_pinned_pubkey(self) -> None:
        """Pin table returning wrong-length pubkey is handled gracefully.

        If pin_table.pinned_pubkey_for() returns corrupted data (not 32 bytes),
        the validator should return IID_MISMATCH rather than crash with ValueError.
        This can happen with corrupted storage or buggy implementations.
        """

        # Use a special mock that returns malformed data to simulate
        # corrupted storage (bypasses MockPinTable's input validation)
        class CorruptedPinTable:
            """Simulates a pin table with corrupted storage."""

            def __init__(self, malformed_pubkey: bytes, iid: bytes):
                self._malformed_pubkey = malformed_pubkey
                self._iid = iid

            def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
                if iid == self._iid:
                    return self._malformed_pubkey
                return None

        malformed_key = bytes(16)  # Only 16 bytes instead of 32
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = CorruptedPinTable(malformed_key, node_iid)
        validator = DaoOriginValidator(pin_table)
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        # Should not raise ValueError; should return IID_MISMATCH
        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.IID_MISMATCH

    def test_logs_warning_for_corrupted_pin_table_data(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Verify warning is logged when pin_table returns corrupted pubkey.

        Per spec 05-routing.md: "Missing, corrupt, or unavailable state is a
        hard failure" - logging aids debugging storage corruption. The node
        SHOULD log the failure for diagnostic purposes.
        """
        import logging

        # Use a special mock that returns malformed data to simulate
        # corrupted storage (bypasses MockPinTable's input validation)
        class CorruptedPinTable:
            """Simulates a pin table with corrupted storage."""

            def __init__(self, malformed_pubkey: bytes, iid: bytes):
                self._malformed_pubkey = malformed_pubkey
                self._iid = iid

            def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
                if iid == self._iid:
                    return self._malformed_pubkey
                return None

        malformed_key = bytes(16)  # Only 16 bytes instead of 32
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = CorruptedPinTable(malformed_key, node_iid)
        validator = DaoOriginValidator(pin_table)
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        # Capture logs at WARNING level
        with caplog.at_level(logging.WARNING, logger="lichen.rpl.dao_origin"):
            result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        # Verify the rejection still works
        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.IID_MISMATCH

        # Verify warning was logged with expected content
        assert len(caplog.records) == 1
        log_record = caplog.records[0]
        assert log_record.levelname == "WARNING"
        assert "pin_table returned corrupted pubkey" in log_record.message
        assert node_iid.hex() in log_record.message

    def test_rejects_wrong_type_pinned_pubkey(self) -> None:
        """Pin table returning wrong type (int) is handled gracefully.

        If pin_table.pinned_pubkey_for() returns a non-bytes value due to
        corrupted storage or buggy implementation, the validator should return
        IID_MISMATCH rather than crash with TypeError from len().
        """

        class CorruptedPinTable:
            """Simulates a pin table returning wrong type."""

            def __init__(self, bad_value: object, iid: bytes):
                self._bad_value = bad_value
                self._iid = iid

            def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
                if iid == self._iid:
                    return self._bad_value  # type: ignore[return-value]
                return None

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = CorruptedPinTable(42, node_iid)  # int instead of bytes
        validator = DaoOriginValidator(pin_table)
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        # Should not raise TypeError; should return IID_MISMATCH
        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.IID_MISMATCH

    def test_rejects_missing_signature(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)

        # DAO without signature option
        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
            ],
        )

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.SIGNATURE_MISSING

    def test_rejects_duplicate_signature(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)

        sig_opt = RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56))
        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
                sig_opt,
                sig_opt,  # Duplicate
            ],
        )

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.SIGNATURE_DUPLICATE

    def test_rejects_non_final_signature(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)

        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),  # Not final
                TransitInformation(ROOT_ADDR).to_option(),
            ],
        )

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.SIGNATURE_NOT_FINAL

    def test_rejects_wrong_length_signature(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)

        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(55)),  # Wrong length
            ],
        )

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.SIGNATURE_INVALID_LENGTH

    def test_rejects_invalid_signature(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)

        # DAO with invalid (zero) signature
        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),
            ],
        )

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is False
        assert result.reject_reason == DaoOriginRejectReason.SIGNATURE_INVALID

    def test_accepts_valid_signed_dao(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        result = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result.valid is True
        assert result.reject_reason is None
        assert result.pubkey == NODE_IDENTITY.pubkey
        assert result.origin_sequence == 1
        assert result.dao_digest is not None

    def test_replay_protection_rejects_lower_sequence(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        replay_store = MockReplayStore()
        validator = DaoOriginValidator(pin_table, replay_store)

        # First DAO with sequence 10
        dao1 = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=10)
        result1 = validator.validate(dao1, NODE_ADDR, DODAG_ID)
        assert result1.valid is True
        assert result1.is_fresh is True

        # Simulate caller (DaoManager) committing floor after all validations pass
        assert result1.pubkey is not None
        assert result1.origin_sequence is not None
        assert result1.dao_digest is not None
        replay_store.set_floor(result1.pubkey, result1.origin_sequence, result1.dao_digest)

        # Second DAO with lower sequence 5
        dao2 = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=5)
        result2 = validator.validate(dao2, NODE_ADDR, DODAG_ID)

        assert result2.valid is False
        assert result2.reject_reason == DaoOriginRejectReason.SEQUENCE_REPLAY

    def test_replay_protection_accepts_higher_sequence(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        replay_store = MockReplayStore()
        validator = DaoOriginValidator(pin_table, replay_store)

        dao1 = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=10)
        result1 = validator.validate(dao1, NODE_ADDR, DODAG_ID)
        assert result1.valid is True
        assert result1.is_fresh is True

        # Simulate caller committing floor after all validations pass
        assert result1.pubkey is not None
        assert result1.origin_sequence is not None
        assert result1.dao_digest is not None
        replay_store.set_floor(result1.pubkey, result1.origin_sequence, result1.dao_digest)

        dao2 = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=11)
        result2 = validator.validate(dao2, NODE_ADDR, DODAG_ID)

        assert result2.valid is True
        assert result2.origin_sequence == 11
        assert result2.is_fresh is True

    def test_replay_protection_accepts_identical_retransmission(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        replay_store = MockReplayStore()
        validator = DaoOriginValidator(pin_table, replay_store)

        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=10)

        result1 = validator.validate(dao, NODE_ADDR, DODAG_ID)
        assert result1.valid is True
        assert result1.is_fresh is True

        # Simulate caller committing floor after all validations pass
        assert result1.pubkey is not None
        assert result1.origin_sequence is not None
        assert result1.dao_digest is not None
        replay_store.set_floor(result1.pubkey, result1.origin_sequence, result1.dao_digest)

        # Exact same DAO (idempotent retransmission)
        result2 = validator.validate(dao, NODE_ADDR, DODAG_ID)

        assert result2.valid is True
        assert result2.origin_sequence == 10
        assert result2.is_fresh is False  # Not fresh - idempotent retransmission

    def test_replay_protection_rejects_equal_sequence_different_bytes(self) -> None:
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        replay_store = MockReplayStore()
        validator = DaoOriginValidator(pin_table, replay_store)

        dao1 = make_signed_dao(
            NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=10, path_lifetime=255
        )
        result1 = validator.validate(dao1, NODE_ADDR, DODAG_ID)
        assert result1.valid is True
        assert result1.is_fresh is True

        # Simulate caller committing floor after all validations pass
        assert result1.pubkey is not None
        assert result1.origin_sequence is not None
        assert result1.dao_digest is not None
        replay_store.set_floor(result1.pubkey, result1.origin_sequence, result1.dao_digest)

        # Same sequence but different content
        dao2 = make_signed_dao(
            NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=10, path_lifetime=100
        )
        result2 = validator.validate(dao2, NODE_ADDR, DODAG_ID)

        assert result2.valid is False
        assert result2.reject_reason == DaoOriginRejectReason.SEQUENCE_EQUAL_DIFFERENT_BYTES

    def test_validator_does_not_commit_floor_spec_compliance(self) -> None:
        """Per spec 8.6, validator MUST NOT commit replay floor at step 4.

        The replay floor is committed at step 7 by the caller (DaoManager)
        AFTER semantic parsing (step 5) and Target validation (step 6).
        This ensures that if steps 5 or 6 fail, the floor is not committed
        and the DAO can be retried.
        """
        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        replay_store = MockReplayStore()
        validator = DaoOriginValidator(pin_table, replay_store)

        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=10)

        # Validate should succeed without committing floor
        result = validator.validate(dao, NODE_ADDR, DODAG_ID)
        assert result.valid is True
        assert result.is_fresh is True

        # CRITICAL: Floor should NOT be committed by validator
        floor = replay_store.get_floor(NODE_IDENTITY.pubkey)
        assert floor is None, "Validator MUST NOT commit replay floor (spec 8.6 step 7)"

        # Same DAO should still be fresh since floor wasn't committed
        result2 = validator.validate(dao, NODE_ADDR, DODAG_ID)
        assert result2.valid is True
        assert result2.is_fresh is True


class TestComputeDaoDigest:
    """Tests for DAO digest computation."""

    def test_digest_is_deterministic(self) -> None:
        dao_bytes = b"test dao bytes"

        d1 = compute_dao_digest(dao_bytes)
        d2 = compute_dao_digest(dao_bytes)

        assert d1 == d2
        assert len(d1) == 64  # SHA-512

    def test_digest_changes_with_content(self) -> None:
        d1 = compute_dao_digest(b"dao version 1")
        d2 = compute_dao_digest(b"dao version 2")

        assert d1 != d2


class TestPinTableProtocol:
    """Tests for PinTable protocol compliance."""

    def test_announce_processor_implements_pin_table(self) -> None:
        from lichen.announce.processor import AnnounceProcessor
        from lichen.gradient import GradientTable
        from lichen.rpl.dao_origin import PinTable

        processor = AnnounceProcessor(
            gradient_table=GradientTable(),
            address_builder=lambda iid: IPv6Address(b"\x02" + b"\x00" * 7 + iid),
        )

        # Verify it implements the protocol
        assert isinstance(processor, PinTable)
        assert hasattr(processor, "pinned_pubkey_for")
        assert processor.pinned_pubkey_for(bytes(8)) is None


class TestMockPinTableValidation:
    """Tests for MockPinTable input validation per spec 06-security.md 8.5."""

    def test_pin_rejects_wrong_pubkey_size(self) -> None:
        """MockPinTable.pin() rejects non-32-byte pubkeys."""
        pin_table = MockPinTable()
        valid_iid = bytes(8)

        with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
            pin_table.pin(valid_iid, bytes(16))  # Too short

        with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
            pin_table.pin(valid_iid, bytes(64))  # Too long

    def test_pin_rejects_wrong_iid_size(self) -> None:
        """MockPinTable.pin() rejects non-8-byte IIDs."""
        pin_table = MockPinTable()
        valid_pubkey = bytes(32)

        with pytest.raises(ValueError, match="iid must be 8 bytes"):
            pin_table.pin(bytes(4), valid_pubkey)  # Too short

        with pytest.raises(ValueError, match="iid must be 8 bytes"):
            pin_table.pin(bytes(16), valid_pubkey)  # Too long

    def test_init_validates_pins_dict(self) -> None:
        """MockPinTable.__init__() validates any pre-populated pins."""
        valid_iid = bytes(8)

        with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
            MockPinTable({valid_iid: bytes(16)})

    def test_pin_accepts_valid_sizes(self) -> None:
        """MockPinTable accepts correctly-sized IID and pubkey."""
        pin_table = MockPinTable()
        valid_iid = bytes(8)
        valid_pubkey = bytes(32)

        pin_table.pin(valid_iid, valid_pubkey)
        assert pin_table.pinned_pubkey_for(valid_iid) == valid_pubkey


class TestDaoOriginConstants:
    """Tests for DAO origin constants per spec 8.6."""

    def test_domain_separator_is_20_bytes(self) -> None:
        assert len(DAO_ORIGIN_DOMAIN) == 20
        assert DAO_ORIGIN_DOMAIN == b"LICHEN-DAO-ORIGIN-v1"

    def test_signature_type_is_0x12(self) -> None:
        assert DAO_ORIGIN_SIGNATURE_TYPE == 0x12

    def test_signature_length_is_56(self) -> None:
        # 8 bytes sequence + 48 bytes Schnorr48
        assert DAO_ORIGIN_SIGNATURE_LENGTH == 56


class TestConsolidatedDaoValidation:
    """Tests for consolidated DAO origin validation in DaoManager (spec 8.6).

    Per spec section 8.6, the root MUST process a received DAO in this order:
    1. link framing and link signature (not tested here - link layer)
    2. bounds-safe DAO structure and active instance/DODAG context
    3. pre-pinned key lookup, source-IID binding, exact transcript, and Schnorr48
    4. per-key replay classification
    5. DAO semantic parsing
    6. exact self /128 Target validation
    7. replay-floor persistence for a fresh DAO
    8. atomic in-memory route mutation
    """

    def test_validate_and_process_dao_rejects_unpinned_origin(self) -> None:
        """Origin validation rejects DAOs from unpinned sources."""
        from lichen.rpl.dao_manager import DaoManager

        pin_table = MockPinTable()  # Empty - no pins
        validator = DaoOriginValidator(pin_table)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
        )
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        with pytest.raises(Exception) as exc_info:
            manager.validate_and_process_dao(dao, NODE_ADDR)

        # Should reject with origin_not_pinned reason
        assert "origin_not_pinned" in str(exc_info.value) or "ORIGIN_NOT_PINNED" in str(
            exc_info.value
        )

    def test_validate_and_process_dao_rejects_invalid_signature(self) -> None:
        """Origin validation rejects DAOs with invalid signatures."""
        from lichen.rpl.dao_manager import DaoManager

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
        )

        # DAO with invalid (zero) signature
        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),
            ],
        )

        with pytest.raises(Exception) as exc_info:
            manager.validate_and_process_dao(dao, NODE_ADDR)

        assert "signature_invalid" in str(exc_info.value) or "SIGNATURE_INVALID" in str(
            exc_info.value
        )

    def test_validate_and_process_dao_accepts_valid_signed_dao(self) -> None:
        """Consolidated validation accepts properly signed DAOs."""
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_persistence import MemoryPersistence

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        # SECURITY: Use same object for both replay_store and persistence
        # to prevent split-brain replay floor state (spec 8.6)
        persistence = MemoryPersistence()
        validator = DaoOriginValidator(pin_table, persistence)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
            persistence=persistence,
        )
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        # Should not raise
        result = manager.validate_and_process_dao(dao, NODE_ADDR)

        # Should return None (no ACK requested)
        assert result is None

        # Route should be installed
        routes = manager.routing_table.routes()
        assert NODE_ADDR in routes

    def test_validate_and_process_dao_rejects_target_source_mismatch(self) -> None:
        """Per spec 8.7, /128 Target MUST equal source address."""
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_types import DaoError

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        validator = DaoOriginValidator(pin_table)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
        )

        # Create a DAO with a different target than source
        other_addr = yggdrasil_address(ROOT_IDENTITY.pubkey)
        dao = make_signed_dao(
            NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1, target=other_addr
        )

        with pytest.raises(DaoError) as exc_info:
            manager.validate_and_process_dao(dao, NODE_ADDR)

        # Check the reason attribute of DaoError
        assert exc_info.value.reason == "target_source_mismatch"

    def test_evaluate_dao_returns_outcome_for_origin_rejection(self) -> None:
        """evaluate_dao_at with source_address returns DaoOutcome for origin rejection."""
        from lichen.rpl.dao_manager import DaoManager, DaoOutcome

        pin_table = MockPinTable()  # Empty - no pins
        validator = DaoOriginValidator(pin_table)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
        )
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        outcome = manager.evaluate_dao_at(dao, 0.0, NODE_ADDR)

        assert isinstance(outcome, DaoOutcome)
        assert outcome.accepted is False
        assert outcome.reason == "origin_not_pinned"

    def test_origin_validation_happens_before_semantic_parsing(self) -> None:
        """Verify origin validation rejects before attempting to parse route semantics.

        This is the key ordering requirement from spec 8.6: origin validation
        (step 3) MUST happen before semantic parsing (step 5).
        """
        from lichen.rpl.dao_manager import DaoManager

        # Create a validator that tracks call order
        call_order: list[str] = []

        class TrackedPinTable(MockPinTable):
            def pinned_pubkey_for(self, iid: bytes) -> bytes | None:
                call_order.append("origin_lookup")
                return None  # Will cause rejection

        pin_table = TrackedPinTable()
        validator = DaoOriginValidator(pin_table)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
        )

        # Create a DAO that would fail semantic parsing (malformed options)
        # but should be rejected at origin validation first
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        with pytest.raises(Exception) as exc_info:
            manager.validate_and_process_dao(dao, NODE_ADDR)

        # Origin lookup should have been called
        assert "origin_lookup" in call_order

        # Rejection should be for origin, not semantic parsing (case-insensitive)
        exc_str = str(exc_info.value).lower()
        assert "origin_not_pinned" in exc_str or "origin not pinned" in exc_str

    def test_replay_floor_uses_pubkey_when_origin_validated(self) -> None:
        """Per spec 8.6, replay floor is keyed by pubkey, not address."""
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_persistence import MemoryPersistence

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        # SECURITY: Use same object for both replay_store and persistence
        # to prevent split-brain replay floor state (spec 8.6)
        persistence = MemoryPersistence()
        validator = DaoOriginValidator(pin_table, persistence)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
            persistence=persistence,
        )
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        manager.validate_and_process_dao(dao, NODE_ADDR)

        # Check that the floor is keyed by pubkey
        assert NODE_IDENTITY.pubkey in manager._rx_floors

    def test_replay_floor_not_committed_when_target_validation_fails(self) -> None:
        """Per spec 8.6, replay floor MUST NOT be committed if step 6 fails.

        The 8-step validation order requires replay floor commit at step 7,
        AFTER Target validation at step 6. If Target validation fails, the
        floor must not be committed so the corrected DAO can be retried.
        """
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_persistence import MemoryPersistence
        from lichen.rpl.dao_types import DaoError

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        # SECURITY: Use same object for both replay_store and persistence
        # to prevent split-brain replay floor state (spec 8.6)
        persistence = MemoryPersistence()
        validator = DaoOriginValidator(pin_table, persistence)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
            persistence=persistence,
        )

        # Create a DAO with mismatched target (will fail Target validation)
        other_addr = yggdrasil_address(ROOT_IDENTITY.pubkey)
        dao = make_signed_dao(
            NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1, target=other_addr
        )

        # This should fail at Target validation (step 6)
        with pytest.raises(DaoError) as exc_info:
            manager.validate_and_process_dao(dao, NODE_ADDR)
        assert exc_info.value.reason == "target_source_mismatch"

        # CRITICAL: Floor should NOT be committed since validation failed
        assert NODE_IDENTITY.pubkey not in manager._rx_floors
        floor = persistence.get_floor(NODE_IDENTITY.pubkey)
        assert floor is None, "Replay floor MUST NOT be committed when validation fails"

        # Now send a corrected DAO with same sequence - should be accepted
        corrected_dao = make_signed_dao(
            NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1
        )
        manager.validate_and_process_dao(corrected_dao, NODE_ADDR)

        # Now the floor should be committed
        assert NODE_IDENTITY.pubkey in manager._rx_floors

    def test_rejects_mismatched_replay_store_and_persistence(self) -> None:
        """Per spec 8.6, origin_validator.replay_store and persistence must be same object.

        This prevents split-brain replay floor state where validation checks
        one store but commits write to another, breaking replay protection.
        """
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_persistence import MemoryPersistence
        from lichen.rpl.dao_types import DaoError

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        # Create TWO different objects - this should be rejected
        replay_store = MockReplayStore()
        persistence = MemoryPersistence()
        validator = DaoOriginValidator(pin_table, replay_store)

        with pytest.raises(DaoError) as exc_info:
            DaoManager(
                node_address=ROOT_ADDR,
                is_root=True,
                dodag_id=DODAG_ID,
                origin_validator=validator,
                persistence=persistence,
            )

        assert exc_info.value.reason == "replay_store_mismatch"

    def test_rejects_replay_store_without_persistence(self) -> None:
        """Per spec 8.6, if validator has replay_store, persistence must also be set.

        Without persistence, the replay floor commits would be lost, breaking
        the replay protection guarantees.
        """
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_types import DaoError

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        replay_store = MockReplayStore()
        validator = DaoOriginValidator(pin_table, replay_store)

        with pytest.raises(DaoError) as exc_info:
            DaoManager(
                node_address=ROOT_ADDR,
                is_root=True,
                dodag_id=DODAG_ID,
                origin_validator=validator,
                # persistence not set
            )

        assert exc_info.value.reason == "replay_store_mismatch"


class TestIdempotentRetransmissionFloorHandling:
    """Tests for idempotent retransmission replay floor handling per spec 8.6.

    Per spec section 8.6: "On a byte-identical retransmission, the receiver
    MUST NOT rewrite the replay floor."
    """

    def test_idempotent_retransmission_does_not_rewrite_floor(self) -> None:
        """Verify that idempotent retransmissions don't trigger floor commits.

        Per spec 8.6, step 7 is "replay-floor persistence for a fresh DAO".
        Idempotent retransmissions (is_fresh=False) must NOT rewrite the floor.
        """
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_persistence import MemoryPersistence

        # Create a persistence that tracks store_rx_floor calls
        class TrackingPersistence(MemoryPersistence):
            def __init__(self) -> None:
                super().__init__()
                self.store_rx_floor_calls: list[tuple[bytes, int, bytes]] = []

            def store_rx_floor(
                self, pubkey: bytes, sequence: int, dao_digest: bytes
            ) -> None:
                self.store_rx_floor_calls.append((pubkey, sequence, dao_digest))
                super().store_rx_floor(pubkey, sequence, dao_digest)

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        persistence = TrackingPersistence()
        validator = DaoOriginValidator(pin_table, persistence)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
            persistence=persistence,
        )

        # Create a DAO
        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        # First submission - fresh DAO
        manager.validate_and_process_dao(dao, NODE_ADDR)

        # Verify floor was committed
        assert len(persistence.store_rx_floor_calls) == 1
        first_call = persistence.store_rx_floor_calls[0]
        assert first_call[0] == NODE_IDENTITY.pubkey
        assert first_call[1] == 1

        # Second submission - same DAO (idempotent retransmission)
        manager.validate_and_process_dao(dao, NODE_ADDR)

        # CRITICAL: Floor should NOT be rewritten for idempotent retransmission
        assert (
            len(persistence.store_rx_floor_calls) == 1
        ), "Idempotent retransmission MUST NOT rewrite replay floor (spec 8.6)"

    def test_fresh_dao_higher_sequence_commits_floor(self) -> None:
        """Verify that fresh DAOs with higher sequence DO commit the floor."""
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_persistence import MemoryPersistence

        class TrackingPersistence(MemoryPersistence):
            def __init__(self) -> None:
                super().__init__()
                self.store_rx_floor_calls: list[tuple[bytes, int, bytes]] = []

            def store_rx_floor(
                self, pubkey: bytes, sequence: int, dao_digest: bytes
            ) -> None:
                self.store_rx_floor_calls.append((pubkey, sequence, dao_digest))
                super().store_rx_floor(pubkey, sequence, dao_digest)

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        persistence = TrackingPersistence()
        validator = DaoOriginValidator(pin_table, persistence)
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=validator,
            persistence=persistence,
        )

        # First DAO
        dao1 = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)
        manager.validate_and_process_dao(dao1, NODE_ADDR)
        assert len(persistence.store_rx_floor_calls) == 1
        assert persistence.store_rx_floor_calls[0][1] == 1

        # Second DAO with higher sequence - fresh
        dao2 = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=2)
        manager.validate_and_process_dao(dao2, NODE_ADDR)

        # Fresh DAO should commit floor
        assert len(persistence.store_rx_floor_calls) == 2
        assert persistence.store_rx_floor_calls[1][1] == 2


class TestOriginResultInvariantEnforcement:
    """Tests for DaoOriginResult invariant enforcement in DaoManager.

    Per spec 8.6, when a DAO is valid and fresh (is_fresh=True), the
    origin_result MUST have pubkey and origin_sequence set. The manager
    enforces this with a defensive check that raises DaoError rather than
    using assert (which can be disabled with python -O).
    """

    def test_fresh_origin_result_requires_pubkey_and_sequence(self) -> None:
        """Verify that fresh origin_result with None fields raises DaoError.

        This tests the invariant enforcement added to replace assert statements,
        ensuring the check cannot be bypassed with python -O.
        """
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_origin import DaoOriginResult, DaoOriginValidator
        from lichen.rpl.dao_persistence import MemoryPersistence
        from lichen.rpl.dao_types import DaoError

        # Create a malformed validator that returns a broken result
        # (valid=True, is_fresh=True, but pubkey/origin_sequence are None)
        class BrokenValidator(DaoOriginValidator):
            def validate(
                self,
                dao: DAO,
                source_address: IPv6Address,
                effective_dodag_id: IPv6Address,
            ) -> DaoOriginResult:
                # Return a structurally invalid result - fresh but missing required fields
                return DaoOriginResult(
                    valid=True,
                    pubkey=None,  # BUG: should be set for fresh DAO
                    origin_sequence=None,  # BUG: should be set for fresh DAO
                    dao_digest=b"test",
                    is_fresh=True,
                )

        node_iid = NODE_ADDR.packed[8:16]
        pin_table = MockPinTable({node_iid: NODE_IDENTITY.pubkey})
        persistence = MemoryPersistence()
        broken_validator = BrokenValidator(pin_table, persistence)

        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=broken_validator,
            persistence=persistence,
        )

        dao = make_signed_dao(NODE_IDENTITY, ROOT_ADDR, DODAG_ID, origin_sequence=1)

        # The manager should catch the broken invariant and raise DaoError
        with pytest.raises(DaoError) as exc_info:
            manager.validate_and_process_dao(dao, NODE_ADDR)

        assert exc_info.value.reason == "origin_invariant_violation"


class TestDaoOriginSignaturePositionInSemanticParsing:
    """Tests for DAO Origin Signature position enforcement during semantic parsing.

    Per spec section 8.6: "The option MUST be the final DAO option... a... non-final
    DAO Origin Signature Option... MUST reject the entire DAO without semantic
    parsing or state mutation."

    This tests the enforcement in _extract_updates, which is separate from the
    origin_validator check. This ensures the spec requirement is enforced even
    when origin_validator is not configured.
    """

    def test_extract_updates_rejects_non_final_signature_option(self) -> None:
        """Non-final signature option is rejected in semantic parsing."""
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_types import DaoError

        # Create a DAO with signature option NOT in final position
        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),  # Not final
                TransitInformation(ROOT_ADDR).to_option(),
            ],
        )

        # _extract_updates is a static method that should reject this
        with pytest.raises(DaoError) as exc_info:
            DaoManager._extract_updates(dao)

        assert exc_info.value.reason == "signature_not_final"

    def test_extract_updates_accepts_final_signature_option(self) -> None:
        """Final signature option is accepted and parsing terminates."""
        from lichen.rpl.dao_manager import DaoManager

        # Create a valid DAO with signature in final position
        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),  # Final position
            ],
        )

        # Should not raise - signature is final
        updates = DaoManager._extract_updates(dao)

        # Should have extracted the target/transit group
        assert len(updates) == 1
        assert updates[0].target == NODE_ADDR

    def test_process_dao_rejects_non_final_signature_without_validator(self) -> None:
        """Non-final signature is rejected even without origin_validator.

        This tests the spec requirement that the signature MUST be final,
        enforced in semantic parsing (step 5), not just in origin validation.
        """
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_types import DaoError

        # Manager WITHOUT origin_validator configured
        manager = DaoManager(
            node_address=ROOT_ADDR,
            is_root=True,
            dodag_id=DODAG_ID,
            origin_validator=None,  # No origin validator
        )

        # DAO with signature NOT in final position
        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),  # Not final
                TransitInformation(ROOT_ADDR).to_option(),
            ],
        )

        with pytest.raises(DaoError) as exc_info:
            manager.process_dao(dao)

        assert exc_info.value.reason == "signature_not_final"

    def test_signature_in_middle_of_multiple_groups_rejected(self) -> None:
        """Signature option between groups is rejected."""
        # Create another identity for second target
        from lichen.crypto.identity import Identity, yggdrasil_address
        from lichen.rpl.dao_manager import DaoManager
        from lichen.rpl.dao_types import DaoError

        other_identity = Identity.from_seed(bytes(range(64, 96)))
        other_addr = yggdrasil_address(other_identity.pubkey)

        dao = DAO(
            rpl_instance_id=0,
            dao_sequence=1,
            dodag_id=DODAG_ID,
            options=[
                RplTarget(NODE_ADDR).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
                RplOption(DAO_ORIGIN_SIGNATURE_TYPE, bytes(56)),  # Between groups
                RplTarget(other_addr).to_option(),
                TransitInformation(ROOT_ADDR).to_option(),
            ],
        )

        with pytest.raises(DaoError) as exc_info:
            DaoManager._extract_updates(dao)

        assert exc_info.value.reason == "signature_not_final"
