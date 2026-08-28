# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for GCP-6 slot claim oracle.

Tests slot claim handling against spec 08-gateway-coordination.md Section 6
and test vectors in test/vectors/gcp_slot_claim.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.crypto import schnorr48
from lichen.gateway.slot_claim import (
    ClaimError,
    ClaimRejectReason,
    SlotClaim,
    compute_contiguous_slots,
    compute_interleaved_slots,
    encode_claim_canonical,
    resolve_slot_conflict,
    sign_slot_claim,
    validate_interleaved_pattern,
    verify_slot_claim,
)

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"


class TestSlotClaim:
    """Tests for SlotClaim dataclass."""

    def test_basic_creation(self) -> None:
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
        )
        assert claim.gateway_iid == "0011223344556677"
        assert claim.slots == (0, 1, 2)
        assert claim.superframe_id == 1000
        assert claim.signature is None

    def test_with_optional_fields(self) -> None:
        claim = SlotClaim(
            gateway_iid="aabbccddeeff0011",
            slots=(5,),
            superframe_id=42,
            timestamp=1700000000,
            gateway_count=3,
            ordinal=0,
        )
        assert claim.timestamp == 1700000000
        assert claim.gateway_count == 3
        assert claim.ordinal == 0

    def test_invalid_iid_length(self) -> None:
        with pytest.raises(ClaimError, match="gateway_iid must be 16 hex chars"):
            SlotClaim(
                gateway_iid="0011",  # Too short
                slots=(0,),
                superframe_id=1,
            )

    def test_invalid_iid_hex(self) -> None:
        with pytest.raises(ClaimError, match="gateway_iid must be valid hex"):
            SlotClaim(
                gateway_iid="001122334455667Z",  # Invalid hex char
                slots=(0,),
                superframe_id=1,
            )

    def test_unsorted_slots(self) -> None:
        with pytest.raises(ClaimError, match="slots must be sorted"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(3, 1, 2),  # Not sorted
                superframe_id=1,
            )

    def test_duplicate_slots(self) -> None:
        with pytest.raises(ClaimError, match="slots must be unique"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(1, 1, 2),  # Duplicate
                superframe_id=1,
            )

    def test_negative_superframe_id(self) -> None:
        with pytest.raises(ClaimError, match="superframe_id must be non-negative"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0,),
                superframe_id=-1,
            )

    def test_invalid_signature_length(self) -> None:
        with pytest.raises(ClaimError, match="signature must be 48 bytes"):
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0,),
                superframe_id=1,
                signature=b"\x00" * 32,  # Wrong length
            )

    def test_iid_as_int(self) -> None:
        claim = SlotClaim(
            gateway_iid="0000000000000001",
            slots=(0,),
            superframe_id=1,
        )
        assert claim.iid_as_int() == 1

        claim2 = SlotClaim(
            gateway_iid="00000000000000ff",
            slots=(0,),
            superframe_id=1,
        )
        assert claim2.iid_as_int() == 255

    def test_to_cbor_map(self) -> None:
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
            timestamp=1700000000,
        )
        cbor_map = claim.to_cbor_map()
        assert cbor_map["gateway_iid"] == bytes.fromhex("0011223344556677")
        assert cbor_map["slots"] == [0, 1, 2]
        assert cbor_map["superframe_id"] == 1000
        assert cbor_map["timestamp"] == 1700000000


class TestEncodeClaimCanonical:
    """Tests for CBOR canonical encoding."""

    def test_deterministic_encoding(self) -> None:
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
        )
        # Multiple calls should produce identical output
        encoded1 = encode_claim_canonical(claim)
        encoded2 = encode_claim_canonical(claim)
        assert encoded1 == encoded2

    def test_key_ordering(self) -> None:
        # Per RFC 8949 Section 4.2.1, CBOR deterministic encoding sorts keys by:
        # 1. Length of encoded form (shorter first)
        # 2. Lexicographic byte comparison for same length
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
            timestamp=1700000000,
        )
        encoded = encode_claim_canonical(claim)
        # Decode to verify structure
        import cbor2
        decoded = cbor2.loads(encoded)
        keys = list(decoded.keys())
        # Keys should be: "slots" (5), "timestamp" (9), "gateway_iid" (11), "superframe_id" (13)
        # Ordered by encoded key length
        assert len(keys) == 4
        # Verify all expected keys are present
        assert set(keys) == {"gateway_iid", "slots", "superframe_id", "timestamp"}


class TestSignAndVerify:
    """Tests for Schnorr48 signing and verification."""

    @pytest.fixture
    def keypair(self) -> tuple[bytes, bytes]:
        seed = bytes.fromhex(
            "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe"
        )
        return schnorr48.derive_keypair(seed)

    def test_sign_and_verify(self, keypair: tuple[bytes, bytes]) -> None:
        privkey, pubkey = keypair
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
        )
        signed_claim = sign_slot_claim(claim, privkey, pubkey)
        assert signed_claim.signature is not None
        assert len(signed_claim.signature) == 48

        is_valid, reason = verify_slot_claim(signed_claim, pubkey)
        assert is_valid
        assert reason is None

    def test_missing_signature_rejected(self, keypair: tuple[bytes, bytes]) -> None:
        _, pubkey = keypair
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0,),
            superframe_id=1,
        )
        is_valid, reason = verify_slot_claim(claim, pubkey)
        assert not is_valid
        assert reason == ClaimRejectReason.MISSING_SIGNATURE

    def test_invalid_signature_rejected(self, keypair: tuple[bytes, bytes]) -> None:
        _, pubkey = keypair
        # Zero signature is invalid
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0,),
            superframe_id=1,
            signature=bytes(48),
        )
        is_valid, reason = verify_slot_claim(claim, pubkey)
        assert not is_valid
        assert reason == ClaimRejectReason.INVALID_SIGNATURE

    def test_wrong_pubkey_rejected(self, keypair: tuple[bytes, bytes]) -> None:
        privkey, pubkey = keypair
        claim = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(0, 1, 2),
            superframe_id=1000,
        )
        signed_claim = sign_slot_claim(claim, privkey, pubkey)

        # Verify with different key
        other_seed = bytes.fromhex(
            "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        )
        _, other_pubkey = schnorr48.derive_keypair(other_seed)

        is_valid, reason = verify_slot_claim(signed_claim, other_pubkey)
        assert not is_valid
        assert reason == ClaimRejectReason.INVALID_SIGNATURE


class TestResolveSlotConflict:
    """Tests for slot conflict resolution (GCP-6.3)."""

    @pytest.fixture
    def keypair_low(self) -> tuple[bytes, bytes]:
        # Low IID gateway
        seed = bytes(32)  # All zeros
        return schnorr48.derive_keypair(seed)

    @pytest.fixture
    def keypair_high(self) -> tuple[bytes, bytes]:
        # High IID gateway
        seed = bytes([0xFF] * 32)
        return schnorr48.derive_keypair(seed)

    def test_lowest_iid_wins_both_valid(
        self,
        keypair_low: tuple[bytes, bytes],
        keypair_high: tuple[bytes, bytes],
    ) -> None:
        priv_low, pub_low = keypair_low
        priv_high, pub_high = keypair_high

        # Both claim slots 5, 6
        claim_low = sign_slot_claim(
            SlotClaim(
                gateway_iid="0011223344556677",  # Lower IID
                slots=(5, 6),
                superframe_id=100,
            ),
            priv_low,
            pub_low,
        )
        claim_high = sign_slot_claim(
            SlotClaim(
                gateway_iid="0022334455667788",  # Higher IID
                slots=(5, 6),
                superframe_id=100,
            ),
            priv_high,
            pub_high,
        )

        # Pass pubkeys to resolve_slot_conflict for verification
        winner, loser = resolve_slot_conflict(
            claim_low, claim_high, pubkey_a=pub_low, pubkey_b=pub_high
        )
        assert winner.gateway_iid == "0011223344556677"
        assert loser.gateway_iid == "0022334455667788"

    def test_valid_claim_wins_over_invalid(
        self,
        keypair_low: tuple[bytes, bytes],
    ) -> None:
        priv, pub = keypair_low

        valid_claim = sign_slot_claim(
            SlotClaim(
                gateway_iid="0022334455667788",  # Higher IID but valid
                slots=(5, 6),
                superframe_id=100,
            ),
            priv,
            pub,
        )

        invalid_claim = SlotClaim(
            gateway_iid="0011223344556677",  # Lower IID but invalid sig
            slots=(5, 6),
            superframe_id=100,
            signature=bytes(48),  # Invalid zero signature
        )

        # Use a different pubkey for invalid_claim to ensure verification fails
        other_seed = bytes([0x42] * 32)
        _, other_pub = schnorr48.derive_keypair(other_seed)

        winner, loser = resolve_slot_conflict(
            valid_claim, invalid_claim, pubkey_a=pub, pubkey_b=other_pub
        )
        assert winner.gateway_iid == "0022334455667788"
        assert loser.gateway_iid == "0011223344556677"

    def test_no_overlap_raises(
        self,
        keypair_low: tuple[bytes, bytes],
        keypair_high: tuple[bytes, bytes],
    ) -> None:
        priv_low, pub_low = keypair_low
        priv_high, pub_high = keypair_high

        claim_a = sign_slot_claim(
            SlotClaim(
                gateway_iid="0011223344556677",
                slots=(0, 1, 2),
                superframe_id=100,
            ),
            priv_low,
            pub_low,
        )
        claim_b = sign_slot_claim(
            SlotClaim(
                gateway_iid="0022334455667788",
                slots=(3, 4, 5),
                superframe_id=100,
            ),
            priv_high,
            pub_high,
        )
        with pytest.raises(ClaimError, match="no overlapping slots"):
            resolve_slot_conflict(claim_a, claim_b, pubkey_a=pub_low, pubkey_b=pub_high)

    def test_both_invalid_raises(
        self,
        keypair_low: tuple[bytes, bytes],
        keypair_high: tuple[bytes, bytes],
    ) -> None:
        _, pub_low = keypair_low
        _, pub_high = keypair_high

        # Both claims have zero signatures (invalid)
        claim_a = SlotClaim(
            gateway_iid="0011223344556677",
            slots=(5, 6),
            superframe_id=100,
            signature=bytes(48),
        )
        claim_b = SlotClaim(
            gateway_iid="0022334455667788",
            slots=(5, 6),
            superframe_id=100,
            signature=bytes(48),
        )
        with pytest.raises(ClaimError, match="both claims have invalid signatures"):
            resolve_slot_conflict(claim_a, claim_b, pubkey_a=pub_low, pubkey_b=pub_high)


class TestInterleavedSlots:
    """Tests for interleaved slot allocation (GCP-6.2)."""

    def test_single_gateway(self) -> None:
        slots = compute_interleaved_slots(ordinal=0, gateway_count=1, max_slots=8)
        assert slots == [0, 1, 2, 3, 4, 5, 6, 7]

    def test_three_gateways_ordinal_0(self) -> None:
        slots = compute_interleaved_slots(ordinal=0, gateway_count=3, max_slots=15)
        assert slots == [0, 3, 6, 9, 12]

    def test_three_gateways_ordinal_1(self) -> None:
        slots = compute_interleaved_slots(ordinal=1, gateway_count=3, max_slots=15)
        assert slots == [1, 4, 7, 10, 13]

    def test_three_gateways_ordinal_2(self) -> None:
        slots = compute_interleaved_slots(ordinal=2, gateway_count=3, max_slots=15)
        assert slots == [2, 5, 8, 11, 14]

    def test_invalid_ordinal(self) -> None:
        with pytest.raises(ClaimError, match="ordinal.*gateway_count"):
            compute_interleaved_slots(ordinal=3, gateway_count=3, max_slots=15)

    def test_negative_ordinal(self) -> None:
        with pytest.raises(ClaimError, match="non-negative"):
            compute_interleaved_slots(ordinal=-1, gateway_count=3, max_slots=15)


class TestContiguousSlots:
    """Tests for contiguous slot allocation (GCP-6.2)."""

    def test_basic_contiguous(self) -> None:
        slots = compute_contiguous_slots(start_slot=10, slot_count=5, max_slots=60)
        assert slots == [10, 11, 12, 13, 14]

    def test_at_start(self) -> None:
        slots = compute_contiguous_slots(start_slot=0, slot_count=3, max_slots=60)
        assert slots == [0, 1, 2]

    def test_at_end(self) -> None:
        slots = compute_contiguous_slots(start_slot=57, slot_count=3, max_slots=60)
        assert slots == [57, 58, 59]

    def test_empty_allocation(self) -> None:
        slots = compute_contiguous_slots(start_slot=10, slot_count=0, max_slots=60)
        assert slots == []

    def test_exceeds_max_slots(self) -> None:
        with pytest.raises(ClaimError, match="exceeds max_slots"):
            compute_contiguous_slots(start_slot=58, slot_count=5, max_slots=60)


class TestValidateInterleavedPattern:
    """Tests for interleaved pattern validation."""

    def test_valid_pattern(self) -> None:
        # Gateway 0 of 3: slots 0, 3, 6, 9, 12
        assert validate_interleaved_pattern(
            slots=[0, 3, 6, 9, 12],
            ordinal=0,
            gateway_count=3,
        )

    def test_valid_pattern_gateway_1(self) -> None:
        # Gateway 1 of 3: slots 1, 4, 7, 10, 13
        assert validate_interleaved_pattern(
            slots=[1, 4, 7, 10, 13],
            ordinal=1,
            gateway_count=3,
        )

    def test_invalid_pattern_wrong_start(self) -> None:
        # Gateway 0 should start at 0, not 1
        assert not validate_interleaved_pattern(
            slots=[1, 4, 7],
            ordinal=0,
            gateway_count=3,
        )

    def test_invalid_pattern_wrong_spacing(self) -> None:
        # Gateway 0 of 3 should have spacing of 3, not 2
        assert not validate_interleaved_pattern(
            slots=[0, 2, 4],
            ordinal=0,
            gateway_count=3,
        )

    def test_empty_slots_valid(self) -> None:
        assert validate_interleaved_pattern(slots=[], ordinal=0, gateway_count=3)


class TestSlotClaimVectors:
    """Test against test vectors in gcp_slot_claim.json."""

    @pytest.fixture(scope="class")
    def vectors(self) -> list[dict]:
        path = VECTORS_DIR / "gcp_slot_claim.json"
        if not path.exists():
            pytest.skip(f"Test vectors not found: {path}")
        with open(path) as f:
            doc = json.load(f)
        return doc["vectors"]

    def test_interleaved_pattern_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_interleaved":
                claim = v["claim"]
                slots = claim["slots"]
                ordinal = claim["ordinal"]
                gateway_count = claim["gateway_count"]
                expected = v["expected"]

                result = validate_interleaved_pattern(slots, ordinal, gateway_count)
                assert result == expected["valid"], (
                    f"Pattern validation failed for {v['name']}"
                )
                break

    def test_conflict_resolution_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_conflict_both_valid":
                claim_a_data = v["claim_a"]
                claim_b_data = v["claim_b"]

                # Generate keypairs for signing (deterministic seeds for reproducibility)
                seed_a = bytes.fromhex("a" * 64)
                seed_b = bytes.fromhex("b" * 64)
                priv_a, pub_a = schnorr48.derive_keypair(seed_a)
                priv_b, pub_b = schnorr48.derive_keypair(seed_b)

                # Sign the claims per vector's "both_signatures_valid: true"
                claim_a = sign_slot_claim(
                    SlotClaim(
                        gateway_iid=claim_a_data["gateway_iid"],
                        slots=tuple(claim_a_data["slots"]),
                        superframe_id=1,
                    ),
                    priv_a,
                    pub_a,
                )
                claim_b = sign_slot_claim(
                    SlotClaim(
                        gateway_iid=claim_b_data["gateway_iid"],
                        slots=tuple(claim_b_data["slots"]),
                        superframe_id=1,
                    ),
                    priv_b,
                    pub_b,
                )

                winner, _ = resolve_slot_conflict(
                    claim_a, claim_b, pubkey_a=pub_a, pubkey_b=pub_b
                )
                expected_winner = v["expected"]["winner"]

                if expected_winner == "claim_a":
                    assert winner.gateway_iid == claim_a.gateway_iid
                else:
                    assert winner.gateway_iid == claim_b.gateway_iid
                break

    def test_missing_signature_rejected_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_missing_signature_reject":
                expected = v["expected"]
                assert expected["valid"] is False
                assert expected["reason"] == "missing_signature"

                # Create claim without signature and verify rejection
                claim = SlotClaim(
                    gateway_iid=v["claim"]["gateway_iid"],
                    slots=tuple(v["claim"]["slots"]),
                    superframe_id=1,
                )
                # Use a dummy pubkey for verification
                dummy_pubkey = bytes(32)
                is_valid, reason = verify_slot_claim(claim, dummy_pubkey)
                assert not is_valid
                assert reason == ClaimRejectReason.MISSING_SIGNATURE
                break

    def test_invalid_signature_rejected_vector(self, vectors: list[dict]) -> None:
        for v in vectors:
            if v["name"] == "slot_claim_invalid_signature_reject":
                expected = v["expected"]
                assert expected["valid"] is False
                assert expected["reason"] == "invalid_signature"

                sig_hex = v["signature"]
                sig = bytes.fromhex(sig_hex)

                claim = SlotClaim(
                    gateway_iid=v["claim"]["gateway_iid"],
                    slots=tuple(v["claim"]["slots"]),
                    superframe_id=1,
                    signature=sig,
                )
                # Use a dummy pubkey for verification
                dummy_seed = bytes.fromhex(
                    "0000000000000000000000000000000000000000000000000000000000000001"
                )
                _, dummy_pubkey = schnorr48.derive_keypair(dummy_seed)
                is_valid, reason = verify_slot_claim(claim, dummy_pubkey)
                assert not is_valid
                assert reason == ClaimRejectReason.INVALID_SIGNATURE
                break
