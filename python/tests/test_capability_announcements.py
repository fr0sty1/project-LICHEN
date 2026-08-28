# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for capability announcements (COSE_Sign1, spec section 8.12)."""

import time

import cbor2
import pytest

from lichen.crypto import (
    SCHNORR48_ED25519_ALG,
    Capability,
    CapabilityAnnouncement,
    CapabilityPayload,
    Identity,
    create_capability_announcement,
    decode_cose_sign1_announcement,
    verify_capability_announcement,
)
from lichen.crypto.capability_announcements import (
    COSE_ALG_LABEL,
    COSE_KID_LABEL,
    _build_sig_structure,
    _encode_protected_header,
)


class TestCapabilityEnum:
    """Test Capability flag enum."""

    def test_egress_bit(self) -> None:
        assert Capability.EGRESS == 0x01
        assert int(Capability.EGRESS) == 1

    def test_prefix_delegation_bit(self) -> None:
        assert Capability.PREFIX_DELEGATION == 0x02
        assert int(Capability.PREFIX_DELEGATION) == 2

    def test_combined_capabilities(self) -> None:
        combined = Capability.EGRESS | Capability.PREFIX_DELEGATION
        assert int(combined) == 0x03


class TestProtectedHeader:
    """Test COSE protected header encoding."""

    def test_encode_protected_header(self) -> None:
        protected = _encode_protected_header()
        decoded = cbor2.loads(protected)
        assert decoded == {COSE_ALG_LABEL: SCHNORR48_ED25519_ALG}
        assert decoded[1] == -65537

    def test_schnorr48_algorithm_id(self) -> None:
        assert SCHNORR48_ED25519_ALG == -65537


class TestSigStructure:
    """Test COSE Sig_structure construction."""

    def test_sig_structure_format(self) -> None:
        protected = b"\xa1\x01\x39\xff\xff"  # {1: -65536} example
        payload = b"\xa1\x01\x02"  # {1: 2} example

        sig_structure = _build_sig_structure(protected, payload)
        decoded = cbor2.loads(sig_structure)

        assert isinstance(decoded, list)
        assert len(decoded) == 4
        assert decoded[0] == "Signature1"
        assert decoded[1] == protected
        assert decoded[2] == b""  # empty external_aad
        assert decoded[3] == payload


class TestCapabilityPayload:
    """Test CapabilityPayload dataclass."""

    def test_valid_payload(self) -> None:
        payload = CapabilityPayload(
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=int(time.time()) + 3600,
            seq=1,
            announcer_iid=bytes(8),
        )
        assert payload.capabilities == 1

    def test_invalid_reserved_bits(self) -> None:
        with pytest.raises(ValueError, match="Reserved capability bits"):
            CapabilityPayload(
                capabilities=0x04,  # Reserved bit 2
                prefix=bytes(16),
                prefix_len=128,
                expiry=int(time.time()) + 3600,
                seq=1,
                announcer_iid=bytes(8),
            )

    def test_invalid_prefix_len(self) -> None:
        with pytest.raises(ValueError, match="prefix_len must be 0-128"):
            CapabilityPayload(
                capabilities=Capability.EGRESS,
                prefix=bytes(17),
                prefix_len=129,  # Invalid
                expiry=int(time.time()) + 3600,
                seq=1,
                announcer_iid=bytes(8),
            )

    def test_prefix_length_mismatch(self) -> None:
        with pytest.raises(ValueError, match="prefix must be"):
            CapabilityPayload(
                capabilities=Capability.EGRESS,
                prefix=bytes(8),  # 8 bytes
                prefix_len=128,  # expects 16 bytes
                expiry=int(time.time()) + 3600,
                seq=1,
                announcer_iid=bytes(8),
            )

    def test_invalid_iid_length(self) -> None:
        with pytest.raises(ValueError, match="announcer_iid must be 8 bytes"):
            CapabilityPayload(
                capabilities=Capability.EGRESS,
                prefix=bytes(16),
                prefix_len=128,
                expiry=int(time.time()) + 3600,
                seq=1,
                announcer_iid=bytes(4),  # Too short
            )

    def test_negative_expiry(self) -> None:
        with pytest.raises(ValueError, match="expiry must be positive"):
            CapabilityPayload(
                capabilities=Capability.EGRESS,
                prefix=bytes(16),
                prefix_len=128,
                expiry=0,
                seq=1,
                announcer_iid=bytes(8),
            )

    def test_negative_seq(self) -> None:
        with pytest.raises(ValueError, match="seq must be non-negative"):
            CapabilityPayload(
                capabilities=Capability.EGRESS,
                prefix=bytes(16),
                prefix_len=128,
                expiry=int(time.time()) + 3600,
                seq=-1,
                announcer_iid=bytes(8),
            )

    def test_cbor_roundtrip(self) -> None:
        original = CapabilityPayload(
            capabilities=Capability.EGRESS | Capability.PREFIX_DELEGATION,
            prefix=bytes.fromhex("20010db8"),
            prefix_len=32,
            expiry=1700000000,
            seq=42,
            announcer_iid=bytes.fromhex("0123456789abcdef"),
        )

        encoded = original.to_cbor()
        decoded = CapabilityPayload.from_cbor(encoded)

        assert decoded.capabilities == original.capabilities
        assert decoded.prefix == original.prefix
        assert decoded.prefix_len == original.prefix_len
        assert decoded.expiry == original.expiry
        assert decoded.seq == original.seq
        assert decoded.announcer_iid == original.announcer_iid

    def test_zero_prefix_len(self) -> None:
        """Zero prefix length is valid (empty prefix)."""
        payload = CapabilityPayload(
            capabilities=Capability.EGRESS,
            prefix=b"",
            prefix_len=0,
            expiry=int(time.time()) + 3600,
            seq=1,
            announcer_iid=bytes(8),
        )
        assert payload.prefix_len == 0
        assert payload.prefix == b""


class TestCapabilityAnnouncement:
    """Test CapabilityAnnouncement dataclass."""

    def test_invalid_signature_length(self) -> None:
        payload = CapabilityPayload(
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=int(time.time()) + 3600,
            seq=1,
            announcer_iid=bytes(8),
        )
        with pytest.raises(ValueError, match="signature must be 48 bytes"):
            CapabilityAnnouncement(payload=payload, signature=bytes(32))


class TestCreateAndVerify:
    """Test end-to-end creation and verification."""

    @pytest.fixture
    def identity(self) -> Identity:
        """Create a test identity with deterministic seed."""
        seed = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        return Identity.from_seed(seed)

    def test_create_announcement(self, identity: Identity) -> None:
        expiry = int(time.time()) + 3600
        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=expiry,
            seq=1,
        )

        assert announcement.payload.capabilities == 1
        assert announcement.payload.announcer_iid == identity.iid
        assert len(announcement.signature) == 48

    def test_verify_valid_announcement(self, identity: Identity) -> None:
        current_time = int(time.time())
        expiry = current_time + 3600

        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=expiry,
            seq=1,
        )

        valid, error = verify_capability_announcement(
            announcement=announcement,
            pubkey=identity.pubkey,
            current_time=current_time,
        )

        assert valid is True
        assert error is None

    def test_verify_expired_announcement(self, identity: Identity) -> None:
        past_time = int(time.time()) - 3600
        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=past_time,  # Already expired
            seq=1,
        )

        valid, error = verify_capability_announcement(
            announcement=announcement,
            pubkey=identity.pubkey,
            current_time=int(time.time()),
        )

        assert valid is False
        assert error == "EXPIRED"

    def test_verify_replay_detected(self, identity: Identity) -> None:
        current_time = int(time.time())
        expiry = current_time + 3600

        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=expiry,
            seq=5,  # seq = 5
        )

        valid, error = verify_capability_announcement(
            announcement=announcement,
            pubkey=identity.pubkey,
            current_time=current_time,
            cached_seq=10,  # cached is higher
        )

        assert valid is False
        assert error == "REPLAY_DETECTED"

    def test_verify_wrong_pubkey(self, identity: Identity) -> None:
        current_time = int(time.time())
        expiry = current_time + 3600

        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=expiry,
            seq=1,
        )

        # Use a different identity's pubkey
        other_identity = Identity.generate()

        valid, error = verify_capability_announcement(
            announcement=announcement,
            pubkey=other_identity.pubkey,
            current_time=current_time,
        )

        assert valid is False
        assert error == "IID_MISMATCH"

    def test_verify_tampered_signature(self, identity: Identity) -> None:
        current_time = int(time.time())
        expiry = current_time + 3600

        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=expiry,
            seq=1,
        )

        # Tamper with signature
        tampered_sig = bytearray(announcement.signature)
        tampered_sig[0] ^= 0xFF
        tampered_announcement = CapabilityAnnouncement(
            payload=announcement.payload,
            signature=bytes(tampered_sig),
        )

        valid, error = verify_capability_announcement(
            announcement=tampered_announcement,
            pubkey=identity.pubkey,
            current_time=current_time,
        )

        assert valid is False
        assert error == "SIGNATURE_INVALID"


class TestCoseSign1Encoding:
    """Test COSE_Sign1 encoding/decoding."""

    @pytest.fixture
    def identity(self) -> Identity:
        seed = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        return Identity.from_seed(seed)

    def test_cose_sign1_roundtrip(self, identity: Identity) -> None:
        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS | Capability.PREFIX_DELEGATION,
            prefix=bytes.fromhex("20010db8"),
            prefix_len=32,
            expiry=1700000000,
            seq=42,
        )

        # Encode to COSE_Sign1
        encoded = announcement.to_cose_sign1()

        # Decode back
        decoded = decode_cose_sign1_announcement(encoded)

        assert decoded.payload.capabilities == announcement.payload.capabilities
        assert decoded.payload.prefix == announcement.payload.prefix
        assert decoded.payload.prefix_len == announcement.payload.prefix_len
        assert decoded.payload.expiry == announcement.payload.expiry
        assert decoded.payload.seq == announcement.payload.seq
        assert decoded.payload.announcer_iid == announcement.payload.announcer_iid
        assert decoded.signature == announcement.signature

    def test_cose_sign1_structure(self, identity: Identity) -> None:
        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=1700000000,
            seq=1,
        )

        encoded = announcement.to_cose_sign1()
        decoded_array = cbor2.loads(encoded)

        # COSE_Sign1 is a 4-element array
        assert isinstance(decoded_array, list)
        assert len(decoded_array) == 4

        protected, unprotected, payload, signature = decoded_array

        # Protected header contains algorithm
        protected_decoded = cbor2.loads(protected)
        assert protected_decoded[COSE_ALG_LABEL] == SCHNORR48_ED25519_ALG

        # Unprotected header contains kid
        assert COSE_KID_LABEL in unprotected
        assert unprotected[COSE_KID_LABEL] == identity.iid

        # Signature is 48 bytes
        assert len(signature) == 48

    def test_decode_wrong_algorithm(self) -> None:
        """Test rejection of wrong algorithm in protected header."""
        # Create a fake COSE_Sign1 with wrong algorithm
        protected = cbor2.dumps({COSE_ALG_LABEL: -8})  # EdDSA instead of Schnorr48
        unprotected = {COSE_KID_LABEL: bytes(8)}
        payload = cbor2.dumps({
            1: 1,
            2: bytes(16),
            3: 128,
            4: 1700000000,
            5: 1,
            6: bytes(8),
        })
        signature = bytes(48)

        fake_cose = cbor2.dumps([protected, unprotected, payload, signature])

        with pytest.raises(ValueError, match="Algorithm must be -65537"):
            decode_cose_sign1_announcement(fake_cose)

    def test_decode_kid_mismatch(self) -> None:
        """Test rejection when kid doesn't match announcer_iid."""
        protected = _encode_protected_header()
        unprotected = {COSE_KID_LABEL: bytes(8)}  # All zeros
        payload = cbor2.dumps({
            1: 1,
            2: bytes(16),
            3: 128,
            4: 1700000000,
            5: 1,
            6: bytes.fromhex("0102030405060708"),  # Different IID
        })
        signature = bytes(48)

        fake_cose = cbor2.dumps([protected, unprotected, payload, signature])

        with pytest.raises(ValueError, match="kid .* must match announcer_iid"):
            decode_cose_sign1_announcement(fake_cose)


class TestSpecCompliance:
    """Tests verifying compliance with spec section 8.12."""

    def test_capability_bits_per_spec(self) -> None:
        """Verify capability bit assignments match spec."""
        # Bit 0: egress
        assert Capability.EGRESS == 0b00000001
        # Bit 1: prefix-delegation
        assert Capability.PREFIX_DELEGATION == 0b00000010

    def test_payload_keys_are_integers(self) -> None:
        """Verify payload uses integer keys per spec."""
        payload = CapabilityPayload(
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=1700000000,
            seq=1,
            announcer_iid=bytes(8),
        )
        encoded = payload.to_cbor()
        decoded = cbor2.loads(encoded)

        # All keys should be integers 1-6
        assert all(isinstance(k, int) for k in decoded)
        assert set(decoded) == {1, 2, 3, 4, 5, 6}

    def test_schnorr48_algorithm_value(self) -> None:
        """Verify Schnorr48-Ed25519 algorithm ID is -65537."""
        assert SCHNORR48_ED25519_ALG == -65537

    def test_signature_length_is_48_bytes(self) -> None:
        """Verify signature is exactly 48 bytes (16 + 32)."""
        identity = Identity.generate()
        announcement = create_capability_announcement(
            identity=identity,
            capabilities=Capability.EGRESS,
            prefix=bytes(16),
            prefix_len=128,
            expiry=int(time.time()) + 3600,
            seq=1,
        )
        assert len(announcement.signature) == 48
