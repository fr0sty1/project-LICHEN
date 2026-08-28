# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Key Rotation Attestation COSE_Sign1 implementation (spec 8.7.4)."""

from __future__ import annotations

import time

import cbor2
import pytest

from lichen.crypto import Identity
from lichen.crypto.key_rotation_attestation import (
    COSE_ALG_LABEL,
    COSE_KID_LABEL,
    SCHNORR48_ED25519_ALG,
    KeyRotationAttestation,
    KeyRotationAttestationPayload,
    _encode_protected_header,
    create_key_rotation_attestation,
    decode_key_rotation_attestation,
    get_new_iid,
    verify_key_rotation_attestation,
)


class TestKeyRotationAttestationPayload:
    """Tests for KeyRotationAttestationPayload dataclass."""

    @pytest.fixture
    def old_identity(self) -> Identity:
        """Create old identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def new_identity(self) -> Identity:
        """Create new identity for testing."""
        return Identity.from_seed(bytes(range(32, 64)))

    def test_valid_payload(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test creating a valid payload."""
        payload = KeyRotationAttestationPayload(
            old_pubkey=old_identity.pubkey,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=int(time.time()) + 3600,
        )
        assert payload.old_pubkey == old_identity.pubkey
        assert payload.new_pubkey == new_identity.pubkey
        assert payload.rotation_seq == 1

    def test_invalid_old_pubkey_length(self, new_identity: Identity) -> None:
        """Test that short old_pubkey is rejected."""
        with pytest.raises(ValueError, match="old_pubkey must be 32 bytes"):
            KeyRotationAttestationPayload(
                old_pubkey=bytes(16),
                new_pubkey=new_identity.pubkey,
                rotation_seq=1,
                expiry=int(time.time()) + 3600,
            )

    def test_invalid_new_pubkey_length(self, old_identity: Identity) -> None:
        """Test that short new_pubkey is rejected."""
        with pytest.raises(ValueError, match="new_pubkey must be 32 bytes"):
            KeyRotationAttestationPayload(
                old_pubkey=old_identity.pubkey,
                new_pubkey=bytes(16),
                rotation_seq=1,
                expiry=int(time.time()) + 3600,
            )

    def test_same_key_rejected(self, old_identity: Identity) -> None:
        """Test that same old and new key is rejected."""
        with pytest.raises(ValueError, match="key rotation must change"):
            KeyRotationAttestationPayload(
                old_pubkey=old_identity.pubkey,
                new_pubkey=old_identity.pubkey,
                rotation_seq=1,
                expiry=int(time.time()) + 3600,
            )

    def test_zero_rotation_seq_rejected(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test that rotation_seq=0 is rejected."""
        with pytest.raises(ValueError, match="rotation_seq must be 1"):
            KeyRotationAttestationPayload(
                old_pubkey=old_identity.pubkey,
                new_pubkey=new_identity.pubkey,
                rotation_seq=0,
                expiry=int(time.time()) + 3600,
            )

    def test_invalid_expiry(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test that non-positive expiry is rejected."""
        with pytest.raises(ValueError, match="expiry must be positive"):
            KeyRotationAttestationPayload(
                old_pubkey=old_identity.pubkey,
                new_pubkey=new_identity.pubkey,
                rotation_seq=1,
                expiry=0,
            )

    def test_cbor_roundtrip(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test CBOR encode/decode roundtrip."""
        payload = KeyRotationAttestationPayload(
            old_pubkey=old_identity.pubkey,
            new_pubkey=new_identity.pubkey,
            rotation_seq=42,
            expiry=1700000000,
        )
        encoded = payload.to_cbor()
        decoded = KeyRotationAttestationPayload.from_cbor(encoded)

        assert decoded.old_pubkey == payload.old_pubkey
        assert decoded.new_pubkey == payload.new_pubkey
        assert decoded.rotation_seq == payload.rotation_seq
        assert decoded.expiry == payload.expiry


class TestKeyRotationAttestation:
    """Tests for KeyRotationAttestation COSE_Sign1 wrapper."""

    @pytest.fixture
    def old_identity(self) -> Identity:
        """Create old identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def new_identity(self) -> Identity:
        """Create new identity for testing."""
        return Identity.from_seed(bytes(range(32, 64)))

    @pytest.fixture
    def valid_attestation(
        self, old_identity: Identity, new_identity: Identity
    ) -> KeyRotationAttestation:
        """Create a valid Key Rotation Attestation."""
        return create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=int(time.time()) + 3600,
        )

    def test_create_and_verify(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test creating and verifying a Key Rotation Attestation."""
        future_time = int(time.time()) + 3600
        attestation = create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=future_time,
        )

        valid, error = verify_key_rotation_attestation(
            attestation,
            old_pubkey=old_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is True
        assert error is None

    def test_cose_sign1_roundtrip(
        self, valid_attestation: KeyRotationAttestation
    ) -> None:
        """Test COSE_Sign1 encode/decode roundtrip."""
        encoded = valid_attestation.to_cose_sign1()
        decoded = decode_key_rotation_attestation(encoded)

        assert decoded.old_iid == valid_attestation.old_iid
        assert decoded.signature == valid_attestation.signature
        assert decoded.payload.old_pubkey == valid_attestation.payload.old_pubkey
        assert decoded.payload.new_pubkey == valid_attestation.payload.new_pubkey
        assert decoded.payload.rotation_seq == valid_attestation.payload.rotation_seq

    def test_protected_header_format(self) -> None:
        """Test protected header encodes correctly per spec."""
        protected = _encode_protected_header()
        decoded = cbor2.loads(protected)
        assert decoded == {COSE_ALG_LABEL: SCHNORR48_ED25519_ALG}

    def test_cose_sign1_structure(
        self, valid_attestation: KeyRotationAttestation
    ) -> None:
        """Test COSE_Sign1 structure matches spec."""
        encoded = valid_attestation.to_cose_sign1()
        cose_array = cbor2.loads(encoded)

        assert isinstance(cose_array, list)
        assert len(cose_array) == 4

        protected_bytes, unprotected, payload_bytes, signature = cose_array

        # Check protected header
        protected = cbor2.loads(protected_bytes)
        assert protected[COSE_ALG_LABEL] == SCHNORR48_ED25519_ALG

        # Check unprotected header has kid
        assert COSE_KID_LABEL in unprotected
        assert len(unprotected[COSE_KID_LABEL]) == 8

        # Check signature length
        assert len(signature) == 48

    def test_get_new_iid(
        self, valid_attestation: KeyRotationAttestation, new_identity: Identity
    ) -> None:
        """Test deriving new IID from attestation."""
        new_iid = get_new_iid(valid_attestation)
        assert new_iid == new_identity.iid


class TestVerification:
    """Tests for Key Rotation Attestation verification."""

    @pytest.fixture
    def old_identity(self) -> Identity:
        """Create old identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def new_identity(self) -> Identity:
        """Create new identity for testing."""
        return Identity.from_seed(bytes(range(32, 64)))

    def test_expired_attestation(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test that expired attestations are rejected."""
        past_time = int(time.time()) - 3600
        attestation = create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=past_time,
        )

        valid, error = verify_key_rotation_attestation(
            attestation,
            old_pubkey=old_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is False
        assert error == "EXPIRED"

    def test_replay_detection(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test that replay attacks are detected."""
        future_time = int(time.time()) + 3600
        attestation = create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=5,
            expiry=future_time,
        )

        # Should fail if cached_rotation_seq >= rotation_seq
        valid, error = verify_key_rotation_attestation(
            attestation,
            old_pubkey=old_identity.pubkey,
            current_time=int(time.time()),
            cached_rotation_seq=5,
        )
        assert valid is False
        assert error == "REPLAY_DETECTED"

        # Should pass with lower cached_rotation_seq
        valid, error = verify_key_rotation_attestation(
            attestation,
            old_pubkey=old_identity.pubkey,
            current_time=int(time.time()),
            cached_rotation_seq=4,
        )
        assert valid is True
        assert error is None

    def test_iid_mismatch(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test that wrong pubkey IID is rejected."""
        future_time = int(time.time()) + 3600
        attestation = create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=future_time,
        )

        # Use different identity's pubkey
        wrong_identity = Identity.from_seed(bytes([0xFF] * 32))

        valid, error = verify_key_rotation_attestation(
            attestation,
            old_pubkey=wrong_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is False
        assert error == "IID_MISMATCH"

    def test_old_pubkey_mismatch(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test that mismatched old_pubkey in payload is rejected."""
        future_time = int(time.time()) + 3600
        attestation = create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=future_time,
        )

        # Create another identity with different key but we forge kid
        other_identity = Identity.from_seed(bytes([0xAA] * 32))

        # Manually create a bad attestation where kid matches but payload differs
        bad_payload = KeyRotationAttestationPayload(
            old_pubkey=other_identity.pubkey,  # Different from old_identity
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=future_time,
        )
        bad_attestation = KeyRotationAttestation(
            payload=bad_payload,
            old_iid=old_identity.iid,  # IID matches old_identity
            signature=attestation.signature,  # Reuse original signature
        )

        valid, error = verify_key_rotation_attestation(
            bad_attestation,
            old_pubkey=old_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is False
        assert error == "OLD_PUBKEY_MISMATCH"

    def test_tampered_signature(
        self, old_identity: Identity, new_identity: Identity
    ) -> None:
        """Test that tampered signatures are rejected."""
        future_time = int(time.time()) + 3600
        attestation = create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=future_time,
        )

        # Tamper with signature
        tampered_sig = (
            bytes([b ^ 0xFF for b in attestation.signature[:4]])
            + attestation.signature[4:]
        )
        tampered = KeyRotationAttestation(
            payload=attestation.payload,
            old_iid=attestation.old_iid,
            signature=tampered_sig,
        )

        valid, error = verify_key_rotation_attestation(
            tampered,
            old_pubkey=old_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is False
        assert error == "SIGNATURE_INVALID"


class TestCoseSign1Decoding:
    """Tests for COSE_Sign1 decoding error handling."""

    def test_invalid_array_length(self) -> None:
        """Test that non-4-element arrays are rejected."""
        bad_data = cbor2.dumps([b"protected", {}, b"payload"])
        with pytest.raises(ValueError, match="must be a 4-element array"):
            decode_key_rotation_attestation(bad_data)

    def test_wrong_algorithm(self) -> None:
        """Test that wrong algorithm is rejected."""
        old_identity = Identity.from_seed(bytes(range(32)))
        new_identity = Identity.from_seed(bytes(range(32, 64)))

        # Create COSE_Sign1 with wrong algorithm
        protected = cbor2.dumps({COSE_ALG_LABEL: -7})  # ES256 instead
        payload = KeyRotationAttestationPayload(
            old_pubkey=old_identity.pubkey,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=int(time.time()) + 3600,
        )
        cose_array = [
            protected,
            {COSE_KID_LABEL: bytes(8)},
            payload.to_cbor(),
            bytes(48),
        ]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="Algorithm must be"):
            decode_key_rotation_attestation(bad_data)

    def test_invalid_kid_length(self) -> None:
        """Test that wrong kid length is rejected."""
        old_identity = Identity.from_seed(bytes(range(32)))
        new_identity = Identity.from_seed(bytes(range(32, 64)))

        protected = _encode_protected_header()
        payload = KeyRotationAttestationPayload(
            old_pubkey=old_identity.pubkey,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=int(time.time()) + 3600,
        )
        cose_array = [
            protected,
            {COSE_KID_LABEL: bytes(4)},
            payload.to_cbor(),
            bytes(48),
        ]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="kid in unprotected header must be 8-byte"):
            decode_key_rotation_attestation(bad_data)


class TestIntegrationWithTrustStore:
    """Tests for integration between attestation and trust store."""

    def test_attestation_provides_new_iid_for_trust_update(self) -> None:
        """Test that attestation provides correct new IID for trust store update."""
        old_identity = Identity.from_seed(bytes(range(32)))
        new_identity = Identity.from_seed(bytes(range(32, 64)))

        attestation = create_key_rotation_attestation(
            old_identity=old_identity,
            new_pubkey=new_identity.pubkey,
            rotation_seq=1,
            expiry=int(time.time()) + 3600,
        )

        # Verify attestation
        valid, error = verify_key_rotation_attestation(
            attestation,
            old_pubkey=old_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is True
        assert error is None

        # Get new IID for trust store update
        new_iid = get_new_iid(attestation)
        assert new_iid == new_identity.iid

        # The rotation_seq from attestation should be persisted
        assert attestation.payload.rotation_seq == 1
