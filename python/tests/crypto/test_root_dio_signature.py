# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Root DIO Signature COSE_Sign1 implementation (spec 8.10.1)."""

from __future__ import annotations

import time
from ipaddress import IPv6Address

import cbor2
import pytest

from lichen.crypto import Identity
from lichen.crypto.root_dio_signature import (
    COSE_ALG_LABEL,
    COSE_KID_LABEL,
    SCHNORR48_ED25519_ALG,
    RootDioSignature,
    RootDioSignaturePayload,
    _encode_protected_header,
    create_root_dio_signature,
    decode_root_dio_signature,
    verify_root_dio_signature,
)


class TestRootDioSignaturePayload:
    """Tests for RootDioSignaturePayload dataclass."""

    def test_valid_payload(self) -> None:
        """Test creating a valid payload."""
        payload = RootDioSignaturePayload(
            dodag_id=bytes(16),
            instance=1,
            version=1,
            rank=256,
            expiry=int(time.time()) + 3600,
            root_seq=1,
            mop=2,
        )
        assert len(payload.dodag_id) == 16
        assert payload.instance == 1
        assert payload.version == 1
        assert payload.rank == 256
        assert payload.mop == 2

    def test_invalid_dodag_id_length(self) -> None:
        """Test that short dodag_id is rejected."""
        with pytest.raises(ValueError, match="dodag_id must be 16 bytes"):
            RootDioSignaturePayload(
                dodag_id=bytes(8),
                instance=1,
                version=1,
                rank=256,
                expiry=int(time.time()) + 3600,
                root_seq=1,
                mop=2,
            )

    def test_invalid_instance_range(self) -> None:
        """Test that out-of-range instance is rejected."""
        with pytest.raises(ValueError, match="instance must be 0-255"):
            RootDioSignaturePayload(
                dodag_id=bytes(16),
                instance=256,
                version=1,
                rank=256,
                expiry=int(time.time()) + 3600,
                root_seq=1,
                mop=2,
            )

    def test_invalid_mop_range(self) -> None:
        """Test that out-of-range MOP is rejected."""
        with pytest.raises(ValueError, match="mop must be 0-7"):
            RootDioSignaturePayload(
                dodag_id=bytes(16),
                instance=1,
                version=1,
                rank=256,
                expiry=int(time.time()) + 3600,
                root_seq=1,
                mop=8,
            )

    def test_invalid_expiry(self) -> None:
        """Test that non-positive expiry is rejected."""
        with pytest.raises(ValueError, match="expiry must be positive"):
            RootDioSignaturePayload(
                dodag_id=bytes(16),
                instance=1,
                version=1,
                rank=256,
                expiry=0,
                root_seq=1,
                mop=2,
            )

    def test_cbor_roundtrip(self) -> None:
        """Test CBOR encode/decode roundtrip."""
        payload = RootDioSignaturePayload(
            dodag_id=bytes(range(16)),
            instance=42,
            version=3,
            rank=256,
            expiry=1700000000,
            root_seq=100,
            mop=2,
        )
        encoded = payload.to_cbor()
        decoded = RootDioSignaturePayload.from_cbor(encoded)

        assert decoded.dodag_id == payload.dodag_id
        assert decoded.instance == payload.instance
        assert decoded.version == payload.version
        assert decoded.rank == payload.rank
        assert decoded.expiry == payload.expiry
        assert decoded.root_seq == payload.root_seq
        assert decoded.mop == payload.mop


class TestRootDioSignature:
    """Tests for RootDioSignature COSE_Sign1 wrapper."""

    @pytest.fixture
    def root_identity(self) -> Identity:
        """Create a root identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def valid_signature(self, root_identity: Identity) -> RootDioSignature:
        """Create a valid Root DIO Signature."""
        return create_root_dio_signature(
            identity=root_identity,
            dodag_id=root_identity.ygg_addr,
            instance=1,
            version=1,
            rank=256,
            expiry=int(time.time()) + 3600,
            root_seq=1,
            mop=2,
        )

    def test_create_and_verify(self, root_identity: Identity) -> None:
        """Test creating and verifying a Root DIO Signature."""
        future_time = int(time.time()) + 3600
        sig = create_root_dio_signature(
            identity=root_identity,
            dodag_id=root_identity.ygg_addr,
            instance=1,
            version=1,
            rank=256,
            expiry=future_time,
            root_seq=1,
            mop=2,
        )

        valid, error = verify_root_dio_signature(
            sig,
            pubkey=root_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is True
        assert error is None

    def test_cose_sign1_roundtrip(self, valid_signature: RootDioSignature) -> None:
        """Test COSE_Sign1 encode/decode roundtrip."""
        encoded = valid_signature.to_cose_sign1()
        decoded = decode_root_dio_signature(encoded)

        assert decoded.root_iid == valid_signature.root_iid
        assert decoded.signature == valid_signature.signature
        assert decoded.payload.dodag_id == valid_signature.payload.dodag_id
        assert decoded.payload.instance == valid_signature.payload.instance

    def test_protected_header_format(self) -> None:
        """Test protected header encodes correctly per spec."""
        protected = _encode_protected_header()
        decoded = cbor2.loads(protected)
        assert decoded == {COSE_ALG_LABEL: SCHNORR48_ED25519_ALG}

    def test_cose_sign1_structure(self, valid_signature: RootDioSignature) -> None:
        """Test COSE_Sign1 structure matches spec."""
        encoded = valid_signature.to_cose_sign1()
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


class TestVerification:
    """Tests for Root DIO Signature verification."""

    @pytest.fixture
    def root_identity(self) -> Identity:
        """Create a root identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    def test_expired_signature(self, root_identity: Identity) -> None:
        """Test that expired signatures are rejected."""
        past_time = int(time.time()) - 3600
        sig = create_root_dio_signature(
            identity=root_identity,
            dodag_id=root_identity.ygg_addr,
            instance=1,
            version=1,
            rank=256,
            expiry=past_time,
            root_seq=1,
            mop=2,
        )

        valid, error = verify_root_dio_signature(
            sig,
            pubkey=root_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is False
        assert error == "EXPIRED"

    def test_replay_detection(self, root_identity: Identity) -> None:
        """Test that replay attacks are detected."""
        future_time = int(time.time()) + 3600
        sig = create_root_dio_signature(
            identity=root_identity,
            dodag_id=root_identity.ygg_addr,
            instance=1,
            version=1,
            rank=256,
            expiry=future_time,
            root_seq=5,
            mop=2,
        )

        # Should fail if cached_root_seq >= root_seq
        valid, error = verify_root_dio_signature(
            sig,
            pubkey=root_identity.pubkey,
            current_time=int(time.time()),
            cached_root_seq=5,
        )
        assert valid is False
        assert error == "REPLAY_DETECTED"

        # Should pass with lower cached_root_seq
        valid, error = verify_root_dio_signature(
            sig,
            pubkey=root_identity.pubkey,
            current_time=int(time.time()),
            cached_root_seq=4,
        )
        assert valid is True
        assert error is None

    def test_iid_mismatch(self, root_identity: Identity) -> None:
        """Test that wrong pubkey IID is rejected."""
        future_time = int(time.time()) + 3600
        sig = create_root_dio_signature(
            identity=root_identity,
            dodag_id=root_identity.ygg_addr,
            instance=1,
            version=1,
            rank=256,
            expiry=future_time,
            root_seq=1,
            mop=2,
        )

        # Use different identity's pubkey
        wrong_identity = Identity.from_seed(bytes([0xFF] * 32))

        valid, error = verify_root_dio_signature(
            sig,
            pubkey=wrong_identity.pubkey,
            current_time=int(time.time()),
        )
        assert valid is False
        assert error == "IID_MISMATCH"

    def test_dio_field_mismatch(self, root_identity: Identity) -> None:
        """Test that mismatched DIO fields are rejected."""
        future_time = int(time.time()) + 3600
        sig = create_root_dio_signature(
            identity=root_identity,
            dodag_id=root_identity.ygg_addr,
            instance=1,
            version=1,
            rank=256,
            expiry=future_time,
            root_seq=1,
            mop=2,
        )

        # Mismatch instance
        valid, error = verify_root_dio_signature(
            sig,
            pubkey=root_identity.pubkey,
            current_time=int(time.time()),
            dio_instance=99,
        )
        assert valid is False
        assert error == "INSTANCE_MISMATCH"

        # Mismatch MOP
        valid, error = verify_root_dio_signature(
            sig,
            pubkey=root_identity.pubkey,
            current_time=int(time.time()),
            dio_mop=0,
        )
        assert valid is False
        assert error == "MOP_MISMATCH"

    def test_tampered_signature(self, root_identity: Identity) -> None:
        """Test that tampered signatures are rejected."""
        future_time = int(time.time()) + 3600
        sig = create_root_dio_signature(
            identity=root_identity,
            dodag_id=root_identity.ygg_addr,
            instance=1,
            version=1,
            rank=256,
            expiry=future_time,
            root_seq=1,
            mop=2,
        )

        # Tamper with signature
        tampered_sig = bytes([b ^ 0xFF for b in sig.signature[:4]]) + sig.signature[4:]
        tampered = RootDioSignature(
            payload=sig.payload,
            root_iid=sig.root_iid,
            signature=tampered_sig,
        )

        valid, error = verify_root_dio_signature(
            tampered,
            pubkey=root_identity.pubkey,
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
            decode_root_dio_signature(bad_data)

    def test_wrong_algorithm(self) -> None:
        """Test that wrong algorithm is rejected."""
        # Create COSE_Sign1 with wrong algorithm
        protected = cbor2.dumps({COSE_ALG_LABEL: -7})  # ES256 instead
        payload = RootDioSignaturePayload(
            dodag_id=bytes(16),
            instance=1,
            version=1,
            rank=256,
            expiry=int(time.time()) + 3600,
            root_seq=1,
            mop=2,
        )
        cose_array = [protected, {COSE_KID_LABEL: bytes(8)}, payload.to_cbor(), bytes(48)]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="Algorithm must be"):
            decode_root_dio_signature(bad_data)

    def test_invalid_kid_length(self) -> None:
        """Test that wrong kid length is rejected."""
        protected = _encode_protected_header()
        payload = RootDioSignaturePayload(
            dodag_id=bytes(16),
            instance=1,
            version=1,
            rank=256,
            expiry=int(time.time()) + 3600,
            root_seq=1,
            mop=2,
        )
        cose_array = [protected, {COSE_KID_LABEL: bytes(4)}, payload.to_cbor(), bytes(48)]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="kid in unprotected header must be 8-byte IID"):
            decode_root_dio_signature(bad_data)


class TestIPv6AddressSupport:
    """Tests for IPv6Address input support."""

    def test_ipv6_address_dodag_id(self) -> None:
        """Test that IPv6Address can be used for dodag_id."""
        identity = Identity.from_seed(bytes(range(32)))
        dodag_id = IPv6Address("2001:db8::1")

        sig = create_root_dio_signature(
            identity=identity,
            dodag_id=dodag_id,
            instance=1,
            version=1,
            rank=256,
            expiry=int(time.time()) + 3600,
            root_seq=1,
            mop=2,
        )

        assert sig.payload.dodag_id == dodag_id.packed

    def test_verify_with_ipv6_address(self) -> None:
        """Test verification with IPv6Address for DIO cross-check."""
        identity = Identity.from_seed(bytes(range(32)))
        dodag_id = identity.ygg_addr

        sig = create_root_dio_signature(
            identity=identity,
            dodag_id=dodag_id,
            instance=1,
            version=1,
            rank=256,
            expiry=int(time.time()) + 3600,
            root_seq=1,
            mop=2,
        )

        valid, error = verify_root_dio_signature(
            sig,
            pubkey=identity.pubkey,
            current_time=int(time.time()),
            dio_dodag_id=dodag_id,
        )
        assert valid is True
        assert error is None
