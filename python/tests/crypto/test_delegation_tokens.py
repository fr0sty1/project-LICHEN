# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for Delegation Tokens COSE_Sign1 implementation (spec 18.8.6)."""

from __future__ import annotations

import time

import cbor2
import pytest

from lichen.crypto import Identity
from lichen.crypto.delegation_tokens import (
    ADMIN_DELEGATABLE_SCOPE,
    COSE_ALG_LABEL,
    COSE_KID_LABEL,
    SCHNORR48_ED25519_ALG,
    VALID_SCOPE_MASK,
    DelegationScope,
    DelegationToken,
    DelegationTokenPayload,
    _encode_protected_header,
    check_delegation_scope,
    create_delegation_token,
    decode_delegation_token,
    verify_delegation_token,
)


class TestDelegationScope:
    """Tests for DelegationScope enum."""

    def test_scope_values(self) -> None:
        """Test that scope bit values match spec."""
        assert int(DelegationScope.INVITE) == 0x01
        assert int(DelegationScope.REMOVE) == 0x02
        assert int(DelegationScope.DISTRIBUTE_KEY) == 0x04
        assert int(DelegationScope.REKEY) == 0x08
        assert int(DelegationScope.READ_MEMBERS) == 0x10

    def test_admin_delegatable_scope(self) -> None:
        """Test that admin delegatable scope is bits 0, 1, 4 (0x13)."""
        assert int(ADMIN_DELEGATABLE_SCOPE) == 0x13
        assert DelegationScope.INVITE in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.REMOVE in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.READ_MEMBERS in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.DISTRIBUTE_KEY not in ADMIN_DELEGATABLE_SCOPE
        assert DelegationScope.REKEY not in ADMIN_DELEGATABLE_SCOPE

    def test_valid_scope_mask(self) -> None:
        """Test valid scope mask covers bits 0-4."""
        assert VALID_SCOPE_MASK == 0x1F


class TestDelegationTokenPayload:
    """Tests for DelegationTokenPayload dataclass."""

    def test_valid_payload(self) -> None:
        """Test creating a valid payload."""
        delegate = bytes(8)
        payload = DelegationTokenPayload(
            delegate=delegate,
            scope=int(DelegationScope.INVITE | DelegationScope.REMOVE),
            resource="team-alpha",
            expiry=int(time.time()) + 3600,
            seq=1,
        )
        assert payload.delegate == delegate
        assert payload.scope == 0x03
        assert payload.resource == "team-alpha"

    def test_invalid_delegate_length(self) -> None:
        """Test that short delegate IID is rejected."""
        with pytest.raises(ValueError, match="delegate must be 8 bytes"):
            DelegationTokenPayload(
                delegate=bytes(4),
                scope=int(DelegationScope.INVITE),
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_invalid_scope_bits(self) -> None:
        """Test that invalid scope bits are rejected."""
        with pytest.raises(ValueError, match="Invalid scope bits"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=0x20,  # bit 5 is invalid
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_empty_scope(self) -> None:
        """Test that empty scope is rejected."""
        with pytest.raises(ValueError, match="scope must grant at least one capability"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=0,
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_empty_resource(self) -> None:
        """Test that empty resource is rejected."""
        with pytest.raises(ValueError, match="resource must be non-empty"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=int(DelegationScope.INVITE),
                resource="",
                expiry=int(time.time()) + 3600,
                seq=1,
            )

    def test_invalid_expiry(self) -> None:
        """Test that non-positive expiry is rejected."""
        with pytest.raises(ValueError, match="expiry must be positive"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=int(DelegationScope.INVITE),
                resource="test",
                expiry=0,
                seq=1,
            )

    def test_negative_seq(self) -> None:
        """Test that negative seq is rejected."""
        with pytest.raises(ValueError, match="seq must be non-negative"):
            DelegationTokenPayload(
                delegate=bytes(8),
                scope=int(DelegationScope.INVITE),
                resource="test",
                expiry=int(time.time()) + 3600,
                seq=-1,
            )

    def test_cbor_roundtrip(self) -> None:
        """Test CBOR encode/decode roundtrip."""
        payload = DelegationTokenPayload(
            delegate=bytes(range(8)),
            scope=int(DelegationScope.INVITE | DelegationScope.READ_MEMBERS),
            resource="group-beta",
            expiry=1700000000,
            seq=100,
        )
        encoded = payload.to_cbor()
        decoded = DelegationTokenPayload.from_cbor(encoded)

        assert decoded.delegate == payload.delegate
        assert decoded.scope == payload.scope
        assert decoded.resource == payload.resource
        assert decoded.expiry == payload.expiry
        assert decoded.seq == payload.seq


class TestDelegationToken:
    """Tests for DelegationToken COSE_Sign1 wrapper."""

    @pytest.fixture
    def delegator_identity(self) -> Identity:
        """Create a delegator identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def delegate_identity(self) -> Identity:
        """Create a delegate identity for testing."""
        return Identity.from_seed(bytes([0xFF - i for i in range(32)]))

    @pytest.fixture
    def valid_token(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> DelegationToken:
        """Create a valid delegation token."""
        return create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE | DelegationScope.REMOVE,
            resource="team-alpha",
            expiry=int(time.time()) + 3600,
            seq=1,
        )

    def test_create_and_verify(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test creating and verifying a delegation token."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is True
        assert error is None

    def test_cose_sign1_roundtrip(self, valid_token: DelegationToken) -> None:
        """Test COSE_Sign1 encode/decode roundtrip."""
        encoded = valid_token.to_cose_sign1()
        decoded = decode_delegation_token(encoded)

        assert decoded.delegator_iid == valid_token.delegator_iid
        assert decoded.signature == valid_token.signature
        assert decoded.payload.delegate == valid_token.payload.delegate
        assert decoded.payload.scope == valid_token.payload.scope
        assert decoded.payload.resource == valid_token.payload.resource

    def test_protected_header_format(self) -> None:
        """Test protected header encodes correctly per spec."""
        protected = _encode_protected_header()
        decoded = cbor2.loads(protected)
        assert decoded == {COSE_ALG_LABEL: SCHNORR48_ED25519_ALG}

    def test_cose_sign1_structure(self, valid_token: DelegationToken) -> None:
        """Test COSE_Sign1 structure matches spec."""
        encoded = valid_token.to_cose_sign1()
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

    def test_invalid_delegator_iid_length(self) -> None:
        """Test that wrong delegator_iid length is rejected."""
        with pytest.raises(ValueError, match="delegator_iid must be 8 bytes"):
            DelegationToken(
                payload=DelegationTokenPayload(
                    delegate=bytes(8),
                    scope=1,
                    resource="test",
                    expiry=int(time.time()) + 3600,
                    seq=1,
                ),
                delegator_iid=bytes(4),
                signature=bytes(48),
            )

    def test_invalid_signature_length(self) -> None:
        """Test that wrong signature length is rejected."""
        with pytest.raises(ValueError, match="signature must be 48 bytes"):
            DelegationToken(
                payload=DelegationTokenPayload(
                    delegate=bytes(8),
                    scope=1,
                    resource="test",
                    expiry=int(time.time()) + 3600,
                    seq=1,
                ),
                delegator_iid=bytes(8),
                signature=bytes(32),
            )


class TestVerification:
    """Tests for delegation token verification."""

    @pytest.fixture
    def delegator_identity(self) -> Identity:
        """Create a delegator identity for testing."""
        return Identity.from_seed(bytes(range(32)))

    @pytest.fixture
    def delegate_identity(self) -> Identity:
        """Create a delegate identity for testing."""
        return Identity.from_seed(bytes([0xFF - i for i in range(32)]))

    def test_expired_token(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that expired tokens are rejected."""
        past_time = int(time.time()) - 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=past_time,
            seq=1,
        )

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "EXPIRED"

    def test_replay_detection(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that replay attacks are detected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=5,
        )

        # Should fail if cached_seq >= seq
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            cached_seq=5,
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "REPLAY_DETECTED"

        # Should pass with lower cached_seq
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            cached_seq=4,
            is_delegator_owner=True,
        )
        assert valid is True
        assert error is None

    def test_delegator_iid_mismatch(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that wrong delegator pubkey is rejected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Use different identity's pubkey
        wrong_identity = Identity.from_seed(bytes([0xAB] * 32))

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=wrong_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "DELEGATOR_IID_MISMATCH"

    def test_delegate_mismatch(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that wrong delegate IID is rejected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Use different delegate IID
        wrong_delegate = Identity.from_seed(bytes([0xCD] * 32))

        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=wrong_delegate.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "DELEGATE_MISMATCH"

    def test_tampered_signature(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that tampered signatures are rejected."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Tamper with signature
        tampered_sig = bytes([b ^ 0xFF for b in token.signature[:4]]) + token.signature[4:]
        tampered = DelegationToken(
            payload=token.payload,
            delegator_iid=token.delegator_iid,
            signature=tampered_sig,
        )

        valid, error = verify_delegation_token(
            tampered,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "SIGNATURE_INVALID"

    def test_admin_scope_exceeded(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that admin cannot delegate owner-only scopes."""
        future_time = int(time.time()) + 3600
        # Create token with owner-only scopes (distribute_key, rekey)
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.DISTRIBUTE_KEY | DelegationScope.REKEY,
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Verify as admin (should fail)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=False,  # Admin, not owner
        )
        assert valid is False
        assert error == "SCOPE_EXCEEDED"

        # Verify as owner (should succeed)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=True,  # Owner
        )
        assert valid is True
        assert error is None

    def test_admin_can_delegate_allowed_scopes(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that admin can delegate invite, remove, read_members."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=ADMIN_DELEGATABLE_SCOPE,  # invite | remove | read_members
            resource="team-alpha",
            expiry=future_time,
            seq=1,
        )

        # Verify as admin (should succeed)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="team-alpha",
            current_time=int(time.time()),
            is_delegator_owner=False,
        )
        assert valid is True
        assert error is None

    def test_resource_mismatch(
        self, delegator_identity: Identity, delegate_identity: Identity
    ) -> None:
        """Test that token for group A is rejected when accessing group B."""
        future_time = int(time.time()) + 3600
        token = create_delegation_token(
            identity=delegator_identity,
            delegate_iid=delegate_identity.iid,
            scope=DelegationScope.INVITE,
            resource="group-alpha",
            expiry=future_time,
            seq=1,
        )

        # Use token for group-alpha to access group-beta (should fail)
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="group-beta",  # Different resource
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is False
        assert error == "RESOURCE_MISMATCH"

        # Same resource should pass
        valid, error = verify_delegation_token(
            token,
            delegator_pubkey=delegator_identity.pubkey,
            delegate_iid=delegate_identity.iid,
            expected_resource="group-alpha",  # Correct resource
            current_time=int(time.time()),
            is_delegator_owner=True,
        )
        assert valid is True
        assert error is None


class TestCoseSign1Decoding:
    """Tests for COSE_Sign1 decoding error handling."""

    def test_invalid_array_length(self) -> None:
        """Test that non-4-element arrays are rejected."""
        bad_data = cbor2.dumps([b"protected", {}, b"payload"])
        with pytest.raises(ValueError, match="must be a 4-element array"):
            decode_delegation_token(bad_data)

    def test_wrong_algorithm(self) -> None:
        """Test that wrong algorithm is rejected."""
        # Create COSE_Sign1 with wrong algorithm
        protected = cbor2.dumps({COSE_ALG_LABEL: -7})  # ES256 instead
        payload = DelegationTokenPayload(
            delegate=bytes(8),
            scope=1,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )
        cose_array = [protected, {COSE_KID_LABEL: bytes(8)}, payload.to_cbor(), bytes(48)]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="Algorithm must be"):
            decode_delegation_token(bad_data)

    def test_invalid_kid_length(self) -> None:
        """Test that wrong kid length is rejected."""
        protected = _encode_protected_header()
        payload = DelegationTokenPayload(
            delegate=bytes(8),
            scope=1,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )
        cose_array = [protected, {COSE_KID_LABEL: bytes(4)}, payload.to_cbor(), bytes(48)]
        bad_data = cbor2.dumps(cose_array)

        with pytest.raises(ValueError, match="kid in unprotected header must be 8-byte IID"):
            decode_delegation_token(bad_data)


class TestCheckDelegationScope:
    """Tests for check_delegation_scope helper."""

    def test_single_scope_match(self) -> None:
        """Test checking single scope match."""
        identity = Identity.from_seed(bytes(range(32)))
        delegate = Identity.from_seed(bytes([0xFF] * 32))
        token = create_delegation_token(
            identity=identity,
            delegate_iid=delegate.iid,
            scope=DelegationScope.INVITE,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )

        assert check_delegation_scope(token, DelegationScope.INVITE) is True
        assert check_delegation_scope(token, DelegationScope.REMOVE) is False

    def test_multi_scope_match(self) -> None:
        """Test checking multiple scope match."""
        identity = Identity.from_seed(bytes(range(32)))
        delegate = Identity.from_seed(bytes([0xFF] * 32))
        token = create_delegation_token(
            identity=identity,
            delegate_iid=delegate.iid,
            scope=DelegationScope.INVITE | DelegationScope.REMOVE | DelegationScope.READ_MEMBERS,
            resource="test",
            expiry=int(time.time()) + 3600,
            seq=1,
        )

        # Single scopes
        assert check_delegation_scope(token, DelegationScope.INVITE) is True
        assert check_delegation_scope(token, DelegationScope.REMOVE) is True
        assert check_delegation_scope(token, DelegationScope.READ_MEMBERS) is True
        assert check_delegation_scope(token, DelegationScope.DISTRIBUTE_KEY) is False

        # Combined scopes
        assert check_delegation_scope(
            token, DelegationScope.INVITE | DelegationScope.REMOVE
        ) is True
        assert check_delegation_scope(
            token, DelegationScope.INVITE | DelegationScope.DISTRIBUTE_KEY
        ) is False


class TestPayloadIntegerKeys:
    """Tests verifying payload uses integer keys per spec."""

    def test_payload_uses_integer_keys(self) -> None:
        """Verify CBOR payload uses integer keys (1-5) per spec 18.8.6."""
        payload = DelegationTokenPayload(
            delegate=bytes(range(8)),
            scope=int(DelegationScope.INVITE),
            resource="team-alpha",
            expiry=1700000000,
            seq=42,
        )
        encoded = payload.to_cbor()
        decoded = cbor2.loads(encoded)

        # Spec says:
        # 1: delegate (bstr 8)
        # 2: scope (uint)
        # 3: resource (tstr)
        # 4: expiry (uint)
        # 5: seq (uint)
        assert 1 in decoded
        assert 2 in decoded
        assert 3 in decoded
        assert 4 in decoded
        assert 5 in decoded

        assert decoded[1] == bytes(range(8))
        assert decoded[2] == int(DelegationScope.INVITE)
        assert decoded[3] == "team-alpha"
        assert decoded[4] == 1700000000
        assert decoded[5] == 42
