# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for BR provisioning channel encryption.

Per spec section 8.7, BR provisioning channels MUST be encrypted and
authenticated. These tests verify:

1. EDHOC-based secure channel establishment
2. Seed encryption/decryption with AES-CCM
3. Authentication requirements (BR must authenticate)
4. State machine correctness
5. Error handling for tampered payloads

Test categories:
1. Happy path: Full provisioning flow
2. Channel establishment
3. Payload encryption/decryption
4. Authentication failures
5. State machine violations
6. Edge cases
"""

import os

import pytest

from lichen.crypto.edhoc import OscoreContext
from lichen.crypto.identity import Identity
from lichen.crypto.provisioning import (
    PAYLOAD_TYPE_ACK,
    PAYLOAD_TYPE_SEED,
    AuthenticationFailedError,
    BRProvisioningSession,
    ChannelNotEstablishedError,
    DecryptionFailedError,
    NodeProvisioningSession,
    ProvisioningError,
    ProvisioningPayload,
    ProvisioningState,
    _decrypt_ack,
    _decrypt_seed,
    _derive_provisioning_key,
    _encrypt_ack,
    _encrypt_seed,
)


class TestFullProvisioningFlow:
    """Test complete provisioning flow between BR and node."""

    def test_happy_path_provisioning(self):
        """Complete provisioning flow: EDHOC + seed transfer + ACK."""
        # Setup: BR has stable identity, node has ephemeral identity
        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))

        # Create sessions (BR knows node pubkey out-of-band, e.g., displayed on node)
        br_session = BRProvisioningSession(br_identity, node_ephemeral.pubkey)
        node_session = NodeProvisioningSession(node_ephemeral)

        # EDHOC handshake: Node initiates
        msg1 = node_session.create_message_1()
        assert node_session.state == ProvisioningState.EDHOC_IN_PROGRESS

        # BR responds
        msg2 = br_session.process_message_1(msg1)
        assert br_session.state == ProvisioningState.EDHOC_IN_PROGRESS

        # Node completes EDHOC (authenticates BR)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        assert node_session.state == ProvisioningState.ESTABLISHED

        # BR verifies node
        br_session.process_message_3(msg3)
        assert br_session.state == ProvisioningState.ESTABLISHED

        # BR provisions new keypair
        new_seed = os.urandom(32)
        encrypted_seed = br_session.encrypt_seed(new_seed)

        # Node decrypts and derives identity
        new_identity = node_session.decrypt_seed(encrypted_seed.encode())
        assert new_identity.seed == new_seed
        assert len(new_identity.pubkey) == 32

        # Node sends ACK
        ack = node_session.create_ack(new_identity.pubkey)
        assert node_session.state == ProvisioningState.COMPLETED

        # BR verifies ACK
        received_pubkey = br_session.decrypt_ack(ack.encode())
        assert received_pubkey == new_identity.pubkey
        assert br_session.state == ProvisioningState.COMPLETED

        # Cleanup
        br_session.wipe()
        node_session.wipe()

    def test_provisioning_with_known_seed(self):
        """Provisioning with deterministic seed for verification."""
        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([2] + [0] * 31))

        br_session = BRProvisioningSession(br_identity, node_ephemeral.pubkey)
        node_session = NodeProvisioningSession(node_ephemeral)

        # EDHOC handshake
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br_identity.pubkey)
        br_session.process_message_3(msg3)

        # Provision known seed
        known_seed = bytes([3] + [0] * 31)
        expected_identity = Identity.from_seed(known_seed)

        encrypted_seed = br_session.encrypt_seed(known_seed)
        new_identity = node_session.decrypt_seed(encrypted_seed.encode())

        # Verify derivation matches
        assert new_identity.pubkey == expected_identity.pubkey
        assert new_identity.iid == expected_identity.iid
        assert new_identity.ygg_addr == expected_identity.ygg_addr


class TestProvisioningPayload:
    """Tests for ProvisioningPayload encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Payload survives encode/decode cycle."""
        payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=os.urandom(13),
            ciphertext=os.urandom(40),  # 32 + 8 tag
        )

        encoded = payload.encode()
        decoded = ProvisioningPayload.decode(encoded)

        assert decoded.payload_type == payload.payload_type
        assert decoded.nonce == payload.nonce
        assert decoded.ciphertext == payload.ciphertext

    def test_decode_rejects_non_map(self):
        """decode() rejects non-map CBOR with generic error message.

        SECURITY: Error message must not reveal why decoding failed.
        """
        import cbor2

        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(cbor2.dumps([1, 2, 3]))

    def test_decode_rejects_missing_fields(self):
        """decode() rejects payloads missing required fields with generic error.

        SECURITY: Error message must not reveal why decoding failed.
        """
        import cbor2

        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(cbor2.dumps({"type": 1}))

    def test_decode_rejects_invalid_type_field(self):
        """decode() rejects non-integer type field with generic error.

        SECURITY: Error message must not reveal why decoding failed.
        """
        import cbor2

        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": "seed", "nonce": bytes(13), "ct": bytes(40)})
            )

    def test_decode_rejects_boolean_type_field(self):
        """decode() rejects boolean type field with generic error.

        SECURITY: In Python, bool is a subclass of int, so isinstance(True, int)
        returns True. This test verifies that boolean values are explicitly
        rejected even though True == 1 would match PAYLOAD_TYPE_SEED. Without
        this check, an attacker could send CBOR with "type": true and bypass
        strict type validation.
        """
        import cbor2

        # True == 1 == PAYLOAD_TYPE_SEED, but must still be rejected as wrong type
        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": True, "nonce": bytes(13), "ct": bytes(40)})
            )

        # False == 0, not a valid payload type, but must be rejected as wrong type
        # (not as invalid payload type value - the type check should catch it first)
        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": False, "nonce": bytes(13), "ct": bytes(40)})
            )

    def test_decode_rejects_non_bytes_nonce(self):
        """decode() rejects non-bytes nonce field with generic error.

        SECURITY: Error message must not reveal why decoding failed.
        """
        import cbor2

        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": PAYLOAD_TYPE_SEED, "nonce": "abc", "ct": bytes(40)})
            )

    def test_decode_rejects_non_bytes_ciphertext(self):
        """decode() rejects non-bytes ct field with generic error.

        SECURITY: Error message must not reveal why decoding failed.
        """
        import cbor2

        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": PAYLOAD_TYPE_SEED, "nonce": bytes(13), "ct": [1, 2, 3]})
            )

    def test_decode_rejects_invalid_payload_type(self):
        """decode() rejects unknown payload type values with generic error.

        SECURITY: Error message must not reveal why decoding failed.
        """
        import cbor2

        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": 0x99, "nonce": bytes(13), "ct": bytes(40)})
            )

    def test_decode_rejects_wrong_nonce_length(self):
        """decode() rejects nonce with incorrect length with generic error.

        SECURITY: Error message must not reveal why decoding failed.
        """
        import cbor2

        # Too short
        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": PAYLOAD_TYPE_SEED, "nonce": bytes(12), "ct": bytes(40)})
            )

        # Too long
        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(
                cbor2.dumps({"type": PAYLOAD_TYPE_SEED, "nonce": bytes(16), "ct": bytes(40)})
            )

    def test_decode_rejects_malformed_cbor(self):
        """decode() raises ProvisioningError for invalid CBOR data.

        SECURITY: Malformed input must not leak cbor2 exceptions; all parsing
        errors produce a generic error message to prevent oracle attacks.
        """
        # Truncated CBOR (incomplete map)
        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(b"\xbf\x64type\x01")

        # Invalid CBOR (indefinite length in invalid context)
        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(b"\x1f")

        # Empty input (premature EOF)
        with pytest.raises(ProvisioningError, match="decode failed"):
            ProvisioningPayload.decode(b"")


class TestSeedEncryption:
    """Tests for seed encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted seed decrypts correctly with same key."""
        # Create a mock OSCORE context for key derivation
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        seed = os.urandom(32)
        payload = _encrypt_seed(key, seed)
        decrypted = _decrypt_seed(key, payload)

        assert decrypted == seed

    def test_wrong_key_fails(self):
        """Decryption fails with wrong key (authentication tag invalid)."""
        ctx1 = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        ctx2 = OscoreContext(
            master_secret=bytes([1] + [0] * 15),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key1 = _derive_provisioning_key(ctx1)
        key2 = _derive_provisioning_key(ctx2)

        seed = os.urandom(32)
        payload = _encrypt_seed(key1, seed)

        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_seed(key2, payload)

    def test_tampered_ciphertext_fails(self):
        """Decryption fails if ciphertext is modified."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        seed = os.urandom(32)
        payload = _encrypt_seed(key, seed)

        # Tamper with ciphertext
        tampered_ct = bytes([payload.ciphertext[0] ^ 0xFF]) + payload.ciphertext[1:]
        tampered = ProvisioningPayload(
            payload_type=payload.payload_type,
            nonce=payload.nonce,
            ciphertext=tampered_ct,
        )

        with pytest.raises(DecryptionFailedError):
            _decrypt_seed(key, tampered)

    def test_wrong_payload_type_fails(self):
        """Decryption fails if payload type is wrong."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        seed = os.urandom(32)
        payload = _encrypt_seed(key, seed)

        # Change payload type
        wrong_type = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,  # Wrong type
            nonce=payload.nonce,
            ciphertext=payload.ciphertext,
        )

        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_seed(key, wrong_type)

    def test_encrypt_rejects_wrong_seed_length(self):
        """encrypt_seed() rejects non-32-byte seeds."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        with pytest.raises(ValueError, match="Seed must be 32 bytes"):
            _encrypt_seed(key, bytes(31))

    def test_decrypt_seed_rejects_invalid_nonce_length(self):
        """_decrypt_seed() rejects nonces with wrong length (defense-in-depth).

        SECURITY: Per AES-CCM-16-64-128, nonce must be exactly 13 bytes.
        This test verifies validation at decrypt time, which provides defense-in-depth
        in case a ProvisioningPayload is constructed directly (bypassing decode()).

        Note: Error message is intentionally generic to prevent oracle attacks.
        """
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        # Create valid payload first, then modify nonce length
        seed = os.urandom(32)
        valid_payload = _encrypt_seed(key, seed)

        # Test with nonce too short (12 bytes)
        short_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=bytes(12),  # Should be 13
            ciphertext=valid_payload.ciphertext,
        )
        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_seed(key, short_nonce_payload)

        # Test with nonce too long (16 bytes)
        long_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=bytes(16),  # Should be 13
            ciphertext=valid_payload.ciphertext,
        )
        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_seed(key, long_nonce_payload)

        # Test with empty nonce
        empty_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=b"",
            ciphertext=valid_payload.ciphertext,
        )
        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_seed(key, empty_nonce_payload)


class TestAckEncryption:
    """Tests for ACK (pubkey) encryption/decryption."""

    def test_encrypt_decrypt_ack_roundtrip(self):
        """Encrypted ACK decrypts correctly."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        pubkey = Identity.generate().pubkey
        payload = _encrypt_ack(key, pubkey)
        decrypted = _decrypt_ack(key, payload)

        assert decrypted == pubkey

    def test_ack_wrong_key_fails(self):
        """ACK decryption fails with wrong key."""
        ctx1 = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        ctx2 = OscoreContext(
            master_secret=bytes([1] + [0] * 15),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key1 = _derive_provisioning_key(ctx1)
        key2 = _derive_provisioning_key(ctx2)

        pubkey = Identity.generate().pubkey
        payload = _encrypt_ack(key1, pubkey)

        with pytest.raises(DecryptionFailedError):
            _decrypt_ack(key2, payload)

    def test_ack_tampered_ciphertext_fails(self):
        """ACK decryption fails if ciphertext is modified."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        pubkey = Identity.generate().pubkey
        payload = _encrypt_ack(key, pubkey)

        # Tamper with ciphertext
        tampered_ct = bytes([payload.ciphertext[0] ^ 0xFF]) + payload.ciphertext[1:]
        tampered = ProvisioningPayload(
            payload_type=payload.payload_type,
            nonce=payload.nonce,
            ciphertext=tampered_ct,
        )

        with pytest.raises(DecryptionFailedError):
            _decrypt_ack(key, tampered)

    def test_ack_wrong_payload_type_fails(self):
        """ACK decryption fails if payload type is wrong."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        pubkey = Identity.generate().pubkey
        payload = _encrypt_ack(key, pubkey)

        # Change payload type
        wrong_type = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,  # Wrong type
            nonce=payload.nonce,
            ciphertext=payload.ciphertext,
        )

        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_ack(key, wrong_type)

    def test_decrypt_ack_rejects_invalid_nonce_length(self):
        """_decrypt_ack() rejects nonces with wrong length (defense-in-depth).

        SECURITY: Per AES-CCM-16-64-128, nonce must be exactly 13 bytes.
        This test verifies validation at decrypt time, which provides defense-in-depth
        in case a ProvisioningPayload is constructed directly (bypassing decode()).

        Note: Error message is intentionally generic to prevent oracle attacks.
        """
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        # Create valid payload first, then modify nonce length
        pubkey = Identity.generate().pubkey
        valid_payload = _encrypt_ack(key, pubkey)

        # Test with nonce too short (12 bytes)
        short_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=bytes(12),  # Should be 13
            ciphertext=valid_payload.ciphertext,
        )
        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_ack(key, short_nonce_payload)

        # Test with nonce too long (16 bytes)
        long_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=bytes(16),  # Should be 13
            ciphertext=valid_payload.ciphertext,
        )
        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_ack(key, long_nonce_payload)

        # Test with empty nonce
        empty_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=b"",
            ciphertext=valid_payload.ciphertext,
        )
        with pytest.raises(DecryptionFailedError, match="decryption failed"):
            _decrypt_ack(key, empty_nonce_payload)


class TestInformationLeakagePrevention:
    """SECURITY: Verify error messages do not leak decryption failure reasons.

    Information leakage through error messages can enable oracle attacks where
    an attacker probes different inputs to learn about internal state. All
    decryption failures MUST produce identical, generic error messages regardless
    of whether the failure was due to:
    - Wrong payload type
    - Invalid nonce length
    - Authentication tag mismatch (wrong key/tampered ciphertext)
    - Invalid plaintext length

    See spec section 8.7 and OWASP crypto guidelines.
    """

    def test_seed_decryption_errors_are_identical(self):
        """All _decrypt_seed() failure modes produce identical error message."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)
        wrong_key = _derive_provisioning_key(
            OscoreContext(
                master_secret=bytes([1] + [0] * 15),
                master_salt=bytes(8),
                sender_id=b"\x00",
                recipient_id=b"\x01",
            )
        )

        seed = os.urandom(32)
        valid_payload = _encrypt_seed(key, seed)

        error_messages = []

        # Failure 1: Wrong payload type
        wrong_type = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=valid_payload.nonce,
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_seed(key, wrong_type)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Failure 2: Invalid nonce length
        short_nonce = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=bytes(12),
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_seed(key, short_nonce)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Failure 3: Wrong key (tag verification fails)
        try:
            _decrypt_seed(wrong_key, valid_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Failure 4: Tampered ciphertext (tag verification fails)
        tampered = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=valid_payload.nonce,
            ciphertext=bytes([valid_payload.ciphertext[0] ^ 0xFF])
            + valid_payload.ciphertext[1:],
        )
        try:
            _decrypt_seed(key, tampered)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # SECURITY: All error messages MUST be identical
        assert len(error_messages) == 4, "Expected 4 failure modes"
        assert all(
            msg == "decryption failed" for msg in error_messages
        ), f"Error messages differ, enabling oracle attacks: {error_messages}"

    def test_ack_decryption_errors_are_identical(self):
        """All _decrypt_ack() failure modes produce identical error message."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)
        wrong_key = _derive_provisioning_key(
            OscoreContext(
                master_secret=bytes([1] + [0] * 15),
                master_salt=bytes(8),
                sender_id=b"\x00",
                recipient_id=b"\x01",
            )
        )

        pubkey = Identity.generate().pubkey
        valid_payload = _encrypt_ack(key, pubkey)

        error_messages = []

        # Failure 1: Wrong payload type
        wrong_type = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=valid_payload.nonce,
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_ack(key, wrong_type)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Failure 2: Invalid nonce length
        short_nonce = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=bytes(12),
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_ack(key, short_nonce)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Failure 3: Wrong key (tag verification fails)
        try:
            _decrypt_ack(wrong_key, valid_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Failure 4: Tampered ciphertext (tag verification fails)
        tampered = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=valid_payload.nonce,
            ciphertext=bytes([valid_payload.ciphertext[0] ^ 0xFF])
            + valid_payload.ciphertext[1:],
        )
        try:
            _decrypt_ack(key, tampered)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # SECURITY: All error messages MUST be identical
        assert len(error_messages) == 4, "Expected 4 failure modes"
        assert all(
            msg == "decryption failed" for msg in error_messages
        ), f"Error messages differ, enabling oracle attacks: {error_messages}"

    def test_authentication_errors_are_generic(self):
        """AuthenticationFailedError messages do not leak exception details."""
        br_identity = Identity.from_seed(bytes(32))
        node_ephemeral = Identity.from_seed(bytes([1] + [0] * 31))
        wrong_br = Identity.from_seed(bytes([2] + [0] * 31))

        # Setup: Node tries to authenticate with wrong BR pubkey
        br_session = BRProvisioningSession(br_identity, node_ephemeral.pubkey)
        node_session = NodeProvisioningSession(node_ephemeral)

        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)

        # Node authenticates with wrong BR pubkey - should fail with generic message
        with pytest.raises(AuthenticationFailedError) as exc_info:
            node_session.process_message_2(msg2, wrong_br.pubkey)

        # SECURITY: Error message must not reveal internal exception details
        error_msg = str(exc_info.value)
        assert error_msg == "authentication failed", (
            f"Error message reveals details: {error_msg}"
        )
        # Verify no exception chaining that could leak internal state
        assert exc_info.value.__cause__ is None, (
            "Exception chaining leaks internal state"
        )

    def test_decode_errors_are_identical(self):
        """All ProvisioningPayload.decode() failure modes produce identical error message.

        SECURITY: Verbose error messages in decode() could enable oracle attacks
        by allowing an attacker to distinguish between:
        - Invalid CBOR encoding
        - Wrong CBOR structure (not a map)
        - Missing required fields
        - Wrong field types
        - Invalid payload type
        - Wrong nonce length

        All these failures MUST return identical error messages.
        """
        import cbor2

        error_messages = []

        # Failure 1: Invalid CBOR (malformed bytes)
        try:
            ProvisioningPayload.decode(b"\xff\xff\xff")
        except ProvisioningError as e:
            error_messages.append(str(e))

        # Failure 2: CBOR is not a map
        try:
            ProvisioningPayload.decode(cbor2.dumps([1, 2, 3]))
        except ProvisioningError as e:
            error_messages.append(str(e))

        # Failure 3: Missing required fields
        try:
            ProvisioningPayload.decode(cbor2.dumps({"type": 1}))
        except ProvisioningError as e:
            error_messages.append(str(e))

        # Failure 4: Wrong type field (string instead of int)
        try:
            ProvisioningPayload.decode(
                cbor2.dumps({"type": "seed", "nonce": bytes(13), "ct": bytes(40)})
            )
        except ProvisioningError as e:
            error_messages.append(str(e))

        # Failure 5: Boolean type field (bool is subclass of int in Python)
        try:
            ProvisioningPayload.decode(
                cbor2.dumps({"type": True, "nonce": bytes(13), "ct": bytes(40)})
            )
        except ProvisioningError as e:
            error_messages.append(str(e))

        # Failure 6: Wrong nonce field (string instead of bytes)
        try:
            ProvisioningPayload.decode(
                cbor2.dumps({"type": PAYLOAD_TYPE_SEED, "nonce": "abc", "ct": bytes(40)})
            )
        except ProvisioningError as e:
            error_messages.append(str(e))

        # Failure 7: Invalid payload type value
        try:
            ProvisioningPayload.decode(
                cbor2.dumps({"type": 0x99, "nonce": bytes(13), "ct": bytes(40)})
            )
        except ProvisioningError as e:
            error_messages.append(str(e))

        # Failure 8: Wrong nonce length
        try:
            ProvisioningPayload.decode(
                cbor2.dumps({"type": PAYLOAD_TYPE_SEED, "nonce": bytes(12), "ct": bytes(40)})
            )
        except ProvisioningError as e:
            error_messages.append(str(e))

        # SECURITY: All error messages MUST be identical
        assert len(error_messages) == 8, f"Expected 8 failure modes, got {len(error_messages)}"
        assert all(
            msg == "decode failed" for msg in error_messages
        ), f"Error messages differ, enabling oracle attacks: {error_messages}"

    def test_decode_error_does_not_chain_internal_exceptions(self):
        """ProvisioningPayload.decode() must not chain internal exceptions.

        SECURITY: Exception chains can reveal internal state (e.g.,
        specific cbor2 exception types or messages that indicate
        where parsing failed).
        """
        # Malformed CBOR that triggers cbor2 exception
        try:
            ProvisioningPayload.decode(b"\xff\xff\xff")
            pytest.fail("Expected ProvisioningError")
        except ProvisioningError as e:
            # __cause__ should be None (from None suppresses chain)
            assert e.__cause__ is None, (
                f"Exception chain leaked: {e.__cause__}"
            )


class TestBRSessionStateMachine:
    """Tests for BR session state transitions."""

    def test_initial_state_is_idle(self):
        """New session starts in IDLE state."""
        br = Identity.generate()
        node = Identity.generate()
        session = BRProvisioningSession(br, node.pubkey)
        assert session.state == ProvisioningState.IDLE

    def test_encrypt_before_established_fails(self):
        """encrypt_seed() fails if channel not established."""
        br = Identity.generate()
        node = Identity.generate()
        session = BRProvisioningSession(br, node.pubkey)

        with pytest.raises(ChannelNotEstablishedError):
            session.encrypt_seed(bytes(32))

    def test_decrypt_ack_before_established_fails(self):
        """decrypt_ack() fails if channel not established."""
        br = Identity.generate()
        node = Identity.generate()
        session = BRProvisioningSession(br, node.pubkey)

        with pytest.raises(ChannelNotEstablishedError):
            session.decrypt_ack(b"anything")

    def test_message_1_in_wrong_state_fails(self):
        """process_message_1() only valid in IDLE state."""
        br = Identity.generate()
        node = Identity.generate()

        session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        msg1 = node_session.create_message_1()
        session.process_message_1(msg1)  # Now in EDHOC_IN_PROGRESS

        with pytest.raises(ProvisioningError, match="Invalid state"):
            session.process_message_1(msg1)


class TestNodeSessionStateMachine:
    """Tests for Node session state transitions."""

    def test_initial_state_is_idle(self):
        """New session starts in IDLE state."""
        node = Identity.generate()
        session = NodeProvisioningSession(node)
        assert session.state == ProvisioningState.IDLE

    def test_decrypt_before_established_fails(self):
        """decrypt_seed() fails if channel not established."""
        node = Identity.generate()
        session = NodeProvisioningSession(node)

        with pytest.raises(ChannelNotEstablishedError):
            session.decrypt_seed(b"anything")

    def test_create_ack_before_established_fails(self):
        """create_ack() fails if channel not established."""
        node = Identity.generate()
        session = NodeProvisioningSession(node)

        with pytest.raises(ChannelNotEstablishedError):
            session.create_ack(bytes(32))

    def test_state_not_completed_if_create_ack_fails(self):
        """State transitions correctly when create_ack() fails.

        Regression test: state must not transition to COMPLETED before
        _encrypt_ack succeeds. With pubkey verification enabled, passing
        wrong pubkey or calling without decrypt_seed() sets state to FAILED.

        Note: Prior to pubkey verification, this tested that wrong pubkey
        length kept state ESTABLISHED. Now, pubkey mismatch check catches
        this first and sets state to FAILED (stronger security property).
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC to reach ESTABLISHED state
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        assert node_session.state == ProvisioningState.ESTABLISHED

        # Decrypt seed to enable pubkey verification
        seed = os.urandom(32)
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())

        assert node_session.state == ProvisioningState.ESTABLISHED

        # Attempt create_ack with mismatched pubkey - should fail with mismatch error
        # and transition state to FAILED (stronger security than staying ESTABLISHED)
        wrong_pubkey = Identity.generate().pubkey
        with pytest.raises(ProvisioningError, match="does not match derived"):
            node_session.create_ack(wrong_pubkey)

        # State transitions to FAILED on security violation (not COMPLETED, not ESTABLISHED)
        assert node_session.state == ProvisioningState.FAILED

    def test_create_ack_succeeds_with_correct_pubkey(self):
        """create_ack() succeeds and transitions to COMPLETED with correct pubkey.

        Verifies the happy path: when correct pubkey is provided, state
        transitions to COMPLETED and ACK payload is returned.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        # Decrypt seed
        seed = os.urandom(32)
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())

        assert node_session.state == ProvisioningState.ESTABLISHED

        # Create ACK with correct pubkey
        ack = node_session.create_ack(new_identity.pubkey)

        assert node_session.state == ProvisioningState.COMPLETED
        assert ack.payload_type == PAYLOAD_TYPE_ACK


class TestAuthenticationFailures:
    """Tests for authentication failure scenarios."""

    def test_wrong_br_pubkey_fails(self):
        """Node rejects BR if pubkey doesn't match signature."""
        br = Identity.generate()
        wrong_br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)

        # Node tries to verify with wrong BR pubkey
        with pytest.raises(AuthenticationFailedError):
            node_session.process_message_2(msg2, wrong_br.pubkey)

        assert node_session.state == ProvisioningState.FAILED

    def test_wrong_node_pubkey_at_message_3_fails(self):
        """BR rejects node if pubkey doesn't match signature in Message 3.

        EDHOC authentication happens at Message 3, not Message 1.
        Message 1 only contains the ephemeral key exchange data.
        """
        br = Identity.generate()
        node = Identity.generate()
        wrong_node = Identity.generate()

        # BR has wrong node pubkey (simulating wrong QR code scan, etc.)
        br_session = BRProvisioningSession(br, wrong_node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Message 1 succeeds (no signature verification yet)
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)

        # Node authenticates BR successfully (BR pubkey is correct)
        msg3 = node_session.process_message_2(msg2, br.pubkey)

        # BR fails to verify node's signature in Message 3
        # because BR expected wrong_node's pubkey
        with pytest.raises(AuthenticationFailedError):
            br_session.process_message_3(msg3)

        assert br_session.state == ProvisioningState.FAILED


class TestKeyDerivation:
    """Tests for provisioning key derivation."""

    def test_key_is_deterministic(self):
        """Same OSCORE context produces same provisioning key."""
        ctx = OscoreContext(
            master_secret=bytes(range(16)),
            master_salt=bytes(range(8)),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )

        key1 = _derive_provisioning_key(ctx)
        key2 = _derive_provisioning_key(ctx)

        assert key1 == key2

    def test_different_contexts_different_keys(self):
        """Different OSCORE contexts produce different keys."""
        ctx1 = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        ctx2 = OscoreContext(
            master_secret=bytes([1] + [0] * 15),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )

        key1 = _derive_provisioning_key(ctx1)
        key2 = _derive_provisioning_key(ctx2)

        assert key1 != key2

    def test_key_length(self):
        """Provisioning key is correct length (16 bytes for AES-128)."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )

        key = _derive_provisioning_key(ctx)
        assert len(key) == 16


class TestWipe:
    """Tests for secure memory cleanup."""

    def test_br_wipe_clears_sensitive_data(self):
        """wipe() clears sensitive fields."""
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        # Provision and store seed
        seed = os.urandom(32)
        br_session.encrypt_seed(seed)

        # Wipe
        br_session.wipe()

        # Verify cleared
        assert br_session._provisioned_seed == b""
        assert br_session._prov_key == b""
        assert br_session._oscore_ctx is None
        assert br_session._edhoc is None

    def test_node_wipe_clears_sensitive_data(self):
        """wipe() clears sensitive fields on node."""
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        node_session.process_message_2(msg2, br.pubkey)

        node_session.wipe()

        assert node_session._prov_key == b""
        assert node_session._oscore_ctx is None
        assert node_session._edhoc is None

    def test_br_wipe_resets_state_to_idle(self):
        """wipe() sets state to IDLE so session is no longer usable.

        SECURITY: Per spec 8.7, after wipe() the session must not be usable
        for cryptographic operations. State must reflect this.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC and reach ESTABLISHED state
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        assert br_session.state == ProvisioningState.ESTABLISHED

        # Wipe should reset state to IDLE
        br_session.wipe()
        assert br_session.state == ProvisioningState.IDLE

    def test_node_wipe_resets_state_to_idle(self):
        """wipe() sets state to IDLE so session is no longer usable.

        SECURITY: Per spec 8.7, after wipe() the session must not be usable
        for cryptographic operations. State must reflect this.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC and reach ESTABLISHED state
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        node_session.process_message_2(msg2, br.pubkey)

        assert node_session.state == ProvisioningState.ESTABLISHED

        # Wipe should reset state to IDLE
        node_session.wipe()
        assert node_session.state == ProvisioningState.IDLE

    def test_br_wipe_from_completed_state(self):
        """wipe() resets state even from COMPLETED state."""
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete full provisioning flow
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        seed = os.urandom(32)
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())
        ack = node_session.create_ack(new_identity.pubkey)
        br_session.decrypt_ack(ack.encode())

        assert br_session.state == ProvisioningState.COMPLETED

        # Wipe should still reset to IDLE
        br_session.wipe()
        assert br_session.state == ProvisioningState.IDLE

    def test_session_not_usable_after_wipe(self):
        """After wipe(), session operations fail with appropriate errors.

        SECURITY: Ensures wiped sessions cannot be reused for crypto operations.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        # Wipe both sessions
        br_session.wipe()
        node_session.wipe()

        # BR session operations should fail (state is IDLE)
        with pytest.raises(ChannelNotEstablishedError):
            br_session.encrypt_seed(bytes(32))

        with pytest.raises(ChannelNotEstablishedError):
            br_session.decrypt_ack(b"anything")

        # Node session operations should fail (state is IDLE)
        with pytest.raises(ChannelNotEstablishedError):
            node_session.decrypt_seed(b"anything")

        with pytest.raises(ChannelNotEstablishedError):
            node_session.create_ack(bytes(32))


class TestNodePubkeyRequired:
    """Tests for node pubkey requirement at construction."""

    def test_br_requires_node_pubkey(self):
        """BR requires node pubkey at construction."""
        br = Identity.generate()
        node = Identity.generate()

        # BR knows node's pubkey (from QR scan, pre-provisioned, etc.)
        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)

        br_session.process_message_3(msg3)
        assert br_session.state == ProvisioningState.ESTABLISHED

    def test_br_rejects_invalid_pubkey_length(self):
        """BR rejects node pubkey of wrong length."""
        br = Identity.generate()

        with pytest.raises(ValueError, match="node_pubkey must be 32 bytes"):
            BRProvisioningSession(br, bytes(31))

        with pytest.raises(ValueError, match="node_pubkey must be 32 bytes"):
            BRProvisioningSession(br, bytes(33))


class TestPubkeyVerification:
    """Tests for ACK pubkey verification (both BR and node side)."""

    def test_br_decrypt_ack_without_seed_fails(self):
        """BR decrypt_ack() MUST fail if encrypt_seed() was never called.

        SECURITY: Per spec 8.7, BR MUST verify node derived the correct pubkey.
        If no seed was provisioned, verification is impossible and MUST fail.
        This prevents skipping verification due to missing seed state.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC handshake
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)
        assert br_session.state == ProvisioningState.ESTABLISHED

        # Create a valid ACK payload (bypassing normal flow)
        # This simulates an attacker trying to inject their own pubkey
        # without the BR having provisioned a seed
        attacker_pubkey = Identity.generate().pubkey
        fake_ack = _encrypt_ack(
            _derive_provisioning_key(br_session._oscore_ctx),
            attacker_pubkey,
        )

        # decrypt_ack() MUST reject because no seed was provisioned
        with pytest.raises(ProvisioningError, match="no seed provisioned"):
            br_session.decrypt_ack(fake_ack.encode())

        assert br_session.state == ProvisioningState.FAILED

    def test_node_create_ack_without_seed_fails(self):
        """Node create_ack() MUST fail if decrypt_seed() was never called.

        SECURITY: Per spec 8.7, node MUST verify pubkey matches provisioned seed.
        If no seed was decrypted, verification is impossible and MUST fail.
        This is defense-in-depth that catches bugs/attacks before BR sees them.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC handshake
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)
        assert node_session.state == ProvisioningState.ESTABLISHED

        # Attempt to create ACK without calling decrypt_seed() first
        arbitrary_pubkey = Identity.generate().pubkey
        with pytest.raises(ProvisioningError, match="no seed decrypted"):
            node_session.create_ack(arbitrary_pubkey)

        assert node_session.state == ProvisioningState.FAILED

    def test_node_create_ack_with_wrong_pubkey_fails(self):
        """Node create_ack() MUST fail if pubkey doesn't match derived value.

        SECURITY: Per spec 8.7, node MUST verify pubkey matches what was derived
        from provisioned seed. This is defense-in-depth - catches mismatches
        before they propagate to BR and protects against implementation bugs.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        # Provision
        seed = os.urandom(32)
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())

        # Attempt to create ACK with wrong pubkey (simulating bug/attack)
        wrong_pubkey = Identity.generate().pubkey
        assert wrong_pubkey != new_identity.pubkey  # Sanity check

        with pytest.raises(ProvisioningError, match="does not match derived"):
            node_session.create_ack(wrong_pubkey)

        assert node_session.state == ProvisioningState.FAILED

    def test_br_wrong_ack_pubkey_fails(self):
        """BR detects if ACK contains wrong pubkey (defense-in-depth test).

        This test bypasses node-side verification by directly creating an
        encrypted ACK to verify the BR still catches pubkey mismatches.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        # Provision
        seed = os.urandom(32)
        encrypted = br_session.encrypt_seed(seed)
        _ = node_session.decrypt_seed(encrypted.encode())

        # Bypass node-side verification by directly encrypting wrong pubkey
        wrong_pubkey = Identity.generate().pubkey
        fake_ack = _encrypt_ack(
            _derive_provisioning_key(node_session._oscore_ctx),
            wrong_pubkey,
        )

        with pytest.raises(ProvisioningError, match="wrong pubkey"):
            br_session.decrypt_ack(fake_ack.encode())

        assert br_session.state == ProvisioningState.FAILED

    def test_node_wipe_clears_provisioned_pubkey(self):
        """wipe() clears _provisioned_pubkey field.

        SECURITY: Sensitive state must be wiped to prevent reuse attacks.
        """
        br = Identity.generate()
        node = Identity.generate()

        br_session = BRProvisioningSession(br, node.pubkey)
        node_session = NodeProvisioningSession(node)

        # Complete EDHOC
        msg1 = node_session.create_message_1()
        msg2 = br_session.process_message_1(msg1)
        msg3 = node_session.process_message_2(msg2, br.pubkey)
        br_session.process_message_3(msg3)

        # Provision and store pubkey internally
        seed = os.urandom(32)
        encrypted = br_session.encrypt_seed(seed)
        new_identity = node_session.decrypt_seed(encrypted.encode())
        assert node_session._provisioned_pubkey == new_identity.pubkey

        # Wipe
        node_session.wipe()

        # Verify cleared
        assert node_session._provisioned_pubkey == b""


class TestNoInformationLeakage:
    """Tests verifying error messages don't reveal internal state.

    SECURITY: Error messages must be generic to prevent oracle attacks.
    Attackers should not be able to distinguish between:
    - Wrong payload type
    - Invalid nonce length
    - Authentication tag failure
    - Wrong plaintext length

    All these failures should produce identical error messages.
    """

    def test_decryption_errors_are_indistinguishable(self):
        """All decryption failures produce identical error messages.

        SECURITY: An attacker trying different payloads should not be able
        to determine which validation step failed based on the error message.
        """
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        # Generate a valid payload for reference
        seed = os.urandom(32)
        valid_payload = _encrypt_seed(key, seed)

        # Collect error messages from different failure modes
        error_messages = []

        # 1. Wrong payload type
        wrong_type_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,  # Wrong type for seed decryption
            nonce=valid_payload.nonce,
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_seed(key, wrong_type_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # 2. Invalid nonce length
        bad_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=bytes(12),  # Wrong length (should be 13)
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_seed(key, bad_nonce_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # 3. Tampered ciphertext (authentication tag failure)
        tampered_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,
            nonce=valid_payload.nonce,
            ciphertext=bytes([valid_payload.ciphertext[0] ^ 0xFF])
            + valid_payload.ciphertext[1:],
        )
        try:
            _decrypt_seed(key, tampered_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # 4. Wrong key
        wrong_key = os.urandom(16)
        try:
            _decrypt_seed(wrong_key, valid_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # All error messages must be identical
        assert len(error_messages) == 4
        assert all(msg == "decryption failed" for msg in error_messages), (
            f"Error messages should be identical, got: {error_messages}"
        )

    def test_ack_decryption_errors_are_indistinguishable(self):
        """ACK decryption failures also produce identical error messages."""
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        # Generate a valid ACK payload
        pubkey = Identity.generate().pubkey
        valid_payload = _encrypt_ack(key, pubkey)

        error_messages = []

        # Wrong type
        wrong_type_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_SEED,  # Wrong type for ACK
            nonce=valid_payload.nonce,
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_ack(key, wrong_type_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Invalid nonce
        bad_nonce_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=bytes(16),  # Wrong length
            ciphertext=valid_payload.ciphertext,
        )
        try:
            _decrypt_ack(key, bad_nonce_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # Tampered ciphertext
        tampered_payload = ProvisioningPayload(
            payload_type=PAYLOAD_TYPE_ACK,
            nonce=valid_payload.nonce,
            ciphertext=bytes(len(valid_payload.ciphertext)),  # All zeros
        )
        try:
            _decrypt_ack(key, tampered_payload)
        except DecryptionFailedError as e:
            error_messages.append(str(e))

        # All identical
        assert len(error_messages) == 3
        assert all(msg == "decryption failed" for msg in error_messages)

    def test_error_does_not_chain_internal_exceptions(self):
        """DecryptionFailedError must not chain internal exceptions.

        SECURITY: Exception chains can reveal internal state (e.g.,
        "InvalidTag" vs "InvalidNonce" from cryptography library).
        Both _decrypt_seed() and _decrypt_ack() must suppress chaining.
        """
        ctx = OscoreContext(
            master_secret=bytes(16),
            master_salt=bytes(8),
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )
        key = _derive_provisioning_key(ctx)

        # Test _decrypt_seed() does not chain exceptions
        seed = os.urandom(32)
        seed_payload = _encrypt_seed(key, seed)

        # Tamper to trigger internal crypto exception
        tampered_seed = ProvisioningPayload(
            payload_type=seed_payload.payload_type,
            nonce=seed_payload.nonce,
            ciphertext=bytes([seed_payload.ciphertext[0] ^ 0xFF])
            + seed_payload.ciphertext[1:],
        )

        try:
            _decrypt_seed(key, tampered_seed)
            pytest.fail("Expected DecryptionFailedError from _decrypt_seed")
        except DecryptionFailedError as e:
            # __cause__ should be None (from None suppresses chain)
            assert e.__cause__ is None, (
                f"_decrypt_seed exception chain leaked: {e.__cause__}"
            )

        # Test _decrypt_ack() does not chain exceptions
        pubkey = Identity.generate().pubkey
        ack_payload = _encrypt_ack(key, pubkey)

        # Tamper to trigger internal crypto exception
        tampered_ack = ProvisioningPayload(
            payload_type=ack_payload.payload_type,
            nonce=ack_payload.nonce,
            ciphertext=bytes([ack_payload.ciphertext[0] ^ 0xFF])
            + ack_payload.ciphertext[1:],
        )

        try:
            _decrypt_ack(key, tampered_ack)
            pytest.fail("Expected DecryptionFailedError from _decrypt_ack")
        except DecryptionFailedError as e:
            # __cause__ should be None (from None suppresses chain)
            assert e.__cause__ is None, (
                f"_decrypt_ack exception chain leaked: {e.__cause__}"
            )
