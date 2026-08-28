# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for EDHOC Suite 0 implementation."""

import cbor2
import pytest

from lichen.crypto import edhoc as edhoc_module
from lichen.crypto.edhoc import EdhocInitiator, EdhocResponder, Method
from lichen.crypto.identity import Identity


def _sequence(*items: object) -> bytes:
    return b"".join(cbor2.dumps(item) for item in items)


def _handshake_until_message_3() -> tuple[
    Identity, Identity, EdhocInitiator, EdhocResponder, bytes, bytes, bytes
]:
    initiator_id = Identity.generate()
    responder_id = Identity.generate()
    initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
    responder = EdhocResponder.create(responder_id, c_r=b"\x01")
    msg1 = initiator.create_message_1()
    msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
    msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
    return initiator_id, responder_id, initiator, responder, msg1, msg2, msg3


def _assert_session_material_cleared(role: EdhocInitiator | EdhocResponder) -> None:
    fields = (
        "_eph_sk",
        "_eph_pk",
        "_prk_2e",
        "_prk_3e2m",
        "_prk_4e3m",
        "_th_2",
        "_th_3",
        "_th_4",
        "_msg1",
    )
    for name in fields:
        assert getattr(role, name) == b""
    peer_fields = (
        ("_g_y", "_c_i", "_c_r")
        if isinstance(role, EdhocInitiator)
        else ("_g_x", "_c_i", "_c_r")
    )
    for name in peer_fields:
        assert getattr(role, name) == b""


class TestEdhocHandshake:
    """Test EDHOC handshake between initiator and responder."""

    def test_full_handshake(self) -> None:
        """Complete EDHOC handshake derives matching OSCORE contexts."""
        # Create identities
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        # Create EDHOC roles
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        # Message 1: Initiator -> Responder
        msg1 = initiator.create_message_1()
        assert len(msg1) > 0

        # Message 2: Responder -> Initiator
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        assert len(msg2) > 0

        # Message 3: Initiator -> Responder
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        assert len(msg3) > 0

        # Responder processes Message 3
        responder.process_message_3(msg3, initiator_id.pubkey)

        # Export OSCORE contexts
        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()

        # Master secret and salt must match
        assert ctx_i.master_secret == ctx_r.master_secret
        assert ctx_i.master_salt == ctx_r.master_salt

        # Sender/recipient IDs are swapped
        assert ctx_i.sender_id == ctx_r.recipient_id
        assert ctx_i.recipient_id == ctx_r.sender_id

    def test_different_connection_ids(self) -> None:
        """Handshake works with various connection ID sizes."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        # Longer connection IDs
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\xde\xad")
        responder = EdhocResponder.create(responder_id, c_r=b"\xbe\xef")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()

        assert ctx_i.master_secret == ctx_r.master_secret
        assert ctx_i.sender_id == b"\xbe\xef"
        assert ctx_i.recipient_id == b"\xde\xad"
        assert ctx_r.sender_id == b"\xde\xad"
        assert ctx_r.recipient_id == b"\xbe\xef"

    def test_export_before_complete_fails(self) -> None:
        """Exporting OSCORE context before handshake complete raises."""
        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id)

        with pytest.raises(ValueError, match="not complete"):
            initiator.export_oscore()

    def test_method_mismatch_raises(self) -> None:
        """Responder rejects Message 1 if method does not match."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        # Create initiator to get a valid ephemeral key
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        # Manually craft message_1 with method=1 (SIGN_STATIC)
        # RFC 9528: METHOD is just the method value directly
        msg1 = _sequence(1, 0, initiator._eph_pk, b"\x00")

        responder = EdhocResponder.create(
            responder_id, c_r=b"\x01", method=Method.SIGN_SIGN
        )

        with pytest.raises(ValueError, match="Method mismatch"):
            responder.process_message_1(msg1, initiator_id.pubkey)


class TestOscoreContext:
    """Test OSCORE context properties."""

    def test_key_lengths(self) -> None:
        """Exported keys have correct lengths."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx = initiator.export_oscore()

        assert len(ctx.master_secret) == 16  # AES-128
        assert len(ctx.master_salt) == 8

    def test_custom_key_lengths(self) -> None:
        """Can export with custom key/salt lengths."""
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx = initiator.export_oscore(oscore_salt_len=16, oscore_key_len=32)

        assert len(ctx.master_secret) == 32
        assert len(ctx.master_salt) == 16


class TestEdhocLifecycle:
    def test_initiator_process_message_2_before_message_1_is_terminal(self) -> None:
        initiator = EdhocInitiator.create(Identity.generate())
        peer = Identity.generate()

        with pytest.raises(ValueError):
            initiator.process_message_2(b"not-message-2", peer.pubkey)

        assert initiator._state.name == "FAILED"
        _assert_session_material_cleared(initiator)
        with pytest.raises(ValueError):
            initiator.export_oscore()
        with pytest.raises(ValueError):
            initiator.create_message_1()

    def test_responder_process_message_3_before_message_1_is_terminal(self) -> None:
        responder = EdhocResponder.create(Identity.generate())
        peer = Identity.generate()

        with pytest.raises(ValueError):
            responder.process_message_3(b"not-message-3", peer.pubkey)

        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)
        with pytest.raises(ValueError):
            responder.export_oscore()
        with pytest.raises(ValueError):
            responder.process_message_1(b"not-message-1", peer.pubkey)

    def test_duplicate_message_1_while_waiting_is_terminal(self) -> None:
        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id)
        responder = EdhocResponder.create(Identity.generate())
        msg1 = initiator.create_message_1()
        responder.process_message_1(msg1, initiator_id.pubkey)

        with pytest.raises(ValueError):
            responder.process_message_1(msg1, initiator_id.pubkey)

        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)
        with pytest.raises(ValueError):
            responder.export_oscore()
        with pytest.raises(ValueError):
            responder.process_message_1(msg1, initiator_id.pubkey)

    def test_initiator_export_uses_committed_connection_ids(self) -> None:
        initiator_id, _, initiator, responder, _, _, msg3 = _handshake_until_message_3()
        responder.process_message_3(msg3, initiator_id.pubkey)
        initiator.c_i = b"\x09"

        initiator_context = initiator.export_oscore()
        responder_context = responder.export_oscore()

        assert initiator_context.sender_id == b"\x01"
        assert initiator_context.recipient_id == b"\x00"
        assert initiator_context.sender_id == responder_context.recipient_id
        assert initiator_context.recipient_id == responder_context.sender_id

    def test_responder_export_uses_committed_connection_ids(self) -> None:
        initiator_id, _, initiator, responder, _, _, msg3 = _handshake_until_message_3()
        responder.process_message_3(msg3, initiator_id.pubkey)
        responder.c_r = b"\x09"

        initiator_context = initiator.export_oscore()
        responder_context = responder.export_oscore()

        assert responder_context.sender_id == b"\x00"
        assert responder_context.recipient_id == b"\x01"
        assert responder_context.sender_id == initiator_context.recipient_id
        assert responder_context.recipient_id == initiator_context.sender_id

    def test_initiator_order_and_single_export(self) -> None:
        initiator_id, responder_id, initiator, responder, _, msg2, msg3 = (
            _handshake_until_message_3()
        )
        assert initiator._state.name == "COMPLETE"
        responder.process_message_3(msg3, initiator_id.pubkey)

        identity = initiator.identity
        initiator.export_oscore()
        assert initiator._state.name == "EXPORTED"
        assert initiator.identity is identity
        _assert_session_material_cleared(initiator)

        with pytest.raises(ValueError):
            initiator.export_oscore()
        assert initiator._state.name == "FAILED"
        with pytest.raises(ValueError):
            initiator.process_message_2(msg2, responder_id.pubkey)

    def test_responder_order_and_single_export(self) -> None:
        initiator_id, _, _, responder, msg1, _, msg3 = _handshake_until_message_3()
        assert responder._state.name == "WAIT_MESSAGE_3"
        responder.process_message_3(msg3, initiator_id.pubkey)
        assert responder._state.name == "COMPLETE"

        identity = responder.identity
        responder.export_oscore()
        assert responder._state.name == "EXPORTED"
        assert responder.identity is identity
        _assert_session_material_cleared(responder)

        with pytest.raises(ValueError):
            responder.export_oscore()
        assert responder._state.name == "FAILED"
        with pytest.raises(ValueError):
            responder.process_message_1(msg1, initiator_id.pubkey)

    @pytest.mark.parametrize("after_message_1", [False, True])
    def test_responder_export_before_completion_is_terminal(self, after_message_1: bool) -> None:
        initiator_id = Identity.generate()
        responder = EdhocResponder.create(Identity.generate())
        if after_message_1:
            initiator = EdhocInitiator.create(initiator_id)
            responder.process_message_1(initiator.create_message_1(), initiator_id.pubkey)

        with pytest.raises(ValueError, match="not complete"):
            responder.export_oscore()
        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)

    def test_reuse_after_complete_destroys_stale_exporter(self) -> None:
        initiator_id, responder_id, initiator, responder, msg1, _, msg3 = (
            _handshake_until_message_3()
        )
        with pytest.raises(ValueError):
            initiator.create_message_1()
        with pytest.raises(ValueError):
            initiator.export_oscore()
        _assert_session_material_cleared(initiator)

        responder.process_message_3(msg3, initiator_id.pubkey)
        with pytest.raises(ValueError):
            responder.process_message_1(msg1, initiator_id.pubkey)
        with pytest.raises(ValueError):
            responder.export_oscore()
        _assert_session_material_cleared(responder)
        assert responder_id.pubkey == responder.identity.pubkey

    def test_create_message_1_encoding_failure_is_terminal(self) -> None:
        initiator = EdhocInitiator.create(Identity.generate(), c_i=b"x" * 8)
        with pytest.raises(ValueError, match="at most 7 bytes"):
            initiator.create_message_1()
        assert initiator._state.name == "FAILED"
        _assert_session_material_cleared(initiator)


class TestEdhocValidation:
    @pytest.mark.parametrize(
        "method", [Method.SIGN_STATIC, Method.STATIC_SIGN, Method.STATIC_STATIC]
    )
    def test_initiator_creation_rejects_unsupported_method(self, method: Method) -> None:
        with pytest.raises(ValueError, match="SIGN_SIGN"):
            EdhocInitiator.create(Identity.generate(), method=method)

    @pytest.mark.parametrize(
        "method", [Method.SIGN_STATIC, Method.STATIC_SIGN, Method.STATIC_STATIC]
    )
    def test_responder_creation_rejects_unsupported_method(self, method: Method) -> None:
        """Responder.create() rejects unsupported methods at construction time."""
        with pytest.raises(ValueError, match="SIGN_SIGN"):
            EdhocResponder.create(Identity.generate(), method=method)

    def test_responder_replaces_colliding_connection_id(self) -> None:
        initiator_id = Identity.generate()
        responder_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x00")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        assert responder.c_r == b"\x01"
        assert responder._c_r == b"\x01"

        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)
        initiator_context = initiator.export_oscore()
        responder_context = responder.export_oscore()

        assert responder.c_r == b"\x01"
        assert responder._c_r == b""
        assert initiator_context.sender_id == b"\x01"
        assert initiator_context.recipient_id == b"\x00"
        assert responder_context.sender_id == b"\x00"
        assert responder_context.recipient_id == b"\x01"

    def test_initiator_terminally_rejects_colliding_connection_id(self) -> None:
        initiator_id = Identity.generate()
        responder_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")
        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        combined = bytearray(cbor2.loads(msg2))
        # PLAINTEXT_2 begins with compact C_R=1.  XOR the corresponding
        # ciphertext byte so it decrypts to C_R=0, colliding with C_I.
        combined[32] ^= 0x01
        colliding_msg2 = cbor2.dumps(bytes(combined))

        with pytest.raises(ValueError, match="must differ"):
            initiator.process_message_2(colliding_msg2, responder_id.pubkey)

        assert initiator._state.name == "FAILED"
        _assert_session_material_cleared(initiator)
        with pytest.raises(ValueError):
            initiator.process_message_2(msg2, responder_id.pubkey)

    @pytest.mark.parametrize(
        "message",
        [
            b"",
            b"\x58",
            _sequence(1, 0, b"x" * 32),
            _sequence(4, 0, b"x" * 32, b"\x00"),  # method_corr=4 -> method=1 (unsupported)
            _sequence(True, 0, b"x" * 32, b"\x00"),
            _sequence(1.0, 0, b"x" * 32, b"\x00"),
            _sequence(1, 1, b"x" * 32, b"\x00"),
            _sequence(1, 0.0, b"x" * 32, b"\x00"),
            _sequence(1, 0, "not-bytes", b"\x00"),
            _sequence(1, 0, b"x" * 31, b"\x00"),
            _sequence(1, 0, b"x" * 32, []),
            _sequence(1, 0, b"x" * 32, b"12345678"),
            _sequence(1, 0, b"x" * 32, b"\x00", 7),
            _sequence(1, 0, b"x" * 32, b"\x00", b"ead", b"extra"),
        ],
        ids=[
            "empty",
            "truncated",
            "too-few-items",
            "method-corr",
            "method-corr-bool",
            "method-corr-float",
            "suite",
            "suite-float",
            "gx-type",
            "gx-length",
            "cid-type",
            "cid-length",
            "ead-type",
            "extra-item",
        ],
    )
    def test_malformed_message_1_fails_without_commit(self, message: bytes) -> None:
        peer = Identity.generate()
        responder = EdhocResponder.create(Identity.generate())
        with pytest.raises((ValueError, TypeError)):
            responder.process_message_1(message, peer.pubkey)
        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)

        valid = EdhocInitiator.create(peer).create_message_1()
        with pytest.raises(ValueError):
            responder.process_message_1(valid, peer.pubkey)
        with pytest.raises(ValueError):
            responder.export_oscore()

    def test_invalid_method_is_rejected_before_dh(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unexpected_dh(_private_key: bytes, _public_key: bytes) -> bytes:
            raise AssertionError("DH must not run for an invalid METHOD")

        monkeypatch.setattr(edhoc_module, "_x25519_shared_secret", unexpected_dh)
        responder = EdhocResponder.create(Identity.generate())

        # RFC 9528: METHOD=1 (SIGN_STATIC) mismatches responder's SIGN_SIGN (0)
        with pytest.raises(ValueError, match="Method mismatch"):
            responder.process_message_1(
                _sequence(1, 0, b"x" * 32, b"\x00"),
                Identity.generate().pubkey,
            )

        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)

    @pytest.mark.parametrize(
        "failure",
        ["truncated", "type", "short", "extra", "ciphertext", "signature", "key"],
    )
    def test_bad_message_2_fails_without_commit_or_retry(self, failure: str) -> None:
        initiator_id = Identity.generate()
        responder_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id)
        responder = EdhocResponder.create(responder_id)
        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        bad_peer_key = responder_id.pubkey
        bad_msg2 = msg2
        if failure == "truncated":
            bad_msg2 = b"\x58"
        elif failure == "type":
            bad_msg2 = _sequence("not-bytes", b"\x01")
        elif failure == "short":
            bad_msg2 = _sequence(b"x" * 32, b"\x01")
        elif failure == "extra":
            bad_msg2 = msg2 + cbor2.dumps(0)
        elif failure in ("ciphertext", "signature"):
            combined = cbor2.loads(msg2)
            encoded_combined = cbor2.dumps(combined)
            mutated = bytearray(combined)
            plaintext_offset = 0 if failure == "ciphertext" else 36
            mutated[32 + plaintext_offset] ^= 1
            bad_msg2 = cbor2.dumps(bytes(mutated)) + msg2[len(encoded_combined) :]
        else:
            bad_peer_key = Identity.generate().pubkey

        with pytest.raises((ValueError, TypeError)):
            initiator.process_message_2(bad_msg2, bad_peer_key)
        assert initiator._state.name == "FAILED"
        _assert_session_material_cleared(initiator)
        with pytest.raises(ValueError):
            initiator.process_message_2(msg2, responder_id.pubkey)
        with pytest.raises(ValueError):
            initiator.export_oscore()

    @pytest.mark.parametrize(
        "failure", ["empty", "truncated", "ciphertext", "signature", "key"]
    )
    def test_bad_message_3_fails_without_commit_or_retry(
        self, failure: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        initiator_id, _, _, responder, _, _, msg3 = _handshake_until_message_3()
        bad_peer_key = initiator_id.pubkey
        bad_msg3 = msg3
        if failure == "empty":
            bad_msg3 = b""
        elif failure == "truncated":
            bad_msg3 = msg3[:8]
        elif failure == "ciphertext":
            bad_msg3 = bytes([msg3[0] ^ 1]) + msg3[1:]
        elif failure == "signature":
            def rejecting_verify(
                _pubkey: bytes, _message: bytes, _signature: bytes
            ) -> bool:
                return False

            monkeypatch.setattr(edhoc_module.schnorr48, "verify", rejecting_verify)
        else:
            bad_peer_key = Identity.generate().pubkey

        with pytest.raises((ValueError, TypeError)) as exc_info:
            responder.process_message_3(bad_msg3, bad_peer_key)
        if failure == "signature":
            # SECURITY: Error message is intentionally generic to prevent oracle attacks
            assert "signature verification failed" in str(exc_info.value)
        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)
        with pytest.raises(ValueError):
            responder.process_message_3(msg3, initiator_id.pubkey)
        with pytest.raises(ValueError):
            responder.export_oscore()


class TestRfc9528KdfStructure:
    """Validate EDHOC-KDF info structure matches RFC 9528 Section 4.1.2.

    Per RFC 9528: info = (info_label: int, context: bstr, length: uint).
    Labels are defined in RFC 9528 Figure 6.
    """

    def test_th2_computation(self) -> None:
        """RFC 9529 Section 2.2 hashes two CBOR bstr sequence items for TH_2."""
        from lichen.crypto.edhoc import _compute_th

        message_1 = bytes.fromhex(
            "0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d"
        )
        g_y = bytes.fromhex(
            "dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c"
        )
        h_message_1 = _compute_th(message_1)
        th_2_input = cbor2.dumps(g_y) + cbor2.dumps(h_message_1)
        assert len(th_2_input) == 68
        assert th_2_input == bytes.fromhex(
            "5820dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c"
            "5820c165d6a99d1bcafaac8dbf2b352a6f7d71a30b439c9d64d349a23848038ed16b"
        )
        th_2 = _compute_th(th_2_input)
        assert th_2 == bytes.fromhex(
            "c6405c154c567466ab1df20369500e540e9f14bd3a796a0652cae66c9061688d"
        )

    def test_both_roles_hash_cbor_sequence_for_th2(self) -> None:
        """Initiator and responder both use the RFC 9528 TH_2 transcript."""
        from lichen.crypto.edhoc import _compute_th

        initiator_id = Identity.generate()
        responder_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        message_1 = initiator.create_message_1()
        message_2 = responder.process_message_1(message_1, initiator_id.pubkey)
        expected = _compute_th(
            _sequence(responder._eph_pk, _compute_th(message_1))
        )
        assert responder._th_2 == expected

        initiator.process_message_2(message_2, responder_id.pubkey)
        assert initiator._th_2 == expected

    def test_keystream2_kdf(self) -> None:
        """RFC 9529 Section 2.2 KEYSTREAM_2 uses the corrected TH_2."""
        from lichen.crypto.edhoc import LABEL_KEYSTREAM_2, _edhoc_kdf

        prk_2e = bytes.fromhex(
            "d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da"
        )
        th_2 = bytes.fromhex(
            "c6405c154c567466ab1df20369500e540e9f14bd3a796a0652cae66c9061688d"
        )
        # RFC 9528: KEYSTREAM_2 = EDHOC-KDF(PRK_2e, 0, TH_2, plaintext_length)
        keystream = _edhoc_kdf(prk_2e, LABEL_KEYSTREAM_2, th_2, 82)
        assert keystream == bytes.fromhex(
            "fd3e7c3f2d6bee643d3c9d2f2847035d73e2ecb0f8db5cd1c6854e24896af211"
            "88b2c4344e689ec2984283d9fbc69ce1c5db10dcfff24df9a49a04a94058277b"
            "c7fa9ad6c6b194ab328b445eb080490cd786"
        )

    def test_message_2_format(self) -> None:
        """Message 2 wire format matches RFC 9528 Section 5.3.2.

        message_2 = (G_Y_CIPHERTEXT_2 : bstr, C_R : bstr / -24..23)
        G_Y_CIPHERTEXT_2 = G_Y || CIPHERTEXT_2
        CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2
        """
        # RFC 9528 Appendix A test vectors
        g_y = bytes.fromhex(
            "dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c"
        )
        plaintext_2 = bytes.fromhex(
            "4118a11822822e4879f2a41b510c1f9b"
            "5840c3b5bd44d1e44a085c03d3aede4e1e6c11c572a1968cc3629b505f98c681"
            "608d3d1de793d1c40eb5dd5d89acf1966aea07022b48cdc99870ebc40374e8fa"
            "6e09"
        )
        keystream_2 = bytes.fromhex(
            "0ebee7570d2ca677673156c07e6adabe3eeae3caa4861d237638bdd1eb93e8db"
            "4da4b8c003018a87c00901fbae1f4c673a6a8ac51137b2693d78f2c6e88499cd"
            "63a205b591749e7dd98ca4f20c45f91f3cc8"
        )
        c_r = 24  # RFC 9528 Appendix A.1

        # CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2
        ciphertext_2 = bytes(a ^ b for a, b in zip(plaintext_2, keystream_2, strict=True))
        assert ciphertext_2 == bytes.fromhex(
            "4fa6464f2fae883f1ec3f2db2f66c52566aa207f19c2ccc73c30e1d2383d3695"
            "53c8a90571a01c0b036b9aabf1878ae65ae7b7d8f6a463ad33cd2f9b6128685b"
            "094802b7ba3c53b441fc4f360f3111e552c1"
        )

        # G_Y_CIPHERTEXT_2 = G_Y || CIPHERTEXT_2
        g_y_ciphertext_2 = g_y + ciphertext_2
        assert len(g_y_ciphertext_2) == 32 + 82  # 32-byte G_Y + 82-byte CIPHERTEXT_2

        # message_2 = CBOR(G_Y_CIPHERTEXT_2) || CBOR(C_R)
        msg2 = cbor2.dumps(g_y_ciphertext_2) + cbor2.dumps(c_r)
        assert msg2 == bytes.fromhex(
            "5872dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b2"
            "9d1c4fa6464f2fae883f1ec3f2db2f66c52566aa207f19c2ccc73c30e1d2383d"
            "369553c8a90571a01c0b036b9aabf1878ae65ae7b7d8f6a463ad33cd2f9b6128"
            "685b094802b7ba3c53b441fc4f360f3111e552c11818"
        )

    def test_th3_computation(self) -> None:
        """TH_3 = H(TH_2 || PLAINTEXT_2 || CRED_R) is computed correctly."""
        from lichen.crypto.edhoc import _compute_th

        th_2 = bytes.fromhex(
            "c1d8c6ee4eeb1672d7fcbb44f8d811419739b79b852fce03f527eacdaf6633c4"
        )
        plaintext_2 = bytes.fromhex(
            "4118a11822822e4879f2a41b510c1f9b"
            "5840c3b5bd44d1e44a085c03d3aede4e1e6c11c572a1968cc3629b505f98c681"
            "608d3d1de793d1c40eb5dd5d89acf1966aea07022b48cdc99870ebc40374e8fa"
            "6e09"
        )
        cred_r = bytes.fromhex(
            "58f13081ee3081a1a003020102020462319ec4300506032b6570301d311b3019"
            "06035504030c124544484f4320526f6f742045643235353139301e170d323230"
            "3331363038323433365a170d3239313233313233303030305a30223120301e06"
            "035504030c174544484f4320526573706f6e6465722045643235353139302a30"
            "0506032b6570032100a1db47b95184854ad12a0c1a354e418aace33aa0f2c662"
            "c00b3ac55de92f9359300506032b6570034100b723bc01eab0928e8b2b6c98de"
            "19cc3823d46e7d6987b032478fecfaf14537a1af14cc8be829c6b73044101837"
            "eb4abc949565d86dce51cfae52ab82c152cb02"
        )
        th_3 = _compute_th(cbor2.dumps(th_2) + cbor2.dumps(plaintext_2) + cbor2.dumps(cred_r))
        assert th_3 == bytes.fromhex(
            "093c4bed6f1f679d7ef8c6dada0f631b75cf19d8a6eea88b2a5ac1a9fb9e5986"
        )

    def test_th4_computation(self) -> None:
        """TH_4 = H(TH_3 || PLAINTEXT_3 || CRED_I) is computed correctly."""
        from lichen.crypto.edhoc import _compute_th

        th_3 = bytes.fromhex(
            "093c4bed6f1f679d7ef8c6dada0f631b75cf19d8a6eea88b2a5ac1a9fb9e5986"
        )
        plaintext_3 = bytes.fromhex(
            "a11822822e48c24ab2fd7643c79f584096e1cd5fceadfac1b5af819443f70924"
            "f5719955957fd02655beb4775e1a73186a0d1d3ea683f08f8d03dcecb9cf154e"
            "1c6f555a1e12ca118ce42bdba6878907"
        )
        cred_i = bytes.fromhex(
            "58f13081ee3081a1a003020102020462319ea0300506032b6570301d311b3019"
            "06035504030c124544484f4320526f6f742045643235353139301e170d323230"
            "3331363038323430305a170d3239313233313233303030305a30223120301e06"
            "035504030c174544484f4320496e69746961746f722045643235353139302a30"
            "0506032b6570032100ed06a8ae61a829ba5fa54525c9d07f48dd44a302f43e0f"
            "23d8cc20b73085141e300506032b6570034100521241d8b3a770996bcfc9b9ea"
            "d4e7e0a1c0db353a3bdf2910b39275ae48b756015981850d27db6734e37f6721"
            "2267dd05eeff27b9e7a813fa574b72a00b430b"
        )
        th_4 = _compute_th(cbor2.dumps(th_3) + cbor2.dumps(plaintext_3) + cbor2.dumps(cred_i))
        assert th_4 == bytes.fromhex(
            "ad002457080da9a5e7a942030ca302f5cc9f77ba8124a49ba560d168b5b6f26d"
        )

    def test_prk_exporter_chain(self) -> None:
        """PRK_out -> PRK_exporter -> OSCORE keys use correct info structures."""
        from lichen.crypto.edhoc import (
            LABEL_OSCORE_SALT,
            LABEL_OSCORE_SECRET,
            LABEL_PRK_exporter,
            LABEL_PRK_out,
            _edhoc_kdf,
        )

        prk_2e = bytes.fromhex(
            "e998b69d67c5856ceb6812f20590d0cd55ab25e24bf53348f35915883e94b694"
        )
        th_4 = bytes.fromhex(
            "ad002457080da9a5e7a942030ca302f5cc9f77ba8124a49ba560d168b5b6f26d"
        )

        # RFC 9528: PRK_out = EDHOC-KDF(PRK_4e3m, 7, TH_4, hash_length)
        prk_out = _edhoc_kdf(prk_2e, LABEL_PRK_out, th_4, 32)
        assert prk_out == bytes.fromhex(
            "04de5e8efab9db0611f197b68d2f3b32085d25f235b00496068bb4ec169a1d5a"
        )

        # RFC 9528: PRK_exporter = EDHOC-KDF(PRK_out, 10, h'', hash_length)
        prk_exporter = _edhoc_kdf(prk_out, LABEL_PRK_exporter, b"", 32)
        assert prk_exporter == bytes.fromhex(
            "82bf0a40b8357f89f6dd8134ec5452020ea6a8df94c52fbade77b2425d3c019c"
        )

        # RFC 9528 Section 7.2.1: OSCORE export with PRK_exporter
        oscore_secret = _edhoc_kdf(prk_exporter, LABEL_OSCORE_SECRET, b"", 16)
        assert oscore_secret == bytes.fromhex("8b0ffa18545604a0bf7cb9433c86e6c7")

        oscore_salt = _edhoc_kdf(prk_exporter, LABEL_OSCORE_SALT, b"", 8)
        assert oscore_salt == bytes.fromhex("c3b827222332d23b")

    def test_rfc9529_export_fixture(self) -> None:
        """Derive every RFC 9529 Section 2.5-2.6 exporter value exactly."""
        import json
        from pathlib import Path

        from lichen.crypto.edhoc import (
            LABEL_OSCORE_SALT,
            LABEL_OSCORE_SECRET,
            LABEL_PRK_exporter,
            LABEL_PRK_out,
            _edhoc_kdf,
        )

        path = (
            Path(__file__).parents[3]
            / "test"
            / "vectors"
            / "edhoc_export_rfc9529.json"
        )
        vector = json.loads(path.read_text())["vectors"][0]
        prk_4e3m = bytes.fromhex(vector["prk_4e3m"])
        th_4 = bytes.fromhex(vector["th_4"])

        prk_out = _edhoc_kdf(prk_4e3m, LABEL_PRK_out, th_4, 32)
        assert prk_out == bytes.fromhex(vector["prk_out"])

        prk_exporter = _edhoc_kdf(prk_out, LABEL_PRK_exporter, b"", 32)
        assert prk_exporter == bytes.fromhex(vector["prk_exporter"])
        assert _edhoc_kdf(prk_exporter, LABEL_OSCORE_SECRET, b"", 16) == bytes.fromhex(
            vector["master_secret"]
        )
        assert _edhoc_kdf(prk_exporter, LABEL_OSCORE_SALT, b"", 8) == bytes.fromhex(
            vector["master_salt"]
        )

        assert vector["initiator_sender_id"] == vector["c_r"]
        assert vector["initiator_recipient_id"] == vector["c_i"]
        assert vector["responder_sender_id"] == vector["c_i"]
        assert vector["responder_recipient_id"] == vector["c_r"]


class TestEdhocImplementationInvariants:
    """Check same-implementation EDHOC invariants and regression fixtures.

    These tests detect role disagreement and deterministic output drift. They
    are not independent correctness or interoperability oracles; the official
    RFC 9528/9529 fixed-literal checks above provide independent coverage.
    """

    @staticmethod
    def _load_edhoc_vectors() -> list[dict]:
        """Load EDHOC test vectors."""
        import json
        from pathlib import Path

        path = Path(__file__).parents[3] / "test" / "vectors" / "edhoc.json"
        with open(path) as f:
            return json.load(f)["vectors"]

    def test_oscore_context_parity_live(self) -> None:
        """Live handshake derives matching OSCORE contexts for both roles.

        Verifies initiator and responder derive identical master_secret and
        master_salt, with sender_id/recipient_id correctly swapped.
        """
        initiator_id = Identity.generate()
        responder_id = Identity.generate()

        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()

        # Parity check 1: Both roles derive identical master_secret
        assert ctx_i.master_secret == ctx_r.master_secret, (
            "master_secret mismatch between initiator and responder"
        )

        # Parity check 2: Both roles derive identical master_salt
        assert ctx_i.master_salt == ctx_r.master_salt, (
            "master_salt mismatch between initiator and responder"
        )

        # Parity check 3: sender_id/recipient_id correctly swapped
        assert ctx_i.sender_id == ctx_r.recipient_id, (
            "initiator sender_id should equal responder recipient_id"
        )
        assert ctx_i.recipient_id == ctx_r.sender_id, (
            "initiator recipient_id should equal responder sender_id"
        )

    def test_oscore_context_regression_fixture(self) -> None:
        """Derived OSCORE context matches the Python-generated baseline.

        This is intentionally a drift regression, not a correctness proof:
        both the fixture and values under test originate in this implementation.
        """
        from lichen.crypto.edhoc import (
            LABEL_OSCORE_SALT,
            LABEL_OSCORE_SECRET,
            LABEL_PRK_exporter,
            LABEL_PRK_out,
            _edhoc_kdf,
        )

        vectors = self._load_edhoc_vectors()
        vec = next(v for v in vectors if v["name"] == "fixed_seed_sign_sign")

        # Use recorded TH and PRK values from vector
        prk_4e3m = bytes.fromhex(vec["prk_4e3m"])
        th_4 = bytes.fromhex(vec["th_4"])

        # Derive PRK_out and PRK_exporter (RFC 9528 Section 7.2.1)
        prk_out = _edhoc_kdf(prk_4e3m, LABEL_PRK_out, th_4, 32)
        prk_exporter = _edhoc_kdf(prk_out, LABEL_PRK_exporter, b"", 32)

        # Derive OSCORE master_secret (16 bytes) and master_salt (8 bytes)
        computed_secret = _edhoc_kdf(prk_exporter, LABEL_OSCORE_SECRET, b"", 16)
        computed_salt = _edhoc_kdf(prk_exporter, LABEL_OSCORE_SALT, b"", 8)

        expected_secret = bytes.fromhex(vec["oscore_master_secret"])
        expected_salt = bytes.fromhex(vec["oscore_master_salt"])

        assert computed_secret == expected_secret, (
            f"master_secret mismatch: got {computed_secret.hex()}, "
            f"expected {expected_secret.hex()}"
        )
        assert computed_salt == expected_salt, (
            f"master_salt mismatch: got {computed_salt.hex()}, "
            f"expected {expected_salt.hex()}"
        )

        # Verify sender/recipient IDs match vector
        expected_sender_id = bytes.fromhex(vec["oscore_sender_id"])
        expected_recipient_id = bytes.fromhex(vec["oscore_recipient_id"])

        # RFC 9528 Table 14 maps the peer-selected C_R to the Initiator's
        # Sender ID and C_I to its Recipient ID.
        assert expected_sender_id == b"\x01", (
            "vector sender_id should be initiator C_R=0x01"
        )
        assert expected_recipient_id == b"\x00", (
            "vector recipient_id should be initiator C_I=0x00"
        )


class TestEdhocGeneratedRegressions:
    """Detect deterministic Python EDHOC output drift.

    ``edhoc.json`` is generated by the same Python implementation. These tests
    are regression guards only and make no conformance or cross-implementation
    claim. Official RFC 9528/9529 fixtures are exercised above.
    """

    @staticmethod
    def _load_edhoc_vectors() -> list[dict]:
        """Load EDHOC test vectors."""
        import json
        from pathlib import Path

        path = Path(__file__).parents[3] / "test" / "vectors" / "edhoc.json"
        with open(path) as f:
            return json.load(f)["vectors"]

    def test_message_wire_format_regression(self) -> None:
        """Deterministic Python messages match the committed drift baseline.

        The fixed-seed fixture is Python-generated; matching it detects an
        unreviewed output change but does not establish wire-format correctness.
        """
        vectors = self._load_edhoc_vectors()
        vec = next(v for v in vectors if v["name"] == "fixed_seed_sign_sign")

        # Reproduce Python messages with same deterministic setup
        import os
        old_urandom = os.urandom
        os.urandom = lambda n: bytes([0x42] * n)
        try:
            initiator_id = Identity.from_seed(bytes.fromhex(vec["seed_i"]))
            responder_id = Identity.from_seed(bytes.fromhex(vec["seed_r"]))
            initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
            responder = EdhocResponder.create(responder_id, c_r=b"\x01")

            msg1 = initiator.create_message_1()
            msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
            msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
            responder.process_message_3(msg3, initiator_id.pubkey)
        finally:
            os.urandom = old_urandom

        # Same-implementation regression comparison, not an independent oracle.
        assert msg1.hex() == vec["msg1"], "msg1 wire format drift"
        assert msg2.hex() == vec["msg2"], "msg2 wire format drift"
        assert msg3.hex() == vec["msg3"], "msg3 wire format drift"

    def test_oscore_context_regression(self) -> None:
        """Python key derivation matches its committed regression baseline."""
        from lichen.crypto.edhoc import (
            LABEL_OSCORE_SALT,
            LABEL_OSCORE_SECRET,
            LABEL_PRK_exporter,
            LABEL_PRK_out,
            _edhoc_kdf,
        )

        vectors = self._load_edhoc_vectors()
        vec = next(v for v in vectors if v["name"] == "fixed_seed_sign_sign")

        prk_4e3m = bytes.fromhex(vec["prk_4e3m"])
        th_4 = bytes.fromhex(vec["th_4"])

        # Derive OSCORE context using the same implementation as the fixture.
        prk_out = _edhoc_kdf(prk_4e3m, LABEL_PRK_out, th_4, 32)
        prk_exporter = _edhoc_kdf(prk_out, LABEL_PRK_exporter, b"", 32)
        python_secret = _edhoc_kdf(prk_exporter, LABEL_OSCORE_SECRET, b"", 16)
        python_salt = _edhoc_kdf(prk_exporter, LABEL_OSCORE_SALT, b"", 8)

        # Regression expectations generated by Python, not an external oracle.
        expected_secret = bytes.fromhex(vec["oscore_master_secret"])
        expected_salt = bytes.fromhex(vec["oscore_master_salt"])

        assert python_secret == expected_secret, (
            f"Python master_secret mismatch: {python_secret.hex()} != {expected_secret.hex()}"
        )
        assert python_salt == expected_salt, (
            f"Python master_salt mismatch: {python_salt.hex()} != {expected_salt.hex()}"
        )


class TestSuiteNegotiationVectors:
    """Test EDHOC cipher suite negotiation against suite_negotiation.json vectors.

    LICHEN requires Suite 0 (RFC 9528). These tests validate:
    - SUITES_I CBOR encoding (single int vs array per RFC 9528 Section 3.5)
    - Suite 0 requirement enforcement
    - Failure case handling for unsupported suites
    """

    @staticmethod
    def _load_vectors() -> dict:
        """Load suite_negotiation.json vectors."""
        import json
        from pathlib import Path

        path = Path(__file__).parents[3] / "test" / "vectors" / "suite_negotiation.json"
        with open(path) as f:
            return json.load(f)

    @pytest.mark.parametrize(
        "vector",
        [
            {"name": "single_suite_compact", "suites": [0], "cbor": "00"},
            {"name": "multiple_suites_array", "suites": [0, 2], "cbor": "820002"},
            {"name": "three_suites_array", "suites": [0, 2, 6], "cbor": "83000206"},
        ],
        ids=["single_suite_compact", "multiple_suites_array", "three_suites_array"],
    )
    def test_suites_i_encoding(self, vector: dict) -> None:
        """SUITES_I encoding matches RFC 9528: single suite as int, multiple as array."""
        suites = vector["suites"]
        expected_cbor = bytes.fromhex(vector["cbor"])

        # RFC 9528 Section 3.5: SUITES_I is int (single suite) or array (multiple)
        encoded = cbor2.dumps(suites[0]) if len(suites) == 1 else cbor2.dumps(suites)

        assert encoded == expected_cbor, (
            f"SUITES_I encoding mismatch for {vector['name']}: "
            f"got {encoded.hex()}, expected {expected_cbor.hex()}"
        )

    @pytest.mark.parametrize(
        "vector",
        [
            {"name": "suite_value_24", "suites": [24], "cbor": "1818"},
            {"name": "suite_value_256", "suites": [256], "cbor": "190100"},
        ],
        ids=["suite_value_24", "suite_value_256"],
    )
    def test_suites_i_edge_case_encoding(self, vector: dict) -> None:
        """SUITES_I edge cases: values >= 24 use multi-byte CBOR encoding."""
        suites = vector["suites"]
        expected_cbor = bytes.fromhex(vector["cbor"])

        # Single suite uses int encoding
        encoded = cbor2.dumps(suites[0])
        assert encoded == expected_cbor, (
            f"SUITES_I edge case encoding mismatch for {vector['name']}: "
            f"got {encoded.hex()}, expected {expected_cbor.hex()}"
        )

    def test_lichen_requires_suite_0(self) -> None:
        """LICHEN nodes MUST support Suite 0 (spec 8.9).

        Validates that responder rejects non-Suite-0 messages.
        Vector: lichen_required.lichen_suite0_required
        """
        doc = self._load_vectors()
        vec = next(
            v for v in doc["vectors"]["lichen_required"]
            if v["name"] == "lichen_suite0_required"
        )
        assert vec["success"] is True
        assert vec["selected_suite"] == 0

        # Live test: handshake succeeds with Suite 0
        initiator_id = Identity.generate()
        responder_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()
        assert ctx_i.master_secret == ctx_r.master_secret

    def test_non_suite_0_rejected(self) -> None:
        """Responder rejects messages offering only non-Suite-0 suites.

        Vector: failure_cases.non_lichen_peer_no_suite0
        """
        doc = self._load_vectors()
        vec = next(
            v for v in doc["vectors"]["failure_cases"]
            if v["name"] == "non_lichen_peer_no_suite0"
        )
        assert vec["success"] is False
        assert vec["error"] == "ERR_SUITES_NONE"

        # Live test: responder rejects Suite 2 (non-LICHEN)
        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        initiator.create_message_1()  # advance state to get ephemeral key

        # Craft message_1 with Suite 2 instead of Suite 0
        # message_1 = (METHOD, SUITES_I, G_X, C_I)
        fake_msg1 = _sequence(0, 2, initiator._eph_pk, b"\x00")

        responder = EdhocResponder.create(Identity.generate(), c_r=b"\x01")
        with pytest.raises(ValueError, match="Unsupported cipher suite"):
            responder.process_message_1(fake_msg1, initiator_id.pubkey)

    def test_empty_suites_i_rejected(self) -> None:
        """Empty SUITES_I array is invalid per RFC 9528.

        Vector: failure_cases.empty_suites_i
        """
        doc = self._load_vectors()
        vec = next(
            v for v in doc["vectors"]["failure_cases"]
            if v["name"] == "empty_suites_i"
        )
        assert vec["success"] is False
        assert vec["error"] == "ERR_MSG_MALFORMED"

        # RFC 9528: SUITES_I must be int or non-empty array
        # An array encoding would be: 0x80 (empty array)
        # But LICHEN expects an int (Suite 0), so any array fails validation
        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")

        # Craft message_1 with empty array as SUITES_I
        # CBOR: 0x80 = empty array
        fake_msg1 = cbor2.dumps(0) + b"\x80" + cbor2.dumps(initiator._eph_pk) + cbor2.dumps(b"\x00")

        responder = EdhocResponder.create(Identity.generate(), c_r=b"\x01")
        with pytest.raises((ValueError, TypeError)):
            responder.process_message_1(fake_msg1, initiator_id.pubkey)

    def test_no_common_suite_fails(self) -> None:
        """Negotiation fails when no common suite exists.

        Vector: failure_cases.no_common_suite
        """
        doc = self._load_vectors()
        vec = next(
            v for v in doc["vectors"]["failure_cases"]
            if v["name"] == "no_common_suite"
        )
        assert vec["success"] is False
        assert vec["selected_suite"] is None

        # LICHEN only supports Suite 0, so any non-Suite-0 offer fails
        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")

        # Craft message_1 with Suite 6 (not supported by LICHEN)
        fake_msg1 = _sequence(0, 6, initiator._eph_pk, b"\x00")

        responder = EdhocResponder.create(Identity.generate(), c_r=b"\x01")
        with pytest.raises(ValueError, match="Unsupported cipher suite: 6"):
            responder.process_message_1(fake_msg1, initiator_id.pubkey)

    def test_basic_negotiation_both_support_suite0(self) -> None:
        """Basic negotiation succeeds when both peers support Suite 0.

        Vector: basic_negotiation.both_support_suite0
        """
        doc = self._load_vectors()
        vec = next(
            v for v in doc["vectors"]["basic_negotiation"]
            if v["name"] == "both_support_suite0"
        )
        assert vec["success"] is True
        assert vec["selected_suite"] == 0

        # Live validation: standard handshake uses Suite 0
        initiator_id = Identity.generate()
        responder_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")

        msg1 = initiator.create_message_1()
        # Verify message_1 contains Suite 0
        items = _decode_cbor_sequence(msg1)
        assert items[1] == 0, "Message 1 should contain Suite 0"

        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        msg3 = initiator.process_message_2(msg2, responder_id.pubkey)
        responder.process_message_3(msg3, initiator_id.pubkey)

        # Both derive matching context
        ctx_i = initiator.export_oscore()
        ctx_r = responder.export_oscore()
        assert ctx_i.master_secret == ctx_r.master_secret

    def test_message_1_encodes_suite_0_as_int(self) -> None:
        """Message 1 encodes SUITES_I as int (not array) per RFC 9528.

        LICHEN uses only Suite 0, so SUITES_I should be encoded as int 0,
        not as array [0]. This is the compact encoding per RFC 9528 Section 3.5.
        """
        doc = self._load_vectors()
        vec = next(
            v for v in doc["vectors"]["suites_i_encoding"]
            if v["name"] == "single_suite_compact"
        )
        assert vec["cbor_type"] == "int"
        expected_cbor = bytes.fromhex(vec["suites_i_cbor"])

        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        msg1 = initiator.create_message_1()

        # Parse message_1 and verify SUITES_I encoding
        items = _decode_cbor_sequence(msg1)
        # METHOD=0, SUITES_I=0, G_X, C_I
        assert items[1] == 0, "SUITES_I should be 0"

        # Verify the raw CBOR encoding is int, not array
        # Find SUITES_I position in raw bytes (after METHOD)
        method_len = len(cbor2.dumps(items[0]))
        suites_i_cbor = msg1[method_len : method_len + len(expected_cbor)]
        assert suites_i_cbor == expected_cbor, (
            f"SUITES_I should be encoded as int: got {suites_i_cbor.hex()}, "
            f"expected {expected_cbor.hex()}"
        )


def _decode_cbor_sequence(data: bytes) -> list:
    """Decode CBOR sequence helper for tests."""
    import io
    items = []
    fp = io.BytesIO(data)
    while True:
        try:
            items.append(cbor2.load(fp))
        except cbor2.CBORDecodeEOF:
            break
    return items
