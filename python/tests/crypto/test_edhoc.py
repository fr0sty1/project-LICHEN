# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for EDHOC Suite 0 implementation."""

import cbor2
import pytest

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
        assert ctx_i.sender_id == b"\xde\xad"
        assert ctx_r.sender_id == b"\xbe\xef"

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

        # Initiator uses SIGN_STATIC, responder expects SIGN_SIGN
        initiator = EdhocInitiator.create(
            initiator_id, c_i=b"\x00", method=Method.SIGN_STATIC
        )
        responder = EdhocResponder.create(
            responder_id, c_r=b"\x01", method=Method.SIGN_SIGN
        )

        msg1 = initiator.create_message_1()

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

        assert initiator_context.sender_id == b"\x00"
        assert initiator_context.recipient_id == b"\x01"
        assert initiator_context.sender_id == responder_context.recipient_id
        assert initiator_context.recipient_id == responder_context.sender_id

    def test_responder_export_uses_committed_connection_ids(self) -> None:
        initiator_id, _, initiator, responder, _, _, msg3 = _handshake_until_message_3()
        responder.process_message_3(msg3, initiator_id.pubkey)
        responder.c_r = b"\x09"

        initiator_context = initiator.export_oscore()
        responder_context = responder.export_oscore()

        assert responder_context.sender_id == b"\x01"
        assert responder_context.recipient_id == b"\x00"
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
    def test_responder_rejects_unsupported_configured_method(self, method: Method) -> None:
        initiator_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id)
        responder = EdhocResponder.create(Identity.generate(), method=method)
        msg1 = initiator.create_message_1()

        with pytest.raises(ValueError, match="SIGN_SIGN"):
            responder.process_message_1(msg1, initiator_id.pubkey)

        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)
        with pytest.raises(ValueError):
            responder.export_oscore()
        with pytest.raises(ValueError):
            responder.process_message_1(msg1, initiator_id.pubkey)

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
        assert initiator_context.sender_id == b"\x00"
        assert initiator_context.recipient_id == b"\x01"
        assert responder_context.sender_id == b"\x01"
        assert responder_context.recipient_id == b"\x00"

    def test_initiator_terminally_rejects_colliding_connection_id(self) -> None:
        initiator_id = Identity.generate()
        responder_id = Identity.generate()
        initiator = EdhocInitiator.create(initiator_id, c_i=b"\x00")
        responder = EdhocResponder.create(responder_id, c_r=b"\x01")
        msg1 = initiator.create_message_1()
        msg2 = responder.process_message_1(msg1, initiator_id.pubkey)
        combined = cbor2.loads(msg2)
        colliding_msg2 = cbor2.dumps(combined) + cbor2.dumps(0)

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
            _sequence(0, 0, b"x" * 32, b"\x00"),
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
            raise AssertionError("DH must not run for an invalid METHOD_CORR")

        monkeypatch.setattr(edhoc_module, "_x25519_shared_secret", unexpected_dh)
        responder = EdhocResponder.create(Identity.generate())

        with pytest.raises(ValueError, match="METHOD_CORR"):
            responder.process_message_1(
                _sequence(0, 0, b"x" * 32, b"\x00"),
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
            class RejectingVerifyKey:
                def __init__(self, _key: bytes) -> None:
                    pass

                def verify(self, _message: bytes, _signature: bytes) -> bytes:
                    raise ValueError("injected verifier failure")

            monkeypatch.setattr(edhoc_module, "VerifyKey", RejectingVerifyKey)
        else:
            bad_peer_key = Identity.generate().pubkey

        with pytest.raises((ValueError, TypeError)) as exc_info:
            responder.process_message_3(bad_msg3, bad_peer_key)
        if failure == "signature":
            assert "Signature_3 verification failed" in str(exc_info.value)
        assert responder._state.name == "FAILED"
        _assert_session_material_cleared(responder)
        with pytest.raises(ValueError):
            responder.process_message_3(msg3, initiator_id.pubkey)
        with pytest.raises(ValueError):
            responder.export_oscore()
