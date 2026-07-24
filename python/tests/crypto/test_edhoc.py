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

        with pytest.raises(ValueError, match="Method mismatch"):
            responder.process_message_1(
                _sequence(4, 0, b"x" * 32, b"\x00"),
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


class TestRfc9529TraceVectors:
    """Cross-validate EDHOC against published RFC 9529 trace vectors.

    Per project policy, test vectors must be validated against an
    independent implementation.  This class verifies that the Python
    EDHOC helper functions produce bit-identical results to the Rust
    implementation for the published RFC 9529 Appendix C.1.1 trace.
    """

    def test_th2_rfc9529(self) -> None:
        """TH_2 = H(G_Y || H(message_1)) matches RFC 9529."""
        from lichen.crypto.edhoc import _compute_th

        message_1 = bytes.fromhex(
            "0000582031f82c7b5b9cbbf0f194d913cc12ef1532d328ef32632a4881a1c0701e237f042d"
        )
        g_y = bytes.fromhex(
            "dc88d2d51da5ed67fc4616356bc8ca74ef9ebe8b387e623a360ba480b9b29d1c"
        )
        th_2 = _compute_th(g_y + _compute_th(message_1))
        assert th_2 == bytes.fromhex(
            "c1d8c6ee4eeb1672d7fcbb44f8d811419739b79b852fce03f527eacdaf6633c4"
        )

    def test_keystream2_rfc9529(self) -> None:
        """KEYSTREAM_2 matches RFC 9529 trace."""
        from lichen.crypto.edhoc import _edhoc_kdf

        prk_2e = bytes.fromhex(
            "e998b69d67c5856ceb6812f20590d0cd55ab25e24bf53348f35915883e94b694"
        )
        th_2 = bytes.fromhex(
            "c1d8c6ee4eeb1672d7fcbb44f8d811419739b79b852fce03f527eacdaf6633c4"
        )
        keystream = _edhoc_kdf(prk_2e, th_2, "KEYSTREAM_2", b"", 82)
        assert keystream == bytes.fromhex(
            "c8419a8f1cae45674cf4c7ba021a110538c7fa2639ae70f316e8c3c34a0faf5d"
            "bf68cf835ec76f8f532fda302c647b303f02397f72710d072bd962118e35c6fe"
            "6d3f0a46a4160fba02a12eeec59e54135c3d"
        )

    def test_th3_rfc9529(self) -> None:
        """TH_3 matches RFC 9529 trace."""
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

    def test_th4_rfc9529(self) -> None:
        """TH_4 matches RFC 9529 trace."""
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

    def test_prk_exporter_rfc9529(self) -> None:
        """PRK_out, PRK_exporter, and exporter secrets match RFC 9529 trace."""
        from lichen.crypto.edhoc import _edhoc_kdf

        prk_2e = bytes.fromhex(
            "e998b69d67c5856ceb6812f20590d0cd55ab25e24bf53348f35915883e94b694"
        )
        th_4 = bytes.fromhex(
            "ad002457080da9a5e7a942030ca302f5cc9f77ba8124a49ba560d168b5b6f26d"
        )

        prk_out = _edhoc_kdf(prk_2e, th_4, "PRK_out", b"", 32)
        assert prk_out == bytes.fromhex(
            "77da318df09d26aa4cc69be602930750c32b5551d7a053d52000265d3c180eac"
        )

        prk_exporter = _edhoc_kdf(prk_out, th_4, "10", b"", 32)
        assert prk_exporter == bytes.fromhex(
            "a0ef8465a68d81f448c85ea6118170d1f65fa03ef4277250b74a599b3353ab02"
        )

        exporter_0 = _edhoc_kdf(prk_exporter, th_4, "0", b"", 16)
        assert exporter_0 == bytes.fromhex("240e728a7ef8fe1129c26da390ce9954")

        exporter_1 = _edhoc_kdf(prk_exporter, th_4, "1", b"", 8)
        assert exporter_1 == bytes.fromhex("32d1a820b919523a")
