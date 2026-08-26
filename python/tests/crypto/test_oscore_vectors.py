# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for OSCORE using RFC 8613 test vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import cbor2
import pytest
from aiocoap import CHANGED, GET, POST
from aiocoap.message import Direction, Message
from aiocoap.oscore import (
    ProtectionInvalid,
    ReplayError,
    RequestIdentifiers,
)

from lichen.crypto.oscore import MemorySecurityContext

# Load test vectors
VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "oscore.json"
with open(VECTORS_PATH) as f:
    VECTORS_DATA = json.load(f)


def get_vectors_by_type(type_name: str) -> list[dict[str, Any]]:
    """Get all test vectors of a specific type."""
    return [v for v in VECTORS_DATA["vectors"] if v.get("type") == type_name]


def get_vector(name: str) -> dict[str, Any]:
    """Get a single test vector by name."""
    matches = [v for v in VECTORS_DATA["vectors"] if v.get("name") == name]
    assert len(matches) == 1, f"Expected exactly one vector named {name!r}"
    return matches[0]


def parse_vector_ids(vector: dict[str, Any]) -> dict[str, Any]:
    """Extract the common context-construction fields from a vector."""
    return {
        "master_secret": bytes.fromhex(vector["master_secret"]),
        "master_salt": bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b"",
        "sender_id": bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b"",
        "recipient_id": bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b"",
        "id_context": bytes.fromhex(vector["id_context"]) if vector.get("id_context") else None,
    }


def swap_sender_recipient(ids: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of context fields with sender and recipient IDs exchanged."""
    swapped = dict(ids)
    swapped["sender_id"] = ids["recipient_id"]
    swapped["recipient_id"] = ids["sender_id"]
    return swapped


def plaintext_message(pt: dict[str, Any]) -> Message:
    """Build an outgoing CoAP message from a vector plaintext {code, options, payload}."""
    msg = Message(code=pt["code"])
    msg.payload = msg.opt.decode(bytes.fromhex(pt["options"]))
    payload = bytes.fromhex(pt["payload"])
    if payload:
        msg.payload = payload
    return msg


class TestKeyDerivation:
    """Test OSCORE key derivation against RFC 8613 Appendix C vectors."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("key_derivation"),
        ids=lambda v: v["name"],
    )
    def test_key_derivation(self, vector: dict[str, Any]) -> None:
        """Verify key derivation matches RFC 8613 expected values."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        sender_id = bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        recipient_id = bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""
        id_context = bytes.fromhex(vector["id_context"]) if vector.get("id_context") else None

        # Create context - this derives keys
        ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
            id_context=id_context,
        )

        expected = vector["expected"]
        assert ctx.sender_key == bytes.fromhex(expected["sender_key"]), (
            f"sender_key mismatch for {vector['name']}"
        )
        assert ctx.recipient_key == bytes.fromhex(expected["recipient_key"]), (
            f"recipient_key mismatch for {vector['name']}"
        )
        assert ctx.common_iv == bytes.fromhex(expected["common_iv"]), (
            f"common_iv mismatch for {vector['name']}"
        )


class TestRequestProtection:
    """Test OSCORE request protection against RFC 8613 Appendix C vectors.

    Cross-validates Python with Rust by testing against the same vectors.
    Both implementations must produce identical ciphertext for interoperability.
    """

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("request_protection"),
        ids=lambda v: v["name"],
    )
    def test_request_protection(self, vector: dict[str, Any]) -> None:
        """Verify request protection produces expected ciphertext and OSCORE option."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        sender_id = bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        recipient_id = bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""
        id_context = bytes.fromhex(vector["id_context"]) if vector.get("id_context") else None
        seq = vector.get("sender_seq", 0)

        # Create context to derive keys
        ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
            id_context=id_context,
        )

        # Construct PIV (partial IV) - variable length, minimum 1 byte
        piv = seq.to_bytes(5, "big").lstrip(b"\x00") or b"\x00"

        # Use aiocoap's nonce construction (includes sender_id length byte per RFC 8613)
        nonce = ctx._construct_nonce(piv, sender_id, ctx.alg_aead)

        # Verify nonce matches expected
        expected = vector["expected"]
        assert nonce.hex() == expected["nonce"], f"nonce mismatch for {vector['name']}"

        # Construct plaintext: code || options || [0xFF || payload]
        # RFC 8613 Section 8.1: payload marker 0xFF precedes payload when present
        pt = vector["plaintext"]
        payload = bytes.fromhex(pt["payload"])
        plaintext = bytes([pt["code"]]) + bytes.fromhex(pt["options"])
        if payload:
            plaintext += b"\xff" + payload

        # Construct AAD per RFC 8613 Section 5.4
        # external_aad = [oscore_version, [alg_aead], request_kid, request_piv, options]
        alg_aead = vector.get("algorithm", 10)
        external_aad = cbor2.dumps([1, [alg_aead], sender_id, piv, b""])

        # Enc_structure = ["Encrypt0", protected, external_aad]
        enc_structure = cbor2.dumps(["Encrypt0", b"", external_aad])

        # Encrypt using aiocoap's algorithm
        ciphertext = ctx.alg_aead.encrypt(plaintext, enc_structure, ctx.sender_key, nonce)

        assert ciphertext.hex() == expected["ciphertext"], (
            f"ciphertext mismatch for {vector['name']}"
        )

        # Verify OSCORE option encoding
        # Format: flags || [piv] || [kid_context] || [kid]
        # For requests: flags always includes k bit (has_kid), even for empty sender_id
        piv_len = len(piv)
        flags = piv_len  # n bits = PIV length
        flags |= 0x08  # k bit = has KID (always present for requests)
        if id_context is not None:
            flags |= 0x10  # h bit = has KID context

        oscore_option = bytes([flags]) + piv
        if id_context is not None:
            oscore_option += bytes([len(id_context)]) + id_context
        oscore_option += sender_id  # KID always present (may be empty)

        assert oscore_option.hex() == expected["oscore_option"], (
            f"OSCORE option mismatch for {vector['name']}"
        )


class TestResponseProtection:
    """Test OSCORE response protection against RFC 8613 Appendix C vectors.

    Cross-validates Python with Rust by testing against the same vectors.
    """

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("response_protection"),
        ids=lambda v: v["name"],
    )
    def test_response_protection(self, vector: dict[str, Any]) -> None:
        """Verify response protection produces expected ciphertext and OSCORE option."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        sender_id = bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        recipient_id = bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""

        # Create context to derive keys
        ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
        )

        # Response nonce uses request PIV and KID
        request_piv = bytes.fromhex(vector["request_piv"])
        request_kid = bytes.fromhex(vector["request_kid"])
        include_piv = vector["include_piv"]

        if include_piv:
            # Response includes its own PIV - nonce derived from sender's PIV and ID
            sender_seq = vector.get("sender_seq", 0)
            response_piv = sender_seq.to_bytes(5, "big").lstrip(b"\x00") or b"\x00"
            nonce = ctx._construct_nonce(response_piv, sender_id, ctx.alg_aead)
        else:
            # Response echoes request nonce (no fresh PIV)
            nonce = ctx._construct_nonce(request_piv, request_kid, ctx.alg_aead)

        # Verify nonce matches expected
        expected = vector["expected"]
        assert nonce.hex() == expected["nonce"], f"nonce mismatch for {vector['name']}"

        # Construct plaintext: code || options || [0xFF || payload]
        # RFC 8613 Section 8.1: payload marker 0xFF precedes payload when present
        pt = vector["plaintext"]
        payload = bytes.fromhex(pt["payload"])
        plaintext = bytes([pt["code"]]) + bytes.fromhex(pt["options"])
        if payload:
            plaintext += b"\xff" + payload

        # Construct AAD for response
        # For responses, external_aad uses request_kid and request_piv
        alg_aead = vector.get("algorithm", 10)
        external_aad = cbor2.dumps([1, [alg_aead], request_kid, request_piv, b""])
        enc_structure = cbor2.dumps(["Encrypt0", b"", external_aad])

        # Encrypt
        alg = ctx.alg_aead
        ciphertext = alg.encrypt(plaintext, enc_structure, ctx.sender_key, nonce)

        assert ciphertext.hex() == expected["ciphertext"], (
            f"ciphertext mismatch for {vector['name']}"
        )

        # Verify OSCORE option encoding
        if include_piv:
            response_piv = vector.get("sender_seq", 0).to_bytes(5, "big").lstrip(b"\x00") or b"\x00"
            oscore_option = bytes([len(response_piv)]) + response_piv
        else:
            oscore_option = b""  # Empty option for response echoing request nonce

        assert oscore_option.hex() == expected["oscore_option"], (
            f"OSCORE option mismatch for {vector['name']}"
        )


class TestRoundtrip:
    """Test OSCORE protect/unprotect roundtrip."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("roundtrip"),
        ids=lambda v: v["name"],
    )
    def test_roundtrip(self, vector: dict[str, Any]) -> None:
        """Verify protect followed by unprotect recovers original plaintext."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        sender_id = bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        recipient_id = bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""

        # Create sender and recipient contexts (symmetric, swapped IDs)
        sender_ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
        )
        recipient_ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=recipient_id,
            recipient_id=sender_id,
        )

        # Verify keys are correctly swapped
        assert sender_ctx.sender_key == recipient_ctx.recipient_key
        assert sender_ctx.recipient_key == recipient_ctx.sender_key
        assert sender_ctx.common_iv == recipient_ctx.common_iv

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("roundtrip"),
        ids=lambda v: v["name"],
    )
    def test_roundtrip_full_exchange(self, vector: dict[str, Any]) -> None:
        """Encrypt with protect(), decrypt with unprotect(): exact recovery.

        Exercises the real message-protection path end to end, including
        replay-window rejection of a duplicated request.
        """
        ids = parse_vector_ids(vector)
        code = vector["plaintext"]["code"]
        raw_options = bytes.fromhex(vector["plaintext"]["options"])
        payload = bytes.fromhex(vector["plaintext"]["payload"])

        sender_ctx = MemorySecurityContext(
            **ids,
            starting_sequence_number=vector.get("sender_seq", 0),
        )
        receiver_ctx = MemorySecurityContext(**swap_sender_recipient(ids))

        protected, _request_id = sender_ctx.protect(plaintext_message(vector["plaintext"]))
        assert protected.opt.oscore is not None
        assert protected.payload != payload or not payload

        protected.direction = Direction.INCOMING
        recovered, _server_request_id = receiver_ctx.unprotect(protected)
        assert recovered.code == code
        assert recovered.opt.encode() == raw_options
        assert recovered.payload == payload

        # The same protected request is a replay and MUST be rejected.
        with pytest.raises(ReplayError):
            receiver_ctx.unprotect(protected)


class TestReplayWindow:
    """Test OSCORE replay window behavior."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("replay"),
        ids=lambda v: v["name"],
    )
    def test_replay_detection(self, vector: dict[str, Any]) -> None:
        """Verify replay window correctly accepts/rejects sequence numbers.

        Note: MemorySecurityContext uses aiocoap's ReplayWindow which has a
        different interface than the Rust implementation. This test verifies
        the basic replay window behavior is correct.
        """
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"1" * 8,
            sender_id=b"\x00",
            recipient_id=b"\x01",
        )

        highest_seq = vector["highest_seq"]
        test_seq = vector["test_seq"]
        expected_is_replay = vector["expected"]["is_replay"]

        # Initialize the replay window to the specified state
        # First, mark the highest_seq as seen
        if highest_seq > 0:
            # Strike (mark as seen) all sequence numbers up to highest
            # This is a simplified setup - in real usage, packets arrive one at a time
            ctx.recipient_replay_window.strike_out(highest_seq)

        # Now test if test_seq would be accepted
        is_replay = ctx.recipient_replay_window.is_valid(test_seq) is False

        assert is_replay == expected_is_replay, (
            f"replay detection mismatch for {vector['name']}: "
            f"highest={highest_seq}, test={test_seq}, "
            f"expected_replay={expected_is_replay}, got_replay={is_replay}"
        )


class TestInvalidInputs:
    """Test OSCORE rejects invalid inputs."""

    def test_sender_id_too_long(self) -> None:
        """Sender ID exceeding 7 bytes should raise ValueError."""
        with pytest.raises(ValueError, match="ID too long"):
            MemorySecurityContext(
                master_secret=b"0" * 16,
                master_salt=b"1" * 8,
                sender_id=b"\x00" * 8,  # 8 bytes - too long
                recipient_id=b"\x01",
            )

    def test_recipient_id_too_long(self) -> None:
        """Recipient ID exceeding 7 bytes should raise ValueError."""
        with pytest.raises(ValueError, match="ID too long"):
            MemorySecurityContext(
                master_secret=b"0" * 16,
                master_salt=b"1" * 8,
                sender_id=b"\x00",
                recipient_id=b"\x01" * 8,  # 8 bytes - too long
            )


class TestEndToEndRequestVectors:
    """Encrypt requests with protect() and decrypt with unprotect().

    Byte-exact validation against RFC 8613 Appendix C.4-C.6 published
    ciphertexts, OSCORE options, and recovered plaintexts.
    """

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("request_protection"),
        ids=lambda v: v["name"],
    )
    def test_protect_then_unprotect_request(self, vector: dict[str, Any]) -> None:
        expected = vector["expected"]
        ids = parse_vector_ids(vector)
        client_ctx = MemorySecurityContext(
            **ids,
            starting_sequence_number=vector.get("sender_seq", 0),
        )
        server_ctx = MemorySecurityContext(**swap_sender_recipient(ids))

        # Encrypt: protect() must reproduce the published ciphertext and
        # OSCORE option byte for byte.
        protected, _client_req_id = client_ctx.protect(plaintext_message(vector["plaintext"]))
        assert protected.opt.oscore.hex() == expected["oscore_option"], (
            f"OSCORE option mismatch for {vector['name']}"
        )
        assert protected.payload.hex() == expected["ciphertext"], (
            f"ciphertext mismatch for {vector['name']}"
        )

        # Decrypt: feed the PUBLISHED option + ciphertext (independent of the
        # output just produced) to the peer context. Per RFC 8613 Section 5.3
        # the outer request code is POST; the real method is inside the
        # encrypted plaintext.
        incoming = Message(code=POST)
        incoming.opt.oscore = bytes.fromhex(expected["oscore_option"])
        incoming.payload = bytes.fromhex(expected["ciphertext"])
        incoming.direction = Direction.INCOMING

        recovered, _server_req_id = server_ctx.unprotect(incoming)
        assert recovered.code == vector["plaintext"]["code"]
        assert recovered.opt.encode() == bytes.fromhex(vector["plaintext"]["options"])
        assert recovered.payload == bytes.fromhex(vector["plaintext"]["payload"])

        # Decrypting the identical message again is a replay.
        with pytest.raises(ReplayError):
            server_ctx.unprotect(incoming)


class TestEndToEndResponseVectors:
    """Full request/response exchange against RFC 8613 Appendix C.7/C.8.

    C.7 reuses the request nonce (empty OSCORE option); C.8 generates a fresh
    Partial IV from the responder's sequence number.
    """

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("response_protection"),
        ids=lambda v: v["name"],
    )
    def test_response_exchange(self, vector: dict[str, Any]) -> None:
        expected = vector["expected"]
        ids = parse_vector_ids(vector)
        # The vector fields describe the responder's perspective.
        server_ctx = MemorySecurityContext(
            **ids,
            starting_sequence_number=vector.get("sender_seq", 0),
        )
        client_ctx = MemorySecurityContext(**swap_sender_recipient(ids))

        request_kid = bytes.fromhex(vector["request_kid"]) if vector["request_kid"] else b""
        request_piv = bytes.fromhex(vector["request_piv"])

        server_req_id = RequestIdentifiers(
            kid=request_kid,
            partial_iv=request_piv,
            can_reuse_nonce=not vector["include_piv"],
            request_code=POST,
        )
        response, _ = server_ctx.protect(plaintext_message(vector["plaintext"]), server_req_id)
        assert response.opt.oscore.hex() == expected["oscore_option"], (
            f"OSCORE option mismatch for {vector['name']}"
        )
        assert response.payload.hex() == expected["ciphertext"], (
            f"ciphertext mismatch for {vector['name']}"
        )

        client_req_id = RequestIdentifiers(
            kid=request_kid,
            partial_iv=request_piv,
            can_reuse_nonce=False,
            request_code=POST,
        )
        incoming = Message(code=CHANGED, payload=response.payload)
        incoming.opt.oscore = response.opt.oscore
        incoming.direction = Direction.INCOMING
        recovered, _ = client_ctx.unprotect(incoming, client_req_id)
        assert recovered.code == vector["plaintext"]["code"]
        assert recovered.opt.encode() == bytes.fromhex(vector["plaintext"]["options"])
        assert recovered.payload == bytes.fromhex(vector["plaintext"]["payload"])


class TestPivBoundaryVectors:
    """Partial IV wire encoding and nonce construction at RFC 8613 boundaries."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("piv_encoding"),
        ids=lambda v: v["name"],
    )
    def test_piv_wire_encoding(self, vector: dict[str, Any]) -> None:
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"",
            sender_id=b"\x01",
            recipient_id=b"\x02",
            starting_sequence_number=vector["piv_value"],
        )
        protected, _ = ctx.protect(Message(code=GET))
        option = protected.opt.oscore
        assert option is not None
        n = option[0] & 0x07
        assert n == vector["expected"]["piv_length"], f"PIV length mismatch for {vector['name']}"
        assert option[1 : 1 + n].hex() == vector["expected"]["piv_bytes"], (
            f"PIV encoding mismatch for {vector['name']}"
        )
        # Requests always carry the KID after the PIV.
        assert len(option) == 1 + n + len(ctx.sender_id)

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("piv_nonce"),
        ids=lambda v: v["name"],
    )
    def test_nonce_construction_at_boundaries(self, vector: dict[str, Any]) -> None:
        sender_id = bytes.fromhex(vector["sender_id"])
        ctx = MemorySecurityContext(
            master_secret=bytes.fromhex(vector["master_secret"]),
            master_salt=bytes.fromhex(vector["master_salt"]),
            sender_id=sender_id,
            recipient_id=b"\x01",
        )
        assert ctx.common_iv.hex() == vector["expected"]["common_iv"]

        piv_value = vector["piv"]
        piv_length = max(1, (piv_value.bit_length() + 7) // 8)
        piv = piv_value.to_bytes(piv_length, "big")
        nonce = ctx._construct_nonce(piv, sender_id, ctx.alg_aead)
        assert nonce.hex() == vector["expected"]["nonce"], f"nonce mismatch for {vector['name']}"


class TestInvalidWireInputVectors:
    """Decrypt-path rejection of malformed protected messages."""

    def test_ciphertext_too_short(self) -> None:
        """Ciphertext shorter than tag+code must be rejected."""
        vector = get_vector("invalid_ciphertext_too_short")
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"",
            sender_id=b"\x02",
            recipient_id=b"\x01",
        )
        msg = Message(code=POST, payload=bytes.fromhex(vector["ciphertext"]))
        msg.opt.oscore = b"\x09\x14\x01"  # k bit, 1-byte PIV, KID
        msg.direction = Direction.INCOMING
        with pytest.raises(ProtectionInvalid):
            ctx.unprotect(msg)

    def test_piv_overflow_rejected(self) -> None:
        """A 6-byte PIV exceeds the RFC 8613 maximum and MUST be discarded."""
        vector = get_vector("piv_overflow_rejected")
        ctx = MemorySecurityContext(
            master_secret=b"0" * 16,
            master_salt=b"",
            sender_id=b"\x02",
            recipient_id=b"\x01",
        )
        msg = Message(code=POST, payload=b"\x11" * 32)
        msg.opt.oscore = bytes([0x08 | 6]) + vector["piv_value"].to_bytes(6, "big") + b"\x01"
        msg.direction = Direction.INCOMING
        with pytest.raises(ProtectionInvalid, match="Partial IV"):
            ctx.unprotect(msg)


class TestSsnRestoreVectors:
    """Test OSCORE SSN restore vectors for NVM failure/recovery edge cases."""

    @pytest.mark.parametrize(
        "vector",
        get_vectors_by_type("ssn_restore"),
        ids=lambda v: v["name"],
    )
    def test_ssn_restore_nonce(self, vector: dict[str, Any]) -> None:
        """Verify restored context produces correct nonce matching vector."""
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        sender_id = bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b""
        recipient_id = bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b""
        id_context = bytes.fromhex(vector["id_context"]) if vector.get("id_context") else None

        starting_seq = vector["starting_sequence_number"]
        ctx = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=sender_id,
            recipient_id=recipient_id,
            id_context=id_context,
            starting_sequence_number=starting_seq,
        )

        expected = vector["expected"]
        algorithm = ctx.alg_aead

        piv = starting_seq.to_bytes(5, "big").lstrip(b"\x00") or b"\x00"
        nonce = ctx._construct_nonce(piv, sender_id, algorithm)
        assert nonce.hex() == expected["nonce"], (
            f"Nonce mismatch for {vector['name']}: got {nonce.hex()}, expected {expected['nonce']}"
        )

        # Verify keys are correctly derived from the restored context
        if "sender_key" in expected:
            assert ctx.sender_key.hex() == expected["sender_key"]
        if "recipient_key" in expected:
            assert ctx.recipient_key.hex() == expected["recipient_key"]

        # Verify restored context can issue sequence numbers at the correct offset
        seqno = ctx.new_sequence_number()
        assert seqno == starting_seq
        assert ctx.sender_sequence_number == starting_seq + 1

    def test_ssn_restore_no_nonce_reuse(self) -> None:
        """Verify prior_sequence_number and starting_sequence_number nonces differ."""
        vectors = [
            v for v in VECTORS_DATA["vectors"] if v.get("name") == "ssn_restore_no_nonce_reuse"
        ]
        assert len(vectors) == 1, "Missing ssn_restore_no_nonce_reuse vector"

        vector = vectors[0]
        master_secret = bytes.fromhex(vector["master_secret"])
        master_salt = bytes.fromhex(vector["master_salt"]) if vector["master_salt"] else b""
        prior_seq = vector["prior_sequence_number"]
        starting_seq = vector["starting_sequence_number"]

        ctx_prior = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=b"",
            recipient_id=b"\x01",
        )
        alg = ctx_prior.alg_aead

        prior_piv = prior_seq.to_bytes(5, "big").lstrip(b"\x00") or b"\x00"
        prior_nonce = ctx_prior._construct_nonce(prior_piv, b"", alg)

        ctx_restored = MemorySecurityContext(
            master_secret=master_secret,
            master_salt=master_salt,
            sender_id=b"",
            recipient_id=b"\x01",
            starting_sequence_number=starting_seq,
        )
        restored_nonce = ctx_restored._construct_nonce(b"\x03\xe8", b"", alg)

        assert prior_nonce != restored_nonce, (
            f"Nonce reuse: seq={prior_seq} and seq={starting_seq} produce "
            f"same nonce {prior_nonce.hex()}"
        )

        assert restored_nonce.hex() == vector["expected"]["nonce"], (
            f"Restored nonce mismatch: got {restored_nonce.hex()}, "
            f"expected {vector['expected']['nonce']}"
        )
