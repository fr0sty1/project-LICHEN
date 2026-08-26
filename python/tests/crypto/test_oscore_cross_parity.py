# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-implementation ciphertext parity: Python vs Rust OSCORE.

Consumes the committed fixture test/vectors/oscore_cross_exchange.json
(regenerate via test/vectors/generate_oscore_cross.py). For every exchange
this suite asserts:

1. Live Python protect() output is byte-identical to BOTH the committed
   python section (drift guard) and the committed rust section (direct
   Rust<->Python ciphertext parity).
2. Python unprotects the RUST-produced option+ciphertext and recovers the
   original plaintext exactly (functional cross-decryption).

The mirror assertions live in rust/lichen-oscore/tests/cross_parity.rs.
The RFC 8613 Appendix C vectors in test/vectors/oscore.json remain the
external correctness oracle for each implementation individually.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from aiocoap import CHANGED, POST
from aiocoap.message import Direction, Message
from aiocoap.oscore import RequestIdentifiers

from lichen.crypto.oscore import MemorySecurityContext

VECTORS_PATH = Path(__file__).parents[3] / "test" / "vectors" / "oscore_cross_exchange.json"
with open(VECTORS_PATH) as f:
    FIXTURE = json.load(f)


def context_ids(entry: dict[str, Any], *, sender_id: str, recipient_id: str) -> dict[str, Any]:
    """Context kwargs for a given role within an exchange."""
    return {
        "master_secret": bytes.fromhex(entry["master_secret"]),
        "master_salt": bytes.fromhex(entry["master_salt"]) if entry["master_salt"] else b"",
        "sender_id": bytes.fromhex(sender_id),
        "recipient_id": bytes.fromhex(recipient_id),
        "id_context": bytes.fromhex(entry["id_context"]) if entry.get("id_context") else None,
    }


def plaintext_message(pt: dict[str, Any]) -> Message:
    msg = Message(code=pt["code"])
    msg.opt.decode(bytes.fromhex(pt["options"]))
    payload = bytes.fromhex(pt["payload"])
    if payload:
        msg.payload = payload
    return msg


def protected_wire_message(option_hex: str, ciphertext_hex: str, code: int) -> Message:
    msg = Message(code=code, payload=bytes.fromhex(ciphertext_hex))
    msg.opt.oscore = bytes.fromhex(option_hex)
    msg.direction = Direction.INCOMING
    return msg


@pytest.mark.parametrize(
    "entry",
    FIXTURE["requests"],
    ids=lambda e: e["name"],
)
class TestRequestParity:
    def test_python_output_matches_both_implementations(self, entry: dict[str, Any]) -> None:
        sender_ctx = MemorySecurityContext(
            **context_ids(entry, sender_id=entry["sender_id"], recipient_id=entry["recipient_id"]),
            starting_sequence_number=entry["sender_seq"],
        )
        protected, _ = sender_ctx.protect(plaintext_message(entry["plaintext"]))

        assert protected.opt.oscore is not None
        assert protected.opt.oscore.hex() == entry["python_protected"]["oscore_option"], (
            f"{entry['name']}: drifted from committed python section"
        )
        assert protected.payload.hex() == entry["python_protected"]["ciphertext"], (
            f"{entry['name']}: drifted from committed python section"
        )
        assert protected.opt.oscore.hex() == entry["rust_protected"]["oscore_option"], (
            f"{entry['name']}: DIVERGES FROM RUST (option)"
        )
        assert protected.payload.hex() == entry["rust_protected"]["ciphertext"], (
            f"{entry['name']}: DIVERGES FROM RUST (ciphertext)"
        )

    def test_python_decrypts_rust_protected_request(self, entry: dict[str, Any]) -> None:
        receiver_ctx = MemorySecurityContext(
            **context_ids(entry, sender_id=entry["recipient_id"], recipient_id=entry["sender_id"]),
        )
        incoming = protected_wire_message(
            entry["rust_protected"]["oscore_option"],
            entry["rust_protected"]["ciphertext"],
            POST,
        )
        recovered, _ = receiver_ctx.unprotect(incoming)

        assert recovered.code == entry["plaintext"]["code"]
        assert recovered.opt.encode() == bytes.fromhex(entry["plaintext"]["options"])
        assert recovered.payload == bytes.fromhex(entry["plaintext"]["payload"])

        # The identical wire bytes are a replay on second sight.
        from aiocoap.oscore import ReplayError

        with pytest.raises(ReplayError):
            receiver_ctx.unprotect(incoming)


@pytest.mark.parametrize(
    "entry",
    FIXTURE["responses"],
    ids=lambda e: e["name"],
)
class TestResponseParity:
    def test_python_output_matches_both_implementations(self, entry: dict[str, Any]) -> None:
        responder_ctx = MemorySecurityContext(
            **context_ids(entry, sender_id=entry["recipient_id"], recipient_id=entry["sender_id"]),
            starting_sequence_number=entry["responder_sender_seq"],
        )
        req_id = RequestIdentifiers(
            kid=bytes.fromhex(entry["request_kid"]),
            partial_iv=bytes.fromhex(entry["request_piv"]),
            can_reuse_nonce=not entry["include_piv"],
            request_code=POST,
        )
        response, _ = responder_ctx.protect(plaintext_message(entry["plaintext"]), req_id)

        assert response.opt.oscore is not None
        assert response.opt.oscore.hex() == entry["python_protected"]["oscore_option"], (
            f"{entry['name']}: drifted from committed python section"
        )
        assert response.payload.hex() == entry["python_protected"]["ciphertext"], (
            f"{entry['name']}: drifted from committed python section"
        )
        assert response.opt.oscore.hex() == entry["rust_protected"]["oscore_option"], (
            f"{entry['name']}: DIVERGES FROM RUST (option)"
        )
        assert response.payload.hex() == entry["rust_protected"]["ciphertext"], (
            f"{entry['name']}: DIVERGES FROM RUST (ciphertext)"
        )

    def test_python_decrypts_rust_protected_response(self, entry: dict[str, Any]) -> None:
        client_ctx = MemorySecurityContext(
            **context_ids(entry, sender_id=entry["sender_id"], recipient_id=entry["recipient_id"]),
        )
        client_req_id = RequestIdentifiers(
            kid=bytes.fromhex(entry["request_kid"]),
            partial_iv=bytes.fromhex(entry["request_piv"]),
            can_reuse_nonce=False,
            request_code=POST,
        )
        incoming = protected_wire_message(
            entry["rust_protected"]["oscore_option"],
            entry["rust_protected"]["ciphertext"],
            CHANGED,
        )
        recovered, _ = client_ctx.unprotect(incoming, client_req_id)

        assert recovered.code == entry["plaintext"]["code"]
        assert recovered.opt.encode() == bytes.fromhex(entry["plaintext"]["options"])
        assert recovered.payload == bytes.fromhex(entry["plaintext"]["payload"])
