#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate test/vectors/oscore_cross_exchange.json.

Cross-implementation (Python <-> Rust) OSCORE ciphertext-parity fixture.
Exchanges are derived deterministically from the canonical RFC-derived
vectors in test/vectors/oscore.json:

- requests: every ``roundtrip`` vector, protected by each implementation
  at the vector's starting sequence number;
- responses: two synthesized responses per ``roundtrip`` context material
  (#response_nopiv echoing the request nonce, #response_piv with a fresh
  Partial IV from responder sequence number 0).

Each side's protected output is recorded under ``python_protected`` /
``rust_protected``. The test suites on both sides assert byte equality
against the other side's section AND functional decryption of the other
side's bytes, proving bidirectional parity.

Usage (fully offline):
    cd python && .venv/bin/python ../test/vectors/generate_oscore_cross.py

Requires the Rust toolchain only to refresh the rust_protected section.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "python" / "src"))

from aiocoap import POST  # noqa: E402
from aiocoap.message import Message  # noqa: E402
from aiocoap.oscore import RequestIdentifiers  # noqa: E402

from lichen.crypto.oscore import MemorySecurityContext  # noqa: E402

VECTORS_PATH = PROJECT_ROOT / "test" / "vectors" / "oscore.json"
FIXTURE_PATH = PROJECT_ROOT / "test" / "vectors" / "oscore_cross_exchange.json"
RUST_DIR = PROJECT_ROOT / "rust"
RESPONSE_CODE = 69  # 2.05 Content
RESPONSE_PAYLOAD = b"LICHEN cross response"


def hex_or_none(value: object) -> bytes | None:
    if value is None:
        return None
    return bytes.fromhex(value)  # type: ignore[arg-type]


def minimal_piv(seq: int) -> bytes:
    if seq == 0:
        return b"\x00"
    return seq.to_bytes((seq.bit_length() + 7) // 8, "big")


def plaintext_message(code: int, options_hex: str, payload_hex: str) -> Message:
    msg = Message(code=code)
    msg.opt.decode(bytes.fromhex(options_hex))
    payload = bytes.fromhex(payload_hex)
    if payload:
        msg.payload = payload
    return msg


def protect_request(vector: dict) -> tuple[str, str]:
    ctx = MemorySecurityContext(
        master_secret=bytes.fromhex(vector["master_secret"]),
        master_salt=hex_or_none(vector["master_salt"]) or b"",
        sender_id=bytes.fromhex(vector["sender_id"]) if vector["sender_id"] else b"",
        recipient_id=bytes.fromhex(vector["recipient_id"]) if vector["recipient_id"] else b"",
        id_context=hex_or_none(vector.get("id_context")),
        starting_sequence_number=vector.get("sender_seq", 0),
    )
    pt = vector["plaintext"]
    protected, _ = ctx.protect(plaintext_message(pt["code"], pt["options"], pt["payload"]))
    option = protected.opt.oscore
    assert option is not None
    return option.hex(), protected.payload.hex()


def protect_response(vector: dict, include_piv: bool) -> tuple[str, str]:
    # Responder perspective: IDs swapped relative to the request vector.
    ctx = MemorySecurityContext(
        master_secret=bytes.fromhex(vector["master_secret"]),
        master_salt=hex_or_none(vector["master_salt"]) or b"",
        sender_id=bytes.fromhex(vector["recipient_id"]),
        recipient_id=bytes.fromhex(vector["sender_id"]),
        id_context=hex_or_none(vector.get("id_context")),
        starting_sequence_number=0,
    )
    request_kid = bytes.fromhex(vector["sender_id"])
    request_piv = minimal_piv(vector.get("sender_seq", 0))
    req_id = RequestIdentifiers(
        kid=request_kid,
        partial_iv=request_piv,
        can_reuse_nonce=not include_piv,
        request_code=POST,
    )
    response, _ = ctx.protect(plaintext_message(RESPONSE_CODE, "", RESPONSE_PAYLOAD.hex()), req_id)
    option = response.opt.oscore
    assert option is not None
    return option.hex(), response.payload.hex()


def collect_python_sections(vectors: list[dict]) -> tuple[list[dict], list[dict]]:
    requests: list[dict] = []
    responses: list[dict] = []
    for vector in vectors:
        if vector.get("type") != "roundtrip":
            continue
        pt = vector["plaintext"]
        opt, ct = protect_request(vector)
        entry = {
            "name": vector["name"],
            "vector": vector["name"],
            "master_secret": vector["master_secret"],
            "master_salt": vector.get("master_salt"),
            "sender_id": vector["sender_id"],
            "recipient_id": vector["recipient_id"],
            "id_context": vector.get("id_context"),
            "sender_seq": vector.get("sender_seq", 0),
            "plaintext": {"code": pt["code"], "options": pt["options"], "payload": pt["payload"]},
            "python_protected": {"oscore_option": opt, "ciphertext": ct},
        }
        requests.append(entry)

        for suffix, include_piv in (("response_nopiv", False), ("response_piv", True)):
            opt, ct = protect_response(vector, include_piv)
            responses.append(
                {
                    "name": f"{vector['name']}#{suffix}",
                    "vector": vector["name"],
                    **{
                        k: entry[k]
                        for k in (
                            "master_secret",
                            "master_salt",
                            "sender_id",
                            "recipient_id",
                            "id_context",
                        )
                    },
                    "request_kid": vector["sender_id"],
                    "request_piv": minimal_piv(vector.get("sender_seq", 0)).hex(),
                    "include_piv": include_piv,
                    "responder_sender_seq": 0,
                    "plaintext": {
                        "code": RESPONSE_CODE,
                        "options": "",
                        "payload": RESPONSE_PAYLOAD.hex(),
                    },
                    "python_protected": {"oscore_option": opt, "ciphertext": ct},
                }
            )
    return requests, responses


def collect_rust_sections() -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    """Run the Rust dump test and index its output by exchange name."""
    cmd = [
        "cargo",
        "test",
        "-p",
        "lichen-oscore",
        "--test",
        "cross_parity",
        "dump_rust_protected",
        "--",
        "--ignored",
        "--nocapture",
    ]
    last_output = ""
    for attempt in range(3):
        proc = subprocess.run(  # noqa: S603 - fixed argv, no user input
            cmd,
            cwd=RUST_DIR,
            capture_output=True,
            text=True,
            timeout=900,
        )
        last_output = proc.stdout + proc.stderr
        if "---BEGIN-RUST-CROSS-JSON---" in proc.stdout:
            break
        print(
            f"attempt {attempt + 1}: cargo dump failed "
            f"(exit {proc.returncode}); retrying after delay",
            file=sys.stderr,
        )
        time.sleep(20)
    else:
        sys.exit(f"Rust dump never produced markers.\n{last_output[-2000:]}")

    body = proc.stdout.split("---BEGIN-RUST-CROSS-JSON---", 1)[1]
    body = body.split("---END-RUST-CROSS-JSON---", 1)[0]
    parsed = json.loads(body)

    def by_name(entries: list[dict]) -> dict[str, dict[str, str]]:
        out = {}
        for e in entries:
            out[e["name"]] = {
                "oscore_option": e["oscore_option"].lower(),
                "ciphertext": e["ciphertext"].lower(),
            }
        return out

    return by_name(parsed["requests"]), by_name(parsed["responses"])


def main() -> int:
    vectors = json.loads(VECTORS_PATH.read_text())["vectors"]
    py_requests, py_responses = collect_python_sections(vectors)
    rust_requests, rust_responses = collect_rust_sections()

    for section, rust_index in (("requests", rust_requests), ("responses", rust_responses)):
        entries = py_requests if section == "requests" else py_responses
        for entry in entries:
            rust = rust_index.get(entry["name"])
            if rust is None:
                sys.exit(f"Rust dump missing exchange {entry['name']!r}")
            entry["rust_protected"] = rust

    fixture = {
        "name": "oscore_cross_exchange",
        "format_version": 1,
        "description": (
            "Cross-implementation OSCORE ciphertext parity fixture. Each "
            "exchange's inputs derive deterministically from "
            "test/vectors/oscore.json (roundtrip vectors plus synthesized "
            "responses over the same contexts); python_protected and "
            "rust_protected record each implementation's independent output."
        ),
        "source_vectors": "test/vectors/oscore.json",
        "generator": "test/vectors/generate_oscore_cross.py",
        "regenerate": "cd python && .venv/bin/python ../test/vectors/generate_oscore_cross.py",
        "requests": py_requests,
        "responses": py_responses,
    }
    FIXTURE_PATH.write_text(json.dumps(fixture, indent=2) + "\n")
    print(
        f"wrote {FIXTURE_PATH.relative_to(PROJECT_ROOT)} "
        f"({len(py_requests)} requests, {len(py_responses)} responses)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
