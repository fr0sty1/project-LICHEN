#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate the domain-separated Announce signature transcript vectors."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

VECTORS_DIR = Path(__file__).resolve().parent
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from atomic_json import (  # noqa: E402
    atomic_write_json_batch,
    json_bytes,
    read_bounded_exact,
)
from reference_schnorr48 import ReferenceIdentity, sign  # noqa: E402

ANNOUNCE_SIGNATURE_DOMAIN = b"LICHEN-ANNOUNCE-v1\x00"
ANNOUNCE_TYPE = 0x01
FORMAT_VERSION = 2
OUTPUT = VECTORS_DIR / "announce_signed_data.json"
SEED = bytes.fromhex("0123456789abcdef" * 4)


def _vector(
    name: str,
    description: str,
    *,
    sequence: int,
    receive_channel: int,
    application_data: bytes,
) -> dict[str, object]:
    identity = ReferenceIdentity.from_seed(SEED)
    transcript = (
        ANNOUNCE_SIGNATURE_DOMAIN
        + identity.iid
        + identity.pubkey
        + sequence.to_bytes(2, "big")
        + bytes((receive_channel,))
        + len(application_data).to_bytes(2, "big")
        + application_data
    )
    signature = sign(identity, transcript)
    frame = (
        bytes((ANNOUNCE_TYPE, receive_channel, 0))
        + sequence.to_bytes(2, "big")
        + identity.iid
        + identity.pubkey
        + signature
        + application_data
    )
    domain_length = len(ANNOUNCE_SIGNATURE_DOMAIN)
    return {
        "name": name,
        "description": description,
        "coverage": "announce_transcript_format",
        "signing_seed": SEED.hex(),
        "public_key": identity.pubkey.hex(),
        "originator_iid": identity.iid.hex(),
        "seq_num": sequence,
        "rx_channel": receive_channel,
        "hop_count": 0,
        "app_data": application_data.hex(),
        "signed_data_transcript": transcript.hex(),
        "signed_data_layout": {
            "domain_offset": 0,
            "domain_length": domain_length,
            "iid_offset": domain_length,
            "iid_length": 8,
            "pubkey_offset": domain_length + 8,
            "pubkey_length": 32,
            "seq_num_offset": domain_length + 40,
            "seq_num_length": 2,
            "rx_channel_offset": domain_length + 42,
            "rx_channel_length": 1,
            "app_data_length_offset": domain_length + 43,
            "app_data_length_length": 2,
            "app_data_offset": domain_length + 45,
            "app_data_length": len(application_data),
        },
        "signature": signature.hex(),
        "announce_frame": frame.hex(),
        "announce_frame_layout": {
            "type_offset": 0,
            "rx_channel_offset": 1,
            "hop_count_offset": 2,
            "seq_num_offset": 3,
            "iid_offset": 5,
            "pubkey_offset": 13,
            "signature_offset": 45,
            "app_data_offset": 93,
            "fixed_length": 93,
            "total_length": len(frame),
        },
        "expected": {"signature_valid": True},
    }


def document() -> dict[str, object]:
    """Return the complete independently generated vector document."""
    return {
        "$schema": "./schema.json",
        "vector_type": "announce_signed_data",
        "format_version": FORMAT_VERSION,
        "description": (
            "Domain-separated Announce signature transcript vectors per CCP-9 "
            "and spec/05-routing.md Section 9.2."
        ),
        "oracle": {
            "basis": "LICHEN spec/05-routing.md Section 9.2",
            "transcript": (
                "LICHEN-ANNOUNCE-v1\\0 || originator_iid(8) || pubkey(32) || "
                "seq_num(2, big-endian) || rx_channel(1) || "
                "app_data_length(2, big-endian) || app_data(variable)"
            ),
            "generator_command": "python3 test/vectors/generate_announce_signed_data.py",
            "cross_check": "independent PyNaCl-backed reference_schnorr48.py",
        },
        "vectors": [
            _vector(
                "announce_signed_data_transcript",
                "Canonical domain-separated Announce transcript with application data.",
                sequence=0x1234,
                receive_channel=3,
                application_data=bytes.fromhex("deadbeef"),
            ),
            _vector(
                "announce_minimal_no_app_data",
                "Minimal Announce with an explicitly encoded zero application-data length.",
                sequence=1,
                receive_channel=0,
                application_data=b"",
            ),
            _vector(
                "announce_rx_channel_7_max",
                "Maximum valid channel in the eight-channel CCP-9 profile.",
                sequence=100,
                receive_channel=7,
                application_data=b"",
            ),
            _vector(
                "announce_seq_num_boundary_max",
                "Maximum unsigned 16-bit Announce sequence number.",
                sequence=0xFFFF,
                receive_channel=0,
                application_data=b"",
            ),
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    generated = document()
    if arguments.check:
        try:
            current = read_bounded_exact(OUTPUT)
        except (FileNotFoundError, RuntimeError):
            current = None
        if current != json_bytes(generated):
            print(f"out-of-date vector file: {OUTPUT.name}", file=sys.stderr)
            return 1
        return 0
    atomic_write_json_batch([(OUTPUT, generated)])
    vectors = generated["vectors"]
    assert isinstance(vectors, list)
    print(f"Wrote {len(vectors)} vectors in {OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
