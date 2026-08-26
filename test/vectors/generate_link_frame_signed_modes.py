#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate signed link-frame vectors for every addressing mode and size limit.

test/vectors/link_frame.json covers every AddrMode value unsigned, but its
signed vectors only exercise broadcast (mode 0) and short (mode 1). This
generator adds canonical signed frames for extended (mode 2) and elided
(mode 3), plus maximum-payload signed frames for all four modes.  Together
with link_frame.json, these cover every spec/02-physical-link.md section 4.3
address form and its exact on-air size boundary.

Both oracles are independent of the code under test:
  - frame bytes are hand-assembled from the spec 4.1 wire table and the
    spec 4.2 LLSec bit table; no production frame code is imported here,
  - signatures come from reference_schnorr48.py (libsodium via PyNaCl),
    never from lichen.crypto.schnorr48.

Regenerate after editing:
    PYTHONPATH=python/src python/.venv/bin/python \
        test/vectors/generate_link_frame_signed_modes.py
"""

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
from reference_schnorr48 import ReferenceIdentity, sign, signature_transcript  # noqa: E402

FORMAT_VERSION = 2
OUTPUT = VECTORS_DIR / "link_frame_signed_modes.json"
SEED = bytes(32)

# Spec 4.2 LLSec bit positions. Bits 2-4 hold the MIC compatibility selector,
# which never changes the on-wire MIC width (signed frames always carry the
# full 48-byte Schnorr-48 value).
_SI_BIT = 0x80
_SIGNATURE_BIT = 0x20

_SIGNATURE_LENGTH = 48

_PROVENANCE = (
    "Independent PyNaCl reference signer over Link Signature Domain Version 1 "
    "and the normative transcript with non-wire DST_LEN={dst_len}. Frame octets "
    "hand-derived from the spec 4.1 wire table and spec 4.2 LLSec bit table."
)


def _signed_vector(
    name: str,
    description: str,
    identity: ReferenceIdentity,
    *,
    epoch: int,
    seqnum: int,
    dst_addr: bytes,
    payload: bytes,
    mic_length: int,
    addr_mode: int,
) -> dict[str, object]:
    """Hand-assemble one signed frame strictly from the spec tables."""
    assert 0 <= epoch <= 0xFF, "epoch out of range"
    assert 0 <= seqnum <= 0xFFFF, "seqnum out of range"
    signer_eui64 = identity.eui64
    assert len(signer_eui64) == 8

    # Modes 0 (broadcast) and 3 (elided) both omit DST octets, so address
    # length alone cannot select a mode.  Require the mode explicitly and
    # independently validate its normative address width.
    assert _ADDR_LENGTH_BY_MODE[addr_mode] == len(dst_addr)

    # Spec 4.1: LENGTH counts LLSec(1)+EPO(1)+SEQ(2)+DST+SIID+PLD+SIG(48)
    # and excludes the LENGTH octet itself.
    length = 4 + len(dst_addr) + len(signer_eui64) + len(payload) + _SIGNATURE_LENGTH
    assert length <= 254, "frame body exceeds the 254-byte spec limit"

    return _assemble(
        name,
        description,
        identity,
        seed=SEED,
        length=length,
        epoch=epoch,
        seqnum=seqnum,
        addr_mode=addr_mode,
        dst_addr=dst_addr,
        payload=payload,
        mic_length=mic_length,
        signer_eui64=signer_eui64,
    )


# Spec 4.3 addressing-mode table.
_ADDR_LENGTH_BY_MODE = {0: 0, 1: 2, 2: 8, 3: 0}


def _assemble(
    name: str,
    description: str,
    identity: ReferenceIdentity,
    *,
    seed: bytes,
    length: int,
    epoch: int,
    seqnum: int,
    addr_mode: int,
    dst_addr: bytes,
    payload: bytes,
    mic_length: int,
    signer_eui64: bytes,
) -> dict[str, object]:
    """Encode one vector from hand-derived field values (spec 4.1/4.2/4.3)."""
    # Spec 4.2 bit layout; signed frames MUST set both S and SI.
    llsec = _SI_BIT | _SIGNATURE_BIT | ((mic_length & 0b111) << 2) | (addr_mode & 0b11)
    wire_prefix = (
        bytes([length, llsec, epoch])
        + seqnum.to_bytes(2, "big")
        + dst_addr
        + signer_eui64
        + payload
    )
    # The wire prefix carries the LENGTH octet itself but not the MIC, so it
    # is one octet longer than the counted body minus the signature (matching
    # signature_transcript()'s slicing, which treats prefix[0] as LENGTH).
    assert len(wire_prefix) == length + 1 - _SIGNATURE_LENGTH
    # DST_LEN is a non-wire transcript octet domain-separating the variable
    # destination field (spec 4.1 canonical transcript).
    transcript = signature_transcript(wire_prefix, len(dst_addr))
    signature = sign(identity, transcript)

    verification = {
        "length": length,
        "llsec": llsec,
        "epoch": epoch,
        "seqnum": seqnum,
        "dst_len": len(dst_addr),
        "dst_addr": dst_addr.hex(),
        "signer_eui64": signer_eui64.hex(),
        "payload": payload.hex(),
        "signature": signature.hex(),
    }
    return {
        "name": name,
        "description": description,
        "fields": {
            "epoch": epoch,
            "seqnum": seqnum,
            "dst_addr": dst_addr.hex(),
            "payload": payload.hex(),
            "mic": signature.hex(),
            "addr_mode": addr_mode,
            "mic_length": mic_length,
            "signature_present": True,
            "encrypted": False,
            "signer_eui64": signer_eui64.hex(),
        },
        "encoded": (wire_prefix + signature).hex(),
        "crypto": {
            "seed": seed.hex(),
            "private_key": identity.private_scalar.hex(),
            "public_key": identity.pubkey.hex(),
            "preimage": transcript.hex(),
            "wire_prefix": wire_prefix.hex(),
            "signature": signature.hex(),
            "verification": verification,
            "provenance": _PROVENANCE.format(dst_len=len(dst_addr)),
        },
    }


def document() -> dict[str, object]:
    """Return the complete independently generated vector document."""
    identity = ReferenceIdentity.from_seed(SEED)
    return {
        "$schema": "./schema.json",
        "format_version": FORMAT_VERSION,
        "description": (
            "Signed link-layer frames for addressing modes 2 (extended EUI-64) "
            "and 3 (elided), plus exact maximum-payload boundaries for all four "
            "address modes; completes signed coverage alongside link_frame.json "
            "(spec section 4, draft-lichen-link-01)."
        ),
        "vectors": [
            _signed_vector(
                "extended_addr_signed",
                "Signed frame with 64-bit extended peer EUI-64 destination and "
                "MIC compatibility selector 1",
                identity,
                epoch=7,
                seqnum=0x0203,
                dst_addr=bytes.fromhex("0011223344556677"),
                payload=b"ext",
                mic_length=1,
                addr_mode=2,
            ),
            _signed_vector(
                "elided_addr_signed",
                "Signed frame with elided destination (context-derived, no "
                "address octets)",
                identity,
                epoch=9,
                seqnum=0x00FF,
                dst_addr=b"",
                payload=b"eld",
                mic_length=0,
                addr_mode=3,
            ),
            _signed_vector(
                "broadcast_signed_max_payload",
                "Signed broadcast at the maximum 194-byte payload boundary",
                identity,
                epoch=0xFF,
                seqnum=0xFFFF,
                dst_addr=b"",
                payload=bytes([0xA0]) * 194,
                mic_length=0,
                addr_mode=0,
            ),
            _signed_vector(
                "short_signed_max_payload",
                "Signed short-address frame at the maximum 192-byte payload boundary",
                identity,
                epoch=0xFE,
                seqnum=0xFFFE,
                dst_addr=bytes.fromhex("abcd"),
                payload=bytes([0xA1]) * 192,
                mic_length=1,
                addr_mode=1,
            ),
            _signed_vector(
                "extended_signed_max_payload",
                "Signed extended-address frame at the maximum 186-byte payload boundary",
                identity,
                epoch=0xFD,
                seqnum=0xFFFD,
                dst_addr=bytes.fromhex("0011223344556677"),
                payload=bytes([0xA2]) * 186,
                mic_length=0,
                addr_mode=2,
            ),
            _signed_vector(
                "elided_signed_max_payload",
                "Signed elided-address frame at the maximum 194-byte payload boundary",
                identity,
                epoch=0xFC,
                seqnum=0xFFFC,
                dst_addr=b"",
                payload=bytes([0xA3]) * 194,
                mic_length=1,
                addr_mode=3,
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
