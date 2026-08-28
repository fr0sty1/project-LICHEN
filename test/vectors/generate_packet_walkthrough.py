#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate spec 09 section 13.1 CoAP-to-PHY packet walkthrough vectors.

Independent oracle: this module does not import lichen.*. CoAP bytes follow
RFC 7252, the IPv6/UDP envelope follows RFC 8200/768, Rule 0 residue packing
follows spec/appendix-schc.md, L2 dispatch is spec 02 section 4 inner-payload
0x14, the signed short-address frame follows spec 02 section 4.1/4.2, and
PHY airtime uses the integer Semtech formula in spec 09 section 14.4.
Signatures come from reference_schnorr48.py (libsodium via PyNaCl).

Spec 13.1 omits MID, addresses, hop limit, and UDP ports. This walkthrough
pins the unspecified fields so each layer has a bit-exact expected output:
  MID 0x0000, hop limit 64, UDP 5683/5683, src fe80::1, dst fe80::2.

Regenerate:
    PYTHONPATH=python/src python3 test/vectors/generate_packet_walkthrough.py
Check without writing:
    PYTHONPATH=python/src python3 test/vectors/generate_packet_walkthrough.py --check
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
OUTPUT = VECTORS_DIR / "packet_walkthrough.json"
SEED = bytes(32)

# Spec 13.1 CoAP example.
_COAP_VERSION = 1
_COAP_TYPE_NON = 1
_COAP_TKL = 1
_COAP_CODE_CONTENT = 0x45  # 2.05
_COAP_MID = 0x0000
_COAP_TOKEN = bytes((0x42,))
_COAP_CONTENT_FORMAT = 60  # application/cbor
_COAP_CBOR_PAYLOAD = bytes.fromhex("a16b74656d7065726174757265f94de0")

_SRC_ADDR = bytes.fromhex("fe800000000000000000000000000001")
_DST_ADDR = bytes.fromhex("fe800000000000000000000000000002")
_HOP_LIMIT = 64
_UDP_PORT = 5683
_UDP_NEXT_HEADER = 17

_EPOCH = 0x01
_SEQNUM = 0x0042
_DST_SHORT = bytes((0x00, 0x01))
_ADDR_MODE_SHORT = 1
_MIC_LENGTH_SELECTOR = 0
_L2_DISPATCH_SCHC = 0x14
_SI_BIT = 0x80
_SIGNATURE_BIT = 0x20
_SIGNATURE_LENGTH = 48

_SF = 10
_BW_HZ = 125_000
_CR = 5
_PREAMBLE_SYMBOLS = 8


class _BitWriter:
    """MSB-first residue packer (RFC 8724). Local to this oracle."""

    def __init__(self) -> None:
        self._acc = 0
        self._nbits = 0

    def write(self, value: int, nbits: int) -> None:
        if nbits < 0:
            raise ValueError("nbits must be non-negative")
        if value < 0 or (nbits < 64 and value >= (1 << nbits)):
            raise ValueError("value does not fit")
        self._acc = (self._acc << nbits) | value
        self._nbits += nbits

    @property
    def bit_length(self) -> int:
        return self._nbits

    def to_bytes(self) -> bytes:
        if self._nbits == 0:
            return b""
        pad = (-self._nbits) % 8
        total = self._nbits + pad
        return (self._acc << pad).to_bytes(total // 8, "big")


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _encode_coap() -> bytes:
    """RFC 7252 header + Content-Format option + CBOR payload."""
    first = (_COAP_VERSION << 6) | (_COAP_TYPE_NON << 4) | _COAP_TKL
    # Option 12 (Content-Format), delta 12, one-byte value 60 -> c1 3c.
    option = bytes((0xC1, _COAP_CONTENT_FORMAT))
    return (
        bytes((first, _COAP_CODE_CONTENT))
        + _COAP_MID.to_bytes(2, "big")
        + _COAP_TOKEN
        + option
        + b"\xff"
        + _COAP_CBOR_PAYLOAD
    )


def _encode_ipv6_udp(coap: bytes) -> bytes:
    udp_length = 8 + len(coap)
    udp_without_checksum = (
        _UDP_PORT.to_bytes(2, "big")
        + _UDP_PORT.to_bytes(2, "big")
        + udp_length.to_bytes(2, "big")
        + bytes(2)
        + coap
    )
    pseudo = (
        _SRC_ADDR
        + _DST_ADDR
        + udp_length.to_bytes(4, "big")
        + bytes(3)
        + bytes((_UDP_NEXT_HEADER,))
    )
    checksum = _internet_checksum(pseudo + udp_without_checksum) or 0xFFFF
    udp = udp_without_checksum[:6] + checksum.to_bytes(2, "big") + coap
    version_tc_fl = 6 << 28
    header = (
        version_tc_fl.to_bytes(4, "big")
        + udp_length.to_bytes(2, "big")
        + bytes((_UDP_NEXT_HEADER, _HOP_LIMIT))
        + _SRC_ADDR
        + _DST_ADDR
    )
    return header + udp


def _compress_rule0(ipv6: bytes) -> bytes:
    """Rule 0: 174-bit residue padded to 22 bytes, then CoAP tail."""
    hop_limit = ipv6[7]
    src_iid = int.from_bytes(ipv6[16:24], "big")
    dst_iid = int.from_bytes(ipv6[32:40], "big")
    src_port = int.from_bytes(ipv6[40:42], "big")
    dst_port = int.from_bytes(ipv6[42:44], "big")
    coap = ipv6[48:]
    coap_type = (coap[0] >> 4) & 0x03
    tkl = coap[0] & 0x0F
    code = coap[1]
    mid = int.from_bytes(coap[2:4], "big")
    tail = coap[4:]
    writer = _BitWriter()
    writer.write(hop_limit, 8)
    writer.write(src_iid, 64)
    writer.write(dst_iid, 64)
    writer.write(src_port & 0x0F, 4)
    writer.write(dst_port & 0x0F, 4)
    writer.write(coap_type, 2)
    writer.write(tkl, 4)
    writer.write(code, 8)
    writer.write(mid, 16)
    residue = writer.to_bytes()
    assert writer.bit_length == 174
    assert len(residue) == 22
    return bytes((0x00,)) + residue + tail


def _wrap_l2(schc: bytes) -> bytes:
    return bytes((_L2_DISPATCH_SCHC,)) + schc


def _encode_link_frame(identity: ReferenceIdentity, payload: bytes) -> tuple[bytes, bytes, bytes]:
    llsec = (
        _SI_BIT
        | _SIGNATURE_BIT
        | ((_MIC_LENGTH_SELECTOR & 0b111) << 2)
        | (_ADDR_MODE_SHORT & 0b11)
    )
    signer_eui64 = identity.eui64
    body_len = 4 + len(_DST_SHORT) + len(signer_eui64) + len(payload) + _SIGNATURE_LENGTH
    wire_prefix = (
        bytes((body_len, llsec, _EPOCH))
        + _SEQNUM.to_bytes(2, "big")
        + _DST_SHORT
        + signer_eui64
        + payload
    )
    transcript = signature_transcript(wire_prefix, len(_DST_SHORT))
    signature = sign(identity, transcript)
    return wire_prefix + signature, transcript, signature


def _airtime_us(payload_len: int) -> int:
    """Integer Semtech airtime matching spec 09 section 14.4 / lichen-core."""
    de = (1 << _SF) * 1_000 >= 16 * _BW_HZ
    numerator = 8 * payload_len - 4 * _SF + 28 + 16 - 0
    denominator = 4 * (_SF - 2 * int(de))
    coded = 0 if numerator <= 0 else (numerator + denominator - 1) // denominator
    payload_symbols = 8 + coded * _CR
    quarter_symbols = 4 * _PREAMBLE_SYMBOLS + 17 + 4 * payload_symbols
    return (quarter_symbols * (1 << _SF) * 1_000_000) // (4 * _BW_HZ)


def _layer(
    name: str,
    description: str,
    category: str,
    *,
    input_hex: str,
    output_hex: str,
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    output = bytes.fromhex(output_hex)
    vector: dict[str, object] = {
        "name": name,
        "description": description,
        "category": category,
        "input_hex": input_hex,
        "output_hex": output_hex,
        "output_len": len(output),
    }
    if extra:
        vector.update(extra)
    return vector


def document() -> dict[str, object]:
    identity = ReferenceIdentity.from_seed(SEED)
    coap = _encode_coap()
    ipv6 = _encode_ipv6_udp(coap)
    schc = _compress_rule0(ipv6)
    l2 = _wrap_l2(schc)
    link, transcript, signature = _encode_link_frame(identity, l2)
    airtime = _airtime_us(len(link))

    assert len(_COAP_CBOR_PAYLOAD) == 16
    assert len(schc) == 43
    assert len(l2) == 44
    assert link[0] == 106
    assert link[1] == 0xA1
    assert len(link) == 107

    coap_fields = {
        "ver": _COAP_VERSION,
        "type": _COAP_TYPE_NON,
        "type_name": "NON",
        "tkl": _COAP_TKL,
        "code": _COAP_CODE_CONTENT,
        "code_name": "2.05",
        "mid": _COAP_MID,
        "token_hex": _COAP_TOKEN.hex(),
        "content_format": _COAP_CONTENT_FORMAT,
        "payload_hex": _COAP_CBOR_PAYLOAD.hex(),
        "payload_len": len(_COAP_CBOR_PAYLOAD),
    }
    ipv6_fields = {
        "src": "fe80::1",
        "dst": "fe80::2",
        "hop_limit": _HOP_LIMIT,
        "src_port": _UDP_PORT,
        "dst_port": _UDP_PORT,
        "next_header": _UDP_NEXT_HEADER,
    }
    schc_fields = {
        "rule_id": 0,
        "residue_len": 22,
        "fixed_header_len": 23,
        "tail_len": 20,
    }
    l2_fields = {"dispatch": _L2_DISPATCH_SCHC}
    link_fields = {
        "Length": 106,
        "LLSec": 0xA1,
        "Epoch": _EPOCH,
        "SeqNum": _SEQNUM,
        "DstAddr": int.from_bytes(_DST_SHORT, "big"),
        "addr_mode": _ADDR_MODE_SHORT,
        "mic_length": _MIC_LENGTH_SELECTOR,
        "signature_present": True,
        "encrypted": False,
        "signer_eui64_hex": identity.eui64.hex(),
        "payload_dispatch": _L2_DISPATCH_SCHC,
        "payload_len": len(l2),
        "signature_len": _SIGNATURE_LENGTH,
        "total_on_wire": len(link),
        "seed_hex": SEED.hex(),
        "public_key_hex": identity.pubkey.hex(),
        "transcript_hex": transcript.hex(),
        "signature_hex": signature.hex(),
    }
    phy_fields = {
        "payload_len": len(link),
        "preamble_symbols": _PREAMBLE_SYMBOLS,
        "explicit_header": True,
        "phy_crc": True,
        "sf": _SF,
        "bw_hz": _BW_HZ,
        "coding_rate": "4/5",
        "airtime_us": airtime,
    }

    vectors: list[dict[str, object]] = [
        _layer(
            "coap_temperature_content",
            "Spec 13.1 plaintext CoAP 2.05 NON Content-Format 60 with CBOR "
            "{temperature: 23.5}. MID is unspecified in the spec and pinned to 0.",
            "coap",
            input_hex=_COAP_CBOR_PAYLOAD.hex(),
            output_hex=coap.hex(),
            extra={"fields": coap_fields},
        ),
        _layer(
            "ipv6_udp_envelope",
            "IPv6 + UDP envelope around the CoAP message: fe80::1 to fe80::2, "
            "ports 5683/5683, hop limit 64, Rule 0 match constraints.",
            "ipv6_udp",
            input_hex=coap.hex(),
            output_hex=ipv6.hex(),
            extra={"fields": ipv6_fields},
        ),
        _layer(
            "schc_rule0_compress",
            "SCHC Rule 0 compression: 1-byte Rule ID + 22-byte residue + 20-byte "
            "CoAP tail = 43 bytes (spec 13.1).",
            "schc",
            input_hex=ipv6.hex(),
            output_hex=schc.hex(),
            extra={"fields": schc_fields},
        ),
        _layer(
            "l2_schc_dispatch",
            "Authenticated L2 inner payload: dispatch 0x14 plus the 43-byte SCHC "
            "packet = 44 bytes (spec 13.1).",
            "l2",
            input_hex=schc.hex(),
            output_hex=l2.hex(),
            extra={"fields": l2_fields},
        ),
        _layer(
            "link_frame_signed_short",
            "Signed short-address link frame: Length 106, LLSec 0xA1, Epoch 0x01, "
            "SeqNum 0x0042, DstAddr 0x0001, 8-byte signer EUI-64, 44-byte payload, "
            "48-byte Schnorr-48 = 107 on-wire bytes (spec 13.1).",
            "link",
            input_hex=l2.hex(),
            output_hex=link.hex(),
            extra={"fields": link_fields},
        ),
        {
            "name": "phy_sf10_airtime",
            "description": (
                "LoRa PHY carries the 107-byte link frame as the PHY payload. "
                "Radio overhead is the 8-symbol preamble, explicit header, and PHY "
                "CRC; those octets are not inside the PHY payload (spec 13.1). "
                "Airtime is the default SF10/125kHz/CR4-5 profile."
            ),
            "category": "phy",
            "input_hex": link.hex(),
            "output_hex": link.hex(),
            "output_len": len(link),
            "fields": phy_fields,
        },
        {
            "name": "spec_13_1_complete_walkthrough",
            "description": (
                "Chained CoAP -> IPv6/UDP -> SCHC Rule 0 -> L2 dispatch -> signed "
                "short-addr link frame -> LoRa PHY for the spec 13.1 temperature "
                "example. Each layer output_hex is the next layer input_hex."
            ),
            "category": "walkthrough",
            "app_payload_len": 16,
            "schc_packet_len": 43,
            "l2_payload_len": 44,
            "body_bytes": 106,
            "total_on_wire": 107,
            "layers": {
                "coap_hex": coap.hex(),
                "ipv6_udp_hex": ipv6.hex(),
                "schc_hex": schc.hex(),
                "l2_hex": l2.hex(),
                "link_hex": link.hex(),
                "phy_payload_hex": link.hex(),
            },
            "coap": coap_fields,
            "ipv6_udp": ipv6_fields,
            "schc": schc_fields,
            "l2": l2_fields,
            "link": link_fields,
            "phy": phy_fields,
        },
    ]
    return {
        "format_version": FORMAT_VERSION,
        "description": (
            "Complete packet walkthrough vectors for spec 09 section 13.1: "
            "plaintext CoAP temperature reading compressed with SCHC Rule 0, "
            "wrapped in authenticated L2 dispatch 0x14, signed as a short-address "
            "link frame, and timed as a LoRa PHY payload. Independent of lichen.*."
        ),
        "vectors": vectors,
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
