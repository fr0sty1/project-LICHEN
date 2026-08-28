#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Generate canonical wire-format v2 link/SCHC vectors.

Consolidates the conformance corpus for the current link and SCHC wire format
(vector schema format_version=2) into one independently derived file:

  - signed link frames with the Signer Identifier (LLSec bit 7 SI) set
    together with bit 5 S on every signed frame ("I=S"), covering short,
    broadcast, and relay-resigned sender-identity forms plus the malformed
    S/SI parity and truncation rejects (spec 02 sections 4.1-4.2),
  - hop re-signing inputs: a relay re-signs a preserved payload under its own
    identity and replay counter; both exact transcripts are recorded,
  - announce epoch replay: one originator announce (fresh) and the same
    announce re-signed by a relay with a fresh link epoch/seqnum and an
    incremented hop count; the announce layer must reject the replay because
    the originator sequence did not advance (spec 05 section 9.3),
  - native SCHC: Rule 1 native ``0200::/8`` MSB(8)/LSB(120) compression with
    an address near-collision pair and a ULA-source non-match fallback,
  - RPL source reconstruction: Rule 3 link-local DIO whose residue carries the
    explicit source/destination IIDs, plus the ``ff02::1a`` multicast-DIO
    Rule 255 fallback that decoders MUST NOT fold into ``fe80::1a``,
  - multicast group IDs: RFC 3306 ``ff35:0040:<02xx /64>::<16-bit group ID>``
    with the 16-bit ID derived from SHA-256 of the group id string; two
    packets for the same group carry byte-identical destination addresses
    (immutable multicast IDs; spec 18.8.3).

Oracles are independent of the implementations under test:
  - frame octets are hand-assembled from the spec 4.1 wire table and the
    spec 4.2 LLSec bit table; no production frame code is imported,
  - SCHC residues are hand-packed bit-by-bit from the spec 5.5 field table
    (registry descriptor order; MSB-first, zero-padded), no production SCHC
    code is imported,
  - signatures come from reference_schnorr48.py (libsodium via PyNaCl) over
    the Link Signature Domain Version 1 and LICHEN-ANNOUNCE-v1 transcripts,
  - multicast group IDs and every checksum come from hashlib SHA-256 and an
    in-file RFC 2460/4443 one's-complement implementation.

Regenerate after editing:
    python3 test/vectors/generate_wire_format_v2.py
Verify without writing:
    python3 test/vectors/generate_wire_format_v2.py --check
"""

from __future__ import annotations

import argparse
import hashlib
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
from reference_schnorr48 import (  # noqa: E402
    ReferenceIdentity,
    sign,
    signature_transcript,
    verify,
)

FORMAT_VERSION = 2
OUTPUT = VECTORS_DIR / "wire_format_v2.json"

SEED_A = bytes(32)
SEED_B = bytes([0x01]) * 32

# Spec 4.2 LLSec bit positions.
_SI_BIT = 0x80
_ENC_BIT = 0x40
_SIGNATURE_BIT = 0x20

# Spec 4.1 dispatch values for the authenticated inner payload.
_DISPATCH_ROUTING = 0x15

_ANNOUNCE_TYPE = 0x01
_ANNOUNCE_SIGNATURE_DOMAIN = b"LICHEN-ANNOUNCE-v1\x00"

_LINK_LOCAL_PREFIX = 0xFE80 << 112
_MESH_PREFIX = bytes.fromhex("0200123456789abc") + bytes(8)

_FRAME_PROVENANCE = (
    "Independent PyNaCl reference signer over Link Signature Domain Version 1 "
    "and the normative transcript with non-wire DST_LEN={dst_len}. Frame octets "
    "hand-derived from the spec 4.1 wire table and spec 4.2 LLSec bit table."
)

_PROVENANCE = {
    "wire_format": (
        "Wire-format v2 = the current signed link frame (LLSec bit 7 SI plus "
        "bit 5 S, 8-byte Signer Identifier after Dst Addr) and the Version 3 "
        "SCHC rule set with native 0200::/8 residues, per spec 02 sections "
        "4.1-4.2, spec 03 section 5.5, and spec/appendix-schc.md. Legacy "
        "v1-schema fixtures (dash-named files) remain versioned migration data."
    ),
    "frames": (
        "Frame octets hand-assembled from the spec 4.1 wire table and 4.2 LLSec "
        "bit table; signatures from reference_schnorr48.py (libsodium/PyNaCl), "
        "never from lichen.crypto.schnorr48."
    ),
    "schc": (
        "Residues hand-packed bit-by-bit from the spec 5.5 field table "
        "(IPv6.hop_limit, address LSBs, UDP port LSB(4)s, CoAP type/tkl/code/"
        "mid for Rule 1; IIDs plus RPL base object for Rule 3); checksums from "
        "an in-file RFC 2460/4443 one's-complement implementation."
    ),
    "multicast": (
        "Group multicast address per spec 18.8.3 (RFC 3306 ff35:0040 + 64-bit "
        "02xx prefix + 16-bit group ID) with the 16-bit ID from SHA-256 of the "
        "group id string; spec 18.8.1 sanctions name-hash group ids. The spec "
        "example ':0001::0001' is internally inconsistent with its own 16-bit "
        "group-ID text; these vectors pin the normative :0000:<gid> layout."
    ),
    "announce": (
        "Announce transcript per spec 05 section 9.2 (LICHEN-ANNOUNCE-v1\\0 "
        "domain, hop count excluded); replay rule per section 9.3: an "
        "originator sequence not greater than the pinned floor is a replay."
    ),
}


# ---------------------------------------------------------------------------
# Independent link-frame encoder (spec 02 sections 4.1 and 4.2)
# ---------------------------------------------------------------------------


def _llsec_byte(
    *,
    si: bool,
    encrypted: bool,
    signature: bool,
    mic_length: int,
    addr_mode: int,
) -> int:
    return (
        (_SI_BIT if si else 0)
        | (_ENC_BIT if encrypted else 0)
        | (_SIGNATURE_BIT if signature else 0)
        | ((mic_length & 0x7) << 2)
        | (addr_mode & 0x3)
    )


def _addr_mode_width(addr_mode: int) -> int:
    return {0: 0, 1: 2, 2: 8, 3: 0}[addr_mode]


def _frame_crypto(
    identity: ReferenceIdentity,
    wire_prefix: bytes,
    dst_len: int,
    signature: bytes,
) -> dict[str, object]:
    return {
        "seed": identity.seed.hex(),
        "private_key": identity.private_scalar.hex(),
        "public_key": identity.pubkey.hex(),
        "preimage": signature_transcript(wire_prefix, dst_len).hex(),
        "wire_prefix": wire_prefix.hex(),
        "signature": signature.hex(),
        "provenance": _FRAME_PROVENANCE.format(dst_len=dst_len),
    }


def _signed_frame_vector(
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
) -> tuple[dict[str, object], bytes]:
    """Hand-assemble one normal signed frame strictly from the spec tables."""
    assert 0 <= epoch <= 0xFF
    assert 0 <= seqnum <= 0xFFFF
    signer_eui64 = identity.eui64
    assert len(signer_eui64) == 8
    width = _addr_mode_width(addr_mode)
    assert len(dst_addr) == width, "dst_addr width must match addr mode"
    max_payload = 254 - 4 - width - 8 - 48
    assert len(payload) <= max_payload, "payload exceeds signed frame bound"

    llsec = _llsec_byte(
        si=True, encrypted=False, signature=True, mic_length=mic_length, addr_mode=addr_mode
    )
    body = (
        bytes([llsec])
        + bytes([epoch])
        + seqnum.to_bytes(2, "big")
        + dst_addr
        + signer_eui64
        + payload
    )
    # LENGTH counts the whole body after the length byte, including the
    # 48-byte signature (spec 4.1: 4-254).
    wire_prefix = bytes([len(body) + 48]) + body
    signature = sign(identity, signature_transcript(wire_prefix, width))
    assert verify(identity.pubkey, signature_transcript(wire_prefix, width), signature)
    encoded = wire_prefix + signature
    fields = {
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
        "signer_eui64_present": True,
    }
    vector = {
        "name": name,
        "description": description,
        "fields": fields,
        "encoded": encoded.hex(),
        "crypto": _frame_crypto(identity, wire_prefix, width, signature),
    }
    return vector, encoded


def _unsigned_parity_vectors(identity: ReferenceIdentity) -> list[dict[str, object]]:
    """Malformed SenderID/I/S parity forms that receivers MUST discard."""
    vectors: list[dict[str, object]] = []

    # S=1 with SI=0: a signature without any Signer Identifier on the wire.
    # The signature itself is valid over the no-SIID transcript; the frame is
    # still discarded because signed frames MUST set both S and SI.
    payload = b"w2s0"
    llsec = _llsec_byte(si=False, encrypted=False, signature=True, mic_length=0, addr_mode=0)
    body = bytes([llsec, 8]) + (12).to_bytes(2, "big") + payload
    wire_prefix = bytes([len(body) + 48]) + body
    signature = sign(identity, signature_transcript(wire_prefix, 0))
    assert verify(identity.pubkey, signature_transcript(wire_prefix, 0), signature)
    vectors.append(
        {
            "name": "wf2_sig_without_sender_id",
            "description": (
                "Malformed S/SI parity: bit 5 S set with bit 7 SI clear, so the "
                "signature has no on-wire Signer Identifier. The Schnorr-48 "
                "signature verifies over the recorded transcript, but a receiver "
                "MUST discard the frame because signed frames MUST set both S "
                "and SI (spec 4.2) and MUST NOT brute-force the signer."
            ),
            "fields": {
                "epoch": 8,
                "seqnum": 12,
                "dst_addr": "",
                "payload": payload.hex(),
                "mic": signature.hex(),
                "addr_mode": 0,
                "mic_length": 0,
                "signature_present": True,
                "encrypted": False,
                "signer_eui64": "",
                "signer_eui64_present": False,
            },
            "encoded": (wire_prefix + signature).hex(),
            "crypto": _frame_crypto(identity, wire_prefix, 0, signature),
            "expect": {"error": "s_si_mismatch_signature_without_sender_id"},
        }
    )

    # S=0 with SI=1: an unsigned frame that still carries an 8-byte Signer
    # Identifier. There is nothing to verify, so the hint MUST NOT be used.
    siid = identity.eui64
    payload = b"w2u0"
    llsec = _llsec_byte(si=True, encrypted=False, signature=False, mic_length=0, addr_mode=0)
    body = bytes([llsec, 4]) + (13).to_bytes(2, "big") + siid + payload
    encoded = bytes([len(body)]) + body
    vectors.append(
        {
            "name": "wf2_sender_id_without_sig",
            "description": (
                "Malformed S/SI parity: bit 7 SI set with bit 5 S clear, so an "
                "unsigned frame carries a Signer Identifier with no signature. "
                "A receiver MUST discard it; the SIID is an unauthenticated hint "
                "and MUST NOT allocate replay, trust, routing, or fragmentation "
                "state (spec 4.2)."
            ),
            "fields": {
                "epoch": 4,
                "seqnum": 13,
                "dst_addr": "",
                "payload": payload.hex(),
                "mic": "",
                "addr_mode": 0,
                "mic_length": 0,
                "signature_present": False,
                "encrypted": False,
                "signer_eui64": siid.hex(),
                "signer_eui64_present": True,
            },
            "encoded": encoded.hex(),
            "expect": {"error": "s_si_mismatch_sender_id_without_signature"},
        }
    )

    # S=1 with SI=1 but the body ends four octets into the declared Signer
    # Identifier: no room for the 8-byte SIID plus the 48-byte signature.
    siid_prefix = siid[:4]
    llsec = _llsec_byte(si=True, encrypted=False, signature=True, mic_length=0, addr_mode=0)
    body = bytes([llsec, 9]) + (14).to_bytes(2, "big") + siid_prefix
    encoded = bytes([len(body)]) + body
    vectors.append(
        {
            "name": "wf2_signed_sender_id_truncated",
            "description": (
                "Malformed truncation: LLSec declares S and SI (needing an "
                "8-byte Signer Identifier plus a 48-byte signature) but the "
                "LENGTH-bounded body ends four octets into the Signer "
                "Identifier. The frame MUST be rejected as truncated; the "
                "partial SIID MUST NOT be used to select or mutate any state."
            ),
            "fields": {
                "epoch": 9,
                "seqnum": 14,
                "dst_addr": "",
                "payload": "",
                "mic": "",
                "addr_mode": 0,
                "mic_length": 0,
                "signature_present": True,
                "encrypted": False,
                "signer_eui64": siid.hex(),
                "signer_eui64_present": True,
            },
            "encoded": encoded.hex(),
            "expect": {"error": "truncated_signer_id"},
        }
    )
    return vectors


# ---------------------------------------------------------------------------
# Announce construction (spec 05 section 9.2) and replay pair (section 9.3)
# ---------------------------------------------------------------------------


def _announce_signed_data(
    identity: ReferenceIdentity, *, seq_num: int, rx_channel: int, app_data: bytes
) -> bytes:
    return (
        _ANNOUNCE_SIGNATURE_DOMAIN
        + identity.iid
        + identity.pubkey
        + seq_num.to_bytes(2, "big")
        + rx_channel.to_bytes(1, "big")
        + len(app_data).to_bytes(2, "big")
        + app_data
    )


def _announce_wire(
    identity: ReferenceIdentity, *, seq_num: int, hop: int, rx_channel: int, app_data: bytes
) -> bytes:
    """Announce wire bytes per spec 05 section 9.2 (signature precomputed)."""
    signature = sign(identity, _announce_signed_data(identity, seq_num=seq_num, rx_channel=rx_channel, app_data=app_data))
    return (
        bytes([_ANNOUNCE_TYPE, rx_channel, hop])
        + seq_num.to_bytes(2, "big")
        + identity.iid
        + identity.pubkey
        + signature
        + app_data
    )


def _announce_frame_vector(
    name: str,
    description: str,
    link_identity: ReferenceIdentity,
    *,
    epoch: int,
    seqnum: int,
    announce_wire: bytes,
    mic_length: int,
) -> dict[str, object]:
    vector, _ = _signed_frame_vector(
        name,
        description,
        link_identity,
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=b"",
        payload=bytes([_DISPATCH_ROUTING]) + announce_wire,
        mic_length=mic_length,
        addr_mode=0,
    )
    return vector


# ---------------------------------------------------------------------------
# Independent bit-level SCHC packing (spec 03 section 5.5, appendix A.3/A.5)
# ---------------------------------------------------------------------------


class _BitWriter:
    def __init__(self) -> None:
        self._bits = 0
        self._count = 0

    def append(self, value: int, width: int) -> None:
        assert 0 <= value < (1 << width), f"value {value} does not fit {width} bits"
        for shift in range(width - 1, -1, -1):
            bit = (value >> shift) & 1
            self._bits = (self._bits << 1) | bit
            self._count += 1

    def append_bytes(self, value: bytes) -> None:
        for octet in value:
            self.append(octet, 8)

    def to_bytes(self) -> bytes:
        pad = (-self._count) % 8
        for _ in range(pad):
            self.append(0, 1)
        out = bytearray()
        for index in range(0, self._count, 8):
            out.append((self._bits >> (self._count - 8 - index)) & 0xFF)
        return bytes(out)


def _rule1_residue(
    *,
    hop_limit: int,
    src: bytes,
    dst: bytes,
    src_port: int,
    dst_port: int,
    coap_type: int,
    coap_tkl: int,
    coap_code: int,
    coap_mid: int,
) -> bytes:
    """Spec 5.5 Rule 1 residue: 286 bits, zero-padded to 36 octets."""
    assert src[0] == 0x02 and dst[0] == 0x02, "Rule 1 matches only native 0200::/8"
    writer = _BitWriter()
    writer.append(hop_limit, 8)
    writer.append_bytes(src[1:])  # LSB(120) after the 0200::/8 MSB
    writer.append_bytes(dst[1:])
    writer.append(src_port & 0xF, 4)
    writer.append(dst_port & 0xF, 4)
    writer.append(coap_type, 2)
    writer.append(coap_tkl, 4)
    writer.append(coap_code, 8)
    writer.append(coap_mid, 16)
    residue = writer.to_bytes()
    assert len(residue) == 36, f"Rule 1 residue must pad to 36 octets, got {len(residue)}"
    return residue


def _rule3_residue(
    *,
    hop_limit: int,
    src_iid: bytes,
    dst_iid: bytes,
    instance: int,
    version: int,
    rank: int,
    gmop: int,
    dtsn: int,
    dodagid: bytes,
) -> bytes:
    """Spec 5.5 Rule 3 residue: 312 bits, exactly 39 octets, no padding."""
    assert len(src_iid) == 8 and len(dst_iid) == 8 and len(dodagid) == 16
    writer = _BitWriter()
    writer.append(hop_limit, 8)
    writer.append_bytes(src_iid)
    writer.append_bytes(dst_iid)
    writer.append(instance, 8)
    writer.append(version, 8)
    writer.append(rank, 16)
    writer.append(gmop, 8)
    writer.append(dtsn, 8)
    writer.append_bytes(dodagid)
    residue = writer.to_bytes()
    assert len(residue) == 39, f"Rule 3 residue must be 39 octets, got {len(residue)}"
    return residue


# ---------------------------------------------------------------------------
# Independent IPv6/UDP/ICMPv6/CoAP packet builders (RFC 8200/768/4443/7252)
# ---------------------------------------------------------------------------


def _ones_complement_sum(data: bytes) -> int:
    total = 0
    for index in range(0, len(data) - 1, 2):
        total += (data[index] << 8) | data[index + 1]
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
    if len(data) % 2:
        total += data[-1] << 8
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _checksum(pseudo: bytes, message: bytes) -> int:
    total = _ones_complement_sum(pseudo + message)
    return (~total) & 0xFFFF


def _pseudo_header(src: bytes, dst: bytes, next_header: int, length: int) -> bytes:
    return src + dst + length.to_bytes(4, "big") + bytes([0, 0, 0, next_header])


def _udp_datagram(src: bytes, dst: bytes, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp = bytearray(8 + len(payload))
    udp[0:2] = src_port.to_bytes(2, "big")
    udp[2:4] = dst_port.to_bytes(2, "big")
    udp[4:6] = len(udp).to_bytes(2, "big")
    udp[8:] = payload
    cksum = _checksum(_pseudo_header(src, dst, 17, len(udp)), bytes(udp))
    udp[6:8] = cksum.to_bytes(2, "big")
    assert cksum != 0, "UDP over IPv6 never serializes 0x0000"
    return bytes(udp)


def _ipv6_packet(src: bytes, dst: bytes, next_header: int, hop_limit: int, payload: bytes) -> bytes:
    header = bytearray(40)
    header[0] = 0x60
    header[4:6] = len(payload).to_bytes(2, "big")
    header[6] = next_header
    header[7] = hop_limit
    header[8:24] = src
    header[24:40] = dst
    return bytes(header) + payload


def _icmpv6_message(src: bytes, dst: bytes, icmp: bytes) -> bytes:
    cksum = _checksum(_pseudo_header(src, dst, 58, len(icmp)), icmp)
    return icmp[:2] + cksum.to_bytes(2, "big") + icmp[4:]


def _coap_request(mid: int, code: int = 0x01) -> bytes:
    # version 1, type CON (0), token length 0.
    return bytes([0x40, code]) + mid.to_bytes(2, "big")


def _udp_packet(src: bytes, dst: bytes, src_port: int, dst_port: int, payload: bytes) -> bytes:
    return _ipv6_packet(src, dst, 17, 64, _udp_datagram(src, dst, src_port, dst_port, payload))


def _native_udp_coap_packet(src: bytes, dst: bytes, mid: int, hop_limit: int = 64) -> bytes:
    coap = _coap_request(mid)
    udp = _udp_datagram(src, dst, 5683, 5683, coap)
    return _ipv6_packet(src, dst, 17, hop_limit, udp)


def _dio_packet(src: bytes, dst: bytes, *, dodagid: bytes, tail: bytes) -> bytes:
    base = bytes([1, 0]) + (0x0100).to_bytes(2, "big") + bytes([0x88, 0x01, 0x00, 0x00]) + dodagid
    icmp = bytes([155, 1, 0, 0]) + base + tail
    icmp = _icmpv6_message(src, dst, icmp)
    return _ipv6_packet(src, dst, 58, 64, icmp)


# ---------------------------------------------------------------------------
# Multicast group IDs (spec 18.8.1/18.8.3)
# ---------------------------------------------------------------------------


def _group_id_from_name(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]


def _group_multicast(group_id: str, prefix: bytes) -> bytes:
    assert len(prefix) == 8 and prefix[0] == 0x02
    gid16 = int.from_bytes(hashlib.sha256(group_id.encode("utf-8")).digest()[:2], "big")
    return bytes.fromhex("ff350040") + prefix + b"\x00\x00" + gid16.to_bytes(2, "big")


# ---------------------------------------------------------------------------
# Document assembly
# ---------------------------------------------------------------------------


def document() -> dict[str, object]:
    identity_a = ReferenceIdentity.from_seed(SEED_A)
    identity_b = ReferenceIdentity.from_seed(SEED_B)
    vectors: list[dict[str, object]] = []

    # --- Normal SenderID/I=S forms --------------------------------------
    short_vector, _ = _signed_frame_vector(
        "wf2_signed_short_sender_id",
        "Normal signed frame in the short-address form: LLSec bit 7 SI and bit "
        "5 S both set, a 2-byte short destination, and the 8-byte Signer "
        "Identifier EUI-64 (key-derived by toggling the U/L bit exactly once) "
        "carried between Dst Addr and Payload.",
        identity_a,
        epoch=5,
        seqnum=100,
        dst_addr=bytes.fromhex("c001"),
        payload=b"w2sh",
        mic_length=1,
        addr_mode=1,
    )
    vectors.append(short_vector)

    broadcast_vector, broadcast_payload = _signed_frame_vector(
        "wf2_signed_broadcast_sender_iid_only",
        "Normal signed broadcast frame: no destination octets (the coordinator "
        "0xffff 'no short address' case) so the sender is identified only by "
        "the SIID EUI-64; receivers bind identity to the verified public key, "
        "never to the hint (spec 4.2).",
        identity_a,
        epoch=5,
        seqnum=101,
        dst_addr=b"",
        payload=b"w2bc",
        mic_length=0,
        addr_mode=0,
    )
    vectors.append(broadcast_vector)

    # --- Hop re-signing inputs ------------------------------------------
    relay_vector, _ = _signed_frame_vector(
        "wf2_hop_resign_inputs",
        "Hop re-signing input: relay B (seed 0x01*32) received "
        "wf2_signed_broadcast_sender_iid_only, preserved the inner payload "
        "octet-for-octet, and signed a new enclosing frame with its own SIID "
        "and replay counter (epoch 6, seqnum 200). crypto.preimage is the "
        "exact re-sign transcript; the preserved payload equals the vector-2 "
        "payload and the origin frame's signature need not verify at the "
        "relay's receivers.",
        identity_b,
        epoch=6,
        seqnum=200,
        dst_addr=b"",
        payload=b"w2bc",
        mic_length=0,
        addr_mode=0,
    )
    vectors.append(relay_vector)

    # --- Announce epoch replay ------------------------------------------
    app_data = b"wf2-replay-probe"
    announce_hop0 = _announce_wire(identity_a, seq_num=4, hop=0, rx_channel=0, app_data=app_data)
    fresh_vector = _announce_frame_vector(
        "wf2_announce_fresh_counter_accept",
        "Announce (originator sequence 4, rx_channel 0) inside a signed "
        "broadcast frame from the originator. First acceptance pins the "
        "persistent per-originator replay floor at sequence 4 for originator "
        "IID 7dd5cfc679ab6342; payload byte 0 is the 0x15 routing dispatch and "
        "bytes 1.. parse as the announce wire value.",
        identity_a,
        epoch=5,
        seqnum=102,
        announce_wire=announce_hop0,
        mic_length=0,
    )
    vectors.append(fresh_vector)

    announce_hop1 = (
        announce_hop0[:2]
        + bytes([1])
        + announce_hop0[3:]
    )
    replay_vector = _announce_frame_vector(
        "wf2_announce_epoch_replay_hop_resigned",
        "Announce epoch replay: relay B re-signed the same originator announce "
        "(sequence 4) with an incremented hop count and a completely fresh "
        "link epoch/seqnum (7/55). The link layer accepts the frame (valid "
        "relay signature, fresh counter) but the announce layer MUST reject it "
        "as STALE_SEQNUM: originator sequence 4 is not greater than the "
        "persistent floor 4 pinned by wf2_announce_fresh_counter_accept "
        "(spec 05 section 9.3, 16-bit modular ordering). The hop count is "
        "excluded from the announce transcript, so the recorded signature "
        "still verifies.",
        identity_b,
        epoch=7,
        seqnum=55,
        announce_wire=announce_hop1,
        mic_length=0,
    )
    vectors.append(replay_vector)

    # --- Malformed SenderID/I/S forms ------------------------------------
    vectors.extend(_unsigned_parity_vectors(identity_a))

    # --- Native SCHC (Rule 1, 0200::/8 residues) -------------------------
    mesh_a = bytes.fromhex("0200123456789abc0000000000000001")
    mesh_b = bytes.fromhex("0200123456789abc0000000000000002")
    packet_rule1 = _native_udp_coap_packet(mesh_a, mesh_b, 0x1234)
    compressed_rule1 = bytes([1]) + _rule1_residue(
        hop_limit=64, src=mesh_a, dst=mesh_b, src_port=5683, dst_port=5683,
        coap_type=0, coap_tkl=0, coap_code=0x01, coap_mid=0x1234,
    )
    vectors.append(
        {
            "name": "wf2_schc_rule1_native_0200",
            "description": "Rule 1 native 0200::/8 compression: 37-byte fixed "
            "compressed header (Rule ID + 286-bit residue zero-padded to 36 "
            "octets). Residue layout MSB-first: hop_limit(8), src LSB(120), "
            "dst LSB(120), src_port LSB(4)=3, dst_port LSB(4)=3, CoAP type(2)=0, "
            "tkl(4)=0, code(8)=1, mid(16)=0x1234; UDP length and both checksums "
            "are COMPUTE and absent. Decompression MUST reconstruct the exact "
            "packet.",
            "rule_id": 1,
            "packet": packet_rule1.hex(),
            "compressed": compressed_rule1.hex(),
        }
    )

    # Near-collision pair: destination differs only in the final octet.
    mesh_c = bytes.fromhex("0200123456789abc0000000000000003")
    packet_collision = _native_udp_coap_packet(mesh_a, mesh_c, 0x1235)
    compressed_collision = bytes([1]) + _rule1_residue(
        hop_limit=64, src=mesh_a, dst=mesh_c, src_port=5683, dst_port=5683,
        coap_type=0, coap_tkl=0, coap_code=0x01, coap_mid=0x1235,
    )
    vectors.append(
        {
            "name": "wf2_schc_rule1_native_collision_probe",
            "description": "Native-address near-collision: destination differs "
            "from wf2_schc_rule1_native_0200 only in the final octet (…0003 vs "
            "…0002) yet the LSB(120) residues differ, so decompression MUST "
            "reconstruct each exact address; eliding more than the 0200::/8 "
            "MSB would collide distinct nodes.",
            "rule_id": 1,
            "packet": packet_collision.hex(),
            "compressed": compressed_collision.hex(),
        }
    )

    # ULA source must not match Rule 1 (or Rule 0); validated Rule 255.
    ula_src = bytes.fromhex("fc000000000000000000000000000001")
    packet_ula = _native_udp_coap_packet(ula_src, mesh_b, 0x1236)
    vectors.append(
        {
            "name": "wf2_schc_rule1_ula_source_nonmatch_fallback255",
            "description": "ULA fc00::/8 source with a native destination: Rule 1 "
            "MUST NOT match (source outside 0200::/8) and Rule 0 MUST NOT match, "
            "so the compressor selects fully validated Rule 255. Compressing "
            "under Rule 1 would collide the address by assuming the 0200::/8 "
            "MSB; there is no provisioned ULA context.",
            "rule_id": 255,
            "packet": packet_ula.hex(),
            "compressed": (bytes([255]) + packet_ula).hex(),
        }
    )

    # --- RPL source reconstruction (Rule 3) ------------------------------
    ll_a = bytes(_LINK_LOCAL_PREFIX.to_bytes(16, "big"))[:8] + identity_a.iid
    ll_b = bytes(_LINK_LOCAL_PREFIX.to_bytes(16, "big"))[:8] + identity_b.iid
    dio_tail = bytes([0x01, 0x02, 0x00, 0x00])
    packet_dio = _dio_packet(ll_a, ll_b, dodagid=identity_a.ygg_addr, tail=dio_tail)
    residue_rule3 = _rule3_residue(
        hop_limit=64, src_iid=identity_a.iid, dst_iid=identity_b.iid,
        instance=1, version=0, rank=0x0100, gmop=0x88, dtsn=0x01,
        dodagid=identity_a.ygg_addr,
    )
    vectors.append(
        {
            "name": "wf2_schc_rule3_rpl_source_reconstruction",
            "description": "Rule 3 link-local RPL DIO: the 39-octet residue "
            "carries the explicit RPL source/destination IDs as IIDs "
            "(residue[1:9] = source IID 7dd5cfc679ab6342, residue[9:17] = "
            "destination IID 3584728ae7309eab) followed by the value-sent DIO "
            "base object (instance, version, rank, gmop, dtsn, DODAGID); "
            "ICMPv6 type 155 code 1 and all lengths/checksums are recomputed "
            "on reconstruction. Decompression MUST rebuild fe80::<src IID> and "
            "fe80::<dst IID> exactly. Options travel verbatim after the "
            "39-octet residue.",
            "rule_id": 3,
            "packet": packet_dio.hex(),
            "compressed": (bytes([3]) + residue_rule3 + dio_tail).hex(),
        }
    )

    # Canonical multicast DIO destination must fall back to Rule 255.
    packet_dio_mcast = _dio_packet(ll_a, bytes.fromhex("ff02000000000000000000000000001a"), dodagid=identity_a.ygg_addr, tail=dio_tail)
    vectors.append(
        {
            "name": "wf2_schc_rule3_multicast_dst_nonmatch_fallback255",
            "description": "Canonical RPL multicast DIO to ff02::1a: Rule 3 does "
            "not match (destination outside fe80::/64) so the sender MUST use "
            "fully validated Rule 255; a decoder MUST NOT turn ff02::1a into "
            "fe80::1a (spec 03 section 5.5, appendix-schc.md A.5).",
            "rule_id": 255,
            "packet": packet_dio_mcast.hex(),
            "compressed": (bytes([255]) + packet_dio_mcast).hex(),
        }
    )

    # --- Immutable multicast group IDs -----------------------------------
    group_id = _group_id_from_name("team-alpha")
    group_prefix = bytes.fromhex("0200123456789abc")
    group_dst = _group_multicast(group_id, group_prefix)
    packet_group1 = _udp_packet(mesh_a, group_dst, 5683, 5683, b"gm1")
    packet_group2 = _udp_packet(mesh_a, group_dst, 5683, 5683, b"gm2")
    vectors.append(
        {
            "name": "wf2_schc_rule255_group_multicast_id",
            "description": "Rule 255 UDP packet whose destination is the spec "
            "18.8.3 group multicast address ff35:0040:0200:1234:5678:9abc:0000:"
            "<gid> for group id "
            f"{group_id} (name-hash of 'team-alpha'); the 16-bit ID is "
            "SHA-256(group id)[:2] big-endian. Multicast IDs are immutable: "
            "consumers MUST derive the identical 16 destination bytes from the "
            "group id string and mesh prefix.",
            "rule_id": 255,
            "packet": packet_group1.hex(),
            "compressed": (bytes([255]) + packet_group1).hex(),
        }
    )
    vectors.append(
        {
            "name": "wf2_schc_rule255_group_multicast_id_stable_reissue",
            "description": "Same group re-issued in a different packet "
            "(different UDP payload): the destination address octets "
            f"{group_dst.hex()} are byte-identical to "
            "wf2_schc_rule255_group_multicast_id, pinning multicast-ID "
            "immutability across re-creation and invitation re-minting.",
            "rule_id": 255,
            "packet": packet_group2.hex(),
            "compressed": (bytes([255]) + packet_group2).hex(),
        }
    )

    return {
        "$schema": "./schema.json",
        "format_version": FORMAT_VERSION,
        "name": "wire_format_v2",
        "description": (
            "Canonical wire-format v2 link/SCHC conformance vectors: signed "
            "frames with SI+S sender-identity forms (normal, relay re-signed, "
            "malformed), hop re-signing inputs, announce epoch replay, native "
            "0200::/8 SCHC residues, RPL source reconstruction, address "
            "near-collisions, and immutable multicast group IDs. Every byte is "
            "hand-derived from the spec tables plus independent oracles; "
            "legacy v1-schema fixtures stay as versioned migration data."
        ),
        "spec": (
            "spec/02-physical-link.md 4.1-4.2; spec/03-adaptation.md 5.5-5.7; "
            "spec/appendix-schc.md; spec/05-routing.md 9.2-9.3; "
            "spec/12-apps.md 18.8; draft-lichen-link-01; draft-lichen-schnorr-00"
        ),
        "provenance": _PROVENANCE,
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