# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Packet format oracles (spec 09-packets-timing.md §13).

Implements size-budget calculators and walk-through validation for
§13.1 Complete Packet Example, §13.2 Packet Size Summary, §13.3 RPL DIO
Packet.  All values are taken verbatim from the spec; no network I/O.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# §13.2 Packet Size Summary (bytes)
# ---------------------------------------------------------------------------
PACKET_SIZE_SUMMARY: dict[str, int | tuple[int, int]] = {
    "app_payload": 17,
    "security_e2e": 10,
    "transport_network": 2,
    "routing_overhead": (0, 6),  # 0-6 bytes
    "link_security": 53,
    "total": (82, 88),  # 82-88 bytes
}

# Breakdown for link security per spec:
# Length(1) + LLSec(1) + Epoch(1) + SeqNum(2) + Signature(48) = 53
# DstAddr counted separately (0/2/8 bytes depending on mode).
LINK_SECURITY_OVERHEAD: int = 53
LINK_SECURITY_BREAKDOWN: dict[str, int] = {
    "Length": 1,
    "LLSec": 1,
    "Epoch": 1,
    "SeqNum": 2,
    "Signature": 48,
}

# ---------------------------------------------------------------------------
# §13.1 Complete Packet Example walk-through
# ---------------------------------------------------------------------------
# Values below reproduce the exact example in spec 13.1.
COMPLETE_PACKET_EXAMPLE: dict[str, object] = {
    "app_payload_cbor_hex": "A16B74656D7065726174757265F94BC0",  # 17 bytes (truncated illustrative)
    "app_payload_len": 17,
    "oscore_overhead": 10,
    "schc_rule_id": 0x00,
    "schc_residue": "compressed",
    "schc_packet_len": 21,  # Rule ID(1)+Residue(1)+Compressed CoAP hdr(2)+Payload(17)
    "schc_dispatch": 0x14,
    "l2_payload_len": 22,  # dispatch 0x14 + SCHC 21
    "link_frame": {
        "Length": 76,  # 0x4C, body bytes after Length
        "LLSec": 0x21,  # signature, no encryption, short addr
        "Epoch": 0x01,
        "SeqNum": 0x0042,
        "DstAddr": 0x0001,
        "payload_dispatch": 0x14,
        "payload_len": 22,
        "signature_len": 48,
        "total_on_wire": 77,  # Length byte + 76-byte body
    },
    "lora_phy": {
        "preamble_symbols": 8,
        "header_bytes": 3,
        "payload_bytes": 60,
        "crc_bytes": 2,
    },
}

# RPL DIO skeletal fields (§13.3)
RPL_DIO_FIELDS: dict[str, object] = {
    "link_layer": ["Len", "LLSec", "Epoch", "SeqNum", "DstAddr=ff02::1a", "Payload", "Sig"],
    "ipv6_compressed": ["SCHC Rule 2", "HopLimit", "Multicast flag"],
    "icmpv6": {"Type": 155, "Code": 1, "label": "DIO"},
    "dio_payload": ["RPLInstanceID", "Version", "Rank", "Flags", "DODAGID"],
    "options": ["DODAG Configuration", "Prefix Information"],
}


@dataclass(frozen=True)
class LinkFrameOverhead:
    """Overhead breakdown for a link-layer frame."""

    length: int = 1
    llsec: int = 1
    epoch: int = 1
    seqnum: int = 2
    dst_addr_len: int = 2  # short addr; 0 for none/elided, 8 for extended
    signature: int = 48  # 0 if unsigned

    @property
    def total(self) -> int:
        return (
            self.length + self.llsec + self.epoch + self.seqnum + self.dst_addr_len + self.signature
        )

    @property
    def body(self) -> int:
        """Body bytes after Length (total - 1)."""
        return self.total - 1


def link_frame_overhead(*, addr_mode: str = "short", signed: bool = True) -> LinkFrameOverhead:
    """Return link-frame overhead for a given addressing mode.

    Args:
        addr_mode: One of ``none``, ``short`` (2B), ``extended`` (8B),
            ``elided`` (0B).  Short matches spec example.
        signed: Whether Schnorr-48 signature (48B) is present.
    """
    addr_len_map = {"none": 0, "short": 2, "extended": 8, "elided": 0}
    if addr_mode not in addr_len_map:
        raise ValueError(f"unknown addr_mode {addr_mode!r}")
    return LinkFrameOverhead(
        dst_addr_len=addr_len_map[addr_mode],
        signature=48 if signed else 0,
    )


def total_packet_size_range(
    *,
    routing_overhead: int = 0,
) -> tuple[int, int]:
    """Return (min_total, max_total) for packet size budget.

    Matches §13.2 table: 82-88 bytes total.
    The routing_overhead 0-6 range shifts the total.
    """
    if not 0 <= routing_overhead <= 6:
        raise ValueError("routing_overhead must be 0..6")
    # Fixed components: app 17 + e2e 10 + transport 2 + link 53 = 82
    base = 17 + 10 + 2 + 53
    return (base + routing_overhead, base + routing_overhead)


def dio_packet_bytes(*, instance_id: int = 0, version: int = 0, rank: int = 256) -> bytes:
    """Return a minimal deterministic DIO payload skeleton.

    This is not a full RPL implementation; it encodes the fields listed
    in §13.3 as a predictable byte sequence for vector comparison.
    Layout: [InstanceID(1), Version(1), Rank(2 BE), Flags(1), DODAGID(16 zero)]
    """
    if not 0 <= instance_id <= 255:
        raise ValueError("instance_id out of range")
    if not 0 <= version <= 255:
        raise ValueError("version out of range")
    if not 0 <= rank <= 0xFFFF:
        raise ValueError("rank out of range")
    return (
        instance_id.to_bytes(1, "big")
        + version.to_bytes(1, "big")
        + rank.to_bytes(2, "big")
        + b"\x00"  # flags
        + b"\x00" * 16  # DODAGID placeholder
    )


def validate_complete_example(frame: dict[str, int]) -> bool:
    """Validate a dict of link-frame fields against §13.1 example."""
    expected = COMPLETE_PACKET_EXAMPLE["link_frame"]  # type: ignore[index]
    if not isinstance(expected, dict):
        return False
    return all(frame.get(k) == v for k, v in expected.items())  # type: ignore[union-attr]
