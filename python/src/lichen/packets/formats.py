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
PACKET_SIZE_SUMMARY: dict[str, int] = {
    "app_payload": 16,
    "security_e2e": 0,
    "transport_network": 27,
    "routing_overhead": 3,
    "link_security": 61,
    "total": 107,
}

# Breakdown for link security per spec:
# Length(1) + LLSec(1) + Epoch(1) + SeqNum(2) + Signer EUI-64(8)
# + Signature(48) = 61. DstAddr and the L2 dispatch are counted separately.
# DstAddr counted separately (0/2/8 bytes depending on mode).
LINK_SECURITY_OVERHEAD: int = 61
LINK_SECURITY_BREAKDOWN: dict[str, int] = {
    "Length": 1,
    "LLSec": 1,
    "Epoch": 1,
    "SeqNum": 2,
    "SignerEui64": 8,
    "Signature": 48,
}

# ---------------------------------------------------------------------------
# §13.1 Complete Packet Example walk-through
# ---------------------------------------------------------------------------
# Values below reproduce the exact example in spec 13.1.
COMPLETE_PACKET_EXAMPLE: dict[str, object] = {
    "app_payload_cbor_hex": "A16B74656D7065726174757265F94DE0",
    "app_payload_len": 16,
    "oscore_overhead": 0,
    "schc_rule_id": 0x00,
    "schc_residue": "compressed",
    "schc_packet_len": 43,
    "schc_dispatch": 0x14,
    "l2_payload_len": 44,
    "link_frame": {
        "Length": 106,  # 0x6A, body bytes after Length
        "LLSec": 0xA1,  # SI + signature, no encryption, short addr
        "Epoch": 0x01,
        "SeqNum": 0x0042,
        "DstAddr": 0x0001,
        "signer_eui64_len": 8,
        "payload_dispatch": 0x14,
        "payload_len": 44,
        "signature_len": 48,
        "total_on_wire": 107,
    },
    "lora_phy": {
        "preamble_symbols": 8,
        "header_bytes": 3,
        "payload_bytes": 107,
        "crc_bytes": 2,
    },
}

# RPL DIO skeletal fields (§13.3)
RPL_DIO_FIELDS: dict[str, object] = {
    "link_layer": ["Len", "LLSec", "Epoch", "SeqNum", "SignerEUI64", "Payload", "Sig"],
    "ipv6_compressed": [
        "validated SCHC Rule 255",
        "full IPv6 header",
        "destination ff02::1a",
    ],
    "icmpv6": {"Type": 155, "Code": 1, "label": "DIO"},
    "dio_payload": [
        "RPLInstanceID",
        "Version",
        "Rank",
        "G/MOP/Prf",
        "DTSN",
        "Flags",
        "Reserved",
        "DODAGID",
    ],
    "options": ["Rule-Version 0x13/0x01/0x03 (mandatory)"],
}


@dataclass(frozen=True)
class LinkFrameOverhead:
    """Overhead breakdown for a link-layer frame."""

    length: int = 1
    llsec: int = 1
    epoch: int = 1
    seqnum: int = 2
    dst_addr_len: int = 2  # short addr; 0 for none/elided, 8 for extended
    signer_eui64: int = 8  # 0 if unsigned
    signature: int = 48  # 0 if unsigned

    @property
    def total(self) -> int:
        return (
            self.length
            + self.llsec
            + self.epoch
            + self.seqnum
            + self.dst_addr_len
            + self.signer_eui64
            + self.signature
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
    if type(addr_mode) is not str:
        raise TypeError("addr_mode must be an exact string")
    if type(signed) is not bool:
        raise TypeError("signed must be an exact boolean")
    if addr_mode not in addr_len_map:
        raise ValueError(f"unknown addr_mode {addr_mode!r}")
    return LinkFrameOverhead(
        dst_addr_len=addr_len_map[addr_mode],
        signer_eui64=8 if signed else 0,
        signature=48 if signed else 0,
    )


def total_packet_size_range(
    *,
    routing_overhead: int = 0,
) -> tuple[int, int]:
    """Return (min_total, max_total) for packet size budget.

    The §13.2 example uses three routing/addressing bytes and totals 107.
    This helper also exposes the surrounding 0-6-byte routing range.
    """
    if type(routing_overhead) is not int:
        raise TypeError("routing_overhead must be an exact integer")
    if not 0 <= routing_overhead <= 6:
        raise ValueError("routing_overhead must be 0..6")
    # Fixed components: app 16 + e2e 0 + transport/network 27 + link 61 = 104.
    base = 16 + 0 + 27 + 61
    return (base + routing_overhead, base + routing_overhead)


def dio_packet_bytes(*, instance_id: int = 0, version: int = 0, rank: int = 256) -> bytes:
    """Return a minimal deterministic DIO payload skeleton.

    This is not a full RPL implementation; it encodes the fields listed
    in §13.3 as a predictable byte sequence for vector comparison.
    Layout: the 24-byte RFC 6550 DIO base followed by the mandatory
    Rule-Version option ``13 01 03``.  This helper returns the DIO bytes only;
    the canonical multicast IPv6 envelope uses validated SCHC Rule 255.
    """
    for name, value in (
        ("instance_id", instance_id),
        ("version", version),
        ("rank", rank),
    ):
        if type(value) is not int:
            raise TypeError(f"{name} must be an exact integer")
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
        + b"\x08"  # G=0, MOP=1, Prf=0
        + b"\x00"  # DTSN
        + b"\x00"  # Flags
        + b"\x00"  # Reserved
        + b"\x00" * 16  # DODAGID placeholder
        + b"\x13\x01\x03"  # mandatory Rule-Version option: version 3
    )


def validate_complete_example(frame: dict[str, int]) -> bool:
    """Validate a dict of link-frame fields against §13.1 example."""
    expected = COMPLETE_PACKET_EXAMPLE["link_frame"]
    if not isinstance(expected, dict):
        return False
    return all(frame.get(k) == v for k, v in expected.items())
