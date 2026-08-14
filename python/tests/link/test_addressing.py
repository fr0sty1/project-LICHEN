# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for LICHEN addressing modes (spec section 4.3) including elided derivation."""

from __future__ import annotations

import json
from ipaddress import IPv6Address
from pathlib import Path

import pytest

from lichen.ipv6.packet import IPv6Header
from lichen.ipv6.udp import UdpDatagram
from lichen.link.addressing import (
    addressing_mode_for_destination,
    derive_elided_destination,
    resolve_destination,
)
from lichen.link.frame import AddrMode, FrameError, LichenFrame
from lichen.schc.headers import compress_packet


def _make_schc_payload(dst_str: str) -> bytes:
    src = IPv6Address("fe80::1")
    dst = IPv6Address(dst_str)
    coap = bytes([0x40, 0x01, 0x12, 0x34])
    hdr = IPv6Header(src_addr=src, dst_addr=dst, next_header=17, payload_length=8 + len(coap), hop_limit=64)
    udp = UdpDatagram(src_port=5683, dst_port=5683, payload=coap)
    raw = hdr.to_bytes() + udp.to_bytes(src, dst)
    return bytes([0x14]) + compress_packet(raw)


class TestAddrModeEncoding:
    def test_all_four_modes_have_correct_lengths(self) -> None:
        assert AddrMode.NONE.addr_len == 0
        assert AddrMode.SHORT.addr_len == 2
        assert AddrMode.EXTENDED.addr_len == 8
        assert AddrMode.ELIDED.addr_len == 0

    def test_none_and_elided_both_zero_but_distinct(self) -> None:
        assert AddrMode.NONE.addr_len == AddrMode.ELIDED.addr_len == 0
        assert AddrMode.NONE != AddrMode.ELIDED

    def test_llsec_encodes_all_modes(self) -> None:
        for mode in AddrMode:
            frame = LichenFrame(epoch=0, seqnum=0, dst_addr=b"\x00" * mode.addr_len, payload=b"\x14\x00", mic=b"", addr_mode=mode)
            llsec = frame.llsec_byte()
            assert (llsec & 0b11) == int(mode), f"mode {mode} not encoded in LLSec"

    def test_wire_roundtrip_all_modes(self) -> None:
        cases = [
            (AddrMode.NONE, b""),
            (AddrMode.SHORT, b"\xab\xcd"),
            (AddrMode.EXTENDED, bytes(range(8))),
            (AddrMode.ELIDED, b""),
        ]
        for mode, dst in cases:
            frame = LichenFrame(epoch=5, seqnum=10, dst_addr=dst, payload=b"\x14\x00\xaa", mic=b"", addr_mode=mode)
            data = frame.to_bytes()
            parsed = LichenFrame.from_bytes(data)
            assert parsed.addr_mode == mode
            assert parsed.dst_addr == dst

    def test_short_requires_two_bytes(self) -> None:
        with pytest.raises(FrameError, match="requires 2"):
            LichenFrame(epoch=0, seqnum=0, dst_addr=b"\xaa", payload=b"", mic=b"", addr_mode=AddrMode.SHORT).to_bytes()

    def test_extended_requires_eight_bytes(self) -> None:
        with pytest.raises(FrameError, match="requires 8"):
            LichenFrame(epoch=0, seqnum=0, dst_addr=b"\xaa\xbb", payload=b"", mic=b"", addr_mode=AddrMode.EXTENDED).to_bytes()

    def test_none_elided_reject_nonempty_dst(self) -> None:
        for mode in (AddrMode.NONE, AddrMode.ELIDED):
            with pytest.raises(FrameError, match="requires 0"):
                LichenFrame(epoch=0, seqnum=0, dst_addr=b"\xaa", payload=b"", mic=b"", addr_mode=mode).to_bytes()


class TestElidedDerivation:
    def test_derive_from_schc_link_local(self) -> None:
        payload = _make_schc_payload("fe80::2")
        assert str(derive_elided_destination(payload)) == "fe80::2"

    def test_derive_from_schc_abcd(self) -> None:
        payload = _make_schc_payload("fe80::abcd")
        assert str(derive_elided_destination(payload)) == "fe80::abcd"

    def test_derive_ula_via_fallback(self) -> None:
        payload = _make_schc_payload("fd00::1234:5678")
        assert str(derive_elided_destination(payload)) == "fd00::1234:5678"

    def test_empty_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            derive_elided_destination(b"")

    def test_routing_dispatch_raises(self) -> None:
        with pytest.raises(ValueError, match="routing/control"):
            derive_elided_destination(bytes([0x15, 0x01, 0x02]))

    def test_unknown_dispatch_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown dispatch"):
            derive_elided_destination(bytes([0x99, 0x00]))

    def test_resolve_none_is_broadcast(self) -> None:
        assert resolve_destination(AddrMode.NONE, b"", b"\x14\x00") is None

    def test_resolve_short(self) -> None:
        addr = resolve_destination(AddrMode.SHORT, bytes.fromhex("abcd"), None)
        assert str(addr) == "fe80::ff:fe00:abcd"

    def test_resolve_extended(self) -> None:
        addr = resolve_destination(AddrMode.EXTENDED, bytes.fromhex("0011223344556677"), None)
        assert str(addr) == "fe80::211:2233:4455:6677"

    def test_resolve_elided_requires_payload(self) -> None:
        with pytest.raises(ValueError, match="requires payload"):
            resolve_destination(AddrMode.ELIDED, b"", None)

    def test_resolve_elided_derives(self) -> None:
        payload = _make_schc_payload("fe80::99")
        addr = resolve_destination(AddrMode.ELIDED, b"", payload)
        assert str(addr) == "fe80::99"

    def test_addressing_mode_for_destination(self) -> None:
        assert addressing_mode_for_destination(None) == AddrMode.NONE
        assert addressing_mode_for_destination(IPv6Address("fe80::1"), use_elided=False) == AddrMode.EXTENDED
        assert addressing_mode_for_destination(IPv6Address("fe80::1"), use_elided=True) == AddrMode.ELIDED


class TestReservedAddressValidation:
    """Validate that reserved short addresses are rejected per spec 02-physical-link.md 4.5."""

    def test_reserved_null_rejected(self) -> None:
        """0x0000 (null/unspecified) must be rejected."""
        with pytest.raises(ValueError, match="reserved short address 0x0000"):
            resolve_destination(AddrMode.SHORT, bytes.fromhex("0000"), None)

    def test_reserved_unspecified_rejected(self) -> None:
        """0xFFFE (802.15.4 unspecified) must be rejected."""
        with pytest.raises(ValueError, match="reserved short address 0xfffe"):
            resolve_destination(AddrMode.SHORT, bytes.fromhex("fffe"), None)

    def test_reserved_broadcast_rejected(self) -> None:
        """0xFFFF (802.15.4 broadcast) must be rejected."""
        with pytest.raises(ValueError, match="reserved short address 0xffff"):
            resolve_destination(AddrMode.SHORT, bytes.fromhex("ffff"), None)

    def test_valid_short_accepted(self) -> None:
        """Non-reserved short addresses should work normally."""
        addr = resolve_destination(AddrMode.SHORT, bytes.fromhex("0001"), None)
        assert str(addr) == "fe80::ff:fe00:1"

        addr = resolve_destination(AddrMode.SHORT, bytes.fromhex("fffd"), None)
        assert str(addr) == "fe80::ff:fe00:fffd"


# Vector-driven cross-validation
VECTORS_PATH = Path(__file__).resolve().parents[2].parent / "test" / "vectors" / "link-addressing.json"


def _load_vectors():
    if not VECTORS_PATH.is_file():
        return []
    doc = json.loads(VECTORS_PATH.read_text())
    return [(v["name"], v) for v in doc["vectors"]]


class TestVectorValidation:
    @pytest.mark.parametrize("name,vector", _load_vectors())
    def test_vector_roundtrip(self, name: str, vector: dict) -> None:
        data = bytes.fromhex(vector["encoded"])
        frame = LichenFrame.from_bytes(data)
        assert int(frame.addr_mode) == vector["addr_mode"]
        assert frame.dst_addr.hex() == vector["dst_addr"]
        assert frame.payload.hex() == vector["payload"]
        assert frame.to_bytes() == data

    @pytest.mark.parametrize("name,vector", _load_vectors())
    def test_vector_destination(self, name: str, vector: dict) -> None:
        data = bytes.fromhex(vector["encoded"])
        frame = LichenFrame.from_bytes(data)
        expected = vector["expected_destination"]

        # Handle reserved address negative tests
        if vector.get("is_reserved"):
            expected_error = vector.get("expected_error", "reserved")
            with pytest.raises(ValueError, match=expected_error):
                resolve_destination(frame.addr_mode, frame.dst_addr, frame.payload)
            return

        if frame.addr_mode == AddrMode.ELIDED:
            derived = derive_elided_destination(frame.payload)
            assert str(derived) == expected, f"{name}: elided derived {derived} != {expected}"
        elif frame.addr_mode == AddrMode.NONE:
            assert resolve_destination(frame.addr_mode, frame.dst_addr, frame.payload) is None
            assert expected is None
        else:
            resolved = resolve_destination(frame.addr_mode, frame.dst_addr, frame.payload)
            assert str(resolved) == expected, f"{name}: resolved {resolved} != {expected}"

    @pytest.mark.parametrize("name,vector", _load_vectors())
    def test_vector_llsec_consistency(self, name: str, vector: dict) -> None:
        data = bytes.fromhex(vector["encoded"])
        frame = LichenFrame.from_bytes(data)
        if "llsec" in vector:
            assert frame.llsec_byte() == vector["llsec"]
        assert (frame.llsec_byte() & 0b11) == vector["addr_mode"]
