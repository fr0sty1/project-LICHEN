# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LICHEN link-layer frame format (spec section 4).

Byte oracles are hand-derived from the spec layout, independent of the code.
"""

from __future__ import annotations

import pytest

from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength


class TestSerialize:
    def test_spec_vector(self) -> None:
        """Hand-computed frame: short addr, 32-bit MIC, no flags.

        body = LLSec(0x01) Epoch(0x01) SeqNum(0x0102) Dst(0xAABB)
               Payload(0x1020) MIC(0xDEADBEEF) = 12 bytes; Length = 0x0C.
        """
        frame = LichenFrame(
            epoch=1,
            seqnum=0x0102,
            dst_addr=b"\xaa\xbb",
            payload=b"\x10\x20",
            mic=b"\xde\xad\xbe\xef",
            addr_mode=AddrMode.SHORT,
            mic_length=MicLength.BITS32,
        )
        assert frame.to_bytes() == bytes.fromhex("0c 0101 0102 aabb 1020 deadbeef".replace(" ", ""))

    def test_broadcast_no_address(self) -> None:
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"",
            payload=b"\x99",
            mic=b"\x00\x00\x00\x00",
            addr_mode=AddrMode.NONE,
        )
        # body = LLSec(00) Epoch(00) SeqNum(0000) Payload(99) MIC(00000000) = 9 bytes
        assert frame.to_bytes() == bytes.fromhex("09" "00" "00" "0000" "99" "00000000")

    def test_llsec_flag_packing(self) -> None:
        """EXTENDED addr + 64-bit MIC + signature + encrypted -> 0x66."""
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"\x00" * 8,
            payload=b"",
            mic=b"\x00" * 8,
            addr_mode=AddrMode.EXTENDED,
            mic_length=MicLength.BITS64,
            signature_present=True,
            encrypted=True,
        )
        assert frame.llsec_byte() == 0x66


class TestRoundTrip:
    @pytest.mark.parametrize(
        "addr_mode,dst",
        [
            (AddrMode.NONE, b""),
            (AddrMode.SHORT, b"\x12\x34"),
            (AddrMode.EXTENDED, bytes(range(8))),
            (AddrMode.ELIDED, b""),
        ],
    )
    @pytest.mark.parametrize("mic_length", [MicLength.BITS32, MicLength.BITS64])
    def test_roundtrip(self, addr_mode: AddrMode, dst: bytes, mic_length: MicLength) -> None:
        original = LichenFrame(
            epoch=200,
            seqnum=0xBEEF,
            dst_addr=dst,
            payload=b"hello link layer",
            mic=bytes(range(mic_length.mic_len)),
            addr_mode=addr_mode,
            mic_length=mic_length,
            signature_present=True,
            encrypted=False,
        )
        assert LichenFrame.from_bytes(original.to_bytes()) == original


class TestValidation:
    def _base(self, **kw: object) -> LichenFrame:
        defaults: dict[str, object] = {
            "epoch": 1, "seqnum": 1, "dst_addr": b"\xaa\xbb",
            "payload": b"", "mic": b"\x00\x00\x00\x00",
            "addr_mode": AddrMode.SHORT, "mic_length": MicLength.BITS32,
        }
        defaults.update(kw)
        return LichenFrame(**defaults)  # type: ignore[arg-type]

    def test_addr_len_mismatch(self) -> None:
        with pytest.raises(FrameError, match="requires 2"):
            self._base(dst_addr=b"\xaa").to_bytes()

    def test_mic_len_mismatch(self) -> None:
        with pytest.raises(FrameError, match="requires 4"):
            self._base(mic=b"\x00\x00").to_bytes()

    def test_epoch_out_of_range(self) -> None:
        with pytest.raises(FrameError, match="epoch"):
            self._base(epoch=256).to_bytes()

    def test_seqnum_out_of_range(self) -> None:
        with pytest.raises(FrameError, match="seqnum"):
            self._base(seqnum=0x10000).to_bytes()

    def test_frame_too_large(self) -> None:
        with pytest.raises(FrameError, match="exceeds 255"):
            self._base(payload=b"\x00" * 300).to_bytes()


class TestAddrModeLookup:
    """Verify AddrMode.addr_len lookup table correctness."""

    def test_addr_len_table_covers_all_modes(self) -> None:
        """Ensure lookup table has entries for all AddrMode values."""
        for mode in AddrMode:
            # Should not raise IndexError
            _ = mode.addr_len

    def test_addr_len_values_correct(self) -> None:
        """Verify each mode returns the expected address length."""
        assert AddrMode.NONE.addr_len == 0
        assert AddrMode.SHORT.addr_len == 2
        assert AddrMode.EXTENDED.addr_len == 8
        assert AddrMode.ELIDED.addr_len == 0


class TestParseErrors:
    def test_empty(self) -> None:
        with pytest.raises(FrameError, match="empty"):
            LichenFrame.from_bytes(b"")

    def test_length_mismatch(self) -> None:
        # Length says 5 but only 4 body bytes present.
        with pytest.raises(FrameError, match="length field"):
            LichenFrame.from_bytes(b"\x05\x00\x00\x00\x00")

    def test_reserved_bit_set(self) -> None:
        # Valid 12-byte body but LLSec bit 7 set (0x81).
        data = bytes.fromhex("0c 81 01 0102 aabb 1020 deadbeef".replace(" ", ""))
        with pytest.raises(FrameError, match="reserved bit"):
            LichenFrame.from_bytes(data)

    def test_reserved_mic_length(self) -> None:
        # LLSec 0x09 -> addr_mode 1, mic-length field = 2 (reserved).
        with pytest.raises(FrameError, match="reserved MIC-length"):
            LichenFrame.from_bytes(b"\x04\x09\x00\x00\x00")

    def test_too_short_body(self) -> None:
        with pytest.raises(FrameError, match="too short"):
            LichenFrame.from_bytes(b"\x03\x00\x00\x00")

    def test_too_short_for_declared_sizes(self) -> None:
        # addr_mode SHORT (2B) + 32-bit MIC (4B) need 4+2+4=10 body bytes; only 4.
        with pytest.raises(FrameError, match="declared address/MIC"):
            LichenFrame.from_bytes(b"\x04\x01\x00\x00\x00")
