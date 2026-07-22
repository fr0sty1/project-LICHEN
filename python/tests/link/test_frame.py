# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LICHEN link-layer frame format (spec section 4).

Byte oracles are hand-derived from the spec layout, independent of the code.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength


class TestSerialize:
    def test_spec_vector(self) -> None:
        """Hand-computed frame: short addr, unsigned, no MIC.

        body = LLSec(0x01) Epoch(0x01) SeqNum(0x0102) Dst(0xAABB)
         Payload(0x1020) = 8 bytes; Length = 0x08.
        """
        frame = LichenFrame(
            epoch=1,
            seqnum=0x0102,
            dst_addr=b"\xaa\xbb",
            payload=b"\x10\x20",
            mic=b"",
            addr_mode=AddrMode.SHORT,
            mic_length=MicLength.BITS32,
        )
        assert frame.to_bytes() == bytes.fromhex("08 0101 0102 aabb 1020".replace(" ", ""))

    def test_broadcast_no_address(self) -> None:
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"",
            payload=b"\x99",
            mic=b"",
            addr_mode=AddrMode.NONE,
        )
        # body = LLSec(00) Epoch(00) SeqNum(0000) Payload(99) = 5 bytes
        assert frame.to_bytes() == bytes.fromhex("05" "00" "00" "0000" "99")

    def test_llsec_flag_packing(self) -> None:
        """LLSec independently packs the signature and encryption bits."""
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"\x00" * 8,
            payload=b"",
            mic=b"\x00" * 48,
            addr_mode=AddrMode.EXTENDED,
            mic_length=MicLength.BITS64,
            signature_present=True,
            encrypted=True,
        )
        assert frame.llsec_byte() == 0x66
        with pytest.raises(FrameError, match="signed and encrypted"):
            frame.to_bytes()


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
    @pytest.mark.parametrize("signature_present", [False, True])
    def test_roundtrip(
        self, addr_mode: AddrMode, dst: bytes, mic_length: MicLength, signature_present: bool
    ) -> None:
        # Signed frames carry the 48-byte signature in MIC.
        if signature_present:
            payload = b"signature-prefixed payload " + bytes(range(48))
        else:
            payload = b"hello link layer"
        original = LichenFrame(
            epoch=200,
            seqnum=0xBEEF,
            dst_addr=dst,
            payload=payload,
            mic=bytes(range(48 if signature_present else 0)),
            addr_mode=addr_mode,
            mic_length=mic_length,
            signature_present=signature_present,
            encrypted=False,
        )
        assert LichenFrame.from_bytes(original.to_bytes()) == original


class TestValidation:
    def _base(self, **kw: object) -> LichenFrame:
        defaults: dict[str, object] = {
            "epoch": 1, "seqnum": 1, "dst_addr": b"\xaa\xbb",
            "payload": b"", "mic": b"",
            "addr_mode": AddrMode.SHORT, "mic_length": MicLength.BITS32,
        }
        defaults.update(kw)
        return LichenFrame(**defaults)  # type: ignore[arg-type]

    def test_addr_len_mismatch(self) -> None:
        with pytest.raises(FrameError, match="requires 2"):
            self._base(dst_addr=b"\xaa").to_bytes()

    def test_mic_len_mismatch(self) -> None:
        with pytest.raises(FrameError, match="0 are required"):
            self._base(mic=b"\x00").to_bytes()

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
        # addr_mode SHORT needs 4+2=6 body bytes; only 4 are present.
        with pytest.raises(FrameError, match="declared address/MIC"):
            LichenFrame.from_bytes(b"\x04\x01\x00\x00\x00")

    def test_signature_present_requires_48_byte_mic(self) -> None:
        data = bytes.fromhex("12" "20" "00" "0000" + "00" * 10 + "deadbeef")
        with pytest.raises(FrameError, match="declared address/MIC"):
            LichenFrame.from_bytes(data)

    def test_signature_present_short_payload_parses(self) -> None:
        data = bytes.fromhex("3a" "20" "00" "0000" + "00" * 6 + "11" * 48)
        frame = LichenFrame.from_bytes(data)
        assert frame.signature_present is True
        assert frame.payload == bytes(6)
        assert frame.mic == bytes.fromhex("11" * 48)

    def test_signed_encrypted_is_rejected(self) -> None:
        data = bytes.fromhex("35 60 03 0004 78" + "00" * 48)
        with pytest.raises(FrameError, match="signed and encrypted"):
            LichenFrame.from_bytes(data)


# ─── Cross-validation tests from spec/test-vectors/frame.json ─────────────────

SPEC_VECTORS = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "frame.json"


def _load_spec_vectors() -> list[tuple[str, dict]]:
    """Load test vectors from spec/test-vectors/frame.json."""
    if not SPEC_VECTORS.is_file():
        return []  # Empty list will skip parametrized tests
    doc = json.loads(SPEC_VECTORS.read_text())
    return [(v["name"], v) for v in doc["vectors"]]


class TestSpecVectors:
    """Cross-validate Python frame parsing against spec/test-vectors/frame.json.

    These vectors are shared with Rust and C implementations to ensure all
    implementations parse frames identically (appendix-c-safety.md policy).
    """

    @pytest.mark.parametrize("name,vector", _load_spec_vectors())
    def test_parse_vector(self, name: str, vector: dict) -> None:
        """Parse each vector and verify fields match expected values."""
        input_hex = vector["input_hex"]
        expected = vector["expected"]

        # Empty frame special case
        if not input_hex:
            with pytest.raises(FrameError, match="empty"):
                LichenFrame.from_bytes(b"")
            return

        data = bytes.fromhex(input_hex)

        # Error cases
        if expected.get("error"):
            with pytest.raises(FrameError):
                LichenFrame.from_bytes(data)
            return

        # Valid frame - parse and verify all fields
        frame = LichenFrame.from_bytes(data)

        assert frame.addr_mode == expected["addr_mode"], f"{name}: addr_mode"
        assert frame.mic_length == expected["mic_length"], f"{name}: mic_length"
        assert frame.signature_present == expected["signature_present"], \
            f"{name}: signature_present"
        assert frame.encrypted == expected["encrypted"], f"{name}: encrypted"
        assert frame.epoch == expected["epoch"], f"{name}: epoch"
        assert frame.seqnum == expected["seqnum"], f"{name}: seqnum"
        assert frame.dst_addr == bytes.fromhex(expected["dst_addr_hex"]), f"{name}: dst_addr"
        assert frame.mic == bytes.fromhex(expected["mic_hex"]), f"{name}: mic"

        # Payload - check by length if specified, else by content
        if "payload_len" in expected:
            assert len(frame.payload) == expected["payload_len"], f"{name}: payload_len"
        else:
            assert frame.payload == bytes.fromhex(expected["payload_hex"]), f"{name}: payload"

    @pytest.mark.parametrize("name,vector", _load_spec_vectors())
    def test_roundtrip_valid_vectors(self, name: str, vector: dict) -> None:
        """Valid vectors should roundtrip: parse -> serialize -> same bytes."""
        expected = vector["expected"]
        if expected.get("error") or not vector["input_hex"]:
            pytest.skip("Error case")

        data = bytes.fromhex(vector["input_hex"])
        frame = LichenFrame.from_bytes(data)
        serialized = frame.to_bytes()
        assert serialized == data, f"{name}: roundtrip failed"
