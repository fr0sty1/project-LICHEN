# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for the LICHEN link-layer frame format (spec section 4).

Byte oracles are hand-derived from the spec layout, independent of the code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import SupportsIndex, overload

import pytest

from lichen.crypto.schnorr48 import verify
from lichen.link.frame import LINK_SIGNATURE_DOMAIN, AddrMode, FrameError, LichenFrame, MicLength
from lichen.link.link_layer import LinkLayer


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
        assert frame.to_bytes() == bytes.fromhex("050000000099")

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
            signer_eui64=bytes.fromhex("0011223344556677"),
        )
        assert frame.llsec_byte() == 0xE6
        with pytest.raises(FrameError, match="encrypted frames are unsupported"):
            frame.to_bytes()


class TestRoundTrip:
    @pytest.mark.parametrize("mic_length", [MicLength.BITS32, MicLength.BITS64])
    @pytest.mark.parametrize(
        ("signature_present", "expected"),
        [(False, 0), (True, 48)],
    )
    def test_selector_wire_mic_length_depends_only_on_signature(
        self,
        mic_length: MicLength,
        signature_present: bool,
        expected: int,
    ) -> None:
        assert mic_length.wire_mic_len(signature_present=signature_present) == expected

    def test_selector_wire_mic_length_requires_bool(self) -> None:
        with pytest.raises(TypeError, match="signature_present must be bool"):
            MicLength.BITS32.wire_mic_len(signature_present=1)  # type: ignore[arg-type]

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
            signer_eui64=bytes(range(8)) if signature_present else b"",
        )
        assert LichenFrame.from_bytes(original.to_bytes()) == original


def test_spec_signed_shape_fixture_is_explicitly_parser_only() -> None:
    path = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "frame.json"
    document = json.loads(path.read_text())
    vector = next(item for item in document["vectors"] if item["name"] == "frame_with_signature")
    frame = LichenFrame.from_bytes(bytes.fromhex(vector["input_hex"]))

    assert frame.signature_present is True
    assert len(frame.mic) == 48
    assert vector["expected"]["authentication_expected"] is False
    assert frame.mic == b"\x55" * 48


class TestSignedFields:
    """Consume the shared oracle proving every link transcript field is bound."""

    @staticmethod
    def _canonical_signed_vector() -> dict:
        document = json.loads(CANONICAL_VECTORS.read_text())
        return next(
            vector for vector in document["vectors"] if vector["name"] == "short_addr_signed"
        )

    def test_canonical_signed_oracle_excludes_signature(self, link_layer: LinkLayer) -> None:
        vector = self._canonical_signed_vector()
        crypto = vector["crypto"]
        verification = crypto["verification"]
        wire = bytes.fromhex(vector["encoded"])
        signature = bytes.fromhex(verification["signature"])
        wire_prefix = wire[:-len(signature)]
        transcript = link_layer._build_signable_data(
            verification["epoch"],
            verification["seqnum"],
            bytes.fromhex(verification["dst_addr"]),
            bytes.fromhex(verification["payload"]),
            verification["length"],
            verification["llsec"],
            bytes.fromhex(verification["signer_eui64"]),
        )

        # DST_LEN is the sole non-wire octet. The MIC is deliberately absent.
        expected = (
            LINK_SIGNATURE_DOMAIN
            + wire_prefix[:5]
            + bytes([verification["dst_len"]])
            + wire_prefix[5:]
        )
        assert transcript == expected == bytes.fromhex(crypto["preimage"])
        assert len(transcript) == len(LINK_SIGNATURE_DOMAIN) + len(wire_prefix) + 1
        assert verify(bytes.fromhex(crypto["public_key"]), transcript, signature)

    def test_fixed_tamper_oracles_fail_production_verification(
        self, link_layer: LinkLayer
    ) -> None:
        vector = self._canonical_signed_vector()
        crypto = vector["crypto"]
        cases = crypto["tamper_cases"]
        assert {case["component"] for case in cases} == {
            "length",
            "llsec",
            "epoch",
            "seqnum",
            "dst_len",
            "dst_addr",
            "signer_eui64",
            "payload",
            "signature",
        }

        public_key = bytes.fromhex(crypto["public_key"])
        for case in cases:
            inputs = case["verification"]
            dst_addr = bytes.fromhex(inputs["dst_addr"])
            signer_eui64 = bytes.fromhex(inputs["signer_eui64"])
            payload = bytes.fromhex(inputs["payload"])
            signature = bytes.fromhex(inputs["signature"])
            wire = (
                bytes([inputs["length"], inputs["llsec"], inputs["epoch"]])
                + inputs["seqnum"].to_bytes(2, "big")
                + dst_addr
                + signer_eui64
                + payload
                + signature
            )
            assert wire == bytes.fromhex(case["wire"]), case["name"]
            assert case["expected_valid"] is False

            fixed_preimage = bytes.fromhex(case["preimage"])
            if case["production_path"] == "frame":
                transcript = link_layer._build_signable_data(
                    inputs["epoch"],
                    inputs["seqnum"],
                    dst_addr,
                    payload,
                    inputs["length"],
                    inputs["llsec"],
                    signer_eui64,
                )
                assert transcript == fixed_preimage, case["name"]
            else:
                assert case["component"] == "dst_len"
                assert fixed_preimage[len(LINK_SIGNATURE_DOMAIN) + 5] == inputs["dst_len"]

            assert not verify(public_key, fixed_preimage, signature), case["name"]


class TestValidation:
    @pytest.mark.parametrize(
        ("field", "value", "message"),
        [
            ("addr_mode", 0, "addr_mode must be an AddrMode"),
            ("mic_length", 0, "mic_length must be a supported MicLength selector"),
            ("signature_present", 0, "signature_present must be bool"),
            ("encrypted", 0, "encrypted must be bool"),
            ("epoch", True, "epoch must be an integer"),
            ("epoch", 1.0, "epoch must be an integer"),
            ("seqnum", False, "seqnum must be an integer"),
            ("seqnum", 1.0, "seqnum must be an integer"),
            ("dst_addr", bytearray(), "dst_addr must be bytes"),
            ("payload", bytearray(), "payload must be bytes"),
            ("mic", bytearray(), "mic must be bytes"),
            ("signer_eui64", bytearray(), "signer_eui64 must be bytes"),
        ],
    )
    def test_serializer_rejects_noncanonical_field_types(
        self, field: str, value: object, message: str
    ) -> None:
        values: dict[str, object] = {
            "epoch": 0,
            "seqnum": 0,
            "dst_addr": b"",
            "payload": b"",
            "mic": b"",
            "addr_mode": AddrMode.NONE,
            "mic_length": MicLength.BITS32,
            "signature_present": False,
            "encrypted": False,
            "signer_eui64": b"",
        }
        values[field] = value
        frame = LichenFrame(**values)  # type: ignore[arg-type]
        with pytest.raises(FrameError, match=message):
            frame.to_bytes()

    @pytest.mark.parametrize("data", [bytearray(b"\x04\x00\x00\x00\x00"), memoryview(b"x")])
    def test_parser_requires_exact_bytes(self, data: object) -> None:
        with pytest.raises(FrameError, match="frame must be bytes"):
            LichenFrame.from_bytes(data)  # type: ignore[arg-type]

    def _base(self, **kw: object) -> LichenFrame:
        defaults: dict[str, object] = {
            "epoch": 1,
            "seqnum": 1,
            "dst_addr": b"\xaa\xbb",
            "payload": b"",
            "mic": b"",
            "addr_mode": AddrMode.SHORT,
            "mic_length": MicLength.BITS32,
        }
        defaults.update(kw)
        return LichenFrame(**defaults)  # type: ignore[arg-type]

    def test_addr_len_mismatch(self) -> None:
        with pytest.raises(FrameError, match="requires 2"):
            self._base(dst_addr=b"\xaa").to_bytes()

    def test_mic_len_mismatch(self) -> None:
        with pytest.raises(FrameError, match="0 are required"):
            self._base(mic=b"\x00").to_bytes()

    @pytest.mark.parametrize(
        "signature_present,signer_eui64,mic",
        [
            (True, b"", bytes(48)),
            (False, bytes(8), b""),
        ],
        ids=["S-only-model", "SI-only-model"],
    )
    def test_serializer_rejects_signature_signer_presence_mismatch(
        self, signature_present: bool, signer_eui64: bytes, mic: bytes
    ) -> None:
        frame = self._base(
            signature_present=signature_present,
            signer_eui64=signer_eui64,
            mic=mic,
        )
        with pytest.raises(FrameError, match="presence must match"):
            frame.to_bytes()

    @pytest.mark.parametrize("selector", [2, 7, True, object()])
    def test_serializer_rejects_non_enum_mic_selector(self, selector: object) -> None:
        with pytest.raises(FrameError, match="supported MicLength"):
            self._base(mic_length=selector).to_bytes()

    def test_epoch_out_of_range(self) -> None:
        with pytest.raises(FrameError, match="epoch"):
            self._base(epoch=256).to_bytes()

    def test_seqnum_out_of_range(self) -> None:
        with pytest.raises(FrameError, match="seqnum"):
            self._base(seqnum=0x10000).to_bytes()

    @pytest.mark.parametrize(
        "signature_present,mic,max_payload",
        [(False, b"", 250), (True, b"\x00" * 48, 194)],
    )
    def test_broadcast_payload_boundary(
        self, signature_present: bool, mic: bytes, max_payload: int
    ) -> None:
        frame = self._base(
            dst_addr=b"",
            addr_mode=AddrMode.NONE,
            payload=b"\xaa" * max_payload,
            mic=mic,
            signature_present=signature_present,
            signer_eui64=bytes(8) if signature_present else b"",
        )
        encoded = frame.to_bytes()
        assert len(encoded) == 255
        assert encoded[0] == 254
        assert LichenFrame.from_bytes(encoded) == frame

        frame.payload += b"\xaa"
        with pytest.raises(FrameError, match="frame body is 255 bytes, exceeds 254"):
            frame.to_bytes()

        with pytest.raises(FrameError, match="frame body is 255 bytes, exceeds 254"):
            LichenFrame.from_bytes(b"\xff\x00")

    def test_nonbytes_payload_is_rejected_before_concatenation(self) -> None:
        class ExplodingPayload:
            def __len__(self) -> int:
                return 251

            def __radd__(self, other: object) -> bytes:
                raise AssertionError("payload was concatenated before bounds check")

        with pytest.raises(FrameError, match="payload must be bytes"):
            self._base(dst_addr=b"", addr_mode=AddrMode.NONE, payload=ExplodingPayload()).to_bytes()


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

    def test_bytes_subclass_is_rejected_before_body_slice(self) -> None:
        class ExplodingSlice(bytes):
            @overload
            def __getitem__(self, key: SupportsIndex, /) -> int: ...

            @overload
            def __getitem__(self, key: slice, /) -> bytes: ...

            def __getitem__(self, key: SupportsIndex | slice, /) -> int | bytes:
                if isinstance(key, slice):
                    raise AssertionError("body was sliced before length check")
                return super().__getitem__(key)

        with pytest.raises(FrameError, match="frame must be bytes"):
            LichenFrame.from_bytes(ExplodingSlice(b"\x00" + b"x" * 256))

    @pytest.mark.parametrize("signed", [False, True])
    def test_parser_rejects_256_byte_frame(self, signed: bool) -> None:
        llsec = 0xA0 if signed else 0
        mic = b"\x00" * (48 if signed else 0)
        signer_eui64 = bytes(8) if signed else b""
        payload = b"\xaa" * (195 if signed else 251)
        data = bytes([255, llsec, 0, 0, 0]) + signer_eui64 + payload + mic
        assert len(data) == 256
        with pytest.raises(FrameError, match="frame is 256 bytes, exceeds 255"):
            LichenFrame.from_bytes(data)

    @pytest.mark.parametrize("llsec", [0x20, 0x80])
    def test_signature_and_signer_eui64_presence_must_match(self, llsec: int) -> None:
        data = bytes([4, llsec, 0, 0, 0])
        with pytest.raises(FrameError, match="presence bits must match"):
            LichenFrame.from_bytes(data)

    def test_encrypted_only_rejected(self) -> None:
        """Encrypted frames without signature MUST be rejected per spec 4.2."""
        # LLSec=0x40 sets only encrypted bit (bit 6)
        data = bytes.fromhex("0440000000")
        with pytest.raises(FrameError, match="encrypted frames are unsupported"):
            LichenFrame.from_bytes(data)

    def test_reserved_mic_length(self) -> None:
        for selector in range(2, 8):
            llsec = selector << 2
            with pytest.raises(FrameError) as exc_info:
                LichenFrame.from_bytes(bytes([4, llsec, 0, 0, 0]))
            assert str(exc_info.value) == f"reserved MIC-length value: {selector}"

    def test_too_short_body(self) -> None:
        with pytest.raises(FrameError, match="too short"):
            LichenFrame.from_bytes(b"\x03\x00\x00\x00")

    def test_too_short_for_declared_sizes(self) -> None:
        # addr_mode SHORT needs 4+2=6 body bytes; only 4 are present.
        with pytest.raises(FrameError, match="declared address/MIC"):
            LichenFrame.from_bytes(b"\x04\x01\x00\x00\x00")

    def test_signature_present_requires_48_byte_mic(self) -> None:
        data = bytes.fromhex("1aa0000000" + "00" * 18 + "deadbeef")
        with pytest.raises(FrameError, match="declared address/MIC"):
            LichenFrame.from_bytes(data)

    def test_signature_present_short_payload_parses(self) -> None:
        data = bytes.fromhex("42a0000000" + "22" * 8 + "00" * 6 + "11" * 48)
        frame = LichenFrame.from_bytes(data)
        assert frame.signature_present is True
        assert frame.payload == bytes(6)
        assert frame.mic == bytes.fromhex("11" * 48)
        assert frame.signer_eui64 == bytes.fromhex("22" * 8)


# ─── Cross-validation tests from spec/test-vectors/frame.json ─────────────────

SPEC_VECTORS = Path(__file__).resolve().parents[3] / "spec" / "test-vectors" / "frame.json"
CANONICAL_VECTORS = Path(__file__).resolve().parents[3] / "test" / "vectors" / "link_frame.json"


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

        data = bytes.fromhex(input_hex)

        # Error cases
        if expected.get("error"):
            error_patterns = {
                "empty_frame": "frame is empty",
                "length_mismatch": "length field says",
                "reserved_mic_length": "reserved MIC-length value",
                "reserved_bit_set": "reserved bit is set",
                "signer_presence_mismatch": "signature and signer EUI-64 presence bits must match",
                "frame_too_short": "frame body too short",
                "encrypted_unsupported": "encrypted frames are unsupported",
                "frame_too_large": "exceeds",
            }
            pattern = error_patterns.get(expected["error_type"])
            with pytest.raises(FrameError) as exc_info:
                LichenFrame.from_bytes(data)
            if pattern:
                assert pattern in str(exc_info.value), f"Expected '{pattern}' in '{exc_info.value}'"
            return

        # Valid frame - parse and verify all fields
        frame = LichenFrame.from_bytes(data)

        assert frame.addr_mode == expected["addr_mode"], f"{name}: addr_mode"
        assert frame.mic_length == expected["mic_length"], f"{name}: mic_length"
        assert frame.signature_present == expected["signature_present"], (
            f"{name}: signature_present"
        )
        assert frame.encrypted == expected["encrypted"], f"{name}: encrypted"
        assert frame.epoch == expected["epoch"], f"{name}: epoch"
        assert frame.seqnum == expected["seqnum"], f"{name}: seqnum"
        assert frame.dst_addr == bytes.fromhex(expected["dst_addr_hex"]), f"{name}: dst_addr"
        assert frame.signer_eui64 == bytes.fromhex(expected.get("signer_eui64_hex", "")), (
            f"{name}: signer_eui64"
        )
        if expected["signature_present"]:
            assert frame.mic == bytes.fromhex(expected["mic_hex"]), f"{name}: mic"
        else:
            assert frame.mic == bytes.fromhex(expected["mic_hex"]), f"{name}: mic"

        # Payload - check by length if specified, else by content
        if "payload_len" in expected:
            assert len(frame.payload) == expected["payload_len"], f"{name}: payload_len"
            if "payload_fill_len" in expected:
                fill_len = expected["payload_fill_len"]
                assert frame.payload[:fill_len] == (
                    bytes.fromhex(expected["payload_fill_hex"]) * fill_len
                )
                assert frame.payload[fill_len:] == bytes.fromhex(
                    expected.get("payload_suffix_hex", "")
                )
        else:
            assert frame.payload == bytes.fromhex(expected["payload_hex"]), f"{name}: payload"

    @pytest.mark.parametrize("name,vector", _load_spec_vectors())
    def test_roundtrip_valid_vectors(self, name: str, vector: dict) -> None:
        """Valid vectors should roundtrip: parse -> serialize -> same bytes."""
        expected = vector["expected"]
        data = bytes.fromhex(vector["input_hex"])
        if expected.get("error") or not vector["input_hex"] or len(data) > 255:
            pytest.skip("Error case")

        frame = LichenFrame.from_bytes(data)
        serialized = frame.to_bytes()
        assert serialized == data, f"{name}: roundtrip failed"


def _load_canonical_vectors() -> list[tuple[str, dict]]:
    """Load the canonical cross-implementation link-frame vectors."""
    document = json.loads(CANONICAL_VECTORS.read_text())
    return [(vector["name"], vector) for vector in document["vectors"]]


@pytest.mark.parametrize("name,vector", _load_canonical_vectors())
def test_canonical_link_frame_vector(name: str, vector: dict) -> None:
    """Encode and parse every canonical frame vector, including failures."""
    fields = vector["fields"]
    frame = LichenFrame(
        epoch=fields["epoch"],
        seqnum=fields["seqnum"],
        dst_addr=bytes.fromhex(fields["dst_addr"]),
        payload=bytes.fromhex(fields["payload"]),
        mic=bytes.fromhex(fields["mic"]),
        addr_mode=AddrMode(fields["addr_mode"]),
        mic_length=MicLength(fields["mic_length"]),
        signature_present=fields["signature_present"],
        encrypted=fields["encrypted"],
        signer_eui64=bytes.fromhex(fields["signer_eui64"]),
    )
    encoded = bytes.fromhex(vector["encoded"])

    if vector.get("expect", {}).get("error"):
        with pytest.raises(FrameError):
            frame.to_bytes()
        with pytest.raises(FrameError):
            LichenFrame.from_bytes(encoded)
        return

    assert frame.to_bytes() == encoded, f"{name}: serialization differs from canonical vector"
    assert LichenFrame.from_bytes(encoded) == frame, f"{name}: parsed fields differ"
