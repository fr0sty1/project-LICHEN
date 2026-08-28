# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consumer tests for test/vectors/link-edge-fuzz.json.

Encoded bytes are the oracle for negative cases. Valid frames are
hand-assembled from the spec 4.1/4.2 tables, not from LichenFrame.to_bytes().
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft7Validator

from lichen.link.frame import EncryptedFrameError, FrameError, LichenFrame

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
DOCUMENT = json.loads((VECTORS_DIR / "link-edge-fuzz.json").read_text())
CASES = [(vector["name"], vector) for vector in DOCUMENT["vectors"]]

_ADDR_LEN = {0: 0, 1: 2, 2: 8, 3: 0}
_ERROR_NEEDLES = {
    "reserved_mic_length": ("reserved MIC-length value",),
    "empty_frame": ("frame is empty",),
    "length_mismatch": ("length field says",),
    "frame_too_short": ("frame body too short", "frame too short"),
    "si_without_s": ("signature and signer EUI-64 presence bits must match",),
    "signed_encrypted_unsupported": ("encrypted frames are unsupported",),
    "encryption_unsupported": ("encrypted frames are unsupported",),
    "truncated_mic": ("frame too short for declared address/MIC sizes",),
    "declared_address_mic_short": ("frame too short for declared address/MIC sizes",),
    "truncated_signer_eui64": ("frame too short for declared address/MIC sizes",),
    "frame_too_large": ("exceeds",),
}


def _hand_assemble(fields: dict) -> bytes:
    """Build a well-formed frame from spec 4.1/4.2 tables."""
    dst = bytes.fromhex(fields["dst_addr"])
    payload = bytes.fromhex(fields["payload"])
    mic = bytes.fromhex(fields["mic"])
    signer = bytes.fromhex(fields["signer_eui64"])
    addr_mode = fields["addr_mode"]
    assert len(dst) == _ADDR_LEN[addr_mode]
    llsec = addr_mode & 0x03
    llsec |= (fields["mic_length"] & 0x07) << 2
    if fields["signature_present"]:
        llsec |= 0x20
        assert len(mic) == 48
        assert len(signer) == 8
    else:
        assert mic == b""
        assert signer == b""
    if fields["encrypted"]:
        llsec |= 0x40
    if signer:
        llsec |= 0x80
    body = (
        bytes([llsec, fields["epoch"]])
        + int(fields["seqnum"]).to_bytes(2, "big")
        + dst
        + signer
        + payload
        + mic
    )
    assert 4 <= len(body) <= 254
    return bytes([len(body)]) + body


def test_edge_fuzz_document_is_schema_valid() -> None:
    schema = json.loads((VECTORS_DIR / "schema.json").read_text())
    errors = sorted(Draft7Validator(schema).iter_errors(DOCUMENT), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


def test_edge_fuzz_error_categories_are_known() -> None:
    names = {name for name, _ in CASES}
    assert "edge_encrypted_unsigned_rejected" in names
    assert "edge_fuzz_random_ffff" in names
    categories = {
        vector.get("expect", {}).get("error")
        for _, vector in CASES
        if vector.get("expect", {}).get("error")
    }
    assert categories <= set(_ERROR_NEEDLES)
    assert {
        "reserved_mic_length",
        "empty_frame",
        "length_mismatch",
        "frame_too_short",
        "si_without_s",
        "signed_encrypted_unsupported",
        "encryption_unsupported",
        "truncated_mic",
        "declared_address_mic_short",
        "truncated_signer_eui64",
        "frame_too_large",
    } <= categories


@pytest.mark.parametrize("name,vector", CASES)
def test_edge_fuzz_vector(name: str, vector: dict) -> None:
    encoded = bytes.fromhex(vector["encoded"])
    expected_error = vector.get("expect", {}).get("error")
    if expected_error:
        needles = _ERROR_NEEDLES[expected_error]
        with pytest.raises((FrameError, EncryptedFrameError)) as exc_info:
            LichenFrame.from_bytes(encoded)
        message = str(exc_info.value)
        assert any(needle in message for needle in needles), (
            f"{name}: expected one of {needles} in {message!r}"
        )
        return

    assembled = _hand_assemble(vector["fields"])
    assert assembled == encoded, f"{name}: independent spec assembly drifted"
    frame = LichenFrame.from_bytes(encoded)
    fields = vector["fields"]
    assert frame.epoch == fields["epoch"]
    assert frame.seqnum == fields["seqnum"]
    assert frame.dst_addr == bytes.fromhex(fields["dst_addr"])
    assert frame.payload == bytes.fromhex(fields["payload"])
    assert frame.mic == bytes.fromhex(fields["mic"])
    assert int(frame.addr_mode) == fields["addr_mode"]
    assert int(frame.mic_length) == fields["mic_length"]
    assert frame.signature_present is fields["signature_present"]
    assert frame.encrypted is fields["encrypted"]
    assert frame.signer_eui64 == bytes.fromhex(fields["signer_eui64"])
    assert frame.to_bytes() == encoded
