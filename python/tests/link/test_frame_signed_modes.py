# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consumer tests for link_frame_signed_modes.json.

These vectors complete all-four-addressing-mode signed coverage: they must
parse and re-encode identically through the production frame code AND verify
under the independent PyNaCl reference signer (never the code under test).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft7Validator  # type: ignore[import-untyped]

from lichen.link.frame import AddrMode, FrameError, LichenFrame, MicLength

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from generate_link_frame_signed_modes import document  # noqa: E402
from reference_schnorr48 import signature_transcript, verify  # noqa: E402

DOCUMENT = json.loads((VECTORS_DIR / "link_frame_signed_modes.json").read_text())
CASES = [(vector["name"], vector) for vector in DOCUMENT["vectors"]]


def test_signed_mode_vectors_are_fresh_and_schema_valid() -> None:
    """The committed oracle must reproduce exactly and satisfy the shared schema."""
    assert document() == DOCUMENT
    schema = json.loads((VECTORS_DIR / "schema.json").read_text())
    errors = sorted(Draft7Validator(schema).iter_errors(DOCUMENT), key=lambda error: error.path)
    assert not errors, [error.message for error in errors]


def test_all_address_modes_have_signed_vectors() -> None:
    """Broadcast, short, extended, and elided modes must stay covered."""
    signed_modes = {
        vector["fields"]["addr_mode"]
        for _, vector in CASES
        if vector["fields"]["signature_present"]
    }
    assert signed_modes == {0, 1, 2, 3}


@pytest.mark.parametrize("name,vector", CASES)
def test_signed_mode_frame_encodes_and_parses(name: str, vector: dict) -> None:
    """Production encode/parse must reproduce the canonical oracle bytes."""
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

    assert frame.to_bytes() == encoded, f"{name}: serialization differs"
    assert LichenFrame.from_bytes(encoded) == frame, f"{name}: parsed fields differ"


@pytest.mark.parametrize("name,vector", CASES)
def test_signed_mode_llsec_bits_match_spec(name: str, vector: dict) -> None:
    """Spec 4.2: signed frames set S and SI together and never E."""
    llsec = bytes.fromhex(vector["encoded"])[1]
    assert llsec & 0xA0 == 0xA0, f"{name}: S/SI bits must both be set"
    assert llsec & 0x40 == 0x00, f"{name}: encrypted flag must be clear"
    fields = vector["fields"]
    assert llsec & 0x03 == fields["addr_mode"], f"{name}: addr mode bits"
    assert (llsec >> 2) & 0x07 == fields["mic_length"], f"{name}: MIC selector bits"


@pytest.mark.parametrize("name,vector", CASES)
def test_signed_mode_signature_verifies_under_reference(name: str, vector: dict) -> None:
    """Independent oracle: rebuild the transcript and verify with PyNaCl."""
    crypto = vector["crypto"]
    wire = bytes.fromhex(vector["encoded"])
    prefix, signature = wire[:-48], wire[-48:]
    destination_length = {0: 0, 1: 2, 2: 8, 3: 0}[prefix[1] & 0x03]

    # Rebuild the normative transcript from wire octets only.
    transcript = signature_transcript(prefix, destination_length)
    assert transcript.hex() == crypto["preimage"], f"{name}: preimage layout"

    public_key = bytes.fromhex(crypto["public_key"])
    signer_start = 5 + destination_length
    assert prefix[signer_start : signer_start + 8] == bytes.fromhex(
        vector["fields"]["signer_eui64"]
    ), f"{name}: SIID placement"
    assert verify(public_key, transcript, signature), f"{name}: reference verify"

    # Mutate one octet in every component present in this mode.  DST_LEN is
    # always covered even when broadcast/elided omit DST itself.
    domain_length = len(transcript) - len(prefix) - 1
    destination_start = domain_length + 6
    signer_start_in_transcript = destination_start + destination_length
    payload_start = signer_start_in_transcript + 8
    component_offsets = {
        "length": domain_length,
        "llsec": domain_length + 1,
        "epoch": domain_length + 2,
        "seqnum": domain_length + 3,
        "dst_len": domain_length + 5,
        "signer_eui64": signer_start_in_transcript,
        "payload": payload_start,
    }
    if destination_length:
        component_offsets["dst_addr"] = destination_start
    for component, offset in component_offsets.items():
        tampered_message = bytearray(transcript)
        tampered_message[offset] ^= 0x01
        assert not verify(public_key, bytes(tampered_message), signature), (
            f"{name}: accepted {component} mutation"
        )
    tampered_signature = bytes([signature[0] ^ 0x01]) + signature[1:]
    assert not verify(public_key, transcript, tampered_signature), f"{name}: sig flip"


@pytest.mark.parametrize("name,vector", CASES)
def test_signed_mode_rejects_every_truncation_and_trailing_byte(name: str, vector: dict) -> None:
    """No proper prefix or non-canonical extension of a signed wire is valid."""
    encoded = bytes.fromhex(vector["encoded"])
    for cut in range(len(encoded)):
        with pytest.raises(FrameError):
            LichenFrame.from_bytes(encoded[:cut])
    with pytest.raises(FrameError):
        LichenFrame.from_bytes(encoded + b"\x00")


@pytest.mark.parametrize(
    "name,vector",
    [(name, vector) for name, vector in CASES if "max_payload" in name],
)
def test_signed_mode_max_payload_boundary(name: str, vector: dict) -> None:
    """Each address width has the exact largest payload that fits on air."""
    fields = vector["fields"]
    encoded = bytes.fromhex(vector["encoded"])
    addr_mode = AddrMode(fields["addr_mode"])
    expected_payload_length = 254 - 4 - addr_mode.addr_len - 8 - 48

    assert len(bytes.fromhex(fields["payload"])) == expected_payload_length
    assert len(encoded) == 255
    assert encoded[0] == 254

    oversized = LichenFrame(
        epoch=fields["epoch"],
        seqnum=fields["seqnum"],
        dst_addr=bytes.fromhex(fields["dst_addr"]),
        payload=bytes.fromhex(fields["payload"]) + b"\x00",
        mic=bytes.fromhex(fields["mic"]),
        addr_mode=addr_mode,
        mic_length=MicLength(fields["mic_length"]),
        signature_present=True,
        encrypted=False,
        signer_eui64=bytes.fromhex(fields["signer_eui64"]),
    )
    with pytest.raises(FrameError, match="frame body is 255 bytes, exceeds 254"):
        oversized.to_bytes()
