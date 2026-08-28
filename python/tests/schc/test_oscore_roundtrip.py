# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Production OSCORE -> SCHC Rule 5 -> OSCORE integration coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from aiocoap import POST
from aiocoap.message import Direction, Message
from aiocoap.oscore import ProtectionInvalid, ReplayError

from lichen.crypto.oscore import MAX_OSCORE_SEQUENCE_NUMBER, MemorySecurityContext
from lichen.schc.headers import SchcError, compress_packet, decompress_packet

DOCUMENT = json.loads(
    (Path(__file__).parents[3] / "test" / "vectors" / "oscore_schc_roundtrip.json").read_text()
)
assert DOCUMENT["format_version"] == 2
VECTORS = DOCUMENT["vectors"]


def _context(entry: dict[str, Any], *, receiver: bool = False, secret: bytes | None = None):
    sender = bytes.fromhex(entry["sender_id"])
    recipient = bytes.fromhex(entry["recipient_id"])
    return MemorySecurityContext(
        master_secret=secret or bytes.fromhex(entry["master_secret"]),
        master_salt=bytes.fromhex(entry["master_salt"]) if entry["master_salt"] else b"",
        sender_id=recipient if receiver else sender,
        recipient_id=sender if receiver else recipient,
        id_context=bytes.fromhex(entry["id_context"]) if entry["id_context"] else None,
        starting_sequence_number=0 if receiver else entry["sender_seq"],
    )


def _plaintext(entry: dict[str, Any]) -> Message:
    message = Message(code=entry["plaintext"]["code"])
    message.opt.decode(bytes.fromhex(entry["plaintext"]["options"]))
    message.payload = bytes.fromhex(entry["plaintext"]["payload"])
    return message


def _protected_from_packet(packet: bytes) -> Message:
    assert packet[6] == 17
    coap = packet[48:]
    token_length = coap[0] & 0x0F
    option_offset = 4 + token_length
    option_header = coap[option_offset]
    assert option_header >> 4 == 9
    option_length = option_header & 0x0F
    assert option_length <= 12
    option = coap[option_offset + 1 : option_offset + 1 + option_length]
    marker_offset = option_offset + 1 + option_length
    assert coap[marker_offset] == 0xFF
    message = Message(code=coap[1], payload=coap[marker_offset + 1 :])
    message.opt.oscore = option
    message.direction = Direction.INCOMING
    return message


def _sum16(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(
        int.from_bytes(data[offset : offset + 2], "big") for offset in range(0, len(data), 2)
    )
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _build_packet(option: bytes, ciphertext: bytes) -> bytes:
    assert len(option) <= 12
    source = bytes.fromhex("fe800000000000000000000000000001")
    destination = bytes.fromhex("fe800000000000000000000000000002")
    coap = b"\x40\x02\x12\x34" + bytes((0x90 | len(option),)) + option + b"\xff" + ciphertext
    udp_length = 8 + len(coap)
    udp = (
        (5683).to_bytes(2, "big") * 2
        + udp_length.to_bytes(2, "big")
        + b"\x00\x00"
        + coap
    )
    pseudo = source + destination + udp_length.to_bytes(4, "big") + b"\x00\x00\x00\x11"
    checksum = (~_sum16(pseudo + udp)) & 0xFFFF or 0xFFFF
    udp = udp[:6] + checksum.to_bytes(2, "big") + udp[8:]
    return (
        b"\x60\x00\x00\x00"
        + udp_length.to_bytes(2, "big")
        + b"\x11\x40"
        + source
        + destination
        + udp
    )


@pytest.mark.parametrize("entry", VECTORS, ids=lambda item: item["name"])
def test_protect_compress_decompress_unprotect(entry: dict[str, Any]) -> None:
    sender = _context(entry)
    protected, _ = sender.protect(_plaintext(entry))
    assert protected.code == POST
    assert protected.opt.oscore == bytes.fromhex(entry["oscore_option"])
    assert protected.payload == bytes.fromhex(entry["ciphertext"])

    packet = bytes.fromhex(entry["ipv6_packet"])
    compressed = bytes.fromhex(entry["schc_rule5"])
    assert compress_packet(packet) == compressed
    assert compressed[0] == 5
    restored = decompress_packet(compressed)
    assert restored == packet

    receiver = _context(entry, receiver=True)
    recovered, _ = receiver.unprotect(_protected_from_packet(restored))
    assert int(recovered.code) == entry["plaintext"]["code"]
    assert recovered.opt.encode() == bytes.fromhex(entry["plaintext"]["options"])
    assert recovered.payload == bytes.fromhex(entry["plaintext"]["payload"])
    with pytest.raises(ReplayError):
        receiver.unprotect(_protected_from_packet(restored))


def test_corruption_wrong_context_and_truncation_do_not_advance_replay() -> None:
    entry = VECTORS[0]
    canonical = bytes.fromhex(entry["schc_rule5"])
    restored = decompress_packet(canonical)

    receiver = _context(entry, receiver=True)
    initial = receiver.export_replay_window()
    corrupt = bytearray(canonical)
    corrupt[-1] ^= 0x80
    with pytest.raises(ProtectionInvalid):
        receiver.unprotect(_protected_from_packet(decompress_packet(bytes(corrupt))))
    assert receiver.export_replay_window() == initial

    with pytest.raises(ProtectionInvalid):
        receiver.unprotect(_protected_from_packet(decompress_packet(canonical[:-1])))
    assert receiver.export_replay_window() == initial

    wrong_secret = bytes((bytes.fromhex(entry["master_secret"])[0] ^ 1,)) + bytes.fromhex(
        entry["master_secret"]
    )[1:]
    wrong = _context(entry, receiver=True, secret=wrong_secret)
    wrong_initial = wrong.export_replay_window()
    with pytest.raises(ProtectionInvalid):
        wrong.unprotect(_protected_from_packet(restored))
    assert wrong.export_replay_window() == wrong_initial

    recovered, _ = receiver.unprotect(_protected_from_packet(restored))
    assert recovered.payload == bytes.fromhex(entry["plaintext"]["payload"])

    noncanonical = bytearray(canonical)
    noncanonical[22] |= 0x01
    output_before = bytes(restored)
    with pytest.raises(SchcError):
        decompress_packet(bytes(noncanonical))
    assert restored == output_before


def test_maximum_sender_sequence_round_trips_once_then_exhausts() -> None:
    entry = {**VECTORS[0], "sender_seq": MAX_OSCORE_SEQUENCE_NUMBER}
    sender = _context(entry)
    protected, _ = sender.protect(_plaintext(entry))
    assert protected.opt.oscore is not None
    assert protected.opt.oscore[0] & 0x07 == 5
    with pytest.raises(OverflowError):
        sender.protect(_plaintext(entry))

    packet = _build_packet(protected.opt.oscore, protected.payload)
    compressed = compress_packet(packet)
    assert compressed[0] == 5
    restored = decompress_packet(compressed)
    assert restored == packet
    receiver = _context(entry, receiver=True)
    recovered, _ = receiver.unprotect(_protected_from_packet(restored))
    assert recovered.payload == bytes.fromhex(entry["plaintext"]["payload"])
