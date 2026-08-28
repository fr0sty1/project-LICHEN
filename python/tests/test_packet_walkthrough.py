# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Consume spec 09 section 13.1 CoAP-to-PHY walkthrough vectors.

Production codecs must reproduce each layer's expected output. The JSON file
is the independent oracle; this module never treats lichen.* as its own
expected-value generator.
"""

from __future__ import annotations

import json
import sys
from ipaddress import IPv6Address
from pathlib import Path

from aiocoap import Message
from aiocoap.numbers.codes import CONTENT
from aiocoap.numbers.types import NON

from lichen.coap.schc_channel import unwrap_coap, wrap_coap
from lichen.l2_payload import L2PayloadKind, classify_l2_payload, l2_payload_body, wrap_schc_payload
from lichen.link.frame import AddrMode, LichenFrame, MicLength
from lichen.schc.headers import compress_packet, decompress_packet
from lichen.timing.airtime import airtime_us

VECTORS_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

from generate_packet_walkthrough import document  # noqa: E402
from reference_schnorr48 import signature_transcript, verify  # noqa: E402

DOCUMENT = json.loads((VECTORS_DIR / "packet_walkthrough.json").read_text())
BY_NAME = {vector["name"]: vector for vector in DOCUMENT["vectors"]}


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


def test_walkthrough_oracle_is_fresh() -> None:
    assert document() == DOCUMENT
    assert DOCUMENT["format_version"] == 2
    assert len(DOCUMENT["vectors"]) == 7
    assert list(BY_NAME) == [
        "coap_temperature_content",
        "ipv6_udp_envelope",
        "schc_rule0_compress",
        "l2_schc_dispatch",
        "link_frame_signed_short",
        "phy_sf10_airtime",
        "spec_13_1_complete_walkthrough",
    ]


def test_layer_outputs_chain() -> None:
    names = [
        "coap_temperature_content",
        "ipv6_udp_envelope",
        "schc_rule0_compress",
        "l2_schc_dispatch",
        "link_frame_signed_short",
        "phy_sf10_airtime",
    ]
    for previous, current in zip(names[:-1], names[1:], strict=True):
        assert BY_NAME[previous]["output_hex"] == BY_NAME[current]["input_hex"]
    walkthrough = BY_NAME["spec_13_1_complete_walkthrough"]
    layers = walkthrough["layers"]
    assert layers["coap_hex"] == BY_NAME["coap_temperature_content"]["output_hex"]
    assert layers["ipv6_udp_hex"] == BY_NAME["ipv6_udp_envelope"]["output_hex"]
    assert layers["schc_hex"] == BY_NAME["schc_rule0_compress"]["output_hex"]
    assert layers["l2_hex"] == BY_NAME["l2_schc_dispatch"]["output_hex"]
    assert layers["link_hex"] == BY_NAME["link_frame_signed_short"]["output_hex"]
    assert layers["phy_payload_hex"] == BY_NAME["phy_sf10_airtime"]["output_hex"]
    assert walkthrough["app_payload_len"] == 16
    assert walkthrough["schc_packet_len"] == 43
    assert walkthrough["l2_payload_len"] == 44
    assert walkthrough["body_bytes"] == 106
    assert walkthrough["total_on_wire"] == 107


def test_coap_layer_matches_production_encoder() -> None:
    vector = BY_NAME["coap_temperature_content"]
    fields = vector["fields"]
    message = Message(code=CONTENT, payload=_hex(fields["payload_hex"]))
    message.mtype = NON
    message.token = _hex(fields["token_hex"])
    message.mid = fields["mid"]
    message.opt.content_format = fields["content_format"]
    encoded = bytes(message.encode())
    assert encoded == _hex(vector["output_hex"])
    assert encoded[0] == 0x51
    assert encoded[1] == 0x45
    assert encoded[4] == 0x42
    assert encoded[5:7] == bytes.fromhex("c13c")
    assert encoded[7] == 0xFF
    assert encoded[8:] == _hex(fields["payload_hex"])
    assert len(_hex(fields["payload_hex"])) == 16


def test_ipv6_udp_layer_matches_wrap_coap() -> None:
    vector = BY_NAME["ipv6_udp_envelope"]
    fields = vector["fields"]
    packet = wrap_coap(
        IPv6Address(fields["src"]),
        IPv6Address(fields["dst"]),
        _hex(vector["input_hex"]),
        src_port=fields["src_port"],
        dst_port=fields["dst_port"],
    )
    assert packet == _hex(vector["output_hex"])
    assert packet[6] == fields["next_header"]
    assert packet[7] == fields["hop_limit"]
    assert unwrap_coap(packet) == _hex(vector["input_hex"])


def test_schc_layer_matches_rule0() -> None:
    vector = BY_NAME["schc_rule0_compress"]
    packet = _hex(vector["input_hex"])
    compressed = compress_packet(packet)
    assert compressed == _hex(vector["output_hex"])
    assert compressed[0] == vector["fields"]["rule_id"]
    assert len(compressed) == 43
    assert decompress_packet(compressed) == packet


def test_l2_layer_matches_schc_dispatch() -> None:
    vector = BY_NAME["l2_schc_dispatch"]
    wrapped = wrap_schc_payload(_hex(vector["input_hex"]))
    assert wrapped == _hex(vector["output_hex"])
    assert wrapped[0] == vector["fields"]["dispatch"]
    assert classify_l2_payload(wrapped) is L2PayloadKind.SCHC
    assert l2_payload_body(wrapped) == _hex(vector["input_hex"])
    assert len(wrapped) == 44


def test_link_layer_matches_signed_short_frame() -> None:
    vector = BY_NAME["link_frame_signed_short"]
    fields = vector["fields"]
    payload = _hex(vector["input_hex"])
    signature = _hex(fields["signature_hex"])
    frame = LichenFrame(
        epoch=fields["Epoch"],
        seqnum=fields["SeqNum"],
        dst_addr=fields["DstAddr"].to_bytes(2, "big"),
        payload=payload,
        mic=signature,
        addr_mode=AddrMode(fields["addr_mode"]),
        mic_length=MicLength(fields["mic_length"]),
        signature_present=fields["signature_present"],
        encrypted=fields["encrypted"],
        signer_eui64=_hex(fields["signer_eui64_hex"]),
    )
    encoded = frame.to_bytes()
    assert encoded == _hex(vector["output_hex"])
    assert encoded[0] == fields["Length"]
    assert encoded[1] == fields["LLSec"]
    assert len(encoded) == fields["total_on_wire"]
    parsed = LichenFrame.from_bytes(encoded)
    assert parsed == frame
    transcript = signature_transcript(encoded[: len(encoded) - 48], 2)
    assert transcript == _hex(fields["transcript_hex"])
    assert verify(_hex(fields["public_key_hex"]), transcript, signature)


def test_phy_layer_matches_default_airtime() -> None:
    vector = BY_NAME["phy_sf10_airtime"]
    fields = vector["fields"]
    payload = _hex(vector["input_hex"])
    assert payload == _hex(vector["output_hex"])
    assert len(payload) == fields["payload_len"] == 107
    assert airtime_us(fields["payload_len"]) == fields["airtime_us"] == 1_067_008
    assert fields["preamble_symbols"] == 8
    assert fields["explicit_header"] is True
    assert fields["phy_crc"] is True
    assert fields["sf"] == 10
    assert fields["bw_hz"] == 125_000
