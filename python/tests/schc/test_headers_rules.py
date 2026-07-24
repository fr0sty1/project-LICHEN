# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Round-trip tests for SCHC whole-packet rules 1 (global CoAP) and 3/4 (RPL)."""

from __future__ import annotations

from ipaddress import IPv6Address

import pytest

from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.rpl.messages import DAO, DIO, to_icmpv6
from lichen.schc.codec import SchcError
from lichen.schc.headers import compress_packet, decompress_packet

LL_SRC = IPv6Address("fe80::1")
LL_DST = IPv6Address("fe80::2")
G_SRC = IPv6Address("0202:db8::1")  # 02xx Yggdrasil primary global
G_DST = IPv6Address("0202:db8::2")


def _coap_fixed(code: int = 1, mid: int = 0x1234) -> bytes:
    # CoAP ver=1, type=0, tkl=0, code, mid, + a trivial payload tail.
    return bytes([0x40, code]) + mid.to_bytes(2, "big") + b"\xff" + b"data"


def _udp_ipv6(src: IPv6Address, dst: IPv6Address, payload: bytes) -> bytes:
    udp = UdpDatagram(5683, 5683, payload).to_bytes(src, dst)
    header = IPv6Header(src, dst, NextHeader.UDP, payload_length=len(udp))
    return header.to_bytes() + udp


def _icmpv6_ipv6(src: IPv6Address, dst: IPv6Address, msg: Icmpv6Message) -> bytes:
    body = msg.to_bytes(src, dst)
    header = IPv6Header(src, dst, NextHeader.ICMPV6, payload_length=len(body))
    return header.to_bytes() + body


def test_global_coap_rule1_round_trip() -> None:
    raw = _udp_ipv6(G_SRC, G_DST, _coap_fixed())
    compressed = compress_packet(raw)
    assert compressed[0] == 1  # rule 1 (global CoAP)
    assert decompress_packet(compressed) == raw


def test_link_local_preferred_over_global() -> None:
    # A link-local CoAP packet must select rule 0, not rule 1.
    raw = _udp_ipv6(LL_SRC, LL_DST, _coap_fixed())
    assert compress_packet(raw)[0] == 0


def test_icmpv6_echo_rule2_round_trip() -> None:
    from lichen.ipv6.icmpv6 import EchoRequest

    req = EchoRequest(identifier=0xABCD, sequence=7, data=b"ping")
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, req.to_message())
    compressed = compress_packet(raw)
    assert compressed[0] == 2  # rule 2 (link-local ICMPv6 echo)
    assert decompress_packet(compressed) == raw


def test_icmpv6_echo_reply_round_trip() -> None:
    from lichen.ipv6.icmpv6 import EchoReply

    rep = EchoReply(identifier=1, sequence=99, data=b"")
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, rep.to_message())
    assert compress_packet(raw)[0] == 2
    assert decompress_packet(compress_packet(raw)) == raw


def test_rpl_dio_rule3_round_trip() -> None:
    dio = DIO(
        rpl_instance_id=0, version=1, rank=256, dtsn=0, dodag_id="fe80::1",
        grounded=True,
    )
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dio))
    compressed = compress_packet(raw)
    assert compressed[0] == 3  # rule 3 (RPL DIO)
    assert decompress_packet(compressed) == raw


def test_rpl_dao_rule4_round_trip() -> None:
    dao = DAO(rpl_instance_id=0, dao_sequence=5, dodag_id=IPv6Address("fe80::1"))
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dao))
    compressed = compress_packet(raw)
    assert compressed[0] == 4  # rule 4 (RPL DAO with DODAGID)
    assert decompress_packet(compressed) == raw


def test_rpl_dao_without_dodagid_falls_back() -> None:
    # No DODAGID (D flag clear) -> rule 4 declines, fallback to uncompressed.
    dao = DAO(rpl_instance_id=0, dao_sequence=5)  # no dodag_id
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dao))
    compressed = compress_packet(raw)
    assert compressed[0] == 255
    assert decompress_packet(compressed) == raw


def test_dio_options_travel_as_tail() -> None:
    # A DIO with a trailing option must round-trip (option carried as the tail).
    from lichen.rpl.messages import RplOption, RplOptionType

    dio = DIO(
        rpl_instance_id=0, version=1, rank=256, dtsn=0, dodag_id="fe80::1",
        options=[RplOption(RplOptionType.PADN, b"\x00\x00")],
    )
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dio))
    compressed = compress_packet(raw)
    assert compressed[0] == 3
    restored = decompress_packet(compressed)
    assert restored == raw
    # Confirm the option survived by re-parsing the reconstructed DIO.
    from lichen.rpl.messages import from_icmpv6

    body = restored[HEADER_LENGTH:]
    parsed = from_icmpv6(Icmpv6Message.from_bytes(body))
    assert parsed.options[0].data == b"\x00\x00"


def test_rpl_with_trailing_bytes_falls_back() -> None:
    dio = DIO(rpl_instance_id=0, version=1, rank=256, dtsn=0, dodag_id="fe80::1")
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dio)) + b"junk"
    assert compress_packet(raw)[0] == 255


def test_rpl_with_invalid_checksum_falls_back() -> None:
    dio = DIO(rpl_instance_id=0, version=1, rank=256, dtsn=0, dodag_id="fe80::1")
    raw = bytearray(_icmpv6_ipv6(LL_SRC, LL_DST, to_icmpv6(dio)))
    raw[HEADER_LENGTH + 2] ^= 0x01
    assert compress_packet(bytes(raw))[0] == 255


def test_icmpv6_echo_with_trailing_bytes_falls_back() -> None:
    message = Icmpv6Message(128, 0, bytes.fromhex("abcd0007") + b"ping")
    raw = _icmpv6_ipv6(LL_SRC, LL_DST, message) + b"junk"
    assert compress_packet(raw)[0] == 255


def test_icmpv6_echo_with_invalid_checksum_falls_back() -> None:
    message = Icmpv6Message(128, 0, bytes.fromhex("abcd0007") + b"ping")
    raw = bytearray(_icmpv6_ipv6(LL_SRC, LL_DST, message))
    raw[HEADER_LENGTH + 2] ^= 0x01
    assert compress_packet(bytes(raw))[0] == 255


def _coap_with_oscore(tkl: int = 2) -> bytes:
    """Build a CoAP packet with OSCORE option (option 9).

    Format: CoAP header + token + OSCORE option + payload marker + encrypted data.
    OSCORE option: delta=9, len=2, value=0x09 0x00 (flags + partial IV).
    """
    # CoAP ver=1, type=0, tkl, code=0.01, mid=0x1234
    b0 = 0x40 | (tkl & 0x0F)
    header = bytes([b0, 0x01]) + (0x1234).to_bytes(2, "big")
    token = bytes(range(tkl))  # 0x00, 0x01, ...
    # OSCORE option: delta=9, len=2 -> 0x92; value=0x09 0x00
    oscore_option = bytes([0x92, 0x09, 0x00])
    payload = b"\xff\xde\xad\xbe\xef"  # payload marker + encrypted data
    return header + token + oscore_option + payload


def test_oscore_link_local_rule5_round_trip() -> None:
    """OSCORE-protected CoAP over link-local IPv6 uses rule 5."""
    raw = _udp_ipv6(LL_SRC, LL_DST, _coap_with_oscore())
    compressed = compress_packet(raw)
    assert compressed[0] == 5  # rule 5 (link-local OSCORE)
    assert decompress_packet(compressed) == raw


def test_oscore_global_rule6_round_trip() -> None:
    """OSCORE-protected CoAP over global IPv6 uses rule 6."""
    raw = _udp_ipv6(G_SRC, G_DST, _coap_with_oscore())
    compressed = compress_packet(raw)
    assert compressed[0] == 6  # rule 6 (global OSCORE)
    assert decompress_packet(compressed) == raw


def test_oscore_preferred_over_plain_coap() -> None:
    """OSCORE packets must match rules 5/6, not 0/1."""
    ll_raw = _udp_ipv6(LL_SRC, LL_DST, _coap_with_oscore())
    g_raw = _udp_ipv6(G_SRC, G_DST, _coap_with_oscore())
    # Link-local OSCORE -> rule 5, not rule 0
    assert compress_packet(ll_raw)[0] == 5
    # Global OSCORE -> rule 6, not rule 1
    assert compress_packet(g_raw)[0] == 6


def test_oscore_option_with_empty_payload_marker_is_not_recognized() -> None:
    raw = _udp_ipv6(LL_SRC, LL_DST, _coap_with_oscore()[:-4])
    compressed = compress_packet(raw)
    # Without encrypted payload, OSCORE rule does not match.
    # Falls through to plain CoAP rule 0, not rule 255.
    assert compressed[0] == 0


def test_plain_coap_still_uses_rule0() -> None:
    """Plain CoAP (no OSCORE option) should use rules 0/1, not 5/6."""
    raw = _udp_ipv6(LL_SRC, LL_DST, _coap_fixed())
    assert compress_packet(raw)[0] == 0


def test_malformed_coap_option_length_falls_back() -> None:
    """CoAP with option length exceeding remaining bytes must not match OSCORE.

    A malformed packet where an option declares more bytes than remain
    should be handled gracefully (returned as non-OSCORE), not crash.
    """
    # CoAP header: ver=1, type=0, tkl=0, code=0.01, mid=0x1234
    header = bytes([0x40, 0x01, 0x12, 0x34])
    # Option byte: delta=9 (OSCORE), length=15 (claims 15 bytes follow)
    # But we only supply 2 bytes of value - malformed packet
    malformed_option = bytes([0x9F, 0xAB, 0xCD])  # delta=9, len=15, only 2 value bytes
    coap = header + malformed_option
    raw = _udp_ipv6(LL_SRC, LL_DST, coap)
    # Should fall back to rule 0 (plain CoAP), not crash or match rule 5 (OSCORE)
    compressed = compress_packet(raw)
    assert compressed[0] == 0  # Falls back to plain CoAP rule
