"""Round-trip tests for SCHC whole-packet rules 1 (global CoAP) and 3/4 (RPL)."""

from __future__ import annotations

from ipaddress import IPv6Address

from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.rpl.messages import DAO, DIO, to_icmpv6
from lichen.schc.headers import compress_packet, decompress_packet

LL_SRC = IPv6Address("fe80::1")
LL_DST = IPv6Address("fe80::2")
G_SRC = IPv6Address("2001:db8::1")
G_DST = IPv6Address("2001:db8::2")


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
