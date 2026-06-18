"""Whole-packet SCHC compression: packet bytes <-> field dicts (RFC 8724).

Bridges parsed protocol headers and the field-dict the SCHC codec consumes. A
:class:`PacketProfile` flattens a raw packet of a particular shape into
``{field_id: value}`` (plus a variable tail the rule does not model) and rebuilds
the bytes from decompressed fields. :func:`compress_packet` /
:func:`decompress_packet` drive a profile end to end, falling back to the
uncompressed rule (255) when nothing matches.

Profiles implemented (spec appendix A.1):
- rule 0 / 1: link-local / global IPv6 + UDP + CoAP
- rule 3 / 4: RPL DIO / DAO over link-local ICMPv6

The variable trailer (CoAP token/options/payload, or RPL options) travels
verbatim after the byte-aligned residue. Lengths and checksums are recomputed on
decompression. Address note: link-local /64 prefixes are elided but the 64-bit
IID is carried; global addresses are carried in full (prefix/IID context elision
needs the link layer and is deferred — correct but larger than spec A.1 sizes).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv6Address

from lichen.ipv6.icmpv6 import icmpv6_checksum
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader
from lichen.ipv6.udp import UDP_HEADER_LENGTH, UDP_NEXT_HEADER, UdpDatagram
from lichen.schc.codec import compress, decompress, residue_byte_length
from lichen.schc.rules import (
    GLOBAL_COAP_RULE,
    LINK_LOCAL_COAP_RULE,
    RPL_DAO_RULE,
    RPL_DIO_RULE,
    RULE_ID_UNCOMPRESSED,
    Rule,
)

_LINK_LOCAL_PREFIX64 = 0xFE80_0000_0000_0000  # top 64 bits of fe80::/64
_COAP_FIXED_HEADER = 4
_ICMPV6_RPL_TYPE = 155
_ICMPV6_HEADER = 4  # type, code, checksum
_DIO_BASE = 24
_DAO_BASE_WITH_DODAGID = 20


def _is_link_local(addr: int) -> bool:
    return addr >> 64 == _LINK_LOCAL_PREFIX64


def _is_global(addr: int) -> bool:
    return addr >> 125 == 0b001  # 2000::/3


def _ipv6_fields(header: IPv6Header) -> dict[str, int]:
    return {
        "IPv6.version": 6,
        "IPv6.traffic_class": header.traffic_class,
        "IPv6.flow_label": header.flow_label,
        "IPv6.payload_length": header.payload_length,
        "IPv6.next_header": header.next_header,
        "IPv6.hop_limit": header.hop_limit,
        "IPv6.src": int(header.src_addr),
        "IPv6.dst": int(header.dst_addr),
    }


def _ipv6_header(
    fields: dict[str, int | None], next_header: int, payload_length: int
) -> IPv6Header:
    return IPv6Header(
        src_addr=IPv6Address(fields["IPv6.src"]),
        dst_addr=IPv6Address(fields["IPv6.dst"]),
        next_header=next_header,
        payload_length=payload_length,
        hop_limit=fields["IPv6.hop_limit"],
        traffic_class=fields["IPv6.traffic_class"],
        flow_label=fields["IPv6.flow_label"],
    )


class PacketProfile(ABC):
    """Maps a class of packets to/from a SCHC rule's field dict."""

    rule: Rule

    @abstractmethod
    def matches(self, raw: bytes) -> bool: ...

    @abstractmethod
    def parse(self, raw: bytes) -> tuple[dict[str, int], bytes]: ...

    @abstractmethod
    def build(self, fields: dict[str, int | None], tail: bytes) -> bytes: ...


class _CoapUdpProfile(PacketProfile):
    """IPv6 + UDP + CoAP; subclasses pick the address scope."""

    @abstractmethod
    def _addr_ok(self, addr: int) -> bool: ...

    def matches(self, raw: bytes) -> bool:
        if len(raw) < HEADER_LENGTH + UDP_HEADER_LENGTH + _COAP_FIXED_HEADER:
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except Exception:
            return False
        if header.next_header != UDP_NEXT_HEADER:
            return False
        if len(raw) < HEADER_LENGTH + header.payload_length:
            return False
        if header.payload_length < UDP_HEADER_LENGTH + _COAP_FIXED_HEADER:
            return False
        return self._addr_ok(int(header.src_addr)) and self._addr_ok(
            int(header.dst_addr)
        )

    def parse(self, raw: bytes) -> tuple[dict[str, int], bytes]:
        header = IPv6Header.from_bytes(raw)
        udp = UdpDatagram.from_bytes(
            raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
        )
        coap = udp.payload
        fixed, tail = coap[:_COAP_FIXED_HEADER], coap[_COAP_FIXED_HEADER:]
        b0 = fixed[0]
        fields = _ipv6_fields(header)
        fields.update(
            {
                "UDP.src_port": udp.src_port,
                "UDP.dst_port": udp.dst_port,
                "UDP.length": udp.length,
                "UDP.checksum": udp.checksum,
                "CoAP.version": b0 >> 6,
                "CoAP.type": (b0 >> 4) & 0x3,
                "CoAP.tkl": b0 & 0x0F,
                "CoAP.code": fixed[1],
                "CoAP.mid": int.from_bytes(fixed[2:4], "big"),
            }
        )
        return fields, tail

    def build(self, fields: dict[str, int | None], tail: bytes) -> bytes:
        src = IPv6Address(fields["IPv6.src"])
        dst = IPv6Address(fields["IPv6.dst"])
        b0 = (1 << 6) | ((fields["CoAP.type"] & 0x3) << 4) | (fields["CoAP.tkl"] & 0x0F)
        coap = (
            bytes([b0, fields["CoAP.code"]])
            + int(fields["CoAP.mid"]).to_bytes(2, "big")
            + tail
        )
        udp_bytes = UdpDatagram(
            fields["UDP.src_port"], fields["UDP.dst_port"], coap
        ).to_bytes(src, dst)
        return _ipv6_header(fields, UDP_NEXT_HEADER, len(udp_bytes)).to_bytes() + udp_bytes


class CoapUdpLinkLocalProfile(_CoapUdpProfile):
    """Link-local IPv6 + UDP + CoAP (SCHC rule 0)."""

    rule = LINK_LOCAL_COAP_RULE

    def _addr_ok(self, addr: int) -> bool:
        return _is_link_local(addr)


class CoapUdpGlobalProfile(_CoapUdpProfile):
    """Global IPv6 + UDP + CoAP (SCHC rule 1)."""

    rule = GLOBAL_COAP_RULE

    def _addr_ok(self, addr: int) -> bool:
        return _is_global(addr)


class _RplProfile(PacketProfile):
    """RPL control message over link-local ICMPv6 (type 155)."""

    code: int
    base_length: int

    def matches(self, raw: bytes) -> bool:
        if len(raw) < HEADER_LENGTH + _ICMPV6_HEADER + self.base_length:
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except Exception:
            return False
        if header.next_header != NextHeader.ICMPV6:
            return False
        if len(raw) < HEADER_LENGTH + header.payload_length:
            return False
        if header.payload_length < _ICMPV6_HEADER + self.base_length:
            return False
        if not (_is_link_local(int(header.src_addr)) and _is_link_local(int(header.dst_addr))):
            return False
        icmpv6 = raw[HEADER_LENGTH:]
        return icmpv6[0] == _ICMPV6_RPL_TYPE and icmpv6[1] == self.code

    def parse(self, raw: bytes) -> tuple[dict[str, int], bytes]:
        header = IPv6Header.from_bytes(raw)
        icmpv6 = raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
        rpl = icmpv6[_ICMPV6_HEADER:]
        fields = _ipv6_fields(header)
        fields.update(
            {
                "ICMPv6.type": icmpv6[0],
                "ICMPv6.code": icmpv6[1],
                "ICMPv6.checksum": int.from_bytes(icmpv6[2:4], "big"),
            }
        )
        fields.update(self._parse_base(rpl[: self.base_length]))
        return fields, rpl[self.base_length :]

    def build(self, fields: dict[str, int | None], tail: bytes) -> bytes:
        src = IPv6Address(fields["IPv6.src"])
        dst = IPv6Address(fields["IPv6.dst"])
        body = self._build_base(fields) + tail
        zero = bytes([_ICMPV6_RPL_TYPE, self.code, 0, 0]) + body
        checksum = icmpv6_checksum(src, dst, zero)
        icmpv6 = (
            bytes([_ICMPV6_RPL_TYPE, self.code]) + checksum.to_bytes(2, "big") + body
        )
        header = _ipv6_header(fields, NextHeader.ICMPV6, len(icmpv6))
        return header.to_bytes() + icmpv6

    @abstractmethod
    def _parse_base(self, base: bytes) -> dict[str, int]: ...

    @abstractmethod
    def _build_base(self, fields: dict[str, int | None]) -> bytes: ...


class RplDioProfile(_RplProfile):
    """RPL DIO over link-local ICMPv6 (SCHC rule 3)."""

    rule = RPL_DIO_RULE
    code = 1
    base_length = _DIO_BASE

    def _parse_base(self, base: bytes) -> dict[str, int]:
        return {
            "RPL.instance": base[0],
            "RPL.version": base[1],
            "RPL.rank": int.from_bytes(base[2:4], "big"),
            "RPL.gmop": base[4],
            "RPL.dtsn": base[5],
            "RPL.flags": base[6],
            "RPL.reserved": base[7],
            "RPL.dodagid": int.from_bytes(base[8:24], "big"),
        }

    def _build_base(self, fields: dict[str, int | None]) -> bytes:
        return (
            bytes([fields["RPL.instance"], fields["RPL.version"]])
            + int(fields["RPL.rank"]).to_bytes(2, "big")
            + bytes(
                [fields["RPL.gmop"], fields["RPL.dtsn"], fields["RPL.flags"],
                 fields["RPL.reserved"]]
            )
            + int(fields["RPL.dodagid"]).to_bytes(16, "big")
        )


class RplDaoProfile(_RplProfile):
    """RPL DAO with DODAGID over link-local ICMPv6 (SCHC rule 4)."""

    rule = RPL_DAO_RULE
    code = 2
    base_length = _DAO_BASE_WITH_DODAGID

    def matches(self, raw: bytes) -> bool:
        if not super().matches(raw):
            return False
        # Rule 4 only covers DAOs that carry a DODAGID (the D flag, bit 6).
        icmpv6 = raw[HEADER_LENGTH:]
        kd_flags = icmpv6[_ICMPV6_HEADER + 1]
        return bool(kd_flags & 0x40)

    def _parse_base(self, base: bytes) -> dict[str, int]:
        return {
            "RPL.instance": base[0],
            "RPL.kd_flags": base[1],
            "RPL.reserved": base[2],
            "RPL.seq": base[3],
            "RPL.dodagid": int.from_bytes(base[4:20], "big"),
        }

    def _build_base(self, fields: dict[str, int | None]) -> bytes:
        return (
            bytes(
                [fields["RPL.instance"], fields["RPL.kd_flags"],
                 fields["RPL.reserved"], fields["RPL.seq"]]
            )
            + int(fields["RPL.dodagid"]).to_bytes(16, "big")
        )


DEFAULT_PROFILES: tuple[PacketProfile, ...] = (
    CoapUdpLinkLocalProfile(),
    CoapUdpGlobalProfile(),
    RplDioProfile(),
    RplDaoProfile(),
)


def compress_packet(
    raw: bytes, profiles: tuple[PacketProfile, ...] = DEFAULT_PROFILES
) -> bytes:
    """Compress a full packet, or fall back to the uncompressed rule (255)."""
    for profile in profiles:
        if profile.matches(raw):
            fields, tail = profile.parse(raw)
            return compress(profile.rule, fields) + tail
    return bytes([RULE_ID_UNCOMPRESSED]) + raw


def decompress_packet(
    data: bytes, profiles: tuple[PacketProfile, ...] = DEFAULT_PROFILES
) -> bytes:
    """Reconstruct a full packet from a SCHC-compressed datagram."""
    if not data:
        raise ValueError("empty SCHC packet")
    rule_id = data[0]
    if rule_id == RULE_ID_UNCOMPRESSED:
        return data[1:]
    for profile in profiles:
        if profile.rule.rule_id == rule_id:
            residue_len = residue_byte_length(profile.rule)
            residue = data[: 1 + residue_len]
            tail = data[1 + residue_len :]
            _, fields = decompress(residue, profile.rule)
            return profile.build(fields, tail)
    raise ValueError(f"no profile for rule ID {rule_id}")
