# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv6Address

from lichen.ipv6.icmpv6 import icmpv6_checksum
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader, PacketError
from lichen.ipv6.udp import UDP_HEADER_LENGTH, UDP_NEXT_HEADER, UdpDatagram
from lichen.schc.codec import SchcError, compress, decompress, residue_byte_length
from lichen.schc.rules import (
    GLOBAL_COAP_RULE,
    GLOBAL_OSCORE_RULE,
    LINK_LOCAL_COAP_RULE,
    LINK_LOCAL_ICMPV6_ECHO_RULE,
    LINK_LOCAL_OSCORE_RULE,
    RPL_DAO_RULE,
    RPL_DIO_RULE,
    RULE_ID_UNCOMPRESSED,
    Rule,
)

_LINK_LOCAL_PREFIX64 = 0xFE80_0000_0000_0000
_COAP_FIXED_HEADER = 4
_COAP_OPTION_OSCORE = 9
_ICMPV6_RPL_TYPE = 155
_ICMPV6_ECHO_TYPES = (128, 129)
_ICMPV6_HEADER = 4
_ICMPV6_ECHO_BASE = 8
_DIO_BASE = 24
_DAO_BASE_WITH_DODAGID = 20


def _is_link_local(addr: int) -> bool:
    return addr >> 64 == _LINK_LOCAL_PREFIX64


def _is_global(addr: int) -> bool:
    return addr >> 125 == 0b001


def _coap_has_oscore_option(coap: bytes) -> bool:
    if len(coap) < _COAP_FIXED_HEADER:
        return False
    tkl = coap[0] & 0x0F
    if tkl > 8:
        return False
    offset = _COAP_FIXED_HEADER + tkl
    option_number = 0
    while offset < len(coap):
        byte = coap[offset]
        if byte == 0xFF:
            break
        delta = (byte >> 4) & 0x0F
        length = byte & 0x0F
        offset += 1
        if delta == 13:
            if offset >= len(coap):
                return False
            delta = 13 + coap[offset]
            offset += 1
        elif delta == 14:
            if offset + 1 >= len(coap):
                return False
            delta = 269 + int.from_bytes(coap[offset:offset+2], "big")
            offset += 2
        elif delta == 15:
            return False
        if length == 13:
            if offset >= len(coap):
                return False
            length = 13 + coap[offset]
            offset += 1
        elif length == 14:
            if offset + 1 >= len(coap):
                return False
            length = 269 + int.from_bytes(coap[offset:offset+2], "big")
            offset += 2
        elif length == 15:
            return False
        option_number += delta
        if option_number == _COAP_OPTION_OSCORE:
            return True
        if option_number > _COAP_OPTION_OSCORE:
            return False
        if offset + length > len(coap):
            return False
        offset += length
    return False


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
        # Minimum length: IPv6 header + UDP header + CoAP fixed header
        if len(raw) < HEADER_LENGTH + UDP_HEADER_LENGTH + _COAP_FIXED_HEADER:
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except PacketError:
            return False
        if header.next_header != UDP_NEXT_HEADER:
            return False
        if len(raw) < HEADER_LENGTH + header.payload_length:
            return False
        if header.payload_length < UDP_HEADER_LENGTH + _COAP_FIXED_HEADER:
            return False
        return self._addr_ok(int(header.src_addr)) and self._addr_ok(int(header.dst_addr))

    def parse(self, raw: bytes) -> tuple[dict[str, int], bytes]:
        header = IPv6Header.from_bytes(raw)
        udp = UdpDatagram.from_bytes(raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length])
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
        coap = bytes([b0, fields["CoAP.code"]]) + int(fields["CoAP.mid"]).to_bytes(2, "big") + tail
        udp_bytes = UdpDatagram(fields["UDP.src_port"], fields["UDP.dst_port"], coap).to_bytes(
            src, dst
        )
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


class _OscoreUdpProfile(_CoapUdpProfile):
    """IPv6 + UDP + OSCORE-protected CoAP; subclasses pick the address scope.

    OSCORE-protected CoAP packets (RFC 8613) have the Object-Security option
    present. These rules use distinct rule IDs to explicitly identify secured
    traffic and enable future OSCORE-specific compression optimizations.
    """

    def matches(self, raw: bytes) -> bool:
        # First check standard CoAP/UDP/IPv6 constraints
        if not super().matches(raw):
            return False
        # Then check for OSCORE option presence
        header = IPv6Header.from_bytes(raw)
        udp = UdpDatagram.from_bytes(raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length])
        return _coap_has_oscore_option(udp.payload)


class OscoreUdpLinkLocalProfile(_OscoreUdpProfile):
    """Link-local IPv6 + UDP + OSCORE-protected CoAP (SCHC rule 5)."""

    rule = LINK_LOCAL_OSCORE_RULE

    def _addr_ok(self, addr: int) -> bool:
        return _is_link_local(addr)


class OscoreUdpGlobalProfile(_OscoreUdpProfile):
    """Global IPv6 + UDP + OSCORE-protected CoAP (SCHC rule 6)."""

    rule = GLOBAL_OSCORE_RULE

    def _addr_ok(self, addr: int) -> bool:
        return _is_global(addr)


class _RplProfile(PacketProfile):
    """RPL control message over link-local ICMPv6 (type 155)."""

    code: int
    base_length: int

    def matches(self, raw: bytes) -> bool:
        # Minimum length: IPv6 header + ICMPv6 header + RPL base fields
        if len(raw) < HEADER_LENGTH + _ICMPV6_HEADER + self.base_length:
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except PacketError:
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
        icmpv6 = bytes([_ICMPV6_RPL_TYPE, self.code]) + checksum.to_bytes(2, "big") + body
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
                [
                    fields["RPL.gmop"],
                    fields["RPL.dtsn"],
                    fields["RPL.flags"],
                    fields["RPL.reserved"],
                ]
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
        return bytes(
            [
                fields["RPL.instance"],
                fields["RPL.kd_flags"],
                fields["RPL.reserved"],
                fields["RPL.seq"],
            ]
        ) + int(fields["RPL.dodagid"]).to_bytes(16, "big")


class Icmpv6EchoProfile(PacketProfile):
    """Link-local IPv6 + ICMPv6 Echo Request/Reply (SCHC rule 2)."""

    rule = LINK_LOCAL_ICMPV6_ECHO_RULE

    def matches(self, raw: bytes) -> bool:
        # Minimum length: IPv6 header + ICMPv6 echo base (type, code, checksum, id, seq)
        if len(raw) < HEADER_LENGTH + _ICMPV6_ECHO_BASE:
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except PacketError:
            return False
        if header.next_header != NextHeader.ICMPV6:
            return False
        if len(raw) < HEADER_LENGTH + header.payload_length:
            return False
        if header.payload_length < _ICMPV6_ECHO_BASE:
            return False
        if not (_is_link_local(int(header.src_addr)) and _is_link_local(int(header.dst_addr))):
            return False
        icmpv6 = raw[HEADER_LENGTH:]
        return icmpv6[0] in _ICMPV6_ECHO_TYPES and icmpv6[1] == 0

    def parse(self, raw: bytes) -> tuple[dict[str, int], bytes]:
        header = IPv6Header.from_bytes(raw)
        icmpv6 = raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
        fields = _ipv6_fields(header)
        fields.update(
            {
                "ICMPv6.type": icmpv6[0],
                "ICMPv6.code": icmpv6[1],
                "ICMPv6.checksum": int.from_bytes(icmpv6[2:4], "big"),
                "ICMPv6.identifier": int.from_bytes(icmpv6[4:6], "big"),
                "ICMPv6.sequence": int.from_bytes(icmpv6[6:8], "big"),
            }
        )
        return fields, icmpv6[_ICMPV6_ECHO_BASE:]

    def build(self, fields: dict[str, int | None], tail: bytes) -> bytes:
        src = IPv6Address(fields["IPv6.src"])
        dst = IPv6Address(fields["IPv6.dst"])
        body = (
            int(fields["ICMPv6.identifier"]).to_bytes(2, "big")
            + int(fields["ICMPv6.sequence"]).to_bytes(2, "big")
            + tail
        )
        msg_type = fields["ICMPv6.type"]
        code = fields["ICMPv6.code"]
        zero = bytes([msg_type, code, 0, 0]) + body
        checksum = icmpv6_checksum(src, dst, zero)
        icmpv6 = bytes([msg_type, code]) + checksum.to_bytes(2, "big") + body
        header = _ipv6_header(fields, NextHeader.ICMPV6, len(icmpv6))
        return header.to_bytes() + icmpv6


DEFAULT_PROFILES: tuple[PacketProfile, ...] = (
    # OSCORE profiles must come before regular CoAP profiles so that
    # OSCORE-protected packets match on rules 5/6, not 0/1.
    OscoreUdpLinkLocalProfile(),
    OscoreUdpGlobalProfile(),
    CoapUdpLinkLocalProfile(),
    CoapUdpGlobalProfile(),
    Icmpv6EchoProfile(),
    RplDioProfile(),
    RplDaoProfile(),
)


def compress_packet(raw: bytes, profiles: tuple[PacketProfile, ...] = DEFAULT_PROFILES) -> bytes:
    """Compress a full packet, or fall back to the uncompressed rule (255)."""
    for profile in profiles:
        if profile.matches(raw):
            fields, tail = profile.parse(raw)
            return compress(profile.rule, fields) + tail
    return bytes([RULE_ID_UNCOMPRESSED]) + raw


def decompress_packet(data: bytes, profiles: tuple[PacketProfile, ...] = DEFAULT_PROFILES) -> bytes:
    """Reconstruct a full packet from a SCHC-compressed datagram.

    Args:
        data: One Rule-ID byte followed by the residue and any trailing payload.
        profiles: Packet profiles to match against.

    Returns:
        The decompressed packet bytes.

    Raises:
        ValueError: If data is empty or no profile matches the rule ID.
        SchcError: If the residue is truncated (not enough bytes for the rule).
    """
    if not data:
        raise ValueError("empty SCHC packet")
    rule_id = data[0]
    if rule_id == RULE_ID_UNCOMPRESSED:
        return data[1:]
    for profile in profiles:
        if profile.rule.rule_id == rule_id:
            residue_len = residue_byte_length(profile.rule)
            required_len = 1 + residue_len
            if len(data) < required_len:
                raise SchcError(
                    f"packet too short: need {required_len} bytes for rule {rule_id}, "
                    f"got {len(data)}"
                )
            residue = data[:required_len]
            tail = data[required_len:]
            _, fields = decompress(residue, profile.rule)
            return profile.build(fields, tail)
    raise ValueError(f"no profile for rule ID {rule_id}")
