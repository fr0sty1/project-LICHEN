# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Whole-packet SCHC compression: packet bytes <-> field dicts (RFC 8724).

Bridges parsed protocol headers and the field-dict the SCHC codec consumes. A
:class:`PacketProfile` flattens a raw packet of a particular shape into
``{field_id: value}`` (plus a variable tail the rule does not model) and rebuilds
the bytes from decompressed fields. :func:`compress_packet` /
:func:`decompress_packet` drive a profile end to end, falling back to the
uncompressed rule (255) when nothing matches.

Profiles implemented (spec appendix A.1):
- rule 0 / 1: link-local / global IPv6 + UDP + CoAP
- rule 2: ICMPv6 Echo Request/Reply over link-local IPv6
- rule 3 / 4: RPL DIO / DAO over link-local ICMPv6
- rule 5 / 6: link-local / global IPv6 + UDP + OSCORE-protected CoAP (RFC 8613)

The variable trailer (CoAP token/options/payload, or RPL options) travels
verbatim after the byte-aligned residue. Lengths and checksums are recomputed on
decompression. Address note: link-local /64 prefixes are elided (only 64-bit IID carried);
global (02xx::/7 primary or 2000::/3 GUA) addresses carried in full. Prefix
context elision for globals requires link-layer state (deferred). See
_is_global() and spec/04-network.md for scope assumptions.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv6Address

from lichen.ipv6.icmpv6 import icmpv6_checksum
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, NextHeader, PacketError
from lichen.ipv6.udp import UDP_HEADER_LENGTH, UDP_NEXT_HEADER, UdpDatagram, UdpError, udp_checksum
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

_LINK_LOCAL_PREFIX64 = 0xFE80_0000_0000_0000  # top 64 bits of fe80::/64
_COAP_FIXED_HEADER = 4
_COAP_OPTION_OSCORE = 9  # RFC 8613 Object-Security option
_ICMPV6_RPL_TYPE = 155
_ICMPV6_ECHO_TYPES = (128, 129)  # Echo Request / Reply
_ICMPV6_HEADER = 4  # type, code, checksum
_ICMPV6_ECHO_BASE = 8  # type, code, checksum, identifier, sequence
_DIO_BASE = 24
_DAO_BASE_WITH_DODAGID = 20


def _is_link_local(addr: int) -> bool:
    return addr >> 64 == _LINK_LOCAL_PREFIX64


def _is_global(addr: int) -> bool:
    # Primary: 02xx::/7 (Yggdrasil, first byte 0x02/0x03 per spec/04-network,
    # 06-security). Also standard GUA 2000::/3 (optional BR upstream). Matches
    # current deployment while avoiding some deprecated sub-prefixes.
    first_byte = (addr >> 120) & 0xff
    return (first_byte & 0xfe == 0x02) or (addr >> 125 == 0b001)


def _is_ula(addr: int) -> bool:
    return (addr >> 120) == 0xFD  # fd00::/8


def _is_routable(addr: int) -> bool:
    return _is_link_local(addr) or _is_ula(addr) or _is_global(addr)


def _valid_oscore_option(value: bytes) -> bool:
    if not value:
        return True
    if len(value) > 255:
        return False

    flags = value[0]
    partial_iv_len = flags & 0x07
    if flags & 0xE0 or partial_iv_len > 5 or flags == 0:
        return False

    offset = 1 + partial_iv_len
    if offset > len(value):
        return False
    if partial_iv_len > 1 and value[1] == 0:
        return False
    if flags & 0x10:
        if offset >= len(value):
            return False
        context_len = value[offset]
        offset += 1 + context_len
        if offset > len(value):
            return False
    return bool(flags & 0x08) or offset == len(value)


def _coap_oscore_status(coap: bytes) -> bool | None:
    """Return OSCORE presence, or None when the CoAP framing is malformed.

    OSCORE-protected CoAP packets (RFC 8613) have the Object-Security option
    present in the option list. This function scans the CoAP options to detect it.

    Args:
        coap: Raw CoAP packet bytes (header + options + payload).

    Returns:
        True if OSCORE is present, False if it is absent, or None if malformed.
    """
    if len(coap) < _COAP_FIXED_HEADER:
        return None
    if coap[0] >> 6 != 1:
        return None

    tkl = coap[0] & 0x0F
    if tkl > 8:  # Reserved values 9-15
        return None

    offset = _COAP_FIXED_HEADER + tkl
    if offset > len(coap):
        return None
    option_number = 0
    oscore_found = False

    while offset < len(coap):
        byte = coap[offset]

        # Payload marker (0xFF)
        if byte == 0xFF:
            return oscore_found if offset + 1 < len(coap) else None

        # Parse option delta
        delta = (byte >> 4) & 0x0F
        length = byte & 0x0F
        offset += 1

        if delta == 13:
            if offset + 1 > len(coap):
                return False
            delta = coap[offset] + 13
            offset += 1
        elif delta == 14:
            if offset + 2 > len(coap):
                return False
            delta = int.from_bytes(coap[offset : offset + 2], "big") + 269
            offset += 2
        elif delta == 15:
            return False

        # Parse option length
        if length == 13:
            if offset + 1 > len(coap):
                return False
            length = coap[offset] + 13
            offset += 1
        elif length == 14:
            if offset + 2 > len(coap):
                return False
            length = int.from_bytes(coap[offset : offset + 2], "big") + 269
            offset += 2
        elif length == 15:
            return False

        option_number += delta

        if offset + length > len(coap):
            return None

        if option_number == _COAP_OPTION_OSCORE:
            if oscore_found or not _valid_oscore_option(coap[offset : offset + length]):
                return None
            oscore_found = True

        # Skip option value, checking bounds first
        if offset + length > len(coap):
            return False  # Malformed: declared length exceeds remaining bytes
        offset += length

    return None if oscore_found else False


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


def _require_field(fields: dict[str, int | None], key: str) -> int:
    val = fields.get(key)
    assert val is not None, f"decompress returned None for non-COMPUTE {key}"
    return int(val)


def _ipv6_header(
    fields: dict[str, int | None], next_header: int, payload_length: int
) -> IPv6Header:
    return IPv6Header(
        src_addr=IPv6Address(_require_field(fields, "IPv6.src")),
        dst_addr=IPv6Address(_require_field(fields, "IPv6.dst")),
        next_header=next_header,
        payload_length=payload_length,
        hop_limit=_require_field(fields, "IPv6.hop_limit"),
        traffic_class=_require_field(fields, "IPv6.traffic_class"),
        flow_label=_require_field(fields, "IPv6.flow_label"),
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
        if len(raw) != HEADER_LENGTH + header.payload_length:
            return False
        if header.payload_length < UDP_HEADER_LENGTH + _COAP_FIXED_HEADER:
            return False
        try:
            udp = UdpDatagram.from_bytes(raw[HEADER_LENGTH:])
        except UdpError:
            return False
        if udp.checksum == 0 or udp_checksum(header.src_addr, header.dst_addr, raw[HEADER_LENGTH:]):
            return False
        coap = udp.payload
        tkl = coap[0] & 0x0F
        if coap[0] >> 6 != 1 or tkl > 8 or _COAP_FIXED_HEADER + tkl > len(coap):
            return False
        if _coap_oscore_status(coap) is None:
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
        src = IPv6Address(_require_field(fields, "IPv6.src"))
        dst = IPv6Address(_require_field(fields, "IPv6.dst"))
        coap_type = _require_field(fields, "CoAP.type")
        coap_tkl = _require_field(fields, "CoAP.tkl")
        coap_code = _require_field(fields, "CoAP.code")
        coap_mid = _require_field(fields, "CoAP.mid")
        b0 = (1 << 6) | ((coap_type & 0x3) << 4) | (coap_tkl & 0x0F)
        coap = bytes([b0, coap_code]) + coap_mid.to_bytes(2, "big") + tail
        udp_bytes = UdpDatagram(
            _require_field(fields, "UDP.src_port"),
            _require_field(fields, "UDP.dst_port"),
            coap,
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
        return _coap_oscore_status(udp.payload) is True


class OscoreUdpLinkLocalProfile(_OscoreUdpProfile):
    """Link-local IPv6 + UDP + OSCORE-protected CoAP (SCHC rule 5)."""

    rule = LINK_LOCAL_OSCORE_RULE

    def _addr_ok(self, addr: int) -> bool:
        return _is_link_local(addr)


class OscoreUdpGlobalProfile(_OscoreUdpProfile):
    rule = GLOBAL_OSCORE_RULE

    def _addr_ok(self, addr: int) -> bool:
        return _is_global(addr)


class _RplProfile(PacketProfile):
    code: int
    base_length: int

    def matches(self, raw: bytes) -> bool:
        if len(raw) < HEADER_LENGTH + _ICMPV6_HEADER + self.base_length:
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except PacketError:
            return False
        if header.next_header != NextHeader.ICMPV6:
            return False
        if len(raw) != HEADER_LENGTH + header.payload_length:
            return False
        if header.payload_length < _ICMPV6_HEADER + self.base_length:
            return False
        if not (_is_routable(int(header.src_addr)) and _is_routable(int(header.dst_addr))):
            return False
        icmpv6 = raw[HEADER_LENGTH:]
        if icmpv6_checksum(header.src_addr, header.dst_addr, icmpv6):
            return False
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
        src = IPv6Address(_require_field(fields, "IPv6.src"))
        dst = IPv6Address(_require_field(fields, "IPv6.dst"))
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
            bytes([_require_field(fields, "RPL.instance"), _require_field(fields, "RPL.version")])
            + _require_field(fields, "RPL.rank").to_bytes(2, "big")
            + bytes(
                [
                    _require_field(fields, "RPL.gmop"),
                    _require_field(fields, "RPL.dtsn"),
                    _require_field(fields, "RPL.flags"),
                    _require_field(fields, "RPL.reserved"),
                ]
            )
            + _require_field(fields, "RPL.dodagid").to_bytes(16, "big")
        )


class RplDaoProfile(_RplProfile):
    """RPL DAO with DODAGID over routable IPv6 (SCHC rule 4, multi-hop source model)."""

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
                _require_field(fields, "RPL.instance"),
                _require_field(fields, "RPL.kd_flags"),
                _require_field(fields, "RPL.reserved"),
                _require_field(fields, "RPL.seq"),
            ]
        ) + _require_field(fields, "RPL.dodagid").to_bytes(16, "big")


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
        if len(raw) != HEADER_LENGTH + header.payload_length:
            return False
        if header.payload_length < _ICMPV6_ECHO_BASE:
            return False
        if not (_is_link_local(int(header.src_addr)) and _is_link_local(int(header.dst_addr))):
            return False
        icmpv6 = raw[HEADER_LENGTH:]
        if icmpv6_checksum(header.src_addr, header.dst_addr, icmpv6):
            return False
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
        src = IPv6Address(_require_field(fields, "IPv6.src"))
        dst = IPv6Address(_require_field(fields, "IPv6.dst"))
        ident = _require_field(fields, "ICMPv6.identifier")
        seq = _require_field(fields, "ICMPv6.sequence")
        msg_type = _require_field(fields, "ICMPv6.type")
        code = _require_field(fields, "ICMPv6.code")
        body = ident.to_bytes(2, "big") + seq.to_bytes(2, "big") + tail
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
                    f"packet too short: need {required_len} bytes for residue of rule {rule_id}, "
                    f"got {len(data)}"
                )
            residue = data[:required_len]
            tail = data[required_len:]
            _, fields = decompress(residue, profile.rule)
            raw = profile.build(fields, tail)
            if not profile.matches(raw):
                raise SchcError(f"rule {rule_id} residue does not reconstruct its packet profile")
            if isinstance(profile, _CoapUdpProfile) and not isinstance(
                profile, _OscoreUdpProfile
            ):
                header = IPv6Header.from_bytes(raw)
                udp = UdpDatagram.from_bytes(
                    raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
                )
                if _coap_oscore_status(udp.payload) is True:
                    raise SchcError(f"OSCORE content requires an OSCORE rule, got {rule_id}")
            return raw
    raise ValueError(f"no profile for rule ID {rule_id}")
