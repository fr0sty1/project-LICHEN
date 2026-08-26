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
- rule 7: IPv6 + UDP + MQTT-SN specialized canonical residue

The variable trailer (CoAP token/options/payload, or RPL options) travels
verbatim after the byte-aligned residue. Lengths and checksums are recomputed on
decompression. Link-local rules elide the exact ``fe80::/64`` prefix; global
Rules 1 and 6 elide only canonical Yggdrasil ``0200::/8``. Other global
addresses use validated Rule 255.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv6Address

from lichen.constants import PORT_MQTT_SN
from lichen.ipv6.icmpv6 import icmpv6_checksum
from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header, IPv6Packet, NextHeader, PacketError
from lichen.ipv6.udp import UDP_HEADER_LENGTH, UDP_NEXT_HEADER, UdpDatagram, UdpError, udp_checksum
from lichen.schc.codec import (
    BitReader,
    BitWriter,
    SchcError,
    compress,
    decompress,
    residue_byte_length,
)
from lichen.schc.fragment import MAX_PACKET_SIZE
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
_RULE_MQTT_SN = 7
_MQTT_SN_LINK_LOCAL_RESIDUE_BYTES = 20
_MQTT_SN_FULL_RESIDUE_BYTES = 36
_MAX_IPV6_PACKET_SIZE = HEADER_LENGTH + 0xFFFF


def _is_link_local(addr: int) -> bool:
    return addr >> 64 == _LINK_LOCAL_PREFIX64


def _validate_ipv6_addresses(header: IPv6Header) -> None:
    if header.src_addr.is_unspecified or header.src_addr.is_multicast:
        raise SchcError(f"invalid IPv6 source address {header.src_addr}")
    if header.dst_addr.is_unspecified:
        raise SchcError("invalid unspecified IPv6 destination address")


def validate_rule7_addresses(source: IPv6Address, destination: IPv6Address) -> None:
    """Validate the canonical Rule 7 IPv6 source/destination policy.

    Rule 7 carries native IPv6 endpoints only.  A source must be usable
    unicast; a destination may additionally be multicast when its scope is in
    the link-through-global range (2 through 14).
    """
    if (
        source.is_unspecified
        or source.is_loopback
        or source.is_multicast
        or source.ipv4_mapped is not None
    ):
        raise SchcError(f"invalid Rule 7 source address {source}")
    if destination.is_unspecified or destination.is_loopback or destination.ipv4_mapped is not None:
        raise SchcError(f"invalid Rule 7 destination address {destination}")
    if destination.is_multicast:
        scope = destination.packed[1] & 0x0F
        if not 2 <= scope <= 14:
            raise SchcError(f"invalid Rule 7 multicast destination scope {scope}")


def validate_full_ipv6(raw: bytes) -> bytes:
    """Validate a complete IPv6 packet before Rule 255 delivery."""
    if type(raw) is not bytes:
        raise SchcError("IPv6 packet must be bytes")
    if not HEADER_LENGTH <= len(raw) <= _MAX_IPV6_PACKET_SIZE:
        raise SchcError(
            f"IPv6 packet length must be {HEADER_LENGTH}..{_MAX_IPV6_PACKET_SIZE}, got {len(raw)}"
        )
    try:
        packet = IPv6Packet.from_bytes(raw, strict=True)
    except PacketError as error:
        raise SchcError(f"invalid Rule 255 IPv6 packet: {error}") from error
    _validate_ipv6_addresses(packet.header)
    if packet.header.next_header == UDP_NEXT_HEADER:
        try:
            UdpDatagram.from_bytes(packet.payload, packet.header.src_addr)
        except UdpError as error:
            raise SchcError(f"invalid Rule 255 UDP datagram: {error}") from error
        if not UdpDatagram.verify_checksum(
            packet.header.src_addr, packet.header.dst_addr, packet.payload
        ):
            raise SchcError("invalid Rule 255 IPv6 UDP checksum")
    return raw


def _validate_single_frame_limit(limit: int | None) -> None:
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("single_frame_limit must be a positive integer")


def encode_rule255(raw: bytes, *, single_frame_limit: int | None = None) -> bytes:
    """Encode a validated full IPv6 packet with sender-selected Rule 255."""
    _validate_single_frame_limit(single_frame_limit)
    validated = validate_full_ipv6(raw)
    if len(validated) > MAX_PACKET_SIZE - 1:
        raise SchcError(f"Rule 255 raw IPv6 packet exceeds {MAX_PACKET_SIZE - 1} bytes")
    encoded = bytes((RULE_ID_UNCOMPRESSED,)) + validated
    if single_frame_limit is not None and len(encoded) > single_frame_limit:
        raise SchcError(
            f"Rule 255 packet needs {len(encoded)} bytes, exceeds single frame "
            f"limit {single_frame_limit}"
        )
    return encoded


def decode_rule255(data: bytes, *, single_frame_limit: int | None = None) -> bytes:
    """Decode Rule 255 without reinterpreting malformed or unknown residues."""
    _validate_single_frame_limit(single_frame_limit)
    if type(data) is not bytes or not data or data[0] != RULE_ID_UNCOMPRESSED:
        raise SchcError("version-mismatch mode accepts Rule 255 only")
    if len(data) > MAX_PACKET_SIZE:
        raise SchcError(f"SCHC packet exceeds profile limit {MAX_PACKET_SIZE}")
    if single_frame_limit is not None and len(data) > single_frame_limit:
        raise SchcError(
            f"Rule 255 packet is {len(data)} bytes, exceeds single frame limit {single_frame_limit}"
        )
    return validate_full_ipv6(data[1:])


def _is_global(addr: int) -> bool:
    # Primary: canonical key-derived 0200::/8. Also standard GUA 2000::/3
    # (optional BR upstream).
    first_byte = (addr >> 120) & 0xFF
    return first_byte == 0x02 or (addr >> 125 == 0b001)


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

    # Valid end of options without payload marker: per RFC 7252, 0xFF is only
    # present if there IS a payload. Return OSCORE status.
    return oscore_found


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
    if val is None:
        raise SchcError(f"decompress returned None for required field {key}")
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
        if not (self._addr_ok(int(header.src_addr)) and self._addr_ok(int(header.dst_addr))):
            return False
        try:
            udp = UdpDatagram.from_bytes(raw[HEADER_LENGTH:])
        except UdpError:
            return False
        coap = udp.payload
        token_length = coap[0] & 0x0F
        return token_length <= 8 and _COAP_FIXED_HEADER + token_length <= len(coap)

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
    """Global IPv6 + UDP + CoAP (SCHC rule 1).

    Only matches Yggdrasil 0200::/8 addresses, which is the only global prefix
    LICHEN SCHC can compress (MSB(8) match against 0x0200). Other global
    addresses like 2000::/3 GUA fall back to uncompressed.
    """

    rule = GLOBAL_COAP_RULE

    def _addr_ok(self, addr: int) -> bool:
        # Only 0200::/8 Yggdrasil addresses can be compressed by this rule
        return ((addr >> 120) & 0xFF) == 0x02


class _OscoreUdpProfile(_CoapUdpProfile):
    """IPv6 + UDP + OSCORE-protected CoAP; subclasses pick the address scope.

    OSCORE-protected CoAP packets (RFC 8613) have the Object-Security option
    present. These rules use distinct rule IDs to explicitly identify secured
    traffic and enable future OSCORE-specific compression optimizations.
    """

    def matches(self, raw: bytes) -> bool:
        if not super().matches(raw):
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except PacketError:
            return False
        udp_segment = raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
        if udp_checksum(header.src_addr, header.dst_addr, udp_segment) != 0:
            return False
        udp = UdpDatagram.from_bytes(udp_segment)
        coap = udp.payload
        tkl = coap[0] & 0x0F
        if coap[0] >> 6 != 1 or tkl > 8 or _COAP_FIXED_HEADER + tkl > len(coap):
            return False
        return _coap_oscore_status(coap) is True


class OscoreUdpLinkLocalProfile(_OscoreUdpProfile):
    """Link-local IPv6 + UDP + OSCORE-protected CoAP (SCHC rule 5)."""

    rule = LINK_LOCAL_OSCORE_RULE

    def _addr_ok(self, addr: int) -> bool:
        return _is_link_local(addr)


class OscoreUdpGlobalProfile(_OscoreUdpProfile):
    """Global IPv6 + UDP + OSCORE-protected CoAP (SCHC rule 6)."""

    rule = GLOBAL_OSCORE_RULE

    def _addr_ok(self, addr: int) -> bool:
        # Only 02xx::/8 Yggdrasil addresses can be compressed
        return ((addr >> 120) & 0xFF) == 0x02


class MqttSnProfile:
    """Canonical specialized Rule 7 codec (Rule Set Version 3)."""

    rule_id = _RULE_MQTT_SN

    @staticmethod
    def _candidate(raw: bytes) -> bool:
        if len(raw) < HEADER_LENGTH + UDP_HEADER_LENGTH:
            return False
        try:
            header = IPv6Header.from_bytes(raw)
        except PacketError:
            return False
        if header.next_header != UDP_NEXT_HEADER:
            return False
        src_port = int.from_bytes(raw[40:42], "big")
        dst_port = int.from_bytes(raw[42:44], "big")
        return src_port == PORT_MQTT_SN or dst_port == PORT_MQTT_SN

    def compress_if_matching(self, raw: bytes) -> bytes | None:
        """Return Rule 7 bytes, None for a non-match, or raise on malformed input."""
        if not self._candidate(raw):
            return None
        header = IPv6Header.from_bytes(raw)
        try:
            validate_rule7_addresses(header.src_addr, header.dst_addr)
        except SchcError:
            return None
        if len(raw) != HEADER_LENGTH + header.payload_length:
            raise SchcError("Rule 7 IPv6 payload length mismatch")
        udp_bytes = raw[HEADER_LENGTH:]
        try:
            udp = UdpDatagram.from_bytes(udp_bytes, header.src_addr)
        except UdpError as error:
            raise SchcError(f"invalid Rule 7 UDP datagram: {error}") from error
        if not UdpDatagram.verify_checksum(header.src_addr, header.dst_addr, udp_bytes):
            raise SchcError("invalid Rule 7 IPv6 UDP checksum")
        if header.traffic_class != 0 or header.flow_label != 0:
            return None

        both_link_local = _is_link_local(int(header.src_addr)) and _is_link_local(
            int(header.dst_addr)
        )
        writer = BitWriter()
        writer.write(header.hop_limit, 8)
        writer.write(0 if both_link_local else 1, 1)
        if both_link_local:
            writer.write(int(header.src_addr) & ((1 << 64) - 1), 64)
            writer.write(int(header.dst_addr) & ((1 << 64) - 1), 64)
        else:
            writer.write(int(header.src_addr), 128)
            writer.write(int(header.dst_addr), 128)
        if udp.src_port == PORT_MQTT_SN:
            writer.write(0, 1)
            writer.write(udp.dst_port, 16)
        else:
            writer.write(1, 1)
            writer.write(udp.src_port, 16)
        encoded = bytes((self.rule_id,)) + writer.to_bytes() + udp.payload
        if len(encoded) > MAX_PACKET_SIZE:
            raise SchcError(f"Rule 7 packet exceeds profile limit {MAX_PACKET_SIZE}")
        return encoded

    def decompress(self, data: bytes) -> bytes:
        if type(data) is not bytes or not data or data[0] != self.rule_id:
            raise SchcError("invalid Rule 7 packet")
        if len(data) < 1 + _MQTT_SN_LINK_LOCAL_RESIDUE_BYTES:
            raise SchcError("Rule 7 residue is truncated")
        address_mode = (data[2] >> 7) & 1
        residue_bytes = (
            _MQTT_SN_LINK_LOCAL_RESIDUE_BYTES if address_mode == 0 else _MQTT_SN_FULL_RESIDUE_BYTES
        )
        if len(data) < 1 + residue_bytes:
            raise SchcError("Rule 7 residue is truncated")
        residue = data[1 : 1 + residue_bytes]
        if residue[-1] & 0x3F:
            raise SchcError("nonzero Rule 7 residue padding")
        reader = BitReader(residue)
        hop_limit = reader.read(8)
        parsed_mode = reader.read(1)
        if parsed_mode != address_mode:
            raise SchcError("inconsistent Rule 7 address mode")
        if address_mode == 0:
            src = IPv6Address((_LINK_LOCAL_PREFIX64 << 64) | reader.read(64))
            dst = IPv6Address((_LINK_LOCAL_PREFIX64 << 64) | reader.read(64))
        else:
            src = IPv6Address(reader.read(128))
            dst = IPv6Address(reader.read(128))
            if _is_link_local(int(src)) and _is_link_local(int(dst)):
                raise SchcError("noncanonical full-address Rule 7 residue")
        validate_rule7_addresses(src, dst)
        direction = reader.read(1)
        other_port = reader.read(16)
        if direction == 1 and other_port == PORT_MQTT_SN:
            raise SchcError("noncanonical Rule 7 port direction")
        src_port, dst_port = (
            (PORT_MQTT_SN, other_port) if direction == 0 else (other_port, PORT_MQTT_SN)
        )
        payload_offset = 1 + residue_bytes
        if len(data) > MAX_PACKET_SIZE:
            raise SchcError(f"Rule 7 packet exceeds profile limit {MAX_PACKET_SIZE}")
        payload = data[payload_offset:]
        try:
            udp_bytes = UdpDatagram(src_port, dst_port, payload).to_bytes(src, dst)
        except UdpError as error:
            raise SchcError(f"invalid Rule 7 UDP datagram: {error}") from error
        header = IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=UDP_NEXT_HEADER,
            payload_length=len(udp_bytes),
            hop_limit=hop_limit,
        )
        return header.to_bytes() + udp_bytes


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
        if not (_is_link_local(int(header.src_addr)) and _is_link_local(int(header.dst_addr))):
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
    """RPL DAO with DODAGID over link-local IPv6 (SCHC rule 4)."""

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

    def build(self, fields: dict[str, int | None], tail: bytes) -> bytes:
        if not _require_field(fields, "RPL.kd_flags") & 0x40:
            raise SchcError("Rule 4 DAO residue has the D flag clear")
        return super().build(fields, tail)

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
MQTT_SN_PROFILE = MqttSnProfile()


def compress_packet(raw: bytes, profiles: tuple[PacketProfile, ...] = DEFAULT_PROFILES) -> bytes:
    """Compress a full packet, or use validated Rule 255.

    ``profiles`` customizes generic Rules 0-6. Canonical specialized Rule 7 is
    reserved and always evaluated first, so a custom profile cannot replace its
    wire contract with generic descriptors.
    """
    # Validate transport structure and checksums once before any profile elides
    # fields. Valid field non-matches continue to Rule 255; malformed packets do
    # not get repaired by compression.
    validate_full_ipv6(raw)
    mqtt_sn = MQTT_SN_PROFILE.compress_if_matching(raw)
    if mqtt_sn is not None:
        return mqtt_sn
    for profile in profiles:
        if profile.matches(raw):
            fields, tail = profile.parse(raw)
            from lichen.schc.context import rule_matches

            if rule_matches(profile.rule, fields):
                encoded = compress(profile.rule, fields) + tail
                if len(encoded) > MAX_PACKET_SIZE:
                    raise SchcError(f"SCHC packet exceeds profile limit {MAX_PACKET_SIZE}")
                return encoded
    return encode_rule255(raw)


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
    if type(data) is not bytes:
        raise TypeError("SCHC packet must be bytes")
    if len(data) > MAX_PACKET_SIZE:
        raise SchcError(f"SCHC packet exceeds profile limit {MAX_PACKET_SIZE}")
    if not data:
        raise ValueError("empty SCHC packet")
    rule_id = data[0]
    if rule_id == RULE_ID_UNCOMPRESSED:
        return decode_rule255(data)
    if rule_id == MQTT_SN_PROFILE.rule_id:
        return MQTT_SN_PROFILE.decompress(data)
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
            if isinstance(profile, _CoapUdpProfile) and not isinstance(profile, _OscoreUdpProfile):
                header = IPv6Header.from_bytes(raw)
                udp = UdpDatagram.from_bytes(
                    raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
                )
                if _coap_oscore_status(udp.payload) is True:
                    raise SchcError(f"OSCORE content requires an OSCORE rule, got {rule_id}")
            return raw
    raise ValueError(f"no profile for rule ID {rule_id}")
