"""Whole-packet SCHC compression: packet bytes <-> field dicts (RFC 8724).

Bridges parsed protocol headers and the field-dict the SCHC codec consumes. A
:class:`PacketProfile` knows how to flatten a raw packet of a particular shape
into ``{field_id: value}`` (plus a variable tail the rule does not model) and to
rebuild the bytes from decompressed fields. :func:`compress_packet` /
:func:`decompress_packet` drive a profile end to end, falling back to the
uncompressed rule (255) when nothing matches.

This increment implements rule 0 (link-local IPv6 + UDP + CoAP). The CoAP
token/options/payload travel verbatim as the tail after the byte-aligned
residue. Rules 1/3/4 (global CoAP, RPL DIO/DAO) are additional profiles on this
same framework.

Address note: the link-local /64 prefix is elided but the 64-bit IID is carried
in the residue. Full IID elision (deriving it from the L2 address) needs the
link layer and is deferred; this is correct but larger than spec A.1's sizes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from ipaddress import IPv6Address

from lichen.ipv6.packet import HEADER_LENGTH, IPv6Header
from lichen.ipv6.udp import UDP_HEADER_LENGTH, UDP_NEXT_HEADER, UdpDatagram
from lichen.schc.codec import compress, decompress, residue_byte_length
from lichen.schc.rules import LINK_LOCAL_COAP_RULE, RULE_ID_UNCOMPRESSED, Rule

_LINK_LOCAL_PREFIX64 = 0xFE80_0000_0000_0000  # top 64 bits of fe80::/64
_COAP_FIXED_HEADER = 4


class PacketProfile(ABC):
    """Maps a class of packets to/from a SCHC rule's field dict."""

    rule: Rule

    @abstractmethod
    def matches(self, raw: bytes) -> bool:
        """Whether this profile can compress ``raw``."""

    @abstractmethod
    def parse(self, raw: bytes) -> tuple[dict[str, int], bytes]:
        """Return ``(fields, tail)`` extracted from ``raw``."""

    @abstractmethod
    def build(self, fields: dict[str, int | None], tail: bytes) -> bytes:
        """Rebuild the packet bytes from decompressed ``fields`` and ``tail``."""


class CoapUdpLinkLocalProfile(PacketProfile):
    """Link-local IPv6 + UDP + CoAP (SCHC rule 0)."""

    rule = LINK_LOCAL_COAP_RULE

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
        return (
            int(header.src_addr) >> 64 == _LINK_LOCAL_PREFIX64
            and int(header.dst_addr) >> 64 == _LINK_LOCAL_PREFIX64
        )

    def parse(self, raw: bytes) -> tuple[dict[str, int], bytes]:
        header = IPv6Header.from_bytes(raw)
        udp = UdpDatagram.from_bytes(
            raw[HEADER_LENGTH : HEADER_LENGTH + header.payload_length]
        )
        coap = udp.payload
        fixed, tail = coap[:_COAP_FIXED_HEADER], coap[_COAP_FIXED_HEADER:]
        b0 = fixed[0]
        fields = {
            "IPv6.version": 6,
            "IPv6.traffic_class": header.traffic_class,
            "IPv6.flow_label": header.flow_label,
            "IPv6.payload_length": header.payload_length,
            "IPv6.next_header": header.next_header,
            "IPv6.hop_limit": header.hop_limit,
            "IPv6.src": int(header.src_addr),
            "IPv6.dst": int(header.dst_addr),
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
        header = IPv6Header(
            src_addr=src,
            dst_addr=dst,
            next_header=UDP_NEXT_HEADER,
            payload_length=len(udp_bytes),
            hop_limit=fields["IPv6.hop_limit"],
            traffic_class=fields["IPv6.traffic_class"],
            flow_label=fields["IPv6.flow_label"],
        )
        return header.to_bytes() + udp_bytes


DEFAULT_PROFILES: tuple[PacketProfile, ...] = (CoapUdpLinkLocalProfile(),)


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
