# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""IPv6 packet construction and parsing (RFC 8200, spec section 6).

Provides the fixed 40-byte :class:`IPv6Header`, a generic
:class:`ExtensionHeader` for the common TLV-style headers (Hop-by-Hop Options,
Routing, Destination Options) that RPL relies on, and :class:`IPv6Packet`
which links a header, an optional extension-header chain, and a payload.

Fragment headers (Next Header 44) are intentionally unsupported: LICHEN
fragments at the SCHC layer (spec section 3), so an IPv6 Fragment header should
never appear on-air. Encountering one while parsing raises :class:`PacketError`.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import IntEnum
from ipaddress import IPv6Address

HEADER_LENGTH = 40


class NextHeader(IntEnum):
    """Common IPv6 Next Header / protocol values."""

    HOP_BY_HOP = 0
    ROUTING = 43
    FRAGMENT = 44
    UDP = 17
    ICMPV6 = 58
    NO_NEXT_HEADER = 59
    DEST_OPTIONS = 60


# Extension headers that share the common "next_header / hdr_ext_len / data"
# layout where the total length is (hdr_ext_len + 1) * 8 octets (RFC 8200 4).
_TLV_EXT_HEADERS = frozenset(
    {NextHeader.HOP_BY_HOP, NextHeader.ROUTING, NextHeader.DEST_OPTIONS}
)


class PacketError(Exception):
    """Raised when an IPv6 packet or header is malformed."""


def _as_addr(value: IPv6Address | str | bytes) -> IPv6Address:
    if isinstance(value, IPv6Address):
        return value
    return IPv6Address(value)


@dataclass
class IPv6Header:
    """A fixed 40-byte IPv6 header (RFC 8200 section 3).

    Attributes:
        src_addr: Source address.
        dst_addr: Destination address.
        next_header: Protocol of the byte immediately following this header.
            When carried in an :class:`IPv6Packet` with extension headers, this
            is the *upper-layer* protocol; the on-wire base-header Next Header
            (pointing at the first extension header) is computed during
            serialization.
        payload_length: Length of everything after the 40-byte header. Usually
            left at 0 and recomputed by :class:`IPv6Packet`.
        hop_limit: Hop limit (decremented at each relay).
        traffic_class: 8-bit traffic class.
        flow_label: 20-bit flow label.
    """

    src_addr: IPv6Address
    dst_addr: IPv6Address
    next_header: int
    payload_length: int = 0
    hop_limit: int = 64
    traffic_class: int = 0
    flow_label: int = 0
    version: int = 6

    def __post_init__(self) -> None:
        self.src_addr = _as_addr(self.src_addr)
        self.dst_addr = _as_addr(self.dst_addr)

    def _validate(self) -> None:
        if self.version != 6:
            raise PacketError(f"version must be 6, got {self.version}")
        if not 0 <= self.traffic_class <= 0xFF:
            raise PacketError(f"traffic_class out of range: {self.traffic_class}")
        if not 0 <= self.flow_label <= 0xFFFFF:
            raise PacketError(f"flow_label out of range: {self.flow_label}")
        if not 0 <= self.payload_length <= 0xFFFF:
            raise PacketError(f"payload_length out of range: {self.payload_length}")
        if not 0 <= self.next_header <= 0xFF:
            raise PacketError(f"next_header out of range: {self.next_header}")
        if not 0 <= self.hop_limit <= 0xFF:
            raise PacketError(f"hop_limit out of range: {self.hop_limit}")

    def to_bytes(self) -> bytes:
        """Serialize to the 40-byte on-wire header."""
        self._validate()
        first_word = (
            (self.version << 28) | (self.traffic_class << 20) | self.flow_label
        )
        return (
            first_word.to_bytes(4, "big")
            + self.payload_length.to_bytes(2, "big")
            + bytes([self.next_header, self.hop_limit])
            + self.src_addr.packed
            + self.dst_addr.packed
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> IPv6Header:
        """Parse a 40-byte header from the start of ``data``."""
        if len(data) < HEADER_LENGTH:
            raise PacketError(
                f"need {HEADER_LENGTH} bytes for header, got {len(data)}"
            )
        first_word = int.from_bytes(data[0:4], "big")
        version = first_word >> 28
        if version != 6:
            raise PacketError(f"version must be 6, got {version}")
        traffic_class = (first_word >> 20) & 0xFF
        flow_label = first_word & 0xFFFFF
        payload_length = int.from_bytes(data[4:6], "big")
        next_header = data[6]
        hop_limit = data[7]
        src_addr = IPv6Address(data[8:24])
        dst_addr = IPv6Address(data[24:40])
        return cls(
            src_addr=src_addr,
            dst_addr=dst_addr,
            next_header=next_header,
            payload_length=payload_length,
            hop_limit=hop_limit,
            traffic_class=traffic_class,
            flow_label=flow_label,
            version=version,
        )


@dataclass
class ExtensionHeader:
    """A TLV-style IPv6 extension header (Hop-by-Hop, Routing, Dest Options).

    Attributes:
        header_type: This header's own type (e.g. ``NextHeader.HOP_BY_HOP``).
        data: The header content following the 2-byte ``next_header`` /
            ``hdr_ext_len`` prefix. Its length plus 2 must be a multiple of 8,
            as required by RFC 8200; pad with PadN options to satisfy this.
    """

    header_type: int
    data: bytes

    def __post_init__(self) -> None:
        if self.header_type not in _TLV_EXT_HEADERS:
            raise PacketError(f"unsupported extension header type {self.header_type}")
        if (len(self.data) + 2) % 8 != 0:
            raise PacketError(
                "extension header length (data + 2) must be a multiple of 8, "
                f"got {len(self.data) + 2}"
            )
        if len(self.data) > 2046:
            raise PacketError(f"extension header data too large: {len(self.data)} > 2046")

    def to_bytes(self, next_header: int) -> bytes:
        """Serialize, with ``next_header`` pointing at the following header."""
        if not 0 <= next_header <= 0xFF:
            raise PacketError(f"next_header out of range: {next_header}")
        hdr_ext_len = (len(self.data) + 2) // 8 - 1
        return bytes([next_header, hdr_ext_len]) + self.data


@dataclass
class IPv6Packet:
    """An IPv6 packet: base header, extension-header chain, and payload.

    ``header.next_header`` carries the *upper-layer* protocol of ``payload``.
    Serialization links the extension-header chain and sets the base header's
    on-wire Next Header and payload length automatically; the input header's
    ``next_header`` / ``payload_length`` are not mutated.
    """

    header: IPv6Header
    payload: bytes = b""
    extension_headers: list[ExtensionHeader] = field(default_factory=list)

    def to_bytes(self) -> bytes:
        """Serialize the full packet to bytes."""
        upper = int(self.header.next_header)
        chunks: list[bytes] = []
        for i, ext in enumerate(self.extension_headers):
            nxt = (
                self.extension_headers[i + 1].header_type
                if i + 1 < len(self.extension_headers)
                else upper
            )
            chunks.append(ext.to_bytes(nxt))
        ext_bytes = b"".join(chunks)
        total_payload = len(ext_bytes) + len(self.payload)
        if total_payload > 0xFFFF:
            raise PacketError(
                f"combined payload too large: {len(ext_bytes)} extension + "
                f"{len(self.payload)} payload = {total_payload} > 65535"
            )
        wire_next_header = (
            self.extension_headers[0].header_type
            if self.extension_headers
            else upper
        )
        header = replace(
            self.header,
            next_header=wire_next_header,
            payload_length=total_payload,
        )
        return header.to_bytes() + ext_bytes + self.payload

    @classmethod
    def from_bytes(cls, data: bytes, strict: bool = False) -> IPv6Packet:
        """Parse a full packet, walking any extension-header chain.

        Args:
            data: Raw bytes to parse.
            strict: If True, raise :class:`PacketError` when *data* contains
                trailing bytes beyond the parsed packet. Defaults to False for
                compatibility with padded buffers and similar use cases.
        """
        header = IPv6Header.from_bytes(data)
        end = HEADER_LENGTH + header.payload_length
        body = data[HEADER_LENGTH:end]
        if len(body) != header.payload_length:
            raise PacketError(
                f"payload_length says {header.payload_length} but "
                f"{len(body)} bytes present"
            )
        if strict and len(data) > end:
            raise PacketError(
                f"{len(data) - end} trailing byte(s) after packet"
            )

        ext_headers: list[ExtensionHeader] = []
        next_header = header.next_header
        offset = 0
        while next_header in _TLV_EXT_HEADERS:
            if offset + 2 > len(body):
                raise PacketError("truncated extension header")
            following = body[offset]
            hdr_ext_len = body[offset + 1]
            total = (hdr_ext_len + 1) * 8
            if offset + total > len(body):
                raise PacketError("extension header runs past end of payload")
            ext_data = body[offset + 2 : offset + total]
            ext_headers.append(ExtensionHeader(header_type=next_header, data=ext_data))
            offset += total
            next_header = following

        if next_header == NextHeader.FRAGMENT:
            raise PacketError("IPv6 Fragment headers are not supported (use SCHC)")

        # next_header is now the upper-layer protocol; surface it on the header.
        parsed_header = replace(header, next_header=next_header)
        return cls(
            header=parsed_header,
            payload=body[offset:],
            extension_headers=ext_headers,
        )
