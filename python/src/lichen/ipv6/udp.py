# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""UDP header codec over IPv6 (RFC 768, RFC 8200 pseudo-header checksum).

A minimal UDP datagram: an 8-byte header (source/destination ports, length,
checksum) followed by the payload. The checksum covers the IPv6 pseudo-header
(source, destination, UDP length, Next Header = 17) and the UDP datagram, so
computing/verifying it requires the enclosing IPv6 addresses.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address

UDP_NEXT_HEADER = 17
UDP_HEADER_LENGTH = 8


class UdpError(Exception):
    """Raised when a UDP datagram is malformed."""


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_checksum(
    src: IPv6Address, dst: IPv6Address, header_and_payload: bytes
) -> int:
    """Checksum over the IPv6 pseudo-header and the UDP datagram."""
    pseudo = (
        src.packed
        + dst.packed
        + len(header_and_payload).to_bytes(4, "big")
        + bytes(3)
        + bytes([UDP_NEXT_HEADER])
    )
    return _internet_checksum(pseudo + header_and_payload)


@dataclass
class UdpDatagram:
    """A UDP datagram (header + payload)."""

    src_port: int
    dst_port: int
    payload: bytes
    checksum: int = 0  # 0 means "compute on serialization"

    @property
    def length(self) -> int:
        """Total UDP length (header + payload)."""
        return UDP_HEADER_LENGTH + len(self.payload)

    def to_bytes(self, src: IPv6Address, dst: IPv6Address) -> bytes:
        """Serialize, computing the checksum over the IPv6 pseudo-header."""
        for name, port in (("src_port", self.src_port), ("dst_port", self.dst_port)):
            if not 0 <= port <= 0xFFFF:
                raise UdpError(f"{name} out of range: {port}")
        max_payload = 0xFFFF - UDP_HEADER_LENGTH
        if len(self.payload) > max_payload:
            raise UdpError(f"payload too large: {len(self.payload)} > {max_payload}")
        without_checksum = (
            self.src_port.to_bytes(2, "big")
            + self.dst_port.to_bytes(2, "big")
            + self.length.to_bytes(2, "big")
            + bytes(2)
            + self.payload
        )
        # RFC 768: a computed checksum of zero is transmitted as all ones.
        checksum = udp_checksum(src, dst, without_checksum) or 0xFFFF
        return without_checksum[:6] + checksum.to_bytes(2, "big") + self.payload

    @classmethod
    def from_bytes(cls, data: bytes, src: IPv6Address | None = None) -> UdpDatagram:
        if len(data) < UDP_HEADER_LENGTH:
            raise UdpError(f"UDP datagram too short: {len(data)} bytes")
        src_port = int.from_bytes(data[0:2], "big")
        dst_port = int.from_bytes(data[2:4], "big")
        length = int.from_bytes(data[4:6], "big")
        checksum = int.from_bytes(data[6:8], "big")
        for name, port in (("src_port", src_port), ("dst_port", dst_port)):
            if not 0 <= port <= 0xFFFF:
                raise UdpError(f"{name} out of range: {port}")
        if length < UDP_HEADER_LENGTH:
            raise UdpError(f"UDP length {length} too small (minimum 8 per RFC 768)")
        if length != len(data):
            raise UdpError(f"UDP length {length} != {len(data)} bytes present")
        if checksum == 0:
            raise UdpError("checksum is zero (mandatory for IPv6 per RFC 8200 8.1)")
        if src is not None and (src.is_unspecified or src.is_multicast):
            raise UdpError(f"malformed source: {src}")
        return cls(src_port, dst_port, data[UDP_HEADER_LENGTH:], checksum)

    @staticmethod
    def verify_checksum(src: IPv6Address, dst: IPv6Address, data: bytes) -> bool:
        """Check the checksum of a received UDP datagram.

        SECURITY: For IPv6, UDP checksums are MANDATORY (RFC 8200 section 8.1).
        Callers MUST verify the checksum before processing the payload. Datagrams
        with invalid checksums should be silently discarded.

        Returns True if the checksum is valid, False otherwise.
        """
        if len(data) < UDP_HEADER_LENGTH:
            return False
        return udp_checksum(src, dst, data) == 0
