# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""UDP destination-port dispatch for LICHEN application protocols.

LICHEN assigns application protocols to destination ports instead of adding
an application discriminator byte.  Ports 5680 through 5695 share a 12-bit
prefix that the baseline SCHC rules compress; MQTT-SN uses its registered
port 10883 and a dedicated SCHC rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from lichen.constants import (
    PORT_APRS_IS,
    PORT_CAYENNE_LPP,
    PORT_COAP,
    PORT_COAP_DTLS,
    PORT_COMPACT_COT,
    PORT_MQTT_SN,
    PORT_NMEA,
    PORT_SENML,
)
from lichen.ipv6.packet import IPv6Packet, NextHeader, PacketError
from lichen.ipv6.udp import UdpDatagram, UdpError


class AppProtocol(StrEnum):
    """Application protocol identified by a UDP destination port."""

    COMPACT_COT = "compact_cot"
    SENML = "senml"
    COAP = "coap"
    CAYENNE_LPP = "cayenne_lpp"
    APRS_IS = "aprs_is"
    NMEA = "nmea"
    MQTT_SN = "mqtt_sn"

    @property
    def port(self) -> int:
        """Return this protocol's assigned mesh UDP port."""
        return _PROTOCOL_PORTS[self]


_PORT_PROTOCOLS: dict[int, AppProtocol] = {
    PORT_COMPACT_COT: AppProtocol.COMPACT_COT,
    PORT_SENML: AppProtocol.SENML,
    PORT_COAP: AppProtocol.COAP,
    PORT_CAYENNE_LPP: AppProtocol.CAYENNE_LPP,
    PORT_APRS_IS: AppProtocol.APRS_IS,
    PORT_NMEA: AppProtocol.NMEA,
    PORT_MQTT_SN: AppProtocol.MQTT_SN,
}
_PROTOCOL_PORTS: dict[AppProtocol, int] = {
    protocol: port for port, protocol in _PORT_PROTOCOLS.items()
}


class DispatchError(ValueError):
    """Base class for application port dispatch failures."""


class UnknownPortError(DispatchError):
    """The destination port has no LICHEN application assignment."""

    def __init__(self, port: int) -> None:
        self.port = port
        super().__init__(f"unknown application port {port}")


class ReservedPortError(DispatchError):
    """The destination port is assigned but intentionally unavailable."""

    def __init__(self, port: int = PORT_COAP_DTLS) -> None:
        self.port = port
        super().__init__(f"port {port} is reserved (use OSCORE, not DTLS)")


class NotUdpError(DispatchError):
    """The supplied bytes are not one complete, valid IPv6/UDP datagram."""


@dataclass(frozen=True, slots=True)
class Dispatched:
    """A UDP payload paired with its destination-port protocol."""

    protocol: AppProtocol
    payload: bytes


def _require_port(port: object) -> int:
    if type(port) is not int:
        raise TypeError("port must be an integer")
    if not 0 <= port <= 0xFFFF:
        raise ValueError(f"port out of range: {port}")
    return port


def dispatch_by_port(port: int, payload: bytes) -> Dispatched:
    """Classify an application payload using its UDP destination port.

    Payload validation belongs to the selected application codec. Empty
    payloads are therefore accepted here and can be rejected by that codec.
    """
    port = _require_port(port)
    if type(payload) is not bytes:
        raise TypeError("payload must be bytes")
    if port == PORT_COAP_DTLS:
        raise ReservedPortError(port)
    try:
        protocol = _PORT_PROTOCOLS[port]
    except KeyError:
        raise UnknownPortError(port) from None
    return Dispatched(protocol=protocol, payload=payload)


def is_schc_compressible_port(port: object) -> bool:
    """Return whether *port* matches the SCHC 5680/12 port prefix."""
    return type(port) is int and 5680 <= port <= 5695


def _parse_udp(ipv6: bytes) -> tuple[IPv6Packet, UdpDatagram]:
    if type(ipv6) is not bytes:
        raise TypeError("ipv6 must be bytes")
    try:
        packet = IPv6Packet.from_bytes(ipv6, strict=True)
        if packet.header.next_header != NextHeader.UDP:
            raise NotUdpError("IPv6 packet does not carry UDP")
        datagram = UdpDatagram.from_bytes(packet.payload, packet.header.src_addr)
    except (PacketError, UdpError) as exc:
        raise NotUdpError(f"invalid IPv6/UDP datagram: {exc}") from exc
    if not UdpDatagram.verify_checksum(
        packet.header.src_addr,
        packet.header.dst_addr,
        packet.payload,
    ):
        raise NotUdpError("invalid UDP checksum")
    return packet, datagram


def dispatch_udp(ipv6: bytes) -> Dispatched:
    """Parse and dispatch one complete IPv6/UDP packet."""
    _, datagram = _parse_udp(ipv6)
    return dispatch_by_port(datagram.dst_port, datagram.payload)


def udp_ports(ipv6: bytes) -> tuple[int, int] | None:
    """Return source and destination ports, or ``None`` for invalid/non-UDP input."""
    try:
        _, datagram = _parse_udp(ipv6)
    except NotUdpError:
        return None
    return datagram.src_port, datagram.dst_port


def udp_dst_port(ipv6: bytes) -> int | None:
    """Return the UDP destination port, or ``None`` for invalid/non-UDP input."""
    ports = udp_ports(ipv6)
    return None if ports is None else ports[1]
