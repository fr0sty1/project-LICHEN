# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from ipaddress import IPv6Address

import pytest

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
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.ipv6.udp import UdpDatagram
from lichen.node import Node
from lichen.port_dispatch import (
    AppProtocol,
    NotUdpError,
    ReservedPortError,
    UnknownPortError,
    dispatch_by_port,
    dispatch_udp,
    is_schc_compressible_port,
    udp_dst_port,
    udp_ports,
)

_ASSIGNMENTS = (
    (PORT_COMPACT_COT, AppProtocol.COMPACT_COT),
    (PORT_SENML, AppProtocol.SENML),
    (PORT_COAP, AppProtocol.COAP),
    (PORT_CAYENNE_LPP, AppProtocol.CAYENNE_LPP),
    (PORT_APRS_IS, AppProtocol.APRS_IS),
    (PORT_NMEA, AppProtocol.NMEA),
    (PORT_MQTT_SN, AppProtocol.MQTT_SN),
)


def _udp_packet(dst_port: int, payload: bytes = b"application payload") -> bytes:
    src = IPv6Address("fe80::1")
    dst = IPv6Address("fe80::2")
    udp = UdpDatagram(src_port=49152, dst_port=dst_port, payload=payload).to_bytes(src, dst)
    return IPv6Packet(
        IPv6Header(src_addr=src, dst_addr=dst, next_header=NextHeader.UDP),
        udp,
    ).to_bytes()


@pytest.mark.parametrize(("port", "protocol"), _ASSIGNMENTS)
def test_dispatches_every_assigned_application_port(
    port: int,
    protocol: AppProtocol,
) -> None:
    payload = b"\x00payload"
    dispatched = dispatch_by_port(port, payload)

    assert dispatched.protocol is protocol
    assert dispatched.payload is payload
    assert protocol.port == port


def test_reserved_and_unknown_ports_are_distinct() -> None:
    with pytest.raises(ReservedPortError) as reserved:
        dispatch_by_port(PORT_COAP_DTLS, b"")
    assert reserved.value.port == PORT_COAP_DTLS

    with pytest.raises(UnknownPortError) as unknown:
        dispatch_by_port(8080, b"")
    assert unknown.value.port == 8080


@pytest.mark.parametrize("port", (5680, 5681, 5687, 5695))
def test_schc_port_prefix_boundaries(port: int) -> None:
    assert is_schc_compressible_port(port)


@pytest.mark.parametrize("port", (5679, 5696, PORT_MQTT_SN, True, "5683", None))
def test_non_schc_port_values(port: object) -> None:
    assert not is_schc_compressible_port(port)


def test_dispatch_udp_and_node_helpers() -> None:
    payload = b"mqtt-sn"
    wire = _udp_packet(PORT_MQTT_SN, payload)

    assert dispatch_udp(wire).protocol is AppProtocol.MQTT_SN
    assert dispatch_udp(wire).payload == payload
    assert udp_ports(wire) == (49152, PORT_MQTT_SN)
    assert udp_dst_port(wire) == PORT_MQTT_SN
    assert Node.dispatch_udp(wire).protocol is AppProtocol.MQTT_SN
    assert Node.udp_ports(wire) == (49152, PORT_MQTT_SN)
    assert Node.udp_dst_port(wire) == PORT_MQTT_SN


def test_dispatch_udp_rejects_non_udp_and_bad_checksum() -> None:
    src = IPv6Address("fe80::1")
    dst = IPv6Address("fe80::2")
    icmp = IPv6Packet(
        IPv6Header(src_addr=src, dst_addr=dst, next_header=NextHeader.ICMPV6),
        b"payload",
    ).to_bytes()
    with pytest.raises(NotUdpError, match="does not carry UDP"):
        dispatch_udp(icmp)
    assert udp_ports(icmp) is None

    corrupt = bytearray(_udp_packet(PORT_COAP))
    corrupt[-1] ^= 0x01
    with pytest.raises(NotUdpError, match="checksum"):
        dispatch_udp(bytes(corrupt))
    assert udp_dst_port(bytes(corrupt)) is None


@pytest.mark.parametrize("port", (-1, 65536))
def test_dispatch_rejects_out_of_range_ports(port: int) -> None:
    with pytest.raises(ValueError, match="out of range"):
        dispatch_by_port(port, b"")


@pytest.mark.parametrize("port", (True, 5683.0, "5683"))
def test_dispatch_rejects_non_integer_ports(port: object) -> None:
    with pytest.raises(TypeError, match="port must be an integer"):
        dispatch_by_port(port, b"")  # type: ignore[arg-type]


def test_dispatch_rejects_mutable_payload() -> None:
    with pytest.raises(TypeError, match="payload must be bytes"):
        dispatch_by_port(PORT_COAP, bytearray(b"x"))  # type: ignore[arg-type]
