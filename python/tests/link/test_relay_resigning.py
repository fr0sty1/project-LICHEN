# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""End-to-end link authentication coverage for an IPv6 relay."""

from ipaddress import IPv6Address

import pytest

from lichen.crypto.identity import Identity, PeerIdentity, yggdrasil_address
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.l2_payload import wrap_schc_payload
from lichen.link.frame import AddrMode, LichenFrame
from lichen.link.link_layer import ReceiveError, RxFrame
from lichen.node import Node
from lichen.routing.router import RouteDecision

from .conftest import MockRadio


def _tamper_payload_without_resigning(wire: bytes) -> bytes:
    frame = LichenFrame.from_bytes(wire)
    tampered = bytes((frame.payload[0] ^ 0x01,)) + frame.payload[1:]
    return LichenFrame(
        epoch=frame.epoch,
        seqnum=frame.seqnum,
        dst_addr=frame.dst_addr,
        signer_eui64=frame.signer_eui64,
        payload=tampered,
        mic=frame.mic,
        addr_mode=frame.addr_mode,
        mic_length=frame.mic_length,
        signature_present=frame.signature_present,
        encrypted=frame.encrypted,
    ).to_bytes()


@pytest.mark.asyncio
async def test_relay_verifies_then_mutates_and_resigns_for_next_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin_identity = Identity.from_seed(b"\x11" * 32)
    relay_identity = Identity.from_seed(b"\x22" * 32)
    next_identity = Identity.from_seed(b"\x33" * 32)
    origin_radio = MockRadio()
    relay_radio = MockRadio()
    next_radio = MockRadio()
    origin = Node(origin_identity, origin_radio)
    relay = Node(relay_identity, relay_radio)
    next_node = Node(next_identity, next_radio)

    origin.add_peer(PeerIdentity.from_pubkey(relay_identity.pubkey))
    relay.add_peer(PeerIdentity.from_pubkey(origin_identity.pubkey))
    relay.add_peer(PeerIdentity.from_pubkey(next_identity.pubkey))
    next_node.add_peer(PeerIdentity.from_pubkey(relay_identity.pubkey))

    next_hop = IPv6Address(IPv6Address("fe80::").packed[:8] + next_identity.iid)
    original_ipv6 = IPv6Packet(
        IPv6Header(
            src_addr=yggdrasil_address(origin_identity.pubkey),
            dst_addr=yggdrasil_address(next_identity.pubkey),
            next_header=NextHeader.NO_NEXT_HEADER,
            hop_limit=2,
        )
    ).to_bytes()
    forwarded_ipv6: list[bytes] = []

    monkeypatch.setattr(
        relay.router,
        "route",
        lambda _packet, _now_ms: (RouteDecision.FORWARD, next_hop),
    )
    monkeypatch.setattr(
        relay.link,
        "accept_authenticated_schc_packet",
        lambda _received: original_ipv6,
    )

    def compress_for_next_hop(
        ipv6: bytes,
        remote: bytes,
        *,
        allow_fragmentation: bool,
    ) -> bytes:
        assert remote == next_identity.pubkey
        assert allow_fragmentation is True
        forwarded_ipv6.append(ipv6)
        return b"\xff" + ipv6

    monkeypatch.setattr(relay.link, "compress_schc_for_peer", compress_for_next_hop)

    ingress_payload = wrap_schc_payload(b"\xff" + original_ipv6)
    assert await origin.link.send(
        ingress_payload,
        iid_to_eui64(relay_identity.iid),
        AddrMode.EXTENDED,
    )
    ingress_wire = origin_radio.tx_history[-1]
    relay_radio.queue_rx(ingress_wire)

    received = await relay.link.receive(100)
    assert isinstance(received, RxFrame)
    await relay._process_received(received)

    assert len(forwarded_ipv6) == 1
    forwarded = IPv6Packet.from_bytes(forwarded_ipv6[0], strict=True)
    assert forwarded.header.hop_limit == 1
    assert forwarded.header.src_addr == yggdrasil_address(origin_identity.pubkey)
    assert forwarded.header.dst_addr == yggdrasil_address(next_identity.pubkey)

    ingress_frame = LichenFrame.from_bytes(ingress_wire)
    egress_wire = relay_radio.tx_history[-1]
    egress_frame = LichenFrame.from_bytes(egress_wire)
    assert egress_frame.signer_eui64 == iid_to_eui64(relay_identity.iid)
    assert egress_frame.dst_addr == iid_to_eui64(next_identity.iid)
    assert egress_frame.mic != ingress_frame.mic
    assert egress_frame.payload == wrap_schc_payload(b"\xff" + forwarded_ipv6[0])

    next_radio.queue_rx(egress_wire)
    next_received = await next_node.link.receive(100)
    assert isinstance(next_received, RxFrame)
    assert next_received.sender_pubkey == relay_identity.pubkey
    assert next_received.payload == egress_frame.payload

    # A structurally valid mutation with the origin's old signature must not
    # reach routing, packet mutation, compression, or relay transmission.
    assert await origin.link.send(
        ingress_payload,
        iid_to_eui64(relay_identity.iid),
        AddrMode.EXTENDED,
    )
    relay_radio.queue_rx(_tamper_payload_without_resigning(origin_radio.tx_history[-1]))
    rejected = await relay.link.receive(100)
    assert rejected is ReceiveError.BAD_SIGNATURE
    assert len(forwarded_ipv6) == 1
    assert relay_radio.tx_history == [egress_wire]
