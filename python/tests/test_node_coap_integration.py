"""Integration test: CoAP request/response through SCHC-compressed Node routing (eo8).

Tests that the full stack — SCHC compression, gradient routing, Schnorr-signed link
layer, relay forwarding — delivers CoAP datagrams between non-adjacent nodes.

Topology: A -- B -- C (linear chain)
  A and C cannot hear each other; B relays between them.

Radio wiring (directed links):
  A.transmit → B.rx
  B.transmit → A.rx and C.rx   (B broadcasts; dedup prevents loops)
  C.transmit → B.rx
"""

from __future__ import annotations

import asyncio
from ipaddress import IPv6Address

import aiocoap
import pytest
from aiocoap import GET, Message, resource

from lichen.coap.node_channel import NodeChannel
from lichen.coap.transport import create_lichen_context
from lichen.crypto.identity import Identity, PeerIdentity
from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.node import Node, NodeConfig

# ---------------------------------------------------------------------------
# Radio test infrastructure
# ---------------------------------------------------------------------------


class DirectedRadio:
    """Mock radio with directed delivery: transmit goes to registered peers."""

    def __init__(self) -> None:
        self._rx: asyncio.Queue[tuple[bytes, int, int]] = asyncio.Queue()
        self._peers: list[DirectedRadio] = []

    def connect(self, other: DirectedRadio) -> None:
        self._peers.append(other)

    async def transmit(self, payload: bytes) -> bool:
        for peer in self._peers:
            await peer._rx.put((payload, -60, 7))
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        try:
            return await asyncio.wait_for(self._rx.get(), timeout=timeout_ms / 1000)
        except TimeoutError:
            return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        pass


# ---------------------------------------------------------------------------
# CoAP server resource
# ---------------------------------------------------------------------------


class _Status(resource.Resource):
    async def render_get(self, request: Message) -> Message:
        return Message(payload=b"ok", code=aiocoap.CONTENT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ULA_PREFIX = bytes([0xFD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


def _ula(iid: bytes) -> IPv6Address:
    return IPv6Address(_ULA_PREFIX + iid)


def _ll(iid: bytes) -> IPv6Address:
    return IPv6Address(bytes([0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) + iid)


def _make_node(identity: Identity, radio: DirectedRadio) -> Node:
    return Node(
        identity=identity,
        radio=radio,
        config=NodeConfig(
            receive_timeout_ms=50,
            announce_interval_ms=300_000,
            announce_jitter_ms=0,
        ),
    )


def _seed_gradient(
    table: GradientTable,
    dst_iid: bytes,
    via_iid: bytes,
    hop_count: int,
    now_ms: int,
) -> None:
    table.update(
        GradientEntry(
            destination=_ula(dst_iid),
            next_hop=_ll(via_iid),
            hop_count=hop_count,
            seq_num=1,
            source=GradientSource.ANNOUNCE,
            expires=now_ms + 600_000,
        )
    )


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_coap_get_via_relay() -> None:
    """CoAP GET from A to C is relayed through B and a response returns to A."""
    id_a = Identity.from_seed(bytes(32))
    id_b = Identity.from_seed(bytes([1] + [0] * 31))
    id_c = Identity.from_seed(bytes([2] + [0] * 31))

    # Directed radio topology: A--B--C
    radio_a, radio_b, radio_c = DirectedRadio(), DirectedRadio(), DirectedRadio()
    radio_a.connect(radio_b)       # A → B
    radio_b.connect(radio_a)       # B → A (response path)
    radio_b.connect(radio_c)       # B → C (forward path)
    radio_c.connect(radio_b)       # C → B (response path)

    node_a = _make_node(id_a, radio_a)
    node_b = _make_node(id_b, radio_b)
    node_c = _make_node(id_c, radio_c)

    # Peer databases (link-layer signature verification)
    peer_a = PeerIdentity.from_pubkey(id_a.pubkey)
    peer_b = PeerIdentity.from_pubkey(id_b.pubkey)
    peer_c = PeerIdentity.from_pubkey(id_c.pubkey)
    node_a.add_peer(peer_b)
    node_b.add_peer(peer_a)
    node_b.add_peer(peer_c)
    node_c.add_peer(peer_b)

    # Gradient tables (pre-seeded; in production, populated by Announce)
    now_ms = int(asyncio.get_event_loop().time() * 1000)
    # Forward direction: A→B→C
    _seed_gradient(node_a.gradient_table, id_c.iid, id_b.iid, 2, now_ms)
    _seed_gradient(node_b.gradient_table, id_c.iid, id_c.iid, 1, now_ms)
    # Return direction: C→B→A
    _seed_gradient(node_c.gradient_table, id_a.iid, id_b.iid, 2, now_ms)
    _seed_gradient(node_b.gradient_table, id_a.iid, id_a.iid, 1, now_ms)

    ula_a = str(_ula(id_a.iid))
    ula_c = str(_ula(id_c.iid))

    # CoAP server on C
    site_c = resource.Site()
    site_c.add_resource(["status"], _Status())
    channel_c = NodeChannel(node_c, ula_c)
    ctx_c = await create_lichen_context(channel_c, ula_c, site=site_c)

    # CoAP client on A
    channel_a = NodeChannel(node_a, ula_a)
    ctx_a = await create_lichen_context(channel_a, ula_a)

    await node_a.start()
    await node_b.start()
    await node_c.start()

    try:
        response = await asyncio.wait_for(
            ctx_a.request(Message(code=GET, uri=f"coap://[{ula_c}]/status")).response,
            timeout=5.0,
        )
        assert response.code == aiocoap.CONTENT
        assert response.payload == b"ok"
    finally:
        await node_c.stop()
        await node_b.stop()
        await node_a.stop()
        await ctx_a.shutdown()
        await ctx_c.shutdown()
