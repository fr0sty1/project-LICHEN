"""Integration test: CoAP request/response through SCHC-compressed Node routing (eo8).
Also tests /deaddrop and /confessions resource payload formats.

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
from aiocoap import GET, POST, Message, resource

from lichen.coap.node_channel import NodeChannel
from lichen.coap.transport import create_lichen_context
from lichen.crypto.identity import Identity, PeerIdentity, yggdrasil_address
from lichen.crypto.schnorr48 import sign
from lichen.gradient import GradientEntry, GradientSource, GradientTable
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.icmpv6 import Icmpv6Message
from lichen.ipv6.packet import IPv6Header, IPv6Packet, NextHeader
from lichen.l2_payload import wrap_schc_payload
from lichen.link.frame import LINK_SIGNATURE_DOMAIN, LichenFrame
from lichen.link.link_layer import RxFrame
from lichen.node import Node, NodeConfig
from lichen.rpl.messages import DIO, RPL_ICMPV6_TYPE, RplCode
from lichen.schc.headers import compress_packet

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

    async def cad(self, timeout_ms: int) -> bool:
        return False


# ---------------------------------------------------------------------------
# CoAP server resource
# ---------------------------------------------------------------------------


class _Status(resource.Resource):
    async def render_get(self, request: Message) -> Message:
        return Message(payload=b"ok", code=aiocoap.CONTENT)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
            rpl_instance_id=0,
            rpl_dodag_id=IPv6Address("fe80::1"),
            rpl_dio_expected_role="peer",
        ),
    )


def _dio_schc_payload(remote: Identity) -> bytes:
    dio = DIO(
        rpl_instance_id=0,
        version=1,
        rank=512,
        dtsn=1,
        dodag_id=IPv6Address("fe80::1"),
        mode_of_operation=1,
    )
    source = _ll(remote.iid)
    destination = IPv6Address("ff02::1a")
    icmp = Icmpv6Message(RPL_ICMPV6_TYPE, int(RplCode.DIO), dio.to_bytes()).to_bytes(
        source, destination
    )
    raw = IPv6Packet(
        IPv6Header(
            src_addr=source,
            dst_addr=destination,
            next_header=NextHeader.ICMPV6,
            hop_limit=255,
        ),
        payload=icmp,
    ).to_bytes()
    return wrap_schc_payload(compress_packet(raw))


def _signed_link_wire(remote: Identity, payload: bytes, counter: int) -> bytes:
    epoch, seqnum = counter >> 16, counter & 0xFFFF
    signer_eui64 = iid_to_eui64(remote.iid)
    llsec = 0xA0
    length = 4 + len(signer_eui64) + len(payload) + 48
    transcript = (
        LINK_SIGNATURE_DOMAIN
        + bytes((length, llsec, epoch))
        + seqnum.to_bytes(2, "big")
        + b"\x00"
        + signer_eui64
        + payload
    )
    return LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=b"",
        payload=payload,
        mic=sign(remote.privkey, remote.pubkey, transcript),
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()


async def _bootstrap_peer_policy(node: Node, radio: DirectedRadio, remote: Identity) -> None:
    await radio._rx.put((_signed_link_wire(remote, _dio_schc_payload(remote), 0), -60, 7))
    received = await node.link.receive(100)
    assert isinstance(received, RxFrame)
    await node._process_received(received)


def _seed_gradient(
    table: GradientTable,
    destination: IPv6Address,
    via_iid: bytes,
    hop_count: int,
    now_ms: int,
) -> None:
    table.update(
        GradientEntry(
            destination=destination,
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
async def test_deaddrop_payload_format() -> None:
    """Verify deaddrop vectors produce parseable CoAP frames and SenML payloads."""
    import json
    from pathlib import Path

    from lichen.senml.codec import unpack as senml_unpack

    path = Path(__file__).resolve().parents[2] / "test" / "vectors" / "deaddrop.json"
    doc = json.loads(path.read_text())
    vectors = doc["vectors"]
    assert {v["type"] for v in vectors} >= {
        "post_submission",
        "pickup",
        "oscore_wrapped",
        "rejection",
        "state_transition",
        "observe",
    }
    assert {v["name"] for v in vectors} >= {
        "post_submission_basic",
        "pickup_with_pending",
        "oscore_wrapped_dead_drop",
        "eviction_fifo_order",
        "observe_notification",
    }

    for v in vectors:
        if "encoded" not in v:
            continue
        encoded = bytes.fromhex(v["encoded"].replace("deaddrop", "6465616464726f70"))
        assert len(encoded) >= 4
        assert encoded[0] & 0xC0 == 0x40, f"{v['name']}: not CoAP v1"
        code = encoded[1]
        if v["type"] in ("post_submission", "oscore_wrapped"):
            assert code == POST, f"{v['name']}: expected POST"
        elif v["type"] == "pickup":
            assert code == GET, f"{v['name']}: expected GET"
        if v["name"] in {
            "post_submission_basic",
            "post_submission_string_payload",
            "oscore_wrapped_dead_drop",
        }:
            records = senml_unpack(bytes.fromhex(v["senml_payload"]))
            assert len(records) >= 1, f"{v['name']}: empty SenML"


@pytest.mark.asyncio
async def test_confessions_payload_format() -> None:
    """Verify confessions vectors produce parseable CoAP frames and SenML payloads."""
    import json
    from pathlib import Path

    from lichen.senml.codec import unpack as senml_unpack

    path = Path(__file__).resolve().parents[2] / "test" / "vectors" / "confessions.json"
    doc = json.loads(path.read_text())
    vectors = doc["vectors"]
    assert {v["category"] for v in vectors} >= {
        "anonymous_confession",
        "oscore_group",
        "rate_limit_boundary",
        "storage_eviction",
        "reboot_clear",
        "size_limit",
        "ttl",
        "no_log",
    }
    assert {v["name"] for v in vectors} >= {
        "anonymous_confession_default",
        "oscore_group_confession",
        "rate_limit_13th_post_rejected",
        "storage_full_fifo_eviction",
        "reboot_clear_crash",
        "max_confession_size_exceeded",
        "ttl_expiry",
        "no_log_guarantee_checks",
    }

    for v in vectors:
        if v.get("encoded"):
            encoded = bytes.fromhex(v["encoded"])
            assert len(encoded) >= 4
            assert encoded[0] & 0xC0 == 0x40, f"{v['name']}: not CoAP v1"
            code = encoded[1]
            if v["type"] == "post_submission":
                assert code == POST, f"{v['name']}: expected POST"
            elif v["type"] == "get":
                assert code == GET, f"{v['name']}: expected GET"
        if v.get("senml_payload"):
            records = senml_unpack(bytes.fromhex(v["senml_payload"]))
            assert len(records) >= 1, f"{v['name']}: empty SenML"
        if v.get("senml_cbor_hex"):
            assert bytes.fromhex(v["senml_cbor_hex"]), f"{v['name']}: empty SenML-CBOR"
        if v.get("senml_json"):
            assert isinstance(v["senml_json"], list) and v["senml_json"]
            assert all(isinstance(record, dict) for record in v["senml_json"])
        if v.get("payload"):
            payload_bytes = bytes.fromhex(v["payload"])
            assert len(payload_bytes) >= 1, f"{v['name']}: empty payload"


@pytest.mark.asyncio
async def test_coap_get_via_relay() -> None:
    """CoAP GET from A to C is relayed through B and a response returns to A."""
    id_a = Identity.from_seed(bytes(32))
    id_b = Identity.from_seed(bytes([1] + [0] * 31))
    id_c = Identity.from_seed(bytes([2] + [0] * 31))

    # Directed radio topology: A--B--C
    radio_a, radio_b, radio_c = DirectedRadio(), DirectedRadio(), DirectedRadio()
    radio_a.connect(radio_b)  # A → B
    radio_b.connect(radio_a)  # B → A (response path)
    radio_b.connect(radio_c)  # B → C (forward path)
    radio_c.connect(radio_b)  # C → B (response path)

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

    # SCHC egress/ingress policies are admitted only by authenticated DIOs.
    await _bootstrap_peer_policy(node_a, radio_a, id_b)
    await _bootstrap_peer_policy(node_b, radio_b, id_a)
    await _bootstrap_peer_policy(node_b, radio_b, id_c)
    await _bootstrap_peer_policy(node_c, radio_c, id_b)

    # Gradient tables (pre-seeded; in production, populated by Announce)
    now_ms = int(asyncio.get_event_loop().time() * 1000)
    # Forward direction: A→B→C
    native_a = yggdrasil_address(id_a.pubkey)
    native_c = yggdrasil_address(id_c.pubkey)
    _seed_gradient(node_a.gradient_table, native_c, id_b.iid, 2, now_ms)
    _seed_gradient(node_b.gradient_table, native_c, id_c.iid, 1, now_ms)
    # Return direction: C→B→A
    _seed_gradient(node_c.gradient_table, native_a, id_b.iid, 2, now_ms)
    _seed_gradient(node_b.gradient_table, native_a, id_a.iid, 1, now_ms)

    native_a_text = str(native_a)
    native_c_text = str(native_c)

    # CoAP server on C
    site_c = resource.Site()
    site_c.add_resource(["status"], _Status())
    channel_c = NodeChannel(node_c, native_c_text)
    ctx_c = await create_lichen_context(channel_c, native_c_text, site=site_c)

    # CoAP client on A
    channel_a = NodeChannel(node_a, native_a_text)
    ctx_a = await create_lichen_context(channel_a, native_a_text)

    await node_a.start()
    await node_b.start()
    await node_c.start()

    try:
        response = await asyncio.wait_for(
            ctx_a.request(Message(code=GET, uri=f"coap://[{native_c_text}]/status")).response,
            timeout=5.0,
        )
        assert response.code == aiocoap.CONTENT
        assert response.payload == b"ok"
    finally:
        await asyncio.wait_for(asyncio.gather(ctx_a.shutdown(), ctx_c.shutdown()), timeout=2.0)
        await asyncio.wait_for(
            asyncio.gather(node_c.stop(), node_b.stop(), node_a.stop()), timeout=2.0
        )
