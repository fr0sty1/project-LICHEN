# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Fixed-profile SCHC fragmentation codec and sender tests."""

from __future__ import annotations

import asyncio
import gc
import json
import threading
import weakref
from dataclasses import FrozenInstanceError
from ipaddress import IPv6Address
from pathlib import Path
from typing import Any

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.ipv6.addr import iid_to_eui64
from lichen.ipv6.icmpv6 import EchoRequest
from lichen.ipv6.packet import IPv6Header, NextHeader
from lichen.l2_payload import wrap_schc_payload
from lichen.link.frame import AddrMode, LichenFrame
from lichen.link.link_layer import (
    LinkLayer,
    ReceiveError,
    RxFrame,
    _AuthenticatedPeerSchcIssuance,
    encode_rekey_request,
)
from lichen.link.replay import ReplayProtector
from lichen.link.tx_queue import Priority
from lichen.schc.codec import SchcError
from lichen.schc.context import AuthenticatedPeerSchcContext
from lichen.schc.fragment import (
    ALL_1,
    DEFAULT_WINDOW_SIZE,
    MAX_ACK_REQUESTS,
    MAX_PACKET_SIZE,
    MAX_SCHC_PACKET,
    MAX_SENDER_SESSION_RECORDS,
    MIC_LENGTH,
    TILE_SIZE,
    WINDOW_SIZE,
    Ack,
    Fragment,
    FragmentError,
    FragmentSender,
    _issued_manager,
    ack_request,
    compute_mic,
    fragmentation_message_is_response,
    fragmentation_rule_for_sender,
    receiver_abort,
    sender_abort,
)
from lichen.schc.headers import compress_packet, decompress_packet, encode_rule255
from lichen.schc.reassembly import AUTHENTICATED_HOLD_DOWN_SECONDS
from lichen.schc.rules import SchcRuleVersionOption
from lichen.timing.time_sync import MonotonicClock

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"

SCHC_FRAGMENT_VECTORS = json.loads((VECTORS_DIR / "schc_fragment.json").read_text())["vectors"]
SCHC_SESSION_SECURITY = json.loads((VECTORS_DIR / "schc_session_security.json").read_text())

LOCAL_NODE = Identity.from_seed(bytes(range(32)))
REMOTE_NODE = Identity.from_seed(bytes(range(32, 64)))
LOCAL_IDENTITY = LOCAL_NODE.pubkey
REMOTE_IDENTITY = REMOTE_NODE.pubkey


class _AckWireRadio:
    def __init__(self) -> None:
        self.tx_history: list[bytes] = []
        self.rx_queue: list[tuple[bytes, int, int]] = []

    async def transmit(self, data: bytes) -> bool:
        self.tx_history.append(data)
        return True

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        del timeout_ms
        return self.rx_queue.pop(0) if self.rx_queue else None

    async def cad(self, timeout_ms: int) -> bool:
        del timeout_ms
        return False

    def queue_rx(self, data: bytes) -> None:
        self.rx_queue.append((data, -90, 4))


def _transmit_reserved_test_wire(
    link: LinkLayer,
    radio: _AckWireRadio,
    payload: bytes,
    destination: bytes,
) -> bytes:
    """Craft authenticated peer input without exercising protected local egress."""
    payload = bytes(payload)
    epoch, seqnum = link._epoch, link._seqnum
    frame_length = 4 + len(destination) + 8 + len(payload) + 48
    llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
    signable = link._build_signable_data(
        epoch,
        seqnum,
        destination,
        payload,
        frame_length,
        llsec,
        link._local_eui64,
    )
    frame = LichenFrame(
        epoch=epoch,
        seqnum=seqnum,
        dst_addr=destination,
        payload=payload,
        mic=sign(link.identity.privkey, link.identity.pubkey, signable),
        addr_mode=AddrMode.EXTENDED,
        signature_present=True,
        signer_eui64=link._local_eui64,
    ).to_bytes()
    radio.tx_history.append(frame)
    link._next_seqnum()
    return frame


class SessionHarness:
    def __init__(
        self,
        replay_counter: int,
        *,
        local_node: Identity = LOCAL_NODE,
        remote_node: Identity = REMOTE_NODE,
        additional_remote_nodes: tuple[Identity, ...] = (),
        replay_protector: ReplayProtector | None = None,
        receipt_clock: MonotonicClock | None = None,
    ) -> None:
        self.local_radio = _AckWireRadio()
        self.remote_radio = _AckWireRadio()
        remote_peer = PeerIdentity.from_pubkey(remote_node.pubkey)
        known_peers = [
            remote_peer,
            *(PeerIdentity.from_pubkey(node.pubkey) for node in additional_remote_nodes),
        ]
        self.local_link = LinkLayer(
            radio=self.local_radio,  # type: ignore[arg-type]
            identity=local_node,
            peer_lookup=lambda _hint: remote_peer,
            replay_protector=replay_protector or ReplayProtector(),
            peer_lookup_all=lambda: known_peers,
            cad_enabled=False,
            receipt_clock=receipt_clock,
        )
        self.remote_link = LinkLayer(
            radio=self.remote_radio,  # type: ignore[arg-type]
            identity=remote_node,
            peer_lookup=lambda _hint: None,
            peer_lookup_all=lambda: [],
            cad_enabled=False,
        )
        local_peer = PeerIdentity.from_pubkey(local_node.pubkey)
        self.remote_link._pinned_keys[local_peer.iid] = local_node.pubkey
        self.remote_link._key_generations[local_node.pubkey] = object()
        if replay_counter >= 0:
            result = self.receive(b"baseline", replay_counter)
            assert isinstance(result, RxFrame)

    def receive(self, payload: bytes, replay_counter: int) -> RxFrame | ReceiveError:
        self.remote_link._epoch = replay_counter >> 16
        self.remote_link._seqnum = replay_counter & 0xFFFF
        self.remote_link._exhausted = False
        if payload and payload[0] in (0x78, 0x79):
            _transmit_reserved_test_wire(
                self.remote_link,
                self.remote_radio,
                payload,
                iid_to_eui64(self.local_link.identity.iid),
            )
        else:
            assert asyncio.run(self.remote_link.send(payload))
        self.local_radio.queue_rx(self.remote_radio.tx_history[-1])
        result = asyncio.run(self.local_link.receive(100))
        assert result is not None
        return result

    def authenticated_rekey(self, replacement: Identity, replay_counter: int) -> None:
        evidence = self.receive(encode_rekey_request(replacement.pubkey), replay_counter)
        assert isinstance(evidence, RxFrame)
        self.local_link.apply_authenticated_rekey(evidence)

    def authorize_schc(self, remote_signer_identity: bytes = REMOTE_IDENTITY) -> None:
        """Install a current v3 policy for fragmentation-mechanism tests."""
        _authorize_link_schc(self.local_link, remote_signer_identity)


def _authorize_link_schc(
    link: LinkLayer,
    remote_signer_identity: bytes,
    version: int = 3,
    admitted_counter: int = -1,
) -> None:
    """Install a test-owned v3 context without exercising DIO parsing."""
    peer = PeerIdentity.from_pubkey(remote_signer_identity)
    link._pinned_keys[peer.iid] = remote_signer_identity
    key_generation = link._key_generations.setdefault(remote_signer_identity, object())
    facade = AuthenticatedPeerSchcContext._issue_from_verified_dio(
        SchcRuleVersionOption.from_bytes(bytes((0x13, 1, version))),
        remote_signer_identity,
        owner=link,
    )
    previous = link._schc_peer_contexts.get(remote_signer_identity)
    if previous is not None:
        link._schc_peer_context_issuances.pop(id(previous), None)
    link._schc_peer_contexts[remote_signer_identity] = facade
    link._schc_peer_context_issuances[id(facade)] = _AuthenticatedPeerSchcIssuance(
        facade=facade,
        remote_version=version,
        signer_identity=remote_signer_identity,
        key_generation=key_generation,
        admitted_counter=admitted_counter,
    )


def _receive_raw_authenticated_fragment(
    harness: SessionHarness,
    payload: bytes,
    counter: int,
) -> RxFrame:
    """Inject one correctly signed raw fragment without sender-capability policy."""
    destination = iid_to_eui64(LOCAL_NODE.iid)
    signer_eui64 = iid_to_eui64(REMOTE_NODE.iid)
    frame_length = 4 + len(destination) + len(signer_eui64) + len(payload) + 48
    llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
    signable = harness.remote_link._build_signable_data(
        counter >> 16,
        counter & 0xFFFF,
        destination,
        payload,
        frame_length,
        llsec,
        signer_eui64,
    )
    wire = LichenFrame(
        epoch=counter >> 16,
        seqnum=counter & 0xFFFF,
        dst_addr=destination,
        payload=payload,
        mic=sign(REMOTE_NODE.privkey, REMOTE_NODE.pubkey, signable),
        addr_mode=AddrMode.EXTENDED,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()
    harness.local_radio.queue_rx(wire)
    received = asyncio.run(harness.local_link.receive(100))
    assert isinstance(received, RxFrame)
    return received


def _schc_payload(payload: bytes) -> bytes:
    """Build a canonical Rule 2 packet with the requested encoded length.

    Session-mechanism tests care about fragmentation geometry, not arbitrary
    malformed SCHC bytes.  Rule 2 has a fixed 23-byte encoding overhead, so
    preserving lengths above that minimum keeps every window-boundary assertion
    exact while exercising LinkLayer's whole-packet admission gate.
    """
    encoded_length = max(23, len(payload))
    data_length = encoded_length - 23
    pattern = payload or b"\x00"
    data = (pattern * ((data_length + len(pattern) - 1) // len(pattern)))[:data_length]
    src = IPv6Address("fe80::1")
    dst = IPv6Address("fe80::2")
    icmp = EchoRequest(identifier=1, sequence=1, data=data).to_message().to_bytes(src, dst)
    raw = IPv6Header(src, dst, NextHeader.ICMPV6, payload_length=len(icmp)).to_bytes() + icmp
    encoded = compress_packet(raw)
    assert len(encoded) == encoded_length
    assert encoded[0] == 2
    return encoded


def _rule255_payload(encoded_length: int) -> bytes:
    """Build an exact-length, structurally valid uncompressed SCHC packet."""
    data_length = encoded_length - 1 - 40 - 8
    assert data_length >= 0
    src = IPv6Address("fe80::1")
    dst = IPv6Address("fe80::2")
    icmp = (
        EchoRequest(identifier=1, sequence=1, data=bytes(data_length))
        .to_message()
        .to_bytes(src, dst)
    )
    raw = IPv6Header(src, dst, NextHeader.ICMPV6, payload_length=len(icmp)).to_bytes() + icmp
    encoded = encode_rule255(raw)
    assert len(encoded) == encoded_length
    return encoded


def _link_sender(
    harness: SessionHarness,
    payload: bytes,
    remote_signer_identity: bytes = REMOTE_IDENTITY,
    receiver_limit: int = MAX_SCHC_PACKET,
) -> FragmentSender:
    harness.authorize_schc(remote_signer_identity)
    return harness.local_link.create_fragment_sender(
        _schc_payload(payload), remote_signer_identity, receiver_limit
    )


def bound_sender(
    payload: bytes = b"x",
    replay_counter: int = 0,
    *,
    local_identity: bytes = LOCAL_IDENTITY,
    remote_identity: bytes = REMOTE_IDENTITY,
    receiver_limit: int = MAX_SCHC_PACKET,
    receipt_clock: MonotonicClock | None = None,
) -> tuple[SessionHarness, FragmentSender]:
    if local_identity != LOCAL_IDENTITY or remote_identity != REMOTE_IDENTITY:
        raise ValueError("custom raw identities are unsupported by the signed-wire harness")
    harness = SessionHarness(replay_counter, receipt_clock=receipt_clock)
    sender = _link_sender(harness, payload, remote_identity, receiver_limit)
    return harness, sender


def v(name: str) -> dict[str, Any]:
    return next(x for x in SCHC_FRAGMENT_VECTORS if x["name"] == name)


def test_single_fragment_vector() -> None:
    vec = v("single_fragment")
    packet = bytes.fromhex(vec["packet"])
    wire = bytes.fromhex(vec["fragments"][0])
    frag = Fragment.from_bytes(wire)
    assert frag.rule_id == vec["rule_id"]
    assert frag.is_all_1
    assert compute_mic(packet).hex() == vec["mic"]
    assert frag.to_bytes() == wire


def test_ack_on_error_mic_fail_vector() -> None:
    vec = v("ack_on_error_mic_fail")
    packet = bytes.fromhex(vec["packet"])
    assert compute_mic(packet).hex() == vec["mic"]


def test_ooo_retransmit_vector_mic() -> None:
    vec = v("ooo_retransmit")
    packet = bytes.fromhex(vec["packet"])
    assert compute_mic(packet).hex() == vec["mic"]


def test_multi_fragment_vector_mic() -> None:
    vec = v("multi_fragment")
    packet = bytes.fromhex(vec["packet"])
    assert compute_mic(packet).hex() == vec["mic"]


def test_all1_requires_mic() -> None:
    with pytest.raises(FragmentError):
        Fragment(rule_id=0x78, window=0, fcn=ALL_1, payload=b"x").to_bytes()


def test_window_and_fcn_schedule() -> None:
    packet = bytes(TILE_SIZE * (WINDOW_SIZE + 2))
    sender = FragmentSender(packet, receiver_limit=len(packet))
    frags = sender.all_fragments()
    assert sender.fragment_count == WINDOW_SIZE + 2
    assert (frags[0].window, frags[0].fcn) == (0, 62)
    assert (frags[WINDOW_SIZE - 1].window, frags[WINDOW_SIZE - 1].fcn) == (0, 0)
    assert (frags[WINDOW_SIZE].window, frags[WINDOW_SIZE].fcn) == (1, 62)
    assert (frags[-1].window, frags[-1].fcn) == (1, ALL_1)
    assert all(f.mic == b"" for f in frags[:-1])
    assert frags[-1].mic
    assert all(Fragment.from_bytes(fragment.to_bytes()) == fragment for fragment in frags)


def test_public_default_window_matches_fixed_profile() -> None:
    from lichen.schc import DEFAULT_WINDOW_SIZE as EXPORTED_DEFAULT_WINDOW_SIZE

    assert DEFAULT_WINDOW_SIZE == WINDOW_SIZE == 63
    assert EXPORTED_DEFAULT_WINDOW_SIZE == WINDOW_SIZE


def test_rule_79_one_tile_data_path_literal() -> None:
    wire = bytes.fromhex("797f4c7fc202f0")
    sender = FragmentSender(b"x", rule_id=0x79)
    assert Fragment.from_bytes(wire) == sender.all_fragments()[0]


def test_ack_and_control_vectors() -> None:
    failure = bytes.fromhex("782000000000000000")
    ack = Ack.from_bytes(failure, assigned_fcns=(62, 61, ALL_1))
    assert ack.to_bytes() == failure
    assert ack.bitmap[0] and not ack.bitmap[1] and ack.bitmap[-1]
    assert Ack(0x78, 0, complete=True).to_bytes() == bytes.fromhex("7840")
    assert Ack.from_bytes(bytes.fromhex("78c0")) == Ack(0x78, 1, complete=True)
    assert ack_request(0x78, 0) == bytes.fromhex("7800")
    assert ack_request(0x79, 1) == bytes.fromhex("7980")
    assert sender_abort(0x78) == bytes.fromhex("78fe")
    assert receiver_abort(0x79) == bytes.fromhex("79ffff")


def test_fragmentation_rule_direction_uses_full_canonical_signer_order() -> None:
    assert LOCAL_IDENTITY < REMOTE_IDENTITY
    assert fragmentation_rule_for_sender(LOCAL_IDENTITY, REMOTE_IDENTITY) == 0x78
    assert fragmentation_rule_for_sender(REMOTE_IDENTITY, LOCAL_IDENTITY) == 0x79
    with pytest.raises(FragmentError, match="distinct"):
        fragmentation_rule_for_sender(LOCAL_IDENTITY, LOCAL_IDENTITY)


def test_all_zero_ack_bitmap_round_trip() -> None:
    ack = Ack(0x78, 0, (False,) * 63)
    assert ack.to_bytes() == bytes.fromhex("78000000000000000000")
    assert Ack.from_bytes(ack.to_bytes()) == ack


def test_complete_ack_round_trip() -> None:
    ack = Ack(0x78, 0, complete=True)
    assert ack.to_bytes() == bytes.fromhex("7840")
    assert Ack.from_bytes(bytes.fromhex("7840")) == ack
    ack1 = Ack(0x78, 1, complete=True)
    assert ack1.to_bytes() == bytes.fromhex("78c0")
    assert Ack.from_bytes(bytes.fromhex("78c0")) == ack1


@pytest.mark.parametrize("payload", [bytearray(b"x"), memoryview(b"x"), "x", 1, True])
def test_sender_requires_strict_nonempty_bytes(payload: object) -> None:
    with pytest.raises(FragmentError, match="payload must be bytes"):
        FragmentSender(payload=payload)  # type: ignore[arg-type]


def test_sender_rejects_empty_packet_at_construction() -> None:
    with pytest.raises(FragmentError, match="empty packets cannot be fragmented"):
        FragmentSender(b"")


@pytest.mark.parametrize("rule_id", [True, 0x77, 0x7A, 120.0, "0x78"])
def test_sender_rejects_invalid_rule_id(rule_id: object) -> None:
    with pytest.raises(FragmentError, match="unsupported fragmentation rule"):
        FragmentSender(b"x", rule_id=rule_id)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "tile_size",
    [True, 0, 1, TILE_SIZE - 1, TILE_SIZE + 1, float(TILE_SIZE), str(TILE_SIZE)],
)
def test_sender_requires_fixed_tile_size(tile_size: object) -> None:
    with pytest.raises(
        FragmentError,
        match=rf"tile_size must be the fixed profile value {TILE_SIZE}",
    ):
        FragmentSender(b"x", tile_size=tile_size)  # type: ignore[arg-type]


@pytest.mark.parametrize("window_size", [True, 0, 1, 62, 64, 63.0, "63"])
def test_sender_requires_fixed_window_size(window_size: object) -> None:
    with pytest.raises(FragmentError, match="window_size must be the fixed profile value 63"):
        FragmentSender(b"x", window_size=window_size)  # type: ignore[arg-type]


@pytest.mark.parametrize("receiver_limit", [True, 0, -1, 23_563, 1281.0, "1281"])
def test_sender_rejects_invalid_receiver_limit(receiver_limit: object) -> None:
    with pytest.raises(FragmentError, match="receiver_limit must be an integer"):
        FragmentSender(b"x", receiver_limit=receiver_limit)  # type: ignore[arg-type]


@pytest.mark.parametrize("receiver_limit", [1, MAX_PACKET_SIZE])
def test_sender_accepts_receiver_limit_boundaries(receiver_limit: int) -> None:
    FragmentSender(b"x", receiver_limit=receiver_limit)


def test_sender_security_fields_and_state_are_read_only() -> None:
    sender = FragmentSender(b"x")
    for field_name, value in (
        ("rule_id", 0x79),
        ("receiver_limit", 1),
        ("tile_size", 1),
        ("window_size", 1),
        ("attempts", 99),
        ("status", "succeeded"),
    ):
        with pytest.raises((FrozenInstanceError, AttributeError)):
            setattr(sender, field_name, value)


def test_fragment_sender_rejects_by_default() -> None:
    with pytest.raises(FragmentError, match="payload too large"):
        FragmentSender(payload=bytes(MAX_SCHC_PACKET + 1))
    with pytest.raises(FragmentError, match="payload too large"):
        FragmentSender(payload=bytes(MAX_SCHC_PACKET + 1), receiver_limit=MAX_SCHC_PACKET)


def test_profile_packet_size_ceiling() -> None:
    assert MAX_PACKET_SIZE == 2 * WINDOW_SIZE * TILE_SIZE

    sender = FragmentSender(bytes(MAX_PACKET_SIZE), receiver_limit=MAX_PACKET_SIZE)
    assert sender.fragment_count == 2 * WINDOW_SIZE
    assert sum(len(fragment.payload) for fragment in sender.all_fragments()) == MAX_PACKET_SIZE
    assert all(len(fragment.payload) == TILE_SIZE for fragment in sender.all_fragments())
    assert all(
        Fragment.from_bytes(fragment.to_bytes()) == fragment for fragment in sender.all_fragments()
    )

    with pytest.raises(FragmentError, match="payload exceeds profile capacity"):
        FragmentSender(bytes(MAX_PACKET_SIZE + 1), receiver_limit=MAX_PACKET_SIZE)


def test_fragment_parser_bounds_input_before_large_integer_conversion() -> None:
    maximum = Fragment(0x78, 1, ALL_1, bytes(TILE_SIZE), bytes(MIC_LENGTH)).to_bytes()
    assert len(maximum) == TILE_SIZE + MIC_LENGTH + 2
    assert Fragment.from_bytes(maximum).to_bytes() == maximum

    with pytest.raises(FragmentError, match="maximum wire length"):
        Fragment.from_bytes(maximum + b"\x00")
    with pytest.raises(FragmentError, match="maximum wire length"):
        Fragment.from_bytes(bytes([0x78]) + bytes(100_000))


def test_ack_rejects_oversized_bitmap() -> None:
    with pytest.raises(FragmentError, match="bitmap size exceeds"):
        Ack.from_bytes(bytes.fromhex("7800") + b"\x00" * 20)
    with pytest.raises(FragmentError, match="bitmap size exceeds"):
        Ack.from_bytes(bytes.fromhex("7800") + b"\x00" * 10)


@pytest.mark.parametrize("wire", [bytearray(b"x"), memoryview(b"x"), [0x78, 0x40], "x"])
def test_wire_parsers_require_exact_bytes(wire: object) -> None:
    with pytest.raises(FragmentError, match="fragment must be bytes"):
        Fragment.from_bytes(wire)  # type: ignore[arg-type]
    with pytest.raises(FragmentError, match="ACK must be bytes"):
        Ack.from_bytes(wire)  # type: ignore[arg-type]


@pytest.mark.parametrize("window", [True, False, 0.0, "0"])
def test_control_and_serializers_reject_window_type_confusion(window: object) -> None:
    with pytest.raises(FragmentError, match="ACK REQ window"):
        ack_request(0x78, window)  # type: ignore[arg-type]
    with pytest.raises(FragmentError, match="window or FCN"):
        Fragment(0x78, window, 1, bytes(TILE_SIZE)).to_bytes()  # type: ignore[arg-type]
    with pytest.raises(FragmentError, match="ACK window"):
        Ack(0x78, window, (False,) * WINDOW_SIZE).to_bytes()  # type: ignore[arg-type]


def test_serializers_reject_mutable_or_mistyped_fields() -> None:
    with pytest.raises(FragmentError, match="payload and RCS must be bytes"):
        Fragment(0x78, 0, 1, bytearray(TILE_SIZE)).to_bytes()  # type: ignore[arg-type]
    with pytest.raises(FragmentError, match="window or FCN"):
        Fragment(0x78, 0, True, bytes(TILE_SIZE)).to_bytes()
    with pytest.raises(FragmentError, match="bitmap must be a tuple"):
        Ack(0x78, 0, [False] * WINDOW_SIZE).to_bytes()  # type: ignore[arg-type]
    with pytest.raises(FragmentError, match="bitmap must be a tuple"):
        Ack(0x78, 0, (0,) * WINDOW_SIZE).to_bytes()  # type: ignore[arg-type]
    with pytest.raises(FragmentError, match="complete flag must be bool"):
        Ack(0x78, 0, (), complete=1).to_bytes()  # type: ignore[arg-type]


def test_sender_ack_handler_requires_verified_frame_envelope() -> None:
    _, sender = bound_sender()
    sender.start()
    with pytest.raises(FragmentError, match="verified RxFrame"):
        sender.handle_ack_frame(bytes.fromhex("7840"))  # type: ignore[arg-type]
    assert sender.status == "active"


@pytest.mark.parametrize("wire", [bytes.fromhex("784000"), bytes.fromhex("78ff")])
def test_malformed_ack_vectors(wire: bytes) -> None:
    with pytest.raises(FragmentError):
        Ack.from_bytes(wire)


def test_session_manager_requires_canonical_full_signer_keys() -> None:
    harness = SessionHarness(-1)
    for remote in (b"", bytes(8), bytes(31), bytes(33), bytearray(32)):
        with pytest.raises(FragmentError, match="32-byte signer public key"):
            harness.local_link.create_fragment_sender(b"x", remote)  # type: ignore[arg-type]
    harness.authorize_schc()
    with pytest.raises(FragmentError, match="unsupported fragmentation rule"):
        harness.local_link._schc_session_manager.create_sender(
            _schc_payload(b"x"),
            REMOTE_IDENTITY,
            harness.local_link._key_generations[REMOTE_IDENTITY],
            rule_id=0x77,
            receiver_limit=MAX_SCHC_PACKET,
        )


def test_sender_requires_bound_context_and_fresh_final_window_ack() -> None:
    unbound = FragmentSender(b"x")
    with pytest.raises(FragmentError, match="authenticated link session required"):
        unbound.start()
    assert unbound.status == "ready"

    packet = b"x" + bytes(TILE_SIZE * (WINDOW_SIZE + 1) - 1)
    harness, sender = bound_sender(
        packet,
        10,
        receiver_limit=len(packet),
    )
    sender.start()
    with pytest.raises(FragmentError, match="final window"):
        sender.handle_ack_frame(harness.receive(bytes.fromhex("7840"), 11))
    assert sender.status == "active"
    assert sender.handle_ack_frame(harness.receive(bytes.fromhex("78c0"), 12)) == []
    assert sender.status == "succeeded"


def test_start_emits_complete_ordered_initial_batch_and_counts_all1() -> None:
    packet = b"x" + bytes(TILE_SIZE * 2)
    _, sender = bound_sender(packet, receiver_limit=len(packet))
    expected = [fragment.to_bytes() for fragment in sender.all_fragments()]
    assert sender.start() == expected
    assert len(expected) == 3
    assert Fragment.from_bytes(expected[-1]).is_all_1
    assert sender.attempts == 1


def test_all1_retransmission_omits_ack_request_and_increments_attempts() -> None:
    harness, sender = bound_sender(replay_counter=10)
    sender.start()
    missing_all_1 = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()
    result = sender.handle_ack_frame(harness.receive(missing_all_1, 11))
    assert result == [sender.all_fragments()[-1].to_bytes()]
    assert sender.attempts == 2
    assert ack_request(0x78, 0) not in result


def test_saturated_repair_preserves_other_sessions_unsent_wire_capability() -> None:
    harness = SessionHarness(
        -1,
        replay_protector=ReplayProtector(max_peers=MAX_SENDER_SESSION_RECORDS),
    )
    packet = _rule255_payload(MAX_PACKET_SIZE)
    remotes = [
        Identity.from_seed(bytes([seed]) * 32)
        for seed in range(70, 70 + MAX_SENDER_SESSION_RECORDS - 1)
    ] + [REMOTE_NODE]
    first_wire: bytes | None = None
    repair_sender: FragmentSender | None = None

    for index, remote in enumerate(remotes):
        _authorize_link_schc(harness.local_link, remote.pubkey)
        sender = harness.local_link.create_fragment_sender(
            packet,
            remote.pubkey,
            MAX_PACKET_SIZE,
        )
        initial = sender.start()
        if index == 0:
            first_wire = initial[0]
        if remote is REMOTE_NODE:
            repair_sender = sender

    assert first_wire is not None
    assert repair_sender is not None
    negative = Ack(
        repair_sender.rule_id,
        repair_sender.final_window(),
        (False,) * WINDOW_SIZE,
    ).to_bytes()
    received = harness.receive(negative, 0)
    assert isinstance(received, RxFrame)
    assert len(repair_sender.handle_ack_frame(received)) == WINDOW_SIZE

    first_remote_eui64 = iid_to_eui64(remotes[0].iid)
    assert harness.local_link._schc_session_manager.consume_fragment_wire(
        first_wire,
        first_remote_eui64,
    )


def test_c0_with_all_assigned_fragments_received_aborts_as_unrepairable() -> None:
    harness, sender = bound_sender(replay_counter=10)
    sender.start()
    rcs_failure_without_loss = Ack(0x78, 0, (False,) * 62 + (True,)).to_bytes()
    assert sender.handle_ack_frame(harness.receive(rcs_failure_without_loss, 11)) == [
        sender_abort(0x78)
    ]
    assert sender.status == "aborted"


def test_regular_repair_rounds_exhaust_budget_once() -> None:
    harness, sender = bound_sender(payload=b"x" * (TILE_SIZE + 1), replay_counter=0)
    sender.start()
    missing_regular = Ack(0x78, 0, (False,) * 62 + (True,)).to_bytes()
    for counter in range(1, 4):
        received = harness.receive(missing_regular, counter)
        assert isinstance(received, RxFrame)
        output = sender.handle_ack_frame(received)
        assert output[-1] == ack_request(0x78, sender.final_window())
    assert sender.attempts == MAX_ACK_REQUESTS
    received = harness.receive(missing_regular, 4)
    assert isinstance(received, RxFrame)
    assert sender.handle_ack_frame(received) == [sender_abort(0x78)]
    assert sender.status == "aborted"
    assert sender.timeout() == b""


def test_timeout_rounds_exhaust_budget_once() -> None:
    _, sender = bound_sender(replay_counter=0)
    sender.start()
    for expected_attempts in range(2, MAX_ACK_REQUESTS + 1):
        assert sender.timeout() == ack_request(0x78, sender.final_window())
        assert sender.attempts == expected_attempts
    assert sender.timeout() == sender_abort(0x78)
    assert sender.status == "aborted"
    assert sender.timeout() == b""


def test_active_sender_rejects_unassigned_ack_bits_without_transition() -> None:
    harness, sender = bound_sender(replay_counter=0)
    sender.start()
    malformed = Ack(0x78, 0, (True,) + (False,) * 62).to_bytes()
    received = harness.receive(malformed, 1)
    assert isinstance(received, RxFrame)
    before = (sender.status, sender.attempts)

    with pytest.raises(FragmentError, match="unassigned bitmap bit"):
        sender.handle_ack_frame(received)

    assert (sender.status, sender.attempts) == before


def test_sender_rejects_wrong_peer_prior_session_and_replayed_ack() -> None:
    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()
    harness = SessionHarness(-1)
    prior = harness.receive(bytes.fromhex("7840"), 100)
    sender = _link_sender(harness, b"x")
    sender.start()

    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(prior)
    lower = harness.receive(bytes.fromhex("7840"), 99)
    assert isinstance(lower, RxFrame)
    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(lower)

    accepted = harness.receive(failure, 101)
    assert isinstance(accepted, RxFrame)
    assert sender.handle_ack_frame(accepted)
    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(accepted)
    assert sender.status == "active"


def test_distinct_authenticated_signer_cannot_ack_target_session() -> None:
    third_identity = Identity.from_seed(bytes([0xA5]) * 32)
    harness = SessionHarness(-1, additional_remote_nodes=(third_identity,))
    sender = _link_sender(harness, b"x")
    sender.start()
    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()

    third_radio = _AckWireRadio()
    third_link = LinkLayer(
        radio=third_radio,  # type: ignore[arg-type]
        identity=third_identity,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )
    third_link._pinned_keys[LOCAL_NODE.iid] = LOCAL_IDENTITY
    third_link._key_generations[LOCAL_IDENTITY] = object()
    _transmit_reserved_test_wire(
        third_link,
        third_radio,
        failure,
        iid_to_eui64(harness.local_link.identity.iid),
    )
    harness.local_radio.queue_rx(third_radio.tx_history[-1])
    wrong_signer = asyncio.run(harness.local_link.receive(100))
    assert isinstance(wrong_signer, RxFrame)
    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(wrong_signer)
    assert sender.status == "active"
    assert sender.attempts == 1

    intended = harness.receive(bytes.fromhex("7840"), 1)
    assert isinstance(intended, RxFrame)
    assert sender.handle_ack_frame(intended) == []
    assert sender.status == "succeeded"


def test_sender_rejects_lower_link_fresh_ack_without_generation_discriminator() -> None:
    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()
    harness, sender = bound_sender(replay_counter=100)
    sender.start()

    assert sender.handle_ack_frame(harness.receive(failure, 102))
    lower = harness.receive(bytes.fromhex("7840"), 101)
    assert isinstance(lower, RxFrame)
    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(lower)
    assert sender.status == "active"


def test_verified_envelope_snapshots_authenticated_ack_payload() -> None:
    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()
    harness, sender = bound_sender(replay_counter=100)
    sender.start()
    received = harness.receive(failure, 101)
    assert isinstance(received, RxFrame)
    detached = received.frame
    detached.payload = bytes.fromhex("7840")

    assert sender.handle_ack_frame(received)
    assert sender.status == "active"
    assert received.payload == failure
    assert received.frame.payload == failure


def test_rx_frame_constructor_is_verifier_only() -> None:
    assert not hasattr(RxFrame, "_from_verified")
    with pytest.raises(TypeError):
        RxFrame()  # type: ignore[call-arg]


def test_negative_ack_limit_emits_one_terminal_sender_abort() -> None:
    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()
    harness, sender = bound_sender(replay_counter=10)
    sender.start()

    for counter in (11, 12, 13):
        assert sender.handle_ack_frame(harness.receive(failure, counter))
        assert sender.status == "active"
    assert sender.handle_ack_frame(harness.receive(failure, 14)) == [sender_abort(0x78)]
    assert sender.status == "aborted"
    assert sender.handle_ack_frame(harness.receive(failure, 15)) == []
    assert sender.handle_ack_frame(harness.receive(bytes.fromhex("7840"), 16)) == []
    assert sender.timeout() == b""
    assert sender.status == "aborted"


def test_t0_registry_rejects_overlap_and_retains_terminal_hold_down() -> None:
    now = [100.0]
    harness = SessionHarness(10, receipt_clock=MonotonicClock(lambda: now[0]))
    sender = _link_sender(harness, b"first")
    overlap = _link_sender(harness, b"overlap")
    sender.start()
    with pytest.raises(FragmentError, match="already active"):
        overlap.start()
    assert sender.handle_ack_frame(harness.receive(bytes.fromhex("7840"), 11)) == []

    too_soon = _link_sender(harness, b"too soon")
    with pytest.raises(FragmentError, match="terminal hold-down"):
        too_soon.start()

    now[0] += 60.0
    next_sender = _link_sender(harness, b"second")
    next_sender.start()
    assert harness.receive(bytes.fromhex("7840"), 11) == ReceiveError.REPLAY


def test_session_creation_fails_closed_at_replay_counter_exhaustion() -> None:
    harness = SessionHarness(-1)
    with pytest.warns(UserWarning, match="approaching 24-bit limit"):
        assert harness.local_link.replay_protector._check_and_update_owned(
            REMOTE_IDENTITY,
            0xFF,
            0xFFFF,
            harness.local_link._replay_owner_token,
        )
    sender = _link_sender(harness, b"x")
    with pytest.raises(FragmentError, match="rekey required"):
        sender.start()


def test_session_registry_never_evicts_an_active_tuple() -> None:
    harness = SessionHarness(-1)
    harness.local_link._schc_session_manager._max_records = 1
    first = _link_sender(harness, b"first")
    second = _link_sender(harness, b"second", bytes(reversed(REMOTE_IDENTITY)))
    first.start()
    with pytest.raises(FragmentError, match="registry is full"):
        second.start()
    assert first.status == "active"


def test_copied_sender_binding_cannot_activate_or_share_t0_lease() -> None:
    harness = SessionHarness(-1)
    issued = _link_sender(harness, b"issued")
    copied = FragmentSender(b"copied")
    with pytest.raises(FrozenInstanceError):
        copied._manager = issued._manager
    object.__setattr__(copied, "_manager", issued._manager)
    object.__setattr__(copied, "_remote_signer_identity", issued._remote_signer_identity)
    object.__setattr__(copied, "_security_generation", issued._security_generation)

    with pytest.raises(FragmentError, match="authenticated link session required"):
        copied.start()
    issued.start()
    with pytest.raises(FragmentError, match="authenticated link session required"):
        copied.start()


def test_abandoned_prepared_senders_do_not_exhaust_active_registry() -> None:
    harness = SessionHarness(-1)
    harness.local_link._schc_session_manager._max_records = 1
    abandoned = [_link_sender(harness, b"abandoned") for _ in range(64)]
    with pytest.raises(FragmentError, match="prepared.*registry is full"):
        _link_sender(harness, b"one too many")
    for sender in abandoned:
        sender.cancel()
    live = _link_sender(harness, b"live")
    live.start()
    assert live.status == "active"


def test_idle_session_expires_then_releases_registry_after_hold_down() -> None:
    now = [100.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    manager = harness.local_link._schc_session_manager
    manager._max_records = 1
    stale = _link_sender(harness, b"stale")
    stale.start()

    now[0] += 60.0
    during_hold = _link_sender(harness, b"hold")
    with pytest.raises(FragmentError, match="terminal hold-down"):
        during_hold.start()
    assert stale.timeout() == b""
    assert stale.status == "expired"
    stale.cancel()
    assert stale.status == "expired"

    now[0] += 60.0
    replacement = _link_sender(harness, b"replacement")
    replacement.start()
    assert replacement.status == "active"


@pytest.mark.parametrize(
    "elapsed,expected_status,error",
    [
        (59.999, "active", "already active"),
        (60.0, "expired", "terminal hold-down"),
        (60.001, "expired", "terminal hold-down"),
    ],
)
def test_idle_expiry_exact_boundary(
    elapsed: float,
    expected_status: str,
    error: str,
) -> None:
    now = [100.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    sender = _link_sender(harness, b"first")
    sender.start()
    now[0] += elapsed
    contender = _link_sender(harness, b"second")
    with pytest.raises(FragmentError, match=error):
        contender.start()
    assert sender.status == expected_status
    sender.cancel()
    expected_after_cancel = "expired" if expected_status == "expired" else "aborted"
    assert sender.status == expected_after_cancel


def test_forged_copy_of_real_rxframe_has_no_link_receipt() -> None:
    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()
    harness, sender = bound_sender(replay_counter=10)
    sender.start()
    real = harness.receive(failure, 11)
    assert isinstance(real, RxFrame)
    forged = object.__new__(RxFrame)
    for name in RxFrame.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(real, name))

    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(forged)
    assert sender.handle_ack_frame(real)


def test_replay_floor_survives_tombstone_expiry_and_window_eviction() -> None:
    now = [100.0]
    protector = ReplayProtector(max_peers=1, max_retained_floors=4)
    harness = SessionHarness(
        -1,
        replay_protector=protector,
        receipt_clock=MonotonicClock(lambda: now[0]),
    )
    sender = _link_sender(harness, b"first")
    sender.start()
    completed = harness.receive(bytes.fromhex("7840"), 11)
    assert isinstance(completed, RxFrame)
    captured_wire = harness.remote_radio.tx_history[-1]
    assert sender.handle_ack_frame(completed) == []

    now[0] += 60.0
    replacement = _link_sender(harness, b"second")
    replacement.start()
    replacement.cancel()
    now[0] += 60.0
    # Cleanup releases the pin; another authenticated peer then evicts the
    # window while the retained floor remains authoritative.
    third = _link_sender(harness, b"third")
    third.start()
    third.cancel()
    now[0] += 60.0
    harness.local_link._schc_session_manager._expire_records_unlocked()
    assert protector._check_and_update_owned(
        b"other-peer", 0, 1, harness.local_link._replay_owner_token
    )
    newest = _link_sender(harness, b"newest")
    newest.start()
    harness.local_radio.queue_rx(captured_wire)
    assert asyncio.run(harness.local_link.receive(100)) == ReceiveError.REPLAY


def test_atomic_rekey_invalidates_ready_and_active_senders_and_old_wire() -> None:
    harness = SessionHarness(-1)
    pre_rotation = harness.receive(b"pre-rotation", 1)
    assert isinstance(pre_rotation, RxFrame)
    ready = _link_sender(harness, b"ready")
    active = _link_sender(harness, b"active")
    active.start()
    _transmit_reserved_test_wire(
        harness.remote_link,
        harness.remote_radio,
        bytes.fromhex("7840"),
        iid_to_eui64(harness.local_link.identity.iid),
    )
    old_wire = harness.remote_radio.tx_history[-1]
    replacement = Identity.from_seed(bytes(reversed(range(32))))

    harness.authenticated_rekey(replacement, 3)
    with pytest.raises(FragmentError, match="not link-issued"):
        ready.start()
    assert active.timeout() == b""
    assert active.status == "invalidated"
    with pytest.raises(ValueError, match="unconsumed verified receipt"):
        harness.local_link.consume_verified_receipt(pre_rotation, purpose="dio-time")
    harness.local_radio.queue_rx(old_wire)
    assert asyncio.run(harness.local_link.receive(100)) == ReceiveError.KEY_CHANGE

    replacement_radio = _AckWireRadio()
    replacement_link = LinkLayer(
        radio=replacement_radio,  # type: ignore[arg-type]
        identity=replacement,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )
    assert asyncio.run(replacement_link.send(b"new-key"))
    harness.local_radio.queue_rx(replacement_radio.tx_history[-1])
    assert isinstance(asyncio.run(harness.local_link.receive(100)), RxFrame)


def test_rekey_rejects_live_replacement_without_erasing_its_replay_state() -> None:
    replacement = Identity.from_seed(bytes([0x5A]) * 32)
    harness = SessionHarness(-1, additional_remote_nodes=(replacement,))
    baseline = harness.receive(b"baseline", 0)
    assert isinstance(baseline, RxFrame)
    replacement_radio = _AckWireRadio()
    replacement_link = LinkLayer(
        radio=replacement_radio,  # type: ignore[arg-type]
        identity=replacement,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )
    assert asyncio.run(replacement_link.send(b"replacement-live"))
    replacement_wire = replacement_radio.tx_history[-1]
    harness.local_radio.queue_rx(replacement_wire)
    assert isinstance(asyncio.run(harness.local_link.receive(100)), RxFrame)
    floor = harness.local_link.replay_protector.highest(replacement.pubkey)

    evidence = harness.receive(encode_rekey_request(replacement.pubkey), 1)
    assert isinstance(evidence, RxFrame)
    with pytest.raises(ValueError, match="replacement signer identity"):
        harness.local_link.apply_authenticated_rekey(evidence)
    assert harness.local_link.replay_protector.highest(replacement.pubkey) == floor
    harness.local_radio.queue_rx(replacement_wire)
    assert asyncio.run(harness.local_link.receive(100)) == ReceiveError.REPLAY


def test_rekey_rejects_replacement_with_prepared_sender_capability() -> None:
    replacement = Identity.from_seed(bytes([0x3C]) * 32)
    harness = SessionHarness(-1)
    prepared = _link_sender(harness, b"prepared", replacement.pubkey)
    baseline = harness.receive(b"baseline", 0)
    assert isinstance(baseline, RxFrame)
    evidence = harness.receive(encode_rekey_request(replacement.pubkey), 1)
    assert isinstance(evidence, RxFrame)
    with pytest.raises(ValueError, match="replacement signer identity"):
        harness.local_link.apply_authenticated_rekey(evidence)
    assert prepared.status == "ready"
    prepared.cancel()


def test_general_verified_receipt_is_link_bound_exact_object_and_one_use() -> None:
    harness = SessionHarness(-1)
    received = harness.receive(b"dio", 1)
    assert isinstance(received, RxFrame)
    forged = object.__new__(RxFrame)
    for name in RxFrame.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(received, name))

    with pytest.raises(ValueError, match="unconsumed verified receipt"):
        harness.local_link.consume_verified_receipt(forged, purpose="dio-time")
    original_payload = received.payload
    object.__setattr__(received, "_authenticated_payload", b"caller-mutated")
    snapshot = harness.local_link.consume_verified_receipt(received, purpose="dio-time")
    assert snapshot is not received
    assert snapshot.payload == original_payload
    assert snapshot.sender_pubkey == REMOTE_IDENTITY
    assert snapshot.received_monotonic >= 0
    with pytest.raises(ValueError, match="unconsumed verified receipt"):
        harness.local_link.consume_verified_receipt(received, purpose="dio-time")
    with pytest.raises(ValueError, match="unsupported"):
        harness.local_link.consume_verified_receipt(
            harness.receive(b"next", 2),
            purpose="arbitrary",
        )


def test_concurrent_success_ack_and_timeout_are_serialized() -> None:
    harness, sender = bound_sender(replay_counter=10)
    sender.start()
    success = harness.receive(bytes.fromhex("7840"), 11)
    assert isinstance(success, RxFrame)
    barrier = threading.Barrier(3)
    results: list[object] = []

    def handle_success() -> None:
        barrier.wait()
        results.append(sender.handle_ack_frame(success))

    def handle_timeout() -> None:
        barrier.wait()
        results.append(sender.timeout())

    threads = [threading.Thread(target=handle_success), threading.Thread(target=handle_timeout)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert sender.status == "succeeded"
    assert [] in results
    assert all(result in ([], b"", ack_request(0x78, 0)) for result in results)


def test_ack_transition_and_output_are_atomic_with_key_rotation() -> None:
    harness, sender = bound_sender(replay_counter=10)
    initial = sender.start()
    failure = harness.receive(Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes(), 11)
    assert isinstance(failure, RxFrame)
    replacement = Identity.from_seed(bytes(reversed(range(32))))
    rekey_evidence = harness.receive(encode_rekey_request(replacement.pubkey), 12)
    assert isinstance(rekey_evidence, RxFrame)
    manager = harness.local_link._schc_session_manager
    original_consumer = manager._receipt_consumer
    assert original_consumer is not None
    transition_entered = threading.Event()
    release_transition = threading.Event()
    rotation_done = threading.Event()
    results: list[list[bytes]] = []
    errors: list[BaseException] = []

    def blocking_consumer(received: RxFrame, purpose: str) -> RxFrame:
        authenticated = original_consumer(received, purpose)
        transition_entered.set()
        if not release_transition.wait(1):
            raise AssertionError("test did not release the ACK transition")
        return authenticated

    manager._receipt_consumer = blocking_consumer

    def handle_ack() -> None:
        try:
            results.append(sender.handle_ack_frame(failure))
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    def rotate() -> None:
        try:
            harness.local_link.apply_authenticated_rekey(rekey_evidence)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)
        finally:
            rotation_done.set()

    ack_thread = threading.Thread(target=handle_ack)
    ack_thread.start()
    assert transition_entered.wait(1)
    rotation_thread = threading.Thread(target=rotate)
    rotation_thread.start()
    assert not rotation_done.wait(0.05)
    release_transition.set()
    ack_thread.join()
    rotation_thread.join()

    assert not errors
    assert results == [[initial[-1]]]
    assert sender.status == "invalidated"


def test_timeout_transition_and_output_are_atomic_with_key_rotation() -> None:
    transition_entered = threading.Event()
    release_transition = threading.Event()
    rotation_done = threading.Event()
    blocking = [False]

    def blocking_clock() -> float:
        if blocking[0] and not transition_entered.is_set():
            transition_entered.set()
            if not release_transition.wait(1):
                raise AssertionError("test did not release the timeout transition")
        return 0.0

    harness, sender = bound_sender(
        replay_counter=10,
        receipt_clock=MonotonicClock(blocking_clock),
    )
    sender.start()
    replacement = Identity.from_seed(bytes(reversed(range(32))))
    rekey_evidence = harness.receive(encode_rekey_request(replacement.pubkey), 11)
    assert isinstance(rekey_evidence, RxFrame)
    results: list[bytes] = []
    errors: list[BaseException] = []
    blocking[0] = True

    def handle_timeout() -> None:
        try:
            results.append(sender.timeout())
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    def rotate() -> None:
        try:
            harness.local_link.apply_authenticated_rekey(rekey_evidence)
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)
        finally:
            rotation_done.set()

    timeout_thread = threading.Thread(target=handle_timeout)
    timeout_thread.start()
    assert transition_entered.wait(1)
    rotation_thread = threading.Thread(target=rotate)
    rotation_thread.start()
    assert not rotation_done.wait(0.05)
    release_transition.set()
    timeout_thread.join()
    rotation_thread.join()

    assert not errors
    assert results == [ack_request(0x78, 0)]
    assert sender.status == "invalidated"


def test_session_start_and_receive_boundary_linearize_without_prior_ack_adoption() -> None:
    harness = SessionHarness(10)
    sender = _link_sender(harness, b"race")
    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()
    barrier = threading.Barrier(3)
    received: list[RxFrame | ReceiveError] = []
    errors: list[BaseException] = []

    def start_sender() -> None:
        try:
            barrier.wait()
            sender.start()
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    def receive_ack() -> None:
        try:
            barrier.wait()
            received.append(harness.receive(failure, 11))
        except BaseException as exc:  # pragma: no cover - diagnostic capture
            errors.append(exc)

    with harness.local_link._security_lock:
        threads = [threading.Thread(target=start_sender), threading.Thread(target=receive_ack)]
        for thread in threads:
            thread.start()
        barrier.wait()
    for thread in threads:
        thread.join()

    assert not errors
    assert sender.status == "active"
    assert len(received) == 1 and isinstance(received[0], RxFrame)
    try:
        result = sender.handle_ack_frame(received[0])
    except FragmentError as exc:
        # Receive linearized before activation: it advanced the authoritative
        # baseline but deliberately did not create a session receipt.
        assert "receive receipt" in str(exc)
    else:
        # Activation linearized first: the newer ACK is part of this session.
        assert result


@pytest.mark.asyncio
async def test_over_air_self_signed_frame_is_replay_checked() -> None:
    identity = Identity.from_seed(bytes(range(32)))
    peer = PeerIdentity.from_pubkey(identity.pubkey)
    radio = _AckWireRadio()
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=identity,
        peer_lookup=lambda _hint: peer,
        peer_lookup_all=lambda: [peer],
        cad_enabled=False,
    )
    assert await link.send(b"self")
    wire = radio.tx_history[-1]
    radio.queue_rx(wire)
    assert isinstance(await link.receive(100), RxFrame)
    radio.queue_rx(wire)
    assert await link.receive(100) == ReceiveError.REPLAY


@pytest.mark.asyncio
async def test_self_signed_ambiguous_control_does_not_raise_during_receive() -> None:
    identity = Identity.from_seed(bytes(range(32)))
    peer = PeerIdentity.from_pubkey(identity.pubkey)
    radio = _AckWireRadio()
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=identity,
        peer_lookup=lambda _hint: peer,
        peer_lookup_all=lambda: [peer],
        cad_enabled=False,
    )
    payload = ack_request(0x78, 0)
    signer_eui64 = iid_to_eui64(peer.iid)
    frame_length = 4 + len(peer.iid) + len(signer_eui64) + len(payload) + 48
    llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
    destination = iid_to_eui64(peer.iid)
    signable = link._build_signable_data(
        0, 0, destination, payload, frame_length, llsec, signer_eui64
    )
    wire = LichenFrame(
        epoch=0,
        seqnum=0,
        dst_addr=destination,
        payload=payload,
        mic=sign(identity.privkey, identity.pubkey, signable),
        addr_mode=AddrMode.EXTENDED,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()
    radio.queue_rx(wire)

    received = await link.receive(100)
    assert isinstance(received, RxFrame)
    with pytest.raises(FragmentError, match="distinct signer identities"):
        link.accept_authenticated_schc_sender_control(received)
    assert not link._schc_session_manager._records
    assert not link._schc_reassembly_manager._contexts


@pytest.mark.asyncio
async def test_signed_wire_ack_uses_link_owned_session_and_immutable_envelope() -> None:
    local_identity = Identity.from_seed(bytes(range(32)))
    remote_identity = Identity.from_seed(bytes(range(32, 64)))
    remote_peer = PeerIdentity.from_pubkey(remote_identity.pubkey)
    local_radio = _AckWireRadio()
    remote_radio = _AckWireRadio()

    local_link = LinkLayer(
        radio=local_radio,  # type: ignore[arg-type]
        identity=local_identity,
        peer_lookup=lambda _hint: remote_peer,
        peer_lookup_all=lambda: [remote_peer],
        cad_enabled=False,
    )
    remote_link = LinkLayer(
        radio=remote_radio,  # type: ignore[arg-type]
        identity=remote_identity,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )
    remote_link._pinned_keys[local_identity.iid] = local_identity.pubkey
    remote_link._key_generations[local_identity.pubkey] = object()

    # Establish the authoritative pre-session replay floor through the real
    # signature-verification and replay-commit path.
    assert await remote_link.send(b"baseline")
    local_radio.queue_rx(remote_radio.tx_history[-1])
    baseline = await local_link.receive(100)
    assert isinstance(baseline, RxFrame)

    _authorize_link_schc(local_link, remote_identity.pubkey)
    sender = local_link.create_fragment_sender(_schc_payload(b"x"), remote_identity.pubkey)
    sender.start()

    # A valid envelope received by a different local signer cannot authorize
    # this ordered local/remote session tuple.
    other_identity = Identity.from_seed(bytes(reversed(range(32))))
    other_radio = _AckWireRadio()
    other_link = LinkLayer(
        radio=other_radio,  # type: ignore[arg-type]
        identity=other_identity,
        peer_lookup=lambda _hint: remote_peer,
        peer_lookup_all=lambda: [remote_peer],
        cad_enabled=False,
    )
    remote_link._pinned_keys[other_identity.iid] = other_identity.pubkey
    remote_link._key_generations[other_identity.pubkey] = object()
    wrong_local_failure = Ack(
        fragmentation_rule_for_sender(other_identity.pubkey, remote_identity.pubkey),
        0,
        (False,) * WINDOW_SIZE,
    ).to_bytes()
    _transmit_reserved_test_wire(
        remote_link,
        remote_radio,
        wrong_local_failure,
        iid_to_eui64(other_identity.iid),
    )
    other_radio.queue_rx(remote_radio.tx_history[-1])
    wrong_local = await other_link.receive(100)
    assert isinstance(wrong_local, RxFrame)
    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(wrong_local)

    failure = Ack(0x78, 0, (False,) * WINDOW_SIZE).to_bytes()

    clone_radio = _AckWireRadio()
    clone_link = LinkLayer(
        radio=clone_radio,  # type: ignore[arg-type]
        identity=local_identity,
        peer_lookup=lambda _hint: remote_peer,
        peer_lookup_all=lambda: [remote_peer],
        cad_enabled=False,
    )
    _transmit_reserved_test_wire(
        remote_link,
        remote_radio,
        failure,
        iid_to_eui64(local_identity.iid),
    )
    clone_radio.queue_rx(remote_radio.tx_history[-1])
    wrong_link_instance = await clone_link.receive(100)
    assert isinstance(wrong_link_instance, RxFrame)
    with pytest.raises(FragmentError, match="receive receipt"):
        sender.handle_ack_frame(wrong_link_instance)

    success = bytes.fromhex("7840")
    _transmit_reserved_test_wire(
        remote_link,
        remote_radio,
        success,
        iid_to_eui64(local_identity.iid),
    )
    signed_success = remote_radio.tx_history[-1]
    local_radio.queue_rx(signed_success)
    received = await local_link.receive(100)
    assert isinstance(received, RxFrame)
    detached = received.frame
    detached.payload = failure
    assert received.payload == success
    assert sender.handle_ack_frame(received) == []
    assert sender.status == "succeeded"

    local_radio.queue_rx(signed_success)
    assert await local_link.receive(100) == ReceiveError.REPLAY


def test_ack_transition_uses_detached_receipt_after_facade_corruption() -> None:
    harness, sender = bound_sender(replay_counter=0)
    expected = sender.start()
    received = harness.receive(bytes.fromhex("7840"), 1)
    assert isinstance(received, RxFrame)

    object.__setattr__(received, "_authenticated_payload", bytes.fromhex("7800"))
    object.__setattr__(received, "_authenticated_sender_pubkey", LOCAL_IDENTITY)
    object.__setattr__(received, "_authenticated_local_pubkey", REMOTE_IDENTITY)
    object.__setattr__(received, "_authenticated_epoch", 0)
    object.__setattr__(received, "_authenticated_seqnum", 0)

    assert expected
    assert sender.handle_ack_frame(received) == []
    assert sender.status == "succeeded"


def test_link_issued_sender_ignores_forged_facade_state() -> None:
    harness, sender = bound_sender(payload=b"authoritative", replay_counter=0)
    original_fragments = sender.all_fragments()
    sender.start()
    object.__setattr__(sender, "_manager", None)
    object.__setattr__(sender, "_attempts", 99)
    object.__setattr__(sender, "_status", "succeeded")
    object.__setattr__(sender, "_fragments", ())
    object.__setattr__(sender, "rule_id", 0x79)

    assert sender.status == "active"
    assert sender.attempts == 1
    assert sender.all_fragments() == original_fragments
    received = harness.receive(bytes.fromhex("7840"), 1)
    assert isinstance(received, RxFrame)
    assert sender.handle_ack_frame(received) == []
    assert sender.status == "succeeded"


@pytest.mark.parametrize("elapsed,accepted", [(59.999, True), (60.0, False)])
def test_verified_receipt_has_exact_monotonic_ttl(elapsed: float, accepted: bool) -> None:
    now = [100.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    received = harness.receive(b"authenticated", 0)
    assert isinstance(received, RxFrame)
    now[0] += elapsed

    if accepted:
        snapshot = harness.local_link.consume_verified_receipt(received, purpose="dio-time")
        assert snapshot.payload == b"authenticated"
    else:
        with pytest.raises(ValueError, match="unconsumed verified receipt"):
            harness.local_link.consume_verified_receipt(received, purpose="dio-time")


def test_link_exposes_clock_capability_domain_before_first_receipt() -> None:
    class Clock:
        def __call__(self) -> float:
            return 100.0

    clock = MonotonicClock(Clock())
    harness = SessionHarness(-1, receipt_clock=clock)
    assert harness.local_link.clock_domain_identity is clock.domain_identity
    received = harness.receive(b"clock-bound", 0)
    assert isinstance(received, RxFrame)
    assert received.clock_domain is clock.domain_identity


def test_unlabelled_offset_clocks_receive_distinct_safe_domains() -> None:
    first = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: 10.0))
    second = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: 20.0))
    assert first.local_link.clock_domain_identity is not second.local_link.clock_domain_identity


def test_prepared_sender_expires_at_exact_lease_boundary() -> None:
    now = [0.0]
    harness = SessionHarness(0, receipt_clock=MonotonicClock(lambda: now[0]))
    sender = _link_sender(harness, b"x")
    now[0] = 59.999
    assert sender.status == "ready"
    now[0] = 60.0
    assert sender.status == "expired"
    with pytest.raises(FragmentError, match="not link-issued"):
        sender.start()


def test_authenticated_rekey_is_one_use_and_never_reopens_retired_key() -> None:
    replacement = Identity.from_seed(bytes(range(64, 96)))
    harness = SessionHarness(0, additional_remote_nodes=(replacement,))
    evidence = harness.receive(encode_rekey_request(replacement.pubkey), 1)
    assert isinstance(evidence, RxFrame)
    harness.local_link.apply_authenticated_rekey(evidence)
    with pytest.raises(ValueError, match="unconsumed verified receipt"):
        harness.local_link.apply_authenticated_rekey(evidence)

    replacement_radio = _AckWireRadio()
    replacement_link = LinkLayer(
        radio=replacement_radio,  # type: ignore[arg-type]
        identity=replacement,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )
    replacement_link._epoch = 0
    replacement_link._seqnum = 0
    assert asyncio.run(replacement_link.send(encode_rekey_request(REMOTE_IDENTITY)))
    harness.local_radio.queue_rx(replacement_radio.tx_history[-1])
    reverse = asyncio.run(harness.local_link.receive(100))
    assert isinstance(reverse, RxFrame)
    with pytest.raises(ValueError, match="already has live security state"):
        harness.local_link.apply_authenticated_rekey(reverse)


def test_receipts_stamp_stable_clock_domain_and_rotating_key_generation() -> None:
    replacement = Identity.from_seed(bytes(range(64, 96)))
    harness = SessionHarness(-1, additional_remote_nodes=(replacement,))
    first = harness.receive(b"first", 0)
    evidence = harness.receive(encode_rekey_request(replacement.pubkey), 1)
    assert isinstance(first, RxFrame)
    assert isinstance(evidence, RxFrame)
    assert first.clock_domain is evidence.clock_domain
    assert first.key_generation is evidence.key_generation
    harness.local_link.apply_authenticated_rekey(evidence)

    replacement_radio = _AckWireRadio()
    replacement_link = LinkLayer(
        radio=replacement_radio,  # type: ignore[arg-type]
        identity=replacement,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )
    replacement_link._epoch = 0
    replacement_link._seqnum = 0
    assert asyncio.run(replacement_link.send(b"replacement"))
    harness.local_radio.queue_rx(replacement_radio.tx_history[-1])
    current = asyncio.run(harness.local_link.receive(100))
    assert isinstance(current, RxFrame)
    assert current.clock_domain is first.clock_domain
    assert current.key_generation is not first.key_generation


def test_rotation_revokes_receipt_by_detached_sender_snapshot() -> None:
    replacement = Identity.from_seed(bytes(range(64, 96)))
    harness = SessionHarness(0, additional_remote_nodes=(replacement,))
    stale = harness.receive(b"old", 1)
    evidence = harness.receive(encode_rekey_request(replacement.pubkey), 2)
    assert isinstance(stale, RxFrame)
    assert isinstance(evidence, RxFrame)
    object.__setattr__(stale, "_authenticated_sender_pubkey", replacement.pubkey)
    harness.local_link.apply_authenticated_rekey(evidence)
    with pytest.raises(ValueError, match="unconsumed verified receipt"):
        harness.local_link.consume_verified_receipt(stale, purpose="dio-time")


def test_receipt_elevation_is_linearized_against_key_rotation() -> None:
    replacement = Identity.from_seed(bytes(range(64, 96)))
    harness = SessionHarness(0, additional_remote_nodes=(replacement,))
    received = harness.receive(b"time-option", 1)
    evidence = harness.receive(encode_rekey_request(replacement.pubkey), 2)
    assert isinstance(received, RxFrame)
    assert isinstance(evidence, RxFrame)
    entered = threading.Event()
    release = threading.Event()
    rotated = threading.Event()
    output: list[bytes] = []

    def elevate(snapshot: RxFrame) -> bytes:
        entered.set()
        assert release.wait(2)
        return snapshot.payload

    def run_elevation() -> None:
        output.append(
            harness.local_link.elevate_verified_receipt(
                received, purpose="dio-time", elevate=elevate
            )
        )

    def rotate() -> None:
        harness.local_link.apply_authenticated_rekey(evidence)
        rotated.set()

    elevation_thread = threading.Thread(target=run_elevation)
    rotation_thread = threading.Thread(target=rotate)
    elevation_thread.start()
    assert entered.wait(2)
    rotation_thread.start()
    assert not rotated.wait(0.05)
    release.set()
    elevation_thread.join(2)
    rotation_thread.join(2)
    assert output == [b"time-option"]
    assert rotated.is_set()


def test_one_peer_receipt_flood_cannot_evict_another_peers_receipt() -> None:
    flooder = Identity.from_seed(bytes(range(64, 96)))
    harness = SessionHarness(-1, additional_remote_nodes=(flooder,))
    victim = harness.receive(b"victim", 0)
    assert isinstance(victim, RxFrame)
    flood_radio = _AckWireRadio()
    flood_link = LinkLayer(
        radio=flood_radio,  # type: ignore[arg-type]
        identity=flooder,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: [],
        cad_enabled=False,
    )
    flood_link._epoch = 0
    flood_link._seqnum = 0
    for index in range(17):
        assert asyncio.run(flood_link.send(f"flood-{index}".encode()))
        harness.local_radio.queue_rx(flood_radio.tx_history[-1])
        assert isinstance(asyncio.run(harness.local_link.receive(100)), RxFrame)

    snapshot = harness.local_link.consume_verified_receipt(victim, purpose="dio-time")
    assert snapshot.payload == b"victim"


def test_sender_creation_is_atomic_with_authenticated_rekey() -> None:
    replacement = Identity.from_seed(bytes(range(64, 96)))
    harness = SessionHarness(0, additional_remote_nodes=(replacement,))
    evidence = harness.receive(encode_rekey_request(replacement.pubkey), 1)
    assert isinstance(evidence, RxFrame)
    barrier = threading.Barrier(2)
    returned: list[FragmentSender] = []
    failures: list[BaseException] = []

    def create() -> None:
        barrier.wait()
        try:
            returned.append(_link_sender(harness, b"race"))
        except BaseException as exc:
            failures.append(exc)

    def rotate() -> None:
        barrier.wait()
        harness.local_link.apply_authenticated_rekey(evidence)

    create_thread = threading.Thread(target=create)
    rotate_thread = threading.Thread(target=rotate)
    create_thread.start()
    rotate_thread.start()
    create_thread.join(2)
    rotate_thread.join(2)
    assert not create_thread.is_alive()
    assert not rotate_thread.is_alive()
    assert len(returned) + len(failures) == 1
    if returned:
        assert returned[0].status == "invalidated"
        with pytest.raises(FragmentError, match="not link-issued"):
            returned[0].start()
    else:
        assert isinstance(failures[0], ValueError)
        assert "retired signer" in str(failures[0])


def test_issued_manager_registry_does_not_root_abandoned_link_cycles() -> None:
    from lichen.schc.fragment import _ISSUED_MANAGERS

    gc.collect()
    baseline = len(_ISSUED_MANAGERS)
    link_refs: list[weakref.ReferenceType[LinkLayer]] = []
    sender_refs: list[weakref.ReferenceType[FragmentSender]] = []
    for _ in range(12):
        harness = SessionHarness(0)
        sender = _link_sender(harness, b"gc")
        link_refs.append(weakref.ref(harness.local_link))
        sender_refs.append(weakref.ref(sender))
        del sender, harness
    gc.collect()

    assert all(reference() is None for reference in link_refs)
    assert all(reference() is None for reference in sender_refs)
    assert len(_ISSUED_MANAGERS) == baseline

    live_harness = SessionHarness(0)
    live_sender = _link_sender(live_harness, b"live")
    object.__setattr__(live_sender, "_manager", None)
    assert live_sender.start()
    assert live_sender.status == "active"


def test_peer_policy_gates_unfragmented_ingress_and_egress() -> None:
    packet = _schc_payload(b"peer-policy")
    raw = decompress_packet(packet)

    missing = SessionHarness(-1)
    received = missing.receive(wrap_schc_payload(packet), 0)
    assert isinstance(received, RxFrame)
    with pytest.raises(ValueError, match="authenticated replay-accepted peer DIO"):
        missing.local_link.accept_authenticated_schc_packet(received)
    with pytest.raises(ValueError, match="authenticated replay-accepted peer DIO"):
        missing.local_link.compress_schc_for_peer(raw, REMOTE_IDENTITY)

    compatible = SessionHarness(-1)
    _authorize_link_schc(compatible.local_link, REMOTE_IDENTITY, 3)
    received = compatible.receive(wrap_schc_payload(packet), 0)
    assert isinstance(received, RxFrame)
    assert compatible.local_link.accept_authenticated_schc_packet(received) == raw
    assert compatible.local_link.compress_schc_for_peer(raw, REMOTE_IDENTITY)[0] == 2

    mismatch = SessionHarness(-1)
    _authorize_link_schc(mismatch.local_link, REMOTE_IDENTITY, 2)
    received = mismatch.receive(wrap_schc_payload(packet), 0)
    assert isinstance(received, RxFrame)
    with pytest.raises(SchcError, match="Rule 255"):
        mismatch.local_link.accept_authenticated_schc_packet(received)
    fallback = encode_rule255(raw, single_frame_limit=201)
    received = mismatch.receive(wrap_schc_payload(fallback), 1)
    assert isinstance(received, RxFrame)
    assert mismatch.local_link.accept_authenticated_schc_packet(received) == raw
    assert mismatch.local_link.compress_schc_for_peer(raw, REMOTE_IDENTITY) == fallback

    stale = SessionHarness(-1)
    _authorize_link_schc(stale.local_link, REMOTE_IDENTITY, 3, admitted_counter=5)
    received = stale.receive(wrap_schc_payload(packet), 5)
    assert isinstance(received, RxFrame)
    with pytest.raises(ValueError, match="predates"):
        stale.local_link.accept_authenticated_schc_packet(received)
    received = stale.receive(wrap_schc_payload(packet), 6)
    assert isinstance(received, RxFrame)
    assert stale.local_link.accept_authenticated_schc_packet(received) == raw


def test_fragment_sender_validates_before_allocation_and_seals_wire_once() -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    with pytest.raises(ValueError, match="canonical complete SCHC packet"):
        harness.local_link.create_fragment_sender(b"\x00truncated", REMOTE_IDENTITY)
    assert not harness.local_link._schc_session_manager._prepared

    sender = harness.local_link.create_fragment_sender(_schc_payload(bytes(400)), REMOTE_IDENTITY)
    wires = sender.start()
    assert len(wires) > 1
    assert asyncio.run(
        harness.local_link.send(
            wires[0],
            iid_to_eui64(PeerIdentity.from_pubkey(REMOTE_IDENTITY).iid),
            AddrMode.EXTENDED,
            Priority.BULK,
        )
    )
    with pytest.raises(ValueError, match="stale.*not issued"):
        asyncio.run(
            harness.local_link.send(
                wires[0],
                iid_to_eui64(PeerIdentity.from_pubkey(REMOTE_IDENTITY).iid),
                AddrMode.EXTENDED,
                Priority.BULK,
            )
        )
    with pytest.raises(ValueError, match="raw link dispatches"):
        asyncio.run(harness.local_link.send(wrap_schc_payload(bytes(wires[1]))))
    with pytest.raises(ValueError, match="manager-issued one-use wire"):
        asyncio.run(
            harness.local_link.send(
                bytes(wires[1]),
                iid_to_eui64(PeerIdentity.from_pubkey(REMOTE_IDENTITY).iid),
                AddrMode.EXTENDED,
                Priority.BULK,
            )
        )


@pytest.mark.parametrize(
    "payload",
    [
        b"\x78",
        b"\x79\x01",
        Fragment(0x78, 0, 62, bytes(TILE_SIZE)).to_bytes(),
        ack_request(0x78, 0),
        sender_abort(0x78),
        Ack(0x79, 0, complete=True).to_bytes(),
        receiver_abort(0x79),
    ],
    ids=[
        "truncated",
        "nonzero-padding",
        "valid-fragment-copy",
        "ack-request",
        "sender-abort",
        "ack",
        "receiver-abort",
    ],
)
def test_link_rejects_every_unissued_reserved_fragmentation_wire(payload: bytes) -> None:
    harness = SessionHarness(-1)
    destination = iid_to_eui64(REMOTE_NODE.iid)
    before_counter = (harness.local_link._epoch, harness.local_link._seqnum)

    with pytest.raises(ValueError, match="manager-issued one-use wire"):
        asyncio.run(
            harness.local_link.send(
                payload,
                destination,
                AddrMode.EXTENDED,
                Priority.ACK,
            )
        )

    assert harness.local_radio.tx_history == []
    assert (harness.local_link._epoch, harness.local_link._seqnum) == before_counter


@pytest.mark.parametrize(
    "control,response",
    [
        (ack_request(0x78, 0), False),
        (sender_abort(0x78), False),
        (Ack(0x79, 0, complete=True).to_bytes(), True),
        (receiver_abort(0x79), True),
    ],
)
def test_direct_fragment_control_issuance_requires_link_transition_authority(
    control: bytes, response: bool
) -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    generation = harness.local_link._key_generations[REMOTE_IDENTITY]
    manager = harness.local_link._schc_session_manager
    assert not hasattr(manager, "issue_control_wire")

    with pytest.raises(FragmentError, match="transition authority"):
        manager._issue_link_transition_control_wire(
            object(),
            control,
            REMOTE_IDENTITY,
            generation,
            response=response,
        )

    with pytest.raises(FragmentError, match="not current"):
        manager._issue_link_transition_control_wire(
            harness.local_link._schc_control_issuer_token,
            control,
            REMOTE_IDENTITY,
            object(),
            response=response,
        )


def test_terminal_sender_transition_revokes_outstanding_ack_request_authority() -> None:
    harness, sender = bound_sender(replay_counter=0)
    sender.start()
    request = sender.timeout()
    complete = harness.receive(Ack(0x78, 0, complete=True).to_bytes(), 1)
    assert isinstance(complete, RxFrame)
    assert sender.handle_ack_frame(complete) == []
    assert sender.status == "succeeded"

    with pytest.raises(ValueError, match="stale.*not issued"):
        asyncio.run(
            harness.local_link.send(
                request,
                iid_to_eui64(REMOTE_NODE.iid),
                AddrMode.EXTENDED,
                Priority.ACK,
            )
        )


def test_dropped_prepared_sender_releases_registry_immediately() -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    sender = harness.local_link.create_fragment_sender(_schc_payload(bytes(400)), REMOTE_IDENTITY)
    sender_reference = weakref.ref(sender)
    sender_id = id(sender)
    assert sender_id in harness.local_link._schc_session_manager._prepared

    del sender
    gc.collect()

    assert sender_reference() is None
    assert sender_id not in harness.local_link._schc_session_manager._prepared


def test_fragmented_rule255_uses_reassembly_limit_not_single_frame_limit() -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    packet = _rule255_payload(400)

    sender = harness.remote_link.create_fragment_sender(
        packet,
        LOCAL_IDENTITY,
        receiver_limit=len(packet),
    )
    decoded = None
    for counter, wire in enumerate(sender.start()):
        received = harness.receive(wire, counter)
        assert isinstance(received, RxFrame)
        _, candidate = harness.local_link.accept_authenticated_schc_fragment(received)
        if candidate is not None:
            decoded = candidate

    assert decoded == packet[1:]


def test_link_derives_directional_fragment_rule_and_rejects_caller_mismatch() -> None:
    harness = SessionHarness(-1)
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    local_sender = harness.local_link.create_fragment_sender(
        _schc_payload(bytes(400)), REMOTE_IDENTITY
    )
    assert local_sender.rule_id == 0x78
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        harness.local_link.create_fragment_sender(
            _schc_payload(bytes(400)), REMOTE_IDENTITY, rule_id=0x79
        )

    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    remote_sender = harness.remote_link.create_fragment_sender(
        _schc_payload(bytes(400)), LOCAL_IDENTITY
    )
    assert remote_sender.rule_id == 0x79
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        harness.remote_link.create_fragment_sender(
            _schc_payload(bytes(400)), LOCAL_IDENTITY, rule_id=0x78
        )


def test_authenticated_receiver_abort_terminates_sender_without_receiver_allocation() -> None:
    harness, sender = bound_sender(replay_counter=0)
    sender.start()
    received = harness.receive(receiver_abort(0x78), 1)
    assert isinstance(received, RxFrame)
    assert harness.local_link.accept_authenticated_schc_sender_control(received) == []
    assert sender.status == "aborted"
    assert not harness.local_link._schc_reassembly_manager._contexts


def test_link_owned_authenticated_reassembly_validates_and_completes() -> None:
    harness = SessionHarness(-1)
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    packet = _schc_payload(bytes(400))
    expected = decompress_packet(packet)
    sender = harness.remote_link.create_fragment_sender(packet, LOCAL_IDENTITY)
    wires = sender.start()
    decoded: bytes | None = None
    final_result = None
    for counter, wire in enumerate(wires):
        received = harness.receive(wire, counter)
        assert isinstance(received, RxFrame)
        final_result, decoded = harness.local_link.accept_authenticated_schc_fragment(received)
    assert final_result is not None
    assert final_result.reassembled == packet
    assert final_result.response == Ack(sender.rule_id, 0, complete=True).to_bytes()
    assert decoded == expected
    assert not harness.local_link._schc_reassembly_manager._contexts
    assert len(harness.local_link._schc_reassembly_manager._tombstones) == 1


def test_authenticated_sender_abort_targets_receiver_during_bidirectional_session() -> None:
    harness = SessionHarness(-1)
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    local_sender = harness.local_link.create_fragment_sender(
        _schc_payload(bytes(400)), REMOTE_IDENTITY
    )
    local_sender.start()
    remote_sender = harness.remote_link.create_fragment_sender(
        _schc_payload(bytes(400)), LOCAL_IDENTITY
    )
    first_wire = remote_sender.start()[0]
    received = harness.receive(first_wire, 0)
    assert isinstance(received, RxFrame)
    result, decoded = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.reassembled is None
    assert decoded is None

    received = harness.receive(sender_abort(0x79), 1)
    assert isinstance(received, RxFrame)
    assert harness.local_link.accept_authenticated_schc_sender_control(received) is None
    result, decoded = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.aborted
    assert decoded is None
    assert local_sender.status == "active"
    assert not harness.local_link._schc_reassembly_manager._contexts


def test_authenticated_malformed_fragment_aborts_without_allocating() -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    received = harness.receive(b"\x79", 0)
    assert isinstance(received, RxFrame)
    result, decoded = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.aborted
    assert result.response == receiver_abort(0x79)
    assert decoded is None
    assert not harness.local_link._schc_reassembly_manager._contexts
    rejection = next(iter(harness.local_link._schc_reassembly_manager._rejections.values()))
    assert rejection.high_water == 0

    repeated = harness.receive(b"\x79", 1)
    assert isinstance(repeated, RxFrame)
    repeated_result, _ = harness.local_link.accept_authenticated_schc_fragment(repeated)
    assert repeated_result.response is None
    rejection = next(iter(harness.local_link._schc_reassembly_manager._rejections.values()))
    assert rejection.high_water == 1

    terminal = harness.receive(ack_request(0x79, 0), 2)
    assert isinstance(terminal, RxFrame)
    terminal_result, _ = harness.local_link.accept_authenticated_schc_fragment(terminal)
    assert terminal_result.response is None
    rejection = next(iter(harness.local_link._schc_reassembly_manager._rejections.values()))
    assert rejection.high_water == 2
    assert harness.local_link._schc_reassembly_manager.export_persistence_state() == [
        {
            "remote": REMOTE_IDENTITY.hex(),
            "rule_id": 0x79,
            "high_water": 2,
            "status": "rejected",
            "response": receiver_abort(0x79).hex(),
        }
    ]


def test_tofu_eviction_retires_stale_peer_policy_and_preserves_replay_floor() -> None:
    established = [Identity.from_seed(seed.to_bytes(32, "big")) for seed in range(65, 129)]
    newcomer = Identity.from_seed(bytes([0xF1]) * 32)
    local_radio = _AckWireRadio()
    known = [
        PeerIdentity.from_pubkey(established[0].pubkey),
        PeerIdentity.from_pubkey(newcomer.pubkey),
    ]
    local_link = LinkLayer(
        radio=local_radio,  # type: ignore[arg-type]
        identity=LOCAL_NODE,
        peer_lookup=lambda _hint: None,
        peer_lookup_all=lambda: known,
        replay_protector=ReplayProtector(max_peers=64, max_retained_floors=128),
        cad_enabled=False,
    )
    first_radio = _AckWireRadio()
    first_link = LinkLayer(
        radio=first_radio,  # type: ignore[arg-type]
        identity=established[0],
        peer_lookup=lambda _hint: None,
        cad_enabled=False,
        _epoch=0,
    )
    assert asyncio.run(first_link.send(b"first"))
    local_radio.queue_rx(first_radio.tx_history[-1])
    first_receipt = asyncio.run(local_link.receive(100))
    assert isinstance(first_receipt, RxFrame)
    assert id(first_receipt) in local_link._verified_receipts
    for identity in established:
        _authorize_link_schc(local_link, identity.pubkey)
    victim = established[0]
    victim_context = local_link._schc_peer_contexts[victim.pubkey]

    newcomer_radio = _AckWireRadio()
    newcomer_link = LinkLayer(
        radio=newcomer_radio,  # type: ignore[arg-type]
        identity=newcomer,
        peer_lookup=lambda _hint: None,
        cad_enabled=False,
        _epoch=0,
    )
    assert asyncio.run(newcomer_link.send(b"new"))
    local_radio.queue_rx(newcomer_radio.tx_history[-1])
    admitted = asyncio.run(local_link.receive(100))
    assert isinstance(admitted, RxFrame)
    assert victim.pubkey not in local_link._schc_peer_contexts
    assert id(victim_context) not in local_link._schc_peer_context_issuances
    assert id(first_receipt) not in local_link._verified_receipts
    assert victim.pubkey not in local_link._key_generations
    assert local_link.replay_protector.highest(victim.pubkey) == 0
    assert len(local_link._pinned_keys) == 64
    assert len(local_link._schc_peer_contexts) == 63

    local_link.consume_verified_receipt(admitted, purpose="schc-data")
    assert asyncio.run(first_link.send(b"again"))
    local_radio.queue_rx(first_radio.tx_history[-1])
    readmitted = asyncio.run(local_link.receive(100))
    assert isinstance(readmitted, RxFrame)
    assert local_link.replay_protector.highest(victim.pubkey) == 1


def test_tofu_eviction_blocker_covers_active_and_tombstoned_fragmentation() -> None:
    now = [0.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    harness.authorize_schc()
    sender = harness.local_link.create_fragment_sender(_schc_payload(bytes(400)), REMOTE_IDENTITY)
    sender.start()
    assert harness.local_link._peer_has_eviction_blocker_unlocked(REMOTE_IDENTITY)
    sender.cancel()
    assert harness.local_link._peer_has_eviction_blocker_unlocked(REMOTE_IDENTITY)

    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    inbound = harness.remote_link.create_fragment_sender(_schc_payload(bytes(400)), LOCAL_IDENTITY)
    received = harness.receive(inbound.start()[0], 0)
    assert isinstance(received, RxFrame)
    result, _ = harness.local_link.accept_authenticated_schc_fragment(received)
    assert not result.aborted
    assert harness.local_link._peer_has_eviction_blocker_unlocked(REMOTE_IDENTITY)

    aborted = harness.receive(sender_abort(inbound.rule_id), 1)
    assert isinstance(aborted, RxFrame)
    result, _ = harness.local_link.accept_authenticated_schc_fragment(aborted)
    assert result.aborted
    assert harness.local_link._peer_has_eviction_blocker_unlocked(REMOTE_IDENTITY)

    now[0] = AUTHENTICATED_HOLD_DOWN_SECONDS
    assert not harness.local_link._peer_has_eviction_blocker_unlocked(REMOTE_IDENTITY)
    manager = harness.local_link._schc_reassembly_manager
    assert manager.replacement_occupied(REMOTE_IDENTITY)
    assert any(key[1] == REMOTE_IDENTITY for key in manager._floors)

    replay_floor = harness.local_link.replay_protector.highest(REMOTE_IDENTITY)
    remote_iid = PeerIdentity.from_pubkey(REMOTE_IDENTITY).iid
    harness.local_link._retire_evicted_peer_unlocked(remote_iid, REMOTE_IDENTITY)
    assert REMOTE_IDENTITY not in harness.local_link._key_generations
    assert not manager.replacement_occupied(REMOTE_IDENTITY)
    assert harness.local_link.replay_protector.highest(REMOTE_IDENTITY) == replay_floor


def test_tofu_capacity_rejects_active_session_saturation_until_hold_down_expires() -> None:
    established = [Identity.from_seed(seed.to_bytes(32, "big")) for seed in range(129, 193)]
    newcomer = Identity.from_seed(bytes([0xF2]) * 32)
    newcomer_peer = PeerIdentity.from_pubkey(newcomer.pubkey)
    radio = _AckWireRadio()
    now = [0.0]
    link = LinkLayer(
        radio=radio,  # type: ignore[arg-type]
        identity=LOCAL_NODE,
        peer_lookup=lambda _hint: newcomer_peer,
        peer_lookup_all=lambda: [newcomer_peer],
        replay_protector=ReplayProtector(max_peers=64, max_retained_floors=128),
        cad_enabled=False,
        receipt_clock=MonotonicClock(lambda: now[0]),
    )
    senders: list[FragmentSender] = []
    packet = _schc_payload(b"active")
    for identity in established:
        _authorize_link_schc(link, identity.pubkey)
        sender = link.create_fragment_sender(packet, identity.pubkey)
        sender.start()
        senders.append(sender)
    newcomer_radio = _AckWireRadio()
    newcomer_link = LinkLayer(
        radio=newcomer_radio,  # type: ignore[arg-type]
        identity=newcomer,
        peer_lookup=lambda _hint: None,
        cad_enabled=False,
        _epoch=0,
    )
    assert asyncio.run(newcomer_link.send(b"newcomer"))
    wire = newcomer_radio.tx_history[-1]

    radio.queue_rx(wire)
    assert asyncio.run(link.receive(100)) is ReceiveError.REPLAY
    assert link.replay_protector.highest(newcomer.pubkey) == -1
    assert len(link._pinned_keys) == 64

    senders[0].cancel()
    now[0] = 59.999
    radio.queue_rx(wire)
    assert asyncio.run(link.receive(100)) is ReceiveError.REPLAY
    now[0] = 60.0
    radio.queue_rx(wire)
    admitted = asyncio.run(link.receive(100))
    assert isinstance(admitted, RxFrame)
    assert len(link._pinned_keys) == 64
    assert newcomer_peer.iid in link._pinned_keys


def test_authenticated_duplicate_tile_is_idempotent_but_conflict_aborts() -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    original = Fragment(0x79, 0, 62, bytes(TILE_SIZE)).to_bytes()

    def receive_payload(payload: bytes, counter: int) -> RxFrame:
        signer_eui64 = iid_to_eui64(REMOTE_NODE.iid)
        frame_length = 4 + len(LOCAL_NODE.iid) + len(signer_eui64) + len(payload) + 48
        llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
        destination = iid_to_eui64(LOCAL_NODE.iid)
        signable = harness.remote_link._build_signable_data(
            0,
            counter,
            destination,
            payload,
            frame_length,
            llsec,
            signer_eui64,
        )
        wire = LichenFrame(
            epoch=0,
            seqnum=counter,
            dst_addr=destination,
            payload=payload,
            mic=sign(REMOTE_NODE.privkey, REMOTE_NODE.pubkey, signable),
            addr_mode=AddrMode.EXTENDED,
            signature_present=True,
            signer_eui64=signer_eui64,
        ).to_bytes()
        harness.local_radio.queue_rx(wire)
        received = asyncio.run(harness.local_link.receive(100))
        assert isinstance(received, RxFrame)
        return received

    first, _ = harness.local_link.accept_authenticated_schc_fragment(receive_payload(original, 0))
    assert first.response is None
    contexts = dict(harness.local_link._schc_reassembly_manager._contexts)
    duplicate, _ = harness.local_link.accept_authenticated_schc_fragment(
        receive_payload(original, 1)
    )
    assert duplicate.response is None
    assert harness.local_link._schc_reassembly_manager._contexts == contexts

    conflicting = Fragment(0x79, 0, 62, bytes([1]) * TILE_SIZE).to_bytes()
    conflict, _ = harness.local_link.accept_authenticated_schc_fragment(
        receive_payload(conflicting, 2)
    )
    assert conflict.aborted
    assert conflict.response == receiver_abort(0x79)
    assert not harness.local_link._schc_reassembly_manager._contexts


def test_t0_terminal_barrier_and_replacement_admission_floor() -> None:
    vector = next(
        item
        for item in SCHC_SESSION_SECURITY["vectors"]
        if item["name"] == "late_messages_advance_terminal_floor"
    )
    assert [event.get("counter") for event in vector["events"]] == [0, 1, 2, 3, 4, 5, 3]
    assert SCHC_SESSION_SECURITY["profile"]["all1_may_open"] is False
    now = [0.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    harness.authorize_schc()
    manager = harness.local_link._schc_reassembly_manager
    destination = iid_to_eui64(LOCAL_NODE.iid)
    signer_eui64 = iid_to_eui64(REMOTE_NODE.iid)

    def receive_payload(payload: bytes, counter: int) -> RxFrame | ReceiveError:
        frame_length = 4 + len(destination) + len(signer_eui64) + len(payload) + 48
        llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
        signable = harness.remote_link._build_signable_data(
            0, counter, destination, payload, frame_length, llsec, signer_eui64
        )
        wire = LichenFrame(
            epoch=0,
            seqnum=counter,
            dst_addr=destination,
            payload=payload,
            mic=sign(REMOTE_NODE.privkey, REMOTE_NODE.pubkey, signable),
            addr_mode=AddrMode.EXTENDED,
            signature_present=True,
            signer_eui64=signer_eui64,
        ).to_bytes()
        harness.local_radio.queue_rx(wire)
        return asyncio.run(harness.local_link.receive(100))

    opener = Fragment(0x79, 0, 62, b"a" * TILE_SIZE).to_bytes()
    non_opener = Fragment(0x79, 0, 61, b"b" * TILE_SIZE).to_bytes()
    old_all1 = Fragment(0x79, 0, ALL_1, b"z", compute_mic(b"z")).to_bytes()

    opened = receive_payload(opener, 0)
    assert isinstance(opened, RxFrame)
    harness.local_link.accept_authenticated_schc_fragment(opened)
    aborted = receive_payload(sender_abort(0x79), 1)
    assert isinstance(aborted, RxFrame)
    result, _ = harness.local_link.accept_authenticated_schc_fragment(aborted)
    assert result.aborted

    late_regular = receive_payload(non_opener, 2)
    assert isinstance(late_regular, RxFrame)
    harness.local_link.accept_authenticated_schc_fragment(late_regular)
    late_all1 = receive_payload(old_all1, 3)
    assert isinstance(late_all1, RxFrame)
    harness.local_link.accept_authenticated_schc_fragment(late_all1)
    tombstone = next(iter(manager._tombstones.values()))
    assert tombstone.high_water == 3

    now[0] = AUTHENTICATED_HOLD_DOWN_SECONDS
    after_hold_down = receive_payload(non_opener, 4)
    assert isinstance(after_hold_down, RxFrame)
    ignored, _ = harness.local_link.accept_authenticated_schc_fragment(after_hold_down)
    assert ignored.response is None
    assert not manager._contexts
    floor_key = next(iter(manager._floors))
    assert floor_key[2] is after_hold_down.key_generation
    assert next(iter(manager._floors.values())) == 4

    replacement = receive_payload(opener, 5)
    assert isinstance(replacement, RxFrame)
    harness.local_link.accept_authenticated_schc_fragment(replacement)
    context = next(iter(manager._contexts.values()))
    assert context.admission_floor == 5
    snapshot = dict(manager._contexts)

    # The old All-1 counter predates the immutable replacement admission floor;
    # link replay rejects it before reassembly can mutate the new context.
    replayed_old = receive_payload(old_all1, 3)
    assert replayed_old is ReceiveError.REPLAY
    assert manager._contexts == snapshot


def test_reassembly_same_key_reinstall_uses_distinct_generation_domain() -> None:
    profile = SCHC_SESSION_SECURITY["profile"]
    assert profile["generation_components"] == [
        "local_public_key",
        "remote_public_key",
        "remote_key_generation",
        "directional_rule_id",
    ]
    assert "fixed-local-key owner" in profile["local_generation_policy"]
    vector = next(
        item
        for item in SCHC_SESSION_SECURITY["vectors"]
        if item["name"] == "same_public_key_new_generation"
    )
    assert vector["events"][1]["action"] == "revoke_and_reinstall_same_public_key"
    now = [0.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    harness.authorize_schc()
    manager = harness.local_link._schc_reassembly_manager
    destination = iid_to_eui64(LOCAL_NODE.iid)
    signer_eui64 = iid_to_eui64(REMOTE_NODE.iid)

    def receive_opener(counter: int) -> RxFrame:
        payload = Fragment(0x79, 0, 62, bytes([counter]) * TILE_SIZE).to_bytes()
        frame_length = 4 + len(destination) + len(signer_eui64) + len(payload) + 48
        llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
        signable = harness.remote_link._build_signable_data(
            0, counter, destination, payload, frame_length, llsec, signer_eui64
        )
        wire = LichenFrame(
            epoch=0,
            seqnum=counter,
            dst_addr=destination,
            payload=payload,
            mic=sign(REMOTE_NODE.privkey, REMOTE_NODE.pubkey, signable),
            addr_mode=AddrMode.EXTENDED,
            signature_present=True,
            signer_eui64=signer_eui64,
        ).to_bytes()
        harness.local_radio.queue_rx(wire)
        received = asyncio.run(harness.local_link.receive(100))
        assert isinstance(received, RxFrame)
        return received

    first = receive_opener(0)
    old_generation = first.key_generation
    harness.local_link.accept_authenticated_schc_fragment(first)
    assert next(iter(manager._contexts.values())).generation is old_generation

    replacement_generation = object()
    harness.local_link._key_generations[REMOTE_IDENTITY] = replacement_generation
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    replacement = receive_opener(1)
    assert replacement.key_generation is replacement_generation
    harness.local_link.accept_authenticated_schc_fragment(replacement)

    assert len(manager._contexts) == 1
    key, context = next(iter(manager._contexts.items()))
    assert key[2] is replacement_generation
    assert context.generation is replacement_generation
    assert all(key[2] is not old_generation for key in manager._tombstones)
    assert all(key[2] is not old_generation for key in manager._floors)


def test_public_reassembly_expiry_api_drains_exact_receiver_abort_once() -> None:
    now = [0.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    sender = harness.remote_link.create_fragment_sender(_schc_payload(bytes(400)), LOCAL_IDENTITY)
    first = harness.receive(sender.start()[0], 0)
    assert isinstance(first, RxFrame)
    harness.local_link.accept_authenticated_schc_fragment(first)

    now[0] = AUTHENTICATED_HOLD_DOWN_SECONDS
    assert harness.local_link.expire_authenticated_schc_reassembly() == [
        (
            REMOTE_IDENTITY,
            iid_to_eui64(REMOTE_NODE.iid),
            receiver_abort(sender.rule_id),
        )
    ]
    assert harness.local_link.expire_authenticated_schc_reassembly() == []
    tombstone = next(iter(harness.local_link._schc_reassembly_manager._tombstones.values()))
    assert tombstone.status == "expired"
    assert tombstone.response == receiver_abort(sender.rule_id)


@pytest.mark.parametrize(
    "replacement_status",
    ["active", "aborted", "rejected"],
)
def test_reassembly_floor_replacement_persistence_round_trip(
    replacement_status: str,
) -> None:
    now = [10.0]
    harness = SessionHarness(4, receipt_clock=MonotonicClock(lambda: now[0]))
    harness.authorize_schc()
    manager = harness.local_link._schc_reassembly_manager
    generation = harness.local_link._key_generations[REMOTE_IDENTITY]
    key = (LOCAL_IDENTITY, REMOTE_IDENTITY, generation, 0x79)
    manager._floors[key] = 4

    opener = Fragment(0x79, 0, 62, b"a" * TILE_SIZE).to_bytes()
    first_payload = b"\x79" if replacement_status == "rejected" else opener
    first = _receive_raw_authenticated_fragment(harness, first_payload, 5)
    harness.local_link.accept_authenticated_schc_fragment(first)
    if replacement_status == "aborted":
        terminal = harness.receive(sender_abort(0x79), 6)
        assert isinstance(terminal, RxFrame)
        harness.local_link.accept_authenticated_schc_fragment(terminal)

    state = manager.export_persistence_state()
    assert len(state) == 1
    assert state[0]["status"] == replacement_status
    assert not manager._floors

    manager.fail_closed()
    manager.restore_persistence_state(
        state,
        {REMOTE_IDENTITY: generation},
        harness.local_link.replay_protector.highest,
    )
    restored = manager.export_persistence_state()
    assert len(restored) == 1
    assert restored[0]["status"] == (
        "restarted" if replacement_status == "active" else replacement_status
    )
    manager.restore_persistence_state(
        restored,
        {REMOTE_IDENTITY: generation},
        harness.local_link.replay_protector.highest,
    )


def test_newer_opener_retires_undrained_expiry_control() -> None:
    now = [0.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    harness.authorize_schc()
    manager = harness.local_link._schc_reassembly_manager
    opener = Fragment(0x79, 0, 62, b"a" * TILE_SIZE).to_bytes()

    first = _receive_raw_authenticated_fragment(harness, opener, 0)
    harness.local_link.accept_authenticated_schc_fragment(first)
    now[0] = AUTHENTICATED_HOLD_DOWN_SECONDS
    assert manager.replacement_occupied(REMOTE_IDENTITY)
    assert manager._pending_expiry_controls
    now[0] = 2 * AUTHENTICATED_HOLD_DOWN_SECONDS

    replacement = _receive_raw_authenticated_fragment(harness, opener, 1)
    harness.local_link.accept_authenticated_schc_fragment(replacement)

    assert manager._contexts
    assert not manager._floors
    assert not manager._pending_expiry_controls
    assert harness.local_link.expire_authenticated_schc_reassembly() == []


def test_raising_clock_during_sender_activation_does_not_leak_replay_pin() -> None:
    fail = [False]

    def clock() -> float:
        if fail[0]:
            raise RuntimeError("injected clock failure")
        return 0.0

    harness = SessionHarness(-1, receipt_clock=MonotonicClock(clock))
    manager = harness.local_link._schc_session_manager
    sender = _link_sender(harness, b"clock-failure")
    unrelated = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: 0.0))
    unrelated_manager = unrelated.local_link._schc_session_manager
    unrelated_sender = _link_sender(unrelated, b"unrelated")
    assert _issued_manager(sender) is manager
    assert _issued_manager(unrelated_sender) is unrelated_manager

    fail[0] = True
    with pytest.raises(FragmentError, match="clock"):
        sender.start()

    assert REMOTE_IDENTITY not in harness.local_link.replay_protector._pins
    assert not manager._prepared
    assert not manager._records
    assert sender._status == "invalidated"
    assert _issued_manager(sender) is None
    assert _issued_manager(unrelated_sender) is unrelated_manager


@pytest.mark.parametrize(
    "invalid_time",
    [float("nan"), float("inf"), float("-inf"), -1.0, True, "1", None],
)
def test_invalid_clock_at_reassembly_expiry_fails_closed(invalid_time: object) -> None:
    value: list[object] = [0.0]
    harness = SessionHarness(
        -1,
        receipt_clock=MonotonicClock(lambda: value[0]),  # type: ignore[arg-type,return-value]
    )
    harness.authorize_schc()
    manager = harness.local_link._schc_reassembly_manager
    opener = Fragment(0x79, 0, 62, b"a" * TILE_SIZE).to_bytes()
    first = _receive_raw_authenticated_fragment(harness, opener, 0)
    harness.local_link.accept_authenticated_schc_fragment(first)
    value[0] = invalid_time

    with pytest.raises(FragmentError, match="clock"):
        manager.expire_due()

    assert not manager._contexts
    assert not manager._tombstones
    assert not manager._floors
    with pytest.raises(FragmentError, match="permanently disabled"):
        manager.expire_due()


def test_regressing_clock_at_sender_expiry_releases_active_pin() -> None:
    now = [10.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    manager = harness.local_link._schc_session_manager
    sender = _link_sender(harness, b"regression")
    sender.start()
    assert REMOTE_IDENTITY in harness.local_link.replay_protector._pins
    now[0] = 9.0

    with pytest.raises(FragmentError, match="regressed"):
        sender.timeout()

    assert REMOTE_IDENTITY not in harness.local_link.replay_protector._pins
    assert not manager._records
    assert sender._status == "invalidated"


def test_fragment_wire_authority_expires_at_exact_idle_boundary() -> None:
    now = [0.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: now[0]))
    manager = harness.local_link._schc_session_manager
    sender = _link_sender(harness, b"wire-expiry")
    wire = sender.start()[0]
    now[0] = 60.0

    assert not manager.consume_fragment_wire(wire, iid_to_eui64(REMOTE_NODE.iid))
    assert sender._status == "expired"
    assert not manager._issued_wires


def test_fragment_wire_authority_observes_terminal_clock_failure() -> None:
    value = [0.0]
    harness = SessionHarness(-1, receipt_clock=MonotonicClock(lambda: value[0]))
    manager = harness.local_link._schc_session_manager
    sender = _link_sender(harness, b"wire-clock")
    wire = sender.start()[0]
    value[0] = float("nan")

    with pytest.raises(FragmentError, match="clock"):
        manager.consume_fragment_wire(wire, iid_to_eui64(REMOTE_NODE.iid))

    assert REMOTE_IDENTITY not in harness.local_link.replay_protector._pins
    assert not manager._records
    assert not manager._issued_wires
    assert sender._status == "invalidated"


def test_reentrant_reassembly_clock_is_terminal() -> None:
    manager_holder: list[object] = []

    def reentrant_clock() -> float:
        assert manager_holder
        manager_holder[0].replacement_occupied(REMOTE_IDENTITY)  # type: ignore[attr-defined]
        return 0.0

    harness = SessionHarness(-1, receipt_clock=MonotonicClock(reentrant_clock))
    harness.authorize_schc()
    manager = harness.local_link._schc_reassembly_manager
    manager_holder.append(manager)
    with pytest.raises(FragmentError, match="clock"):
        manager.expire_due()
    with pytest.raises(FragmentError, match="permanently disabled"):
        manager.expire_due()


def test_unsolicited_authenticated_ack_is_silent_receiver_traffic() -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    received = harness.receive(Ack(0x78, 0, complete=True).to_bytes(), 0)
    assert isinstance(received, RxFrame)
    assert harness.local_link.accept_authenticated_schc_sender_control(received) is None
    result, decoded = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.response is None
    assert decoded is None
    assert not harness.local_link._schc_reassembly_manager._contexts


def test_authenticated_ack_is_silent_during_simultaneous_inbound_reassembly() -> None:
    harness = SessionHarness(-1)
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    sender = harness.remote_link.create_fragment_sender(_schc_payload(bytes(400)), LOCAL_IDENTITY)
    first = harness.receive(sender.start()[0], 0)
    assert isinstance(first, RxFrame)
    first_result, _ = harness.local_link.accept_authenticated_schc_fragment(first)
    assert first_result.response is None
    contexts = dict(harness.local_link._schc_reassembly_manager._contexts)

    received = harness.receive(Ack(0x78, 0, complete=True).to_bytes(), 1)
    assert isinstance(received, RxFrame)
    assert harness.local_link.accept_authenticated_schc_sender_control(received) is None
    result, decoded = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.response is None
    assert decoded is None
    assert harness.local_link._schc_reassembly_manager._contexts == contexts


def test_ack_request_routes_to_inbound_reassembly_during_bidirectional_session() -> None:
    harness = SessionHarness(-1)
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    outbound = harness.local_link.create_fragment_sender(_schc_payload(bytes(400)), REMOTE_IDENTITY)
    outbound.start()
    outbound_record = harness.local_link._schc_session_manager._sender_records[id(outbound)]
    inbound = harness.remote_link.create_fragment_sender(_schc_payload(bytes(400)), LOCAL_IDENTITY)
    first = harness.receive(inbound.start()[0], 0)
    assert isinstance(first, RxFrame)
    first_result, _ = harness.local_link.accept_authenticated_schc_fragment(first)
    assert first_result.response is None
    sender_high_water = outbound_record.high_water

    request = harness.receive(ack_request(0x79, 0), 1)
    assert isinstance(request, RxFrame)
    assert harness.local_link.accept_authenticated_schc_sender_control(request) is None
    assert outbound_record.high_water == sender_high_water
    result, decoded = harness.local_link.accept_authenticated_schc_fragment(request)
    assert result.ack is not None
    assert result.response == result.ack.to_bytes()
    assert decoded is None
    assert outbound.status == "active"


def test_byte_identical_ack_request_is_outbound_ack_for_opposite_rule_direction() -> None:
    harness = SessionHarness(-1)
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    outbound = harness.local_link.create_fragment_sender(
        _schc_payload(bytes(TILE_SIZE * 63)),
        REMOTE_IDENTITY,
        receiver_limit=MAX_PACKET_SIZE,
    )
    assert len(outbound.start()) == WINDOW_SIZE

    # 0x7800 is both ACK REQ (structurally) and a canonical compressed C=0
    # ACK.  Remote B cannot originate Rule-0x78 data, so authenticated endpoint
    # direction makes this an ACK for local A's outbound transfer.
    received = harness.receive(ack_request(0x78, 0), 0)
    assert isinstance(received, RxFrame)
    output = harness.local_link.accept_authenticated_schc_sender_control(received)
    assert output is not None
    assert len(output) == 7
    assert output[-1] == ack_request(0x78, 0)
    assert outbound.status == "active"
    assert not harness.local_link._schc_reassembly_manager._contexts


@pytest.mark.parametrize(
    "payload",
    [
        Fragment(0x78, 0, 62, bytes(TILE_SIZE)).to_bytes(),
        sender_abort(0x78),
        Ack(0x79, 0, complete=True).to_bytes(),
        receiver_abort(0x79),
    ],
    ids=["data", "sender-abort", "ack", "receiver-abort"],
)
def test_authenticated_fragment_controls_reject_wrong_endpoint_direction(
    payload: bytes,
) -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    signer_eui64 = iid_to_eui64(REMOTE_NODE.iid)
    frame_length = 4 + len(LOCAL_NODE.iid) + len(signer_eui64) + len(payload) + 48
    llsec = int(AddrMode.EXTENDED) | (1 << 5) | (1 << 7)
    destination = iid_to_eui64(LOCAL_NODE.iid)
    signable = harness.remote_link._build_signable_data(
        0,
        0,
        destination,
        payload,
        frame_length,
        llsec,
        signer_eui64,
    )
    wire = LichenFrame(
        epoch=0,
        seqnum=0,
        dst_addr=destination,
        payload=payload,
        mic=sign(REMOTE_NODE.privkey, REMOTE_NODE.pubkey, signable),
        addr_mode=AddrMode.EXTENDED,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()
    harness.local_radio.queue_rx(wire)
    received = asyncio.run(harness.local_link.receive(100))
    assert isinstance(received, RxFrame)
    if fragmentation_message_is_response(
        payload,
        sender_identity=REMOTE_IDENTITY,
        receiver_identity=LOCAL_IDENTITY,
    ):
        with pytest.raises(ValueError, match="authenticated endpoints"):
            harness.local_link.accept_authenticated_schc_sender_control(received)
    else:
        assert harness.local_link.accept_authenticated_schc_sender_control(received) is None
        with pytest.raises(ValueError, match="endpoint direction"):
            harness.local_link.accept_authenticated_schc_fragment(received)
    assert not harness.local_link._schc_reassembly_manager._contexts


@pytest.mark.parametrize(
    ("addr_mode", "dst_addr"),
    [(AddrMode.NONE, b""), (AddrMode.SHORT, LOCAL_NODE.iid[-2:])],
)
def test_authenticated_fragment_rejects_nonextended_target_modes(
    addr_mode: AddrMode,
    dst_addr: bytes,
) -> None:
    harness = SessionHarness(-1)
    harness.authorize_schc()
    payload = Fragment(0x79, 0, 62, bytes(TILE_SIZE)).to_bytes()
    signer_eui64 = iid_to_eui64(REMOTE_NODE.iid)
    frame_length = 4 + len(dst_addr) + len(signer_eui64) + len(payload) + 48
    llsec = int(addr_mode) | (1 << 5) | (1 << 7)
    signable = harness.remote_link._build_signable_data(
        0, 0, dst_addr, payload, frame_length, llsec, signer_eui64
    )
    wire = LichenFrame(
        epoch=0,
        seqnum=0,
        dst_addr=dst_addr,
        payload=payload,
        mic=sign(REMOTE_NODE.privkey, REMOTE_NODE.pubkey, signable),
        addr_mode=addr_mode,
        signature_present=True,
        signer_eui64=signer_eui64,
    ).to_bytes()
    harness.local_radio.queue_rx(wire)
    received = asyncio.run(harness.local_link.receive(100))
    if addr_mode is AddrMode.SHORT:
        assert received is ReceiveError.NOT_FOR_US
        assert not harness.local_link._schc_reassembly_manager._contexts
        return
    assert isinstance(received, RxFrame)
    with pytest.raises(ValueError, match="exact Extended local target"):
        harness.local_link.accept_authenticated_schc_fragment(received)
    assert not harness.local_link._schc_reassembly_manager._contexts


def test_overheard_extended_fragment_cannot_allocate_wrong_local_receiver() -> None:
    overhearer = Identity.from_seed(bytes([0xC3]) * 32)
    harness = SessionHarness(-1)
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    sender = harness.remote_link.create_fragment_sender(_schc_payload(bytes(400)), LOCAL_IDENTITY)
    first = sender.start()[0]
    assert asyncio.run(
        harness.remote_link.send(
            first,
            iid_to_eui64(LOCAL_NODE.iid),
            AddrMode.EXTENDED,
            Priority.BULK,
        )
    )

    overhear_radio = _AckWireRadio()
    remote_peer = PeerIdentity.from_pubkey(REMOTE_IDENTITY)
    overhear_link = LinkLayer(
        radio=overhear_radio,  # type: ignore[arg-type]
        identity=overhearer,
        peer_lookup=lambda _hint: remote_peer,
        peer_lookup_all=lambda: [remote_peer],
        cad_enabled=False,
    )
    _authorize_link_schc(overhear_link, REMOTE_IDENTITY)
    overhear_radio.queue_rx(harness.remote_radio.tx_history[-1])
    received = asyncio.run(overhear_link.receive(100))
    assert received is ReceiveError.NOT_FOR_US
    assert overhear_link.replay_protector.highest(REMOTE_IDENTITY) == -1
    assert not overhear_link._verified_receipts
    assert not overhear_link._schc_reassembly_manager._contexts


def test_reassembly_capacity_emits_one_bounded_rejection_abort() -> None:
    third_identity = Identity.from_seed(bytes([0xA5]) * 32)
    harness = SessionHarness(-1, additional_remote_nodes=(third_identity,))
    _authorize_link_schc(harness.local_link, REMOTE_IDENTITY)
    _authorize_link_schc(harness.remote_link, LOCAL_IDENTITY)
    _authorize_link_schc(harness.local_link, third_identity.pubkey)
    harness.local_link._schc_reassembly_manager._max_contexts = 1
    packet = _schc_payload(bytes(400))
    accepted_sender = harness.remote_link.create_fragment_sender(
        packet,
        LOCAL_IDENTITY,
    )
    third_radio = _AckWireRadio()
    third_link = LinkLayer(
        radio=third_radio,  # type: ignore[arg-type]
        identity=third_identity,
        peer_lookup=lambda _hint: PeerIdentity.from_pubkey(LOCAL_IDENTITY),
        peer_lookup_all=lambda: [PeerIdentity.from_pubkey(LOCAL_IDENTITY)],
        cad_enabled=False,
    )
    _authorize_link_schc(third_link, LOCAL_IDENTITY)
    rejected_sender = third_link.create_fragment_sender(packet, LOCAL_IDENTITY)
    accepted_wire = accepted_sender.start()[0]
    rejected_wires = rejected_sender.start()

    received = harness.receive(accepted_wire, 0)
    assert isinstance(received, RxFrame)
    result, _ = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.response is None

    assert asyncio.run(
        third_link.send(
            rejected_wires[0],
            iid_to_eui64(LOCAL_NODE.iid),
            AddrMode.EXTENDED,
            Priority.BULK,
        )
    )
    harness.local_radio.queue_rx(third_radio.tx_history[-1])
    received = asyncio.run(harness.local_link.receive(100))
    assert isinstance(received, RxFrame)
    result, _ = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.response == receiver_abort(rejected_sender.rule_id)
    assert len(harness.local_link._schc_reassembly_manager._rejections) == 1

    assert asyncio.run(
        third_link.send(
            rejected_wires[1],
            iid_to_eui64(LOCAL_NODE.iid),
            AddrMode.EXTENDED,
            Priority.BULK,
        )
    )
    harness.local_radio.queue_rx(third_radio.tx_history[-1])
    received = asyncio.run(harness.local_link.receive(100))
    assert isinstance(received, RxFrame)
    result, _ = harness.local_link.accept_authenticated_schc_fragment(received)
    assert result.response is None
    assert len(harness.local_link._schc_reassembly_manager._rejections) == 1
