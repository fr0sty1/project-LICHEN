# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for link layer RX operations and signature verification.

Why these tests: RX is the security boundary. Bugs here mean:
- Unsigned frames accepted (authentication bypass)
- Replays not detected (replay attack)
- Signatures not verified (forgery)
- Key changes not detected (MITM vulnerability)

Test categories:
1. RX: Parsing, verification, replay detection
2. Round-trip: TX -> RX produces valid result
3. Error cases: Malformed frames, bad signatures, replays
4. Metadata: RSSI, SNR, sender info
"""

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.gradient import MAX_ENTRIES
from lichen.ipv6.addr import iid_to_eui64, make_link_local
from lichen.l2_payload import wrap_routing_payload, wrap_schc_payload
from lichen.link.frame import LINK_SIGNATURE_DOMAIN, AddrMode, LichenFrame
from lichen.link.link_layer import SIGNATURE_LENGTH, LinkLayer, ReceiveError, RxFrame
from lichen.schc.headers import encode_rule255

from .conftest import MockRadio


class TestLinkLayerRx:
    """Tests for frame reception."""

    @pytest.mark.asyncio
    async def test_receive_returns_none_on_timeout(self, link_layer: LinkLayer):
        """receive returns None when radio times out."""
        result = await link_layer.receive(timeout_ms=100)
        assert result is None

    @pytest.mark.asyncio
    async def test_receive_rejects_malformed_frame(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ):
        """receive returns ReceiveError.MALFORMED for unparseable frames."""
        mock_radio.queue_rx(b"\x00")  # Too short to parse
        result = await link_layer.receive(timeout_ms=100)
        assert result == ReceiveError.MALFORMED

    @pytest.mark.asyncio
    async def test_receive_classifies_unsupported_encrypted_frame(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ) -> None:
        """E=1 remains parser-rejected but is reported distinctly over RX."""
        mock_radio.queue_rx(bytes([4, 0x40, 0, 0, 0]))

        assert await link_layer.receive(timeout_ms=100) is ReceiveError.ENCRYPTED

    @pytest.mark.asyncio
    async def test_receive_rejects_unsigned_frame(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ):
        """receive rejects frames without signature_present flag."""
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"",
            payload=b"unsigned",
            mic=b"",
            signature_present=False,  # No signature
        )
        mock_radio.queue_rx(frame.to_bytes())

        result = await link_layer.receive(timeout_ms=100)
        assert result == ReceiveError.UNSIGNED

    @pytest.mark.asyncio
    async def test_receive_rejects_truncated_signature(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ):
        """receive rejects signed frames with a truncated MIC signature (parse fails)."""
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"",
            payload=b"test",
            mic=bytes(SIGNATURE_LENGTH),
            signature_present=True,
            signer_eui64=bytes(8),
        )
        mock_radio.queue_rx(frame.to_bytes()[:-1])

        result = await link_layer.receive(timeout_ms=100)
        assert result == ReceiveError.MALFORMED

    @pytest.mark.asyncio
    async def test_receive_rejects_bad_signature(
        self,
        link_layer: LinkLayer,
        mock_radio: MockRadio,
        peer_identity: Identity,
    ):
        """receive rejects frames with invalid signature."""
        payload = b"test"
        # Create frame with garbage signature
        bad_signature = bytes(SIGNATURE_LENGTH)
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"",
            payload=payload,
            mic=bad_signature,
            signature_present=True,
            signer_eui64=iid_to_eui64(peer_identity.iid),
        )
        mock_radio.queue_rx(frame.to_bytes())

        result = await link_layer.receive(timeout_ms=100)
        assert result == ReceiveError.BAD_SIGNATURE

    @pytest.mark.asyncio
    async def test_receive_rejects_replay(
        self,
        link_layer: LinkLayer,
        mock_radio: MockRadio,
        peer_identity: Identity,
    ):
        """receive rejects replayed frames (same epoch/seqnum)."""
        payload = b"test"

        # Build valid signed frame
        # Signable: DOMAIN-v1 || LENGTH || LLSec || EPO || SEQ || DST_LEN || DST || SIID || PLD
        # length = 4 + dst_addr(0) + SIID(8) + payload(4) + sig(48) = 64 = 0x40
        signer_eui64 = iid_to_eui64(peer_identity.iid)
        signable = (
            LINK_SIGNATURE_DOMAIN
            + bytes([0x40, 0xA0, 0])
            + (0).to_bytes(2, "big")  # seqnum
            + bytes([0])  # dst_addr length (0 = broadcast)
            + b""  # dst_addr
            + signer_eui64
            + payload
        )
        signature = sign(peer_identity.privkey, peer_identity.pubkey, signable)

        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"",
            payload=payload,
            mic=signature,
            signature_present=True,
            signer_eui64=signer_eui64,
        )
        frame_bytes = frame.to_bytes()

        # First receive should succeed
        mock_radio.queue_rx(frame_bytes)
        result1 = await link_layer.receive(timeout_ms=100)
        assert result1 is not None
        assert result1.frame.payload == payload
        assert result1.frame.mic == signature

        # Second receive (replay) should fail
        mock_radio.queue_rx(frame_bytes)
        result2 = await link_layer.receive(timeout_ms=100)
        assert result2 == ReceiveError.REPLAY

    @pytest.mark.asyncio
    async def test_receive_rejects_valid_signature_with_wrong_signer_eui64_before_replay(
        self,
        link_layer: LinkLayer,
        mock_radio: MockRadio,
        peer_identity: Identity,
    ) -> None:
        payload = b"wrong-eui"
        signer_eui64 = bytearray(iid_to_eui64(peer_identity.iid))
        signer_eui64[-1] ^= 1
        wire_eui64 = bytes(signer_eui64)
        length = 4 + len(wire_eui64) + len(payload) + SIGNATURE_LENGTH
        llsec = 0xA0
        signable = link_layer._build_signable_data(
            0,
            0,
            b"",
            payload,
            length,
            llsec,
            wire_eui64,
        )
        frame = LichenFrame(
            epoch=0,
            seqnum=0,
            dst_addr=b"",
            payload=payload,
            mic=sign(peer_identity.privkey, peer_identity.pubkey, signable),
            signature_present=True,
            signer_eui64=wire_eui64,
        )
        mock_radio.queue_rx(frame.to_bytes())

        assert await link_layer.receive(timeout_ms=100) == ReceiveError.BAD_SIGNATURE
        assert link_layer.replay_protector.highest(peer_identity.pubkey) == -1


class TestLinkLayerRoundTrip:
    """Tests for TX -> RX round trip."""

    @pytest.mark.asyncio
    async def test_loopback_self_signed_frame(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
    ):
        """Node can receive its own signed frames (loopback)."""

        # Create link layer that knows about itself
        def self_lookup(hint: bytes) -> PeerIdentity | None:
            return PeerIdentity.from_pubkey(node_identity.pubkey)

        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=self_lookup,
        )

        # Send a frame
        original_payload = b"loopback test"
        await ll.send(original_payload)

        # Queue the transmitted frame for reception
        mock_radio.queue_rx(mock_radio.tx_history[0])

        # Receive it
        result = await ll.receive(timeout_ms=100)
        assert isinstance(result, RxFrame)
        assert result.frame.payload == original_payload

    @pytest.mark.asyncio
    async def test_peer_to_peer_frame(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ):
        """Frame from peer is accepted with valid signature."""

        # Create peer's link layer
        def no_lookup(hint: bytes) -> PeerIdentity | None:
            return None

        peer_ll = LinkLayer(
            radio=MockRadio(),
            identity=peer_identity,
            peer_lookup=no_lookup,
        )

        # Peer sends a frame
        original_payload = b"hello from peer"
        await peer_ll.send(original_payload)
        peer_frame_bytes = peer_ll.radio.tx_history[0]

        # Node receives it
        peer_peer = PeerIdentity.from_pubkey(peer_identity.pubkey)

        def peer_lookup(hint: bytes) -> PeerIdentity | None:
            return peer_peer

        def peer_lookup_all() -> list[PeerIdentity]:
            return [peer_peer]

        node_ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=peer_lookup,
            peer_lookup_all=peer_lookup_all,
        )

        mock_radio.queue_rx(peer_frame_bytes)
        result = await node_ll.receive(timeout_ms=100)

        assert isinstance(result, RxFrame)
        assert result.frame.payload == original_payload
        assert result.sender.pubkey == peer_identity.pubkey

    @pytest.mark.parametrize("callback_result", [None, (), object(), [object()]])
    @pytest.mark.asyncio
    async def test_exhaustive_lookup_malformed_result_fails_closed(
        self,
        callback_result: object,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        assert await peer_link.send(b"malformed lookup")

        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: None,
            peer_lookup_all=lambda: callback_result,  # type: ignore[arg-type,return-value]
            cad_enabled=False,
        )
        mock_radio.queue_rx(peer_radio.tx_history[-1])

        assert await node_link.receive(100) is ReceiveError.BAD_SIGNATURE
        assert node_link.replay_protector.highest(peer_identity.pubkey) == -1

    @pytest.mark.asyncio
    async def test_exhaustive_lookup_exception_fails_closed(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        assert await peer_link.send(b"raising lookup")

        def raise_lookup() -> list[PeerIdentity]:
            raise RuntimeError("peer store unavailable")

        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: None,
            peer_lookup_all=raise_lookup,
            cad_enabled=False,
        )
        mock_radio.queue_rx(peer_radio.tx_history[-1])

        assert await node_link.receive(100) is ReceiveError.BAD_SIGNATURE
        assert node_link.replay_protector.highest(peer_identity.pubkey) == -1

    @pytest.mark.asyncio
    async def test_exhaustive_lookup_oversized_result_fails_closed(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        assert await peer_link.send(b"oversized lookup")
        candidates = [peer] * (MAX_ENTRIES + 1)
        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: None,
            peer_lookup_all=lambda: candidates,
            cad_enabled=False,
        )
        mock_radio.queue_rx(peer_radio.tx_history[-1])

        assert await node_link.receive(100) is ReceiveError.BAD_SIGNATURE
        assert node_link.replay_protector.highest(peer_identity.pubkey) == -1

    @pytest.mark.asyncio
    async def test_exhaustive_lookup_snapshots_callback_owned_list(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        candidates: list[object] = []

        class MutatingCandidate:
            @property
            def pubkey(self) -> bytes:
                candidates.clear()
                return b"invalid"

        candidates.extend((MutatingCandidate(), peer))
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        assert await peer_link.send(b"snapshot lookup")
        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: None,
            peer_lookup_all=lambda: candidates,  # type: ignore[arg-type,return-value]
            cad_enabled=False,
        )
        mock_radio.queue_rx(peer_radio.tx_history[-1])

        result = await node_link.receive(100)
        assert isinstance(result, RxFrame)
        assert result.sender == peer
        assert candidates == []

    @pytest.mark.parametrize(
        "payload",
        [
            b"raw-application",
            wrap_schc_payload(
                encode_rule255(
                    bytes.fromhex("6000000000003b40")
                    + make_link_local(bytes.fromhex("0102030405060708")).packed
                    + make_link_local(bytes.fromhex("1112131415161718")).packed
                )
            ),
            wrap_routing_payload(b"\x01rpl-control"),
        ],
        ids=["raw", "single-schc", "rpl"],
    )
    @pytest.mark.asyncio
    async def test_wrong_extended_target_rejected_before_security_mutation(
        self,
        payload: bytes,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: peer,
            peer_lookup_all=lambda: [peer],
            cad_enabled=False,
        )
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        other = Identity.from_seed(bytes([0xD4]) * 32)
        assert await peer_link.send(
            payload,
            iid_to_eui64(other.iid),
            AddrMode.EXTENDED,
        )
        mock_radio.queue_rx(peer_radio.tx_history[-1])

        assert await node_link.receive(100) is ReceiveError.NOT_FOR_US
        assert node_link.replay_protector.highest(peer_identity.pubkey) == -1
        assert not node_link._pinned_keys
        assert not node_link._verified_receipts

    @pytest.mark.asyncio
    async def test_extended_and_configured_short_exact_local_targets(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: peer,
            peer_lookup_all=lambda: [peer],
            cad_enabled=False,
            local_short_addr=0x1234,
        )
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        node_link.identity = Identity.from_seed(bytes([0xD5]) * 32)
        node_link.local_short_addr = 0x9999
        for destination, mode in (
            (iid_to_eui64(node_identity.iid), AddrMode.EXTENDED),
            (bytes.fromhex("1234"), AddrMode.SHORT),
        ):
            assert await peer_link.send(b"local", destination, mode)
            mock_radio.queue_rx(peer_radio.tx_history[-1])
            assert isinstance(await node_link.receive(100), RxFrame)

        assert await peer_link.send(b"wrong-short", bytes.fromhex("1235"), AddrMode.SHORT)
        mock_radio.queue_rx(peer_radio.tx_history[-1])
        assert await node_link.receive(100) is ReceiveError.NOT_FOR_US

    @pytest.mark.asyncio
    async def test_elided_target_accepts_local_and_multicast_only(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: peer,
            peer_lookup_all=lambda: [peer],
            cad_enabled=False,
        )
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        source = make_link_local(peer_identity.iid).packed
        destinations = (
            (make_link_local(node_identity.iid).packed, True),
            (bytes.fromhex("ff020000000000000000000000000001"), True),
            (make_link_local(bytes.fromhex("1112131415161718")).packed, False),
        )
        for destination, accepted in destinations:
            raw = bytes.fromhex("6000000000003b40") + source + destination
            payload = wrap_schc_payload(encode_rule255(raw))
            assert await peer_link.send(payload, b"", AddrMode.ELIDED)
            mock_radio.queue_rx(peer_radio.tx_history[-1])
            received = await node_link.receive(100)
            assert (
                isinstance(received, RxFrame) if accepted else received is ReceiveError.NOT_FOR_US
            )

    @pytest.mark.asyncio
    async def test_malformed_authenticated_elided_schc_fails_closed(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ) -> None:
        peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: peer,
            peer_lookup_all=lambda: [peer],
            cad_enabled=False,
        )
        peer_radio = MockRadio()
        peer_link = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        assert await peer_link.send(b"\x14\x07", b"", AddrMode.ELIDED)
        mock_radio.queue_rx(peer_radio.tx_history[-1])
        assert await node_link.receive(100) is ReceiveError.NOT_FOR_US
        assert node_link.replay_protector.highest(peer_identity.pubkey) == -1
        assert not node_link._pinned_keys

    @pytest.mark.asyncio
    async def test_key_change_detection(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
        peer_identity: Identity,
    ):
        """Overwriting pinned key then receiving from same peer yields KEY_CHANGE."""
        peer_radio = MockRadio()
        peer_peer = PeerIdentity.from_pubkey(peer_identity.pubkey)

        def peer_lookup(hint: bytes) -> PeerIdentity | None:
            return peer_peer

        def peer_lookup_all() -> list[PeerIdentity]:
            return [peer_peer]

        node_ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=peer_lookup,
            peer_lookup_all=peer_lookup_all,
        )

        peer_ll = LinkLayer(
            radio=peer_radio,
            identity=peer_identity,
            peer_lookup=lambda h: None,
        )

        await peer_ll.send(b"first")
        mock_radio.queue_rx(peer_radio.tx_history[0])
        result = await node_ll.receive(timeout_ms=100)
        assert isinstance(result, RxFrame)

        node_ll._pinned_keys[peer_identity.iid] = bytes([0x99] * 32)

        await peer_ll.send(b"second")
        mock_radio.queue_rx(peer_radio.tx_history[0])
        result2 = await node_ll.receive(timeout_ms=100)
        assert result2 == ReceiveError.KEY_CHANGE

    @pytest.mark.parametrize(
        "payload",
        [
            b"raw-application",
            wrap_schc_payload(b"\xff" + bytes.fromhex("6000000000003b40") + bytes(32)),
            wrap_routing_payload(b"\x01rpl-control"),
        ],
        ids=["raw", "schc", "rpl"],
    )
    @pytest.mark.asyncio
    async def test_tofu_capacity_with_all_pins_leased_rejects_atomically(
        self,
        payload: bytes,
        mock_radio: MockRadio,
        node_identity: Identity,
    ) -> None:
        newcomer = Identity.from_seed((250).to_bytes(32, "big"))
        newcomer_peer = PeerIdentity.from_pubkey(newcomer.pubkey)
        node_link = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _hint: newcomer_peer,
            peer_lookup_all=lambda: [newcomer_peer],
            cad_enabled=False,
        )
        established = [
            Identity.from_seed(seed.to_bytes(32, "big")) for seed in range(1, MAX_ENTRIES + 1)
        ]
        for identity in established:
            peer = PeerIdentity.from_pubkey(identity.pubkey)
            node_link._pinned_keys[peer.iid] = identity.pubkey
            node_link._key_generations[identity.pubkey] = object()
            node_link._generation_leases[identity.pubkey] = 1
        original_pins = dict(node_link._pinned_keys)
        original_generations = dict(node_link._key_generations)

        remote_radio = MockRadio()
        remote_link = LinkLayer(
            radio=remote_radio,
            identity=newcomer,
            peer_lookup=lambda _hint: None,
            cad_enabled=False,
        )
        assert await remote_link.send(payload)
        wire = remote_radio.tx_history[-1]
        mock_radio.queue_rx(wire)
        assert await node_link.receive(100) == ReceiveError.REPLAY
        assert dict(node_link._pinned_keys) == original_pins
        assert node_link._key_generations == original_generations
        assert newcomer.pubkey not in node_link._key_generations
        assert node_link.replay_protector.highest(newcomer.pubkey) == -1
        assert not node_link._verified_receipts

        released = established[0]
        node_link._generation_leases.pop(released.pubkey)
        mock_radio.queue_rx(wire)
        admitted = await node_link.receive(100)
        assert isinstance(admitted, RxFrame)
        assert node_link._pinned_keys[newcomer_peer.iid] == newcomer.pubkey
        assert newcomer.pubkey in node_link._key_generations
        assert PeerIdentity.from_pubkey(released.pubkey).iid not in node_link._pinned_keys


class TestRxFrameMetadata:
    """Tests for RxFrame metadata."""

    @pytest.mark.asyncio
    async def test_rxframe_contains_rssi_snr(
        self,
        mock_radio: MockRadio,
        node_identity: Identity,
    ):
        """RxFrame includes RSSI and SNR from radio."""

        def self_lookup(hint: bytes) -> PeerIdentity | None:
            return PeerIdentity.from_pubkey(node_identity.pubkey)

        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=self_lookup,
        )

        await ll.send(b"test")
        mock_radio.queue_rx(mock_radio.tx_history[0], rssi=-75, snr=5)

        result = await ll.receive(timeout_ms=100)
        assert isinstance(result, RxFrame)
        assert result.rssi_dbm == -75
        assert result.snr_db == 5
        assert result.payload == b"test"
        assert result.sender_iid == node_identity.iid
        assert result.sender_pubkey == node_identity.pubkey
