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
from lichen.link.frame import LichenFrame
from lichen.link.link_layer import SIGNATURE_LENGTH, LinkLayer, ReceiveError, RxFrame

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
        # Signable: LENGTH || LLSec || EPO || SEQ || DST_LEN(1) || DST || PLD
        # length = 4 + dst_addr(0) + payload(4) + sig(48) = 56 = 0x38
        signable = (
            bytes([0x38, 0x20, 0])
            + (0).to_bytes(2, "big")  # seqnum
            + bytes([0])              # dst_addr length (0 = broadcast)
            + b""                      # dst_addr
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
