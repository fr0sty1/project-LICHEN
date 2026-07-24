# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for link layer TX/RX with signatures.

Why these tests: The link layer is the security boundary. Bugs here mean:
- Unsigned frames accepted (authentication bypass)
- Replays not detected (replay attack)
- Signatures not verified (forgery)
- Wrong sequence numbers (breaks peer replay windows)

Test categories:
1. TX: Frame construction, signing, sequencing
2. RX: Parsing, verification, replay detection
3. Round-trip: TX -> RX produces valid result
4. Error cases: Malformed frames, bad signatures, replays
"""

import asyncio

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.link.frame import AddrMode, LichenFrame
from lichen.link.link_layer import (
    ReceiveError,
    RxFrame,
    SIGNATURE_LENGTH,
    LinkLayer,
)
from lichen.link.tx_queue import Priority, QueueFullError, TxQueue


class MockRadio:
    """Mock radio for testing link layer without real hardware.

    Why a mock: We're testing link layer logic, not radio behavior.
    The real radio is tested elsewhere (sim_client tests).
    """

    def __init__(self):
        self.tx_history: list[bytes] = []
        self.tx_attempts: list[bytes] = []
        self.rx_queue: list[tuple[bytes, int, int]] = []
        self.cad_returns: bool = False  # False = channel clear
        self.transmit_returns: bool = True
        self.transmit_results: list[bool] = []
        self.transmit_error: Exception | None = None
        self.transmit_started: asyncio.Event | None = None
        self.transmit_release: asyncio.Event | None = None
        self.active_transmits = 0
        self.max_active_transmits = 0
        self.cad_started: asyncio.Event | None = None
        self.cad_release: asyncio.Event | None = None

    async def transmit(self, payload: bytes) -> bool:
        """Record transmitted frames."""
        self.active_transmits += 1
        self.max_active_transmits = max(self.max_active_transmits, self.active_transmits)
        self.tx_attempts.append(payload)
        try:
            if self.transmit_error is not None:
                raise self.transmit_error
            if self.transmit_started is not None:
                self.transmit_started.set()
            if self.transmit_release is not None:
                await self.transmit_release.wait()
            result = (
                self.transmit_results.pop(0)
                if self.transmit_results
                else self.transmit_returns
            )
            if result:
                self.tx_history.append(payload)
            return result
        finally:
            self.active_transmits -= 1

    async def receive(self, timeout_ms: int) -> tuple[bytes, int, int] | None:
        """Return next queued frame or None."""
        if self.rx_queue:
            return self.rx_queue.pop(0)
        return None

    def configure(self, freq_hz: int, tx_power_dbm: int) -> None:
        """No-op for mock."""
        pass

    async def cad(self, timeout_ms: int) -> bool:
        """Return configured CAD result (default: channel clear)."""
        if self.cad_started is not None:
            self.cad_started.set()
        if self.cad_release is not None:
            await self.cad_release.wait()
        return self.cad_returns

    def queue_rx(self, data: bytes, rssi: int = -50, snr: int = 10) -> None:
        """Queue a frame for reception."""
        self.rx_queue.append((data, rssi, snr))


@pytest.fixture
def node_identity() -> Identity:
    """Create a test node identity."""
    # Use fixed seed for reproducibility
    return Identity.from_seed(bytes(32))


@pytest.fixture
def peer_identity() -> Identity:
    """Create a test peer identity."""
    # Different seed than node
    return Identity.from_seed(bytes([1] + [0] * 31))


@pytest.fixture
def mock_radio() -> MockRadio:
    """Create a mock radio."""
    return MockRadio()


@pytest.fixture
def peer_db(peer_identity: Identity) -> dict[bytes, PeerIdentity]:
    """Create a peer database with one known peer."""
    peer = PeerIdentity.from_pubkey(peer_identity.pubkey)
    return {peer.iid: peer}


@pytest.fixture
def link_layer(
    mock_radio: MockRadio,
    node_identity: Identity,
    peer_db: dict[bytes, PeerIdentity],
) -> LinkLayer:
    """Create a link layer instance for testing."""

    def peer_lookup(hint: bytes) -> PeerIdentity | None:
        # For testing: return the first peer (simulating broadcast lookup)
        if peer_db:
            return next(iter(peer_db.values()))
        return None

    ll = LinkLayer(
        radio=mock_radio,
        identity=node_identity,
        peer_lookup=peer_lookup,
    )
    ll.set_sequence(0, 0)  # deterministic epoch for tests
    return ll


class TestLinkLayerEpoch:
    """Tests for unpredictable reboot epoch initialization."""

    def test_epoch_uses_system_entropy(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_radio: MockRadio,
        node_identity: Identity,
    ) -> None:
        calls: list[int] = []

        def randbelow(limit: int) -> int:
            calls.append(limit)
            return 127

        monkeypatch.setattr("lichen.link.link_layer.secrets.randbelow", randbelow)
        ll = LinkLayer(radio=mock_radio, identity=node_identity, peer_lookup=lambda _: None)

        assert calls == [128]
        assert ll.get_sequence() == (255, 0)

    def test_entropy_failure_propagates(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mock_radio: MockRadio,
        node_identity: Identity,
    ) -> None:
        def fail(_: int) -> int:
            raise RuntimeError("entropy unavailable")

        monkeypatch.setattr("lichen.link.link_layer.secrets.randbelow", fail)
        with pytest.raises(RuntimeError, match="entropy unavailable"):
            LinkLayer(radio=mock_radio, identity=node_identity, peer_lookup=lambda _: None)


class TestLinkLayerTx:
    """Tests for frame transmission."""

    def test_signable_data_separates_destination_from_payload(
        self, link_layer: LinkLayer, node_identity: Identity
    ) -> None:
        """Different address/payload partitions produce different signatures."""
        address = bytes.fromhex("0102030405060708")
        payload = bytes.fromhex("0a0b")

        with_address = link_layer._build_signable_data(0, 0, address, payload, 62, 0x22)
        without_address = link_layer._build_signable_data(
            0, 0, b"", address + payload, 62, 0x20
        )

        assert with_address == b">\x22\x00\x00\x00\x08" + address + payload
        assert without_address == b">\x20\x00\x00\x00\x00" + (address + payload)
        assert with_address != without_address
        assert sign(node_identity.privkey, node_identity.pubkey, with_address) != sign(
            node_identity.privkey, node_identity.pubkey, without_address
        )

    @pytest.mark.asyncio
    async def test_send_transmits_frame(self, link_layer: LinkLayer, mock_radio: MockRadio):
        """send() calls radio.transmit with a valid frame."""
        payload = b"hello"
        result = await link_layer.send(payload)

        assert result is True
        assert len(mock_radio.tx_history) == 1

    @pytest.mark.asyncio
    async def test_send_frame_has_signature(self, link_layer: LinkLayer, mock_radio: MockRadio):
        """Transmitted frame has signature_present flag set."""
        await link_layer.send(b"test")

        frame = LichenFrame.from_bytes(mock_radio.tx_history[0])
        assert frame.signature_present is True

    @pytest.mark.asyncio
    async def test_send_frame_contains_signature_bytes(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ):
        """Transmitted frame MIC contains the 48-byte signature."""
        original_payload = b"test"
        await link_layer.send(original_payload)

        frame = LichenFrame.from_bytes(mock_radio.tx_history[0])

        assert frame.payload == original_payload
        assert len(frame.mic) == SIGNATURE_LENGTH

    @pytest.mark.asyncio
    async def test_send_increments_seqnum(self, link_layer: LinkLayer, mock_radio: MockRadio):
        """Each send increments the sequence number."""
        await link_layer.send(b"first")
        await link_layer.send(b"second")
        await link_layer.send(b"third")

        frames = [LichenFrame.from_bytes(data) for data in mock_radio.tx_history]

        assert frames[0].seqnum == 0
        assert frames[1].seqnum == 1
        assert frames[2].seqnum == 2
        # Epoch should stay 0
        assert all(f.epoch == 0 for f in frames)

    @pytest.mark.asyncio
    async def test_send_wraps_seqnum_to_new_epoch(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ):
        """When seqnum wraps, epoch increments."""
        # Set seqnum near wrap point
        link_layer.set_sequence(0, 0xFFFF)

        await link_layer.send(b"before wrap")
        await link_layer.send(b"after wrap")

        frames = [LichenFrame.from_bytes(data) for data in mock_radio.tx_history]

        assert frames[0].epoch == 0
        assert frames[0].seqnum == 0xFFFF
        assert frames[1].epoch == 1
        assert frames[1].seqnum == 0

    @pytest.mark.asyncio
    async def test_signing_failure_consumes_tuple(
        self, link_layer: LinkLayer, monkeypatch: pytest.MonkeyPatch
    ):
        class SigningError(Exception):
            pass

        def fail_sign(*args: object) -> bytes:
            raise SigningError

        monkeypatch.setattr("lichen.link.link_layer.sign", fail_sign)
        with pytest.raises(SigningError):
            await link_layer.send(b"payload")
        assert link_layer.get_sequence() == (0, 1)
        with pytest.raises(RuntimeError, match="cannot be reset after use"):
            link_layer.set_sequence(0, 0)

    @pytest.mark.asyncio
    async def test_terminal_tuple_is_used_once_then_exhausts(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ):
        link_layer.set_sequence(0xFF, 0xFFFE)

        await link_layer.send(b"penultimate")
        assert link_layer.get_sequence() == (0xFF, 0xFFFF)
        await link_layer.send(b"terminal")

        with pytest.raises(OverflowError, match="sequence exhausted"):
            link_layer.get_sequence()
        with pytest.raises(OverflowError, match="sequence exhausted"):
            await link_layer.send(b"reused")
        frames = [LichenFrame.from_bytes(data) for data in mock_radio.tx_history]
        assert [(frame.epoch, frame.seqnum) for frame in frames] == [
            (0xFF, 0xFFFE),
            (0xFF, 0xFFFF),
        ]

    @pytest.mark.asyncio
    async def test_send_with_destination(self, link_layer: LinkLayer, mock_radio: MockRadio):
        """send with destination address sets addr_mode correctly."""
        dst = bytes([0x12, 0x34])
        await link_layer.send(b"unicast", dst_addr=dst, addr_mode=AddrMode.SHORT)

        frame = LichenFrame.from_bytes(mock_radio.tx_history[0])
        assert frame.addr_mode == AddrMode.SHORT
        assert frame.dst_addr == dst

    @pytest.mark.asyncio
    async def test_send_payload_boundary(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ) -> None:
        await link_layer.send(b"\xaa" * 202)
        assert len(mock_radio.tx_history[0]) == 255

    @pytest.mark.asyncio
    async def test_oversized_send_rejects_before_signing_without_mutation(
        self,
        link_layer: LinkLayer,
        mock_radio: MockRadio,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def unexpected_sign(*args: object) -> bytes:
            raise AssertionError("oversized payload was signed")

        monkeypatch.setattr("lichen.link.link_layer.sign", unexpected_sign)
        sequence = link_layer.get_sequence()
        queue_len = len(link_layer.tx_queue)

        with pytest.raises(FrameError, match="frame body is 255 bytes, exceeds 254"):
            await link_layer.send(b"\xaa" * 203)

        assert link_layer.get_sequence() == sequence
        assert len(link_layer.tx_queue) == queue_len
        assert mock_radio.tx_history == []


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
        signable = (
            bytes([0x38, 0x20, 0])
            + (0).to_bytes(2, "big")  # seqnum
            + b""  # dst_addr
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
        def peer_lookup(hint: bytes) -> PeerIdentity | None:
            return PeerIdentity.from_pubkey(peer_identity.pubkey)

        node_ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=peer_lookup,
        )

        mock_radio.queue_rx(peer_frame_bytes)
        result = await node_ll.receive(timeout_ms=100)

        assert isinstance(result, RxFrame)
        assert result.frame.payload == original_payload
        assert result.sender.pubkey == peer_identity.pubkey


class TestSequenceManagement:
    """Tests for sequence number management."""

    def test_get_set_sequence(self, link_layer: LinkLayer):
        """set_sequence and get_sequence work correctly."""
        link_layer.set_sequence(5, 1000)
        epoch, seqnum = link_layer.get_sequence()

        assert epoch == 5
        assert seqnum == 1000

    def test_set_sequence_validates_epoch(self, link_layer: LinkLayer):
        """set_sequence rejects invalid epoch values."""
        with pytest.raises(ValueError, match="epoch out of range"):
            link_layer.set_sequence(256, 0)

        with pytest.raises(ValueError, match="epoch out of range"):
            link_layer.set_sequence(-1, 0)

    def test_set_sequence_validates_seqnum(self, link_layer: LinkLayer):
        """set_sequence rejects invalid seqnum values."""
        with pytest.raises(ValueError, match="seqnum out of range"):
            link_layer.set_sequence(0, 0x10000)

        with pytest.raises(ValueError, match="seqnum out of range"):
            link_layer.set_sequence(0, -1)

    def test_restored_terminal_tuple_fails_closed(self, link_layer: LinkLayer):
        with pytest.raises(OverflowError, match="sequence exhausted"):
            link_layer.set_sequence(0xFF, 0xFFFF)

        with pytest.raises(OverflowError, match="sequence exhausted"):
            link_layer.get_sequence()
        with pytest.raises(OverflowError, match="sequence exhausted"):
            link_layer.set_sequence(0, 0)

    @pytest.mark.asyncio
    async def test_set_sequence_rejects_queued_frame(
        self, link_layer: LinkLayer, mock_radio: MockRadio
    ) -> None:
        mock_radio.cad_returns = True
        assert await link_layer.send(b"queued") is False

        with pytest.raises(RuntimeError, match="cannot be reset"):
            link_layer.set_sequence(0, 0)

        assert link_layer.get_sequence() == (0, 1)
        assert len(link_layer.tx_queue) == 1

    @pytest.mark.asyncio
    async def test_set_sequence_rejects_used_counter(self, link_layer: LinkLayer) -> None:
        assert await link_layer.send(b"sent") is True
        assert len(link_layer.tx_queue) == 0

        with pytest.raises(RuntimeError, match="cannot be reset"):
            link_layer.set_sequence(0, 0)

        assert link_layer.get_sequence() == (0, 1)

class TestLinkLayerConstruction:
    """Tests for LinkLayer construction and validation."""

    def test_requires_identity(self, mock_radio: MockRadio):
        """LinkLayer requires an identity."""
        with pytest.raises(ValueError, match="identity is required"):
            LinkLayer(
                radio=mock_radio,
                identity=None,
                peer_lookup=lambda x: None,
            )

    def test_requires_radio(self, node_identity: Identity):
        """LinkLayer requires a radio."""
        with pytest.raises(ValueError, match="radio is required"):
            LinkLayer(
                radio=None,
                identity=node_identity,
                peer_lookup=lambda x: None,
            )

    def test_requires_peer_lookup(self, mock_radio: MockRadio, node_identity: Identity):
        """LinkLayer requires a peer_lookup callback."""
        with pytest.raises(ValueError, match="peer_lookup callback is required"):
            LinkLayer(
                radio=mock_radio,
                identity=node_identity,
                peer_lookup=None,
            )


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


class TestTxQueueIntegration:
    """Tests for TX queue integration in LinkLayer."""

    @pytest.mark.asyncio
    async def test_send_with_priority(self, link_layer: LinkLayer, mock_radio: MockRadio):
        """send() accepts priority parameter."""
        await link_layer.send(b"routing data", priority=Priority.ROUTING)
        await link_layer.send(b"bulk data", priority=Priority.BULK)

        assert len(mock_radio.tx_history) == 2

    @pytest.mark.asyncio
    async def test_priority_ordering_on_drain(
        self, mock_radio: MockRadio, node_identity: Identity
    ):
        """Higher priority packets are transmitted first."""

        def no_lookup(hint: bytes) -> PeerIdentity | None:
            return None

        # Create link layer with CAD disabled so packets go straight to radio
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=no_lookup,
            cad_enabled=False,
        )
        ll.set_sequence(0, 0)

        # Queue multiple packets (they'll be drained immediately)
        # First send bulk, which gets transmitted immediately
        await ll.send(b"bulk1", priority=Priority.BULK)

        # Now queue another bulk and a routing packet
        # Since queue is drained after each send, both go through
        await ll.send(b"bulk2", priority=Priority.BULK)
        await ll.send(b"routing", priority=Priority.ROUTING)

        # All should be transmitted (no CAD delay)
        assert len(mock_radio.tx_history) == 3

    @pytest.mark.asyncio
    async def test_queue_full_raises_error(
        self, mock_radio: MockRadio, node_identity: Identity
    ):
        """QueueFullError raised when queue is full and can't preempt."""

        def no_lookup(hint: bytes) -> PeerIdentity | None:
            return None

        # Make CAD always return busy so packets stay queued
        mock_radio.cad_returns = True

        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=no_lookup,
            cad_enabled=True,
        )
        ll.set_sequence(0, 0)

        # Fill the queue with ROUTING packets (highest priority)
        # Each send() will queue but fail to transmit due to busy CAD
        for i in range(4):
            await ll.send(f"routing{i}".encode(), priority=Priority.ROUTING)

        # Queue should be full with ROUTING packets
        assert len(ll.tx_queue) == 4

        # Another ROUTING packet cannot preempt
        with pytest.raises(QueueFullError):
            await ll.send(b"overflow", priority=Priority.ROUTING)

    @pytest.mark.asyncio
    async def test_queue_full_does_not_consume_seqnum(
        self, mock_radio: MockRadio, node_identity: Identity
    ):
        """Sequence number not wasted when QueueFullError raised.

        Regression test: send() used to consume the sequence number BEFORE
        attempting to push to the queue. If push raised QueueFullError, the
        sequence number was lost, creating gaps in the counter space.
        """

        def no_lookup(hint: bytes) -> PeerIdentity | None:
            return None

        # Make CAD always return busy so packets stay queued
        mock_radio.cad_returns = True

        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=no_lookup,
            cad_enabled=True,
        )
        ll.set_sequence(0, 0)

        # Fill the queue with ROUTING packets (4 sends = seqnum 0-3 consumed)
        for i in range(4):
            await ll.send(f"routing{i}".encode(), priority=Priority.ROUTING)

        # After 4 successful sends, seqnum should be 4
        assert ll.get_sequence() == (0, 4)

        # Try to send another (queue is full, will raise)
        with pytest.raises(QueueFullError):
            await ll.send(b"overflow", priority=Priority.ROUTING)

        # Seqnum should still be 4 (not consumed on failed push)
        assert ll.get_sequence() == (0, 4)

        # Next successful send should use seqnum 4 (not 5)
        # First make room by clearing CAD and draining
        mock_radio.cad_returns = False
        await ll.drain_tx_queue()

        # Now queue is empty, next send should work
        mock_radio.cad_returns = True  # Keep new packet queued
        await ll.send(b"after_failure", priority=Priority.BULK)

        # Verify the frame used seqnum 4
        assert ll.get_sequence() == (0, 5)
        assert len(ll.tx_queue) == 1

    @pytest.mark.asyncio
    async def test_high_priority_preempts_low(
        self, mock_radio: MockRadio, node_identity: Identity
    ):
        """High priority packet preempts low priority when full."""

        def no_lookup(hint: bytes) -> PeerIdentity | None:
            return None

        mock_radio.cad_returns = True  # Keep packets queued

        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=no_lookup,
            cad_enabled=True,
        )
        ll.set_sequence(0, 0)

        # Fill queue with BULK packets
        for i in range(4):
            await ll.send(f"bulk{i}".encode(), priority=Priority.BULK)

        assert len(ll.tx_queue) == 4

        # ROUTING packet should preempt one BULK
        await ll.send(b"routing", priority=Priority.ROUTING)

        # Still 4 packets, but one was preempted
        assert len(ll.tx_queue) == 4
        assert ll.tx_queue.stats.packets_dropped_preempt == 1

    @pytest.mark.asyncio
    async def test_drain_tx_queue_transmits_pending(
        self, mock_radio: MockRadio, node_identity: Identity
    ):
        """drain_tx_queue() transmits pending packets."""

        def no_lookup(hint: bytes) -> PeerIdentity | None:
            return None

        # Start with CAD busy to queue packets
        mock_radio.cad_returns = True

        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=no_lookup,
            cad_enabled=True,
        )
        ll.set_sequence(0, 0)

        # Queue some packets (won't transmit due to busy CAD)
        await ll.send(b"queued1", priority=Priority.BULK)
        await ll.send(b"queued2", priority=Priority.BULK)

        assert len(mock_radio.tx_history) == 0  # Nothing transmitted yet
        assert len(ll.tx_queue) == 2

        # Now make CAD clear and drain
        mock_radio.cad_returns = False
        result = await ll.drain_tx_queue()

        assert result is True
        assert len(mock_radio.tx_history) == 2
        assert len(ll.tx_queue) == 0

    @pytest.mark.asyncio
    async def test_cad_failure_keeps_packet_queued(
        self, mock_radio: MockRadio, node_identity: Identity
    ):
        """When CAD fails, packet remains queued for retry."""

        def no_lookup(hint: bytes) -> PeerIdentity | None:
            return None

        mock_radio.cad_returns = True  # Always busy

        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=no_lookup,
            cad_enabled=True,
        )
        ll.set_sequence(0, 0)

        await ll.send(b"deferred", priority=Priority.BULK)

        # Packet should be in queue (CAD failed)
        assert len(ll.tx_queue) == 1
        assert len(mock_radio.tx_history) == 0

    @pytest.mark.asyncio
    async def test_cad_busy_preserves_full_same_priority_queue(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        mock_radio.cad_returns = True
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=True,
        )
        ll.set_sequence(0, 0)

        for i in range(4):
            await ll.send(f"routing{i}".encode(), priority=Priority.ROUTING)

        assert len(ll.tx_queue) == 4
        mock_radio.cad_returns = False
        assert await ll.drain_tx_queue() is True
        assert [LichenFrame.from_bytes(raw).seqnum for raw in mock_radio.tx_history] == [
            0,
            1,
            2,
            3,
        ]

    @pytest.mark.asyncio
    async def test_radio_false_preserves_packet_for_retry(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        mock_radio.transmit_returns = False
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=False,
        )
        ll.set_sequence(0, 0)

        assert await ll.send(b"retry", priority=Priority.ACK) is False
        queued = ll.tx_queue.peek()
        assert queued is not None
        frame_bytes, priority = queued
        assert priority == Priority.ACK
        assert LichenFrame.from_bytes(frame_bytes).seqnum == 0
        assert ll.tx_queue.stats.packets_transmitted == 0

        # Overwrite pin to simulate key-change scenario.
        node_ll._pinned_keys[peer_peer.iid] = bytes([0x99] * 32)

        # Second RX: same peer, same signature, but pin now says different key → dropped.
        peer_ll2 = LinkLayer(radio=MockRadio(), identity=peer_identity, peer_lookup=lambda h: None)
        await peer_ll2.send(b"second")
        mock_radio.queue_rx(peer_ll2.radio.tx_history[0])
        result2 = await node_ll.receive(timeout_ms=100)
        assert result2 == ReceiveError.KEY_CHANGE

    @pytest.mark.asyncio
    async def test_radio_exception_preserves_packet_for_retry(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        mock_radio.transmit_error = RuntimeError("radio failed")
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=False,
        )
        ll.set_sequence(0, 0)

        with pytest.raises(RuntimeError, match="radio failed"):
            await ll.send(b"retry", priority=Priority.URGENT)
        queued = ll.tx_queue.peek()
        assert queued is not None
        frame_bytes, priority = queued
        assert priority == Priority.URGENT
        assert LichenFrame.from_bytes(frame_bytes).seqnum == 0
        assert ll.tx_queue.stats.packets_transmitted == 0

        mock_radio.transmit_error = None
        assert await ll.drain_tx_queue() is True
        assert len(ll.tx_queue) == 0
        assert ll.tx_queue.stats.packets_transmitted == 1
        assert mock_radio.tx_attempts == [frame_bytes, frame_bytes]
        assert mock_radio.tx_history == [frame_bytes]

    @pytest.mark.asyncio
    async def test_concurrent_send_cannot_replace_in_flight_packet(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        mock_radio.transmit_started = asyncio.Event()
        mock_radio.transmit_release = asyncio.Event()
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=False,
        )
        ll.set_sequence(0, 0)

        first = asyncio.create_task(ll.send(b"first", priority=Priority.BULK))
        await mock_radio.transmit_started.wait()
        second = asyncio.create_task(ll.send(b"second", priority=Priority.ROUTING))
        await asyncio.sleep(0)

        assert not second.done()
        assert len(ll.tx_queue) == 1
        mock_radio.transmit_release.set()
        assert await first is True
        assert await second is True
        assert [LichenFrame.from_bytes(raw).seqnum for raw in mock_radio.tx_history] == [0, 1]
        assert ll.tx_queue.stats.packets_transmitted == 2

    @pytest.mark.asyncio
    async def test_cancelled_transmit_preserves_packet_and_releases_lock(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        mock_radio.transmit_started = asyncio.Event()
        mock_radio.transmit_release = asyncio.Event()
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=False,
        )
        ll.set_sequence(0, 0)

        send = asyncio.create_task(ll.send(b"cancelled", priority=Priority.ACK))
        await mock_radio.transmit_started.wait()
        send.cancel()
        with pytest.raises(asyncio.CancelledError):
            await send

        queued = ll.tx_queue.peek()
        assert queued is not None
        frame_bytes, priority = queued
        assert priority == Priority.ACK
        assert ll.tx_queue.stats.packets_transmitted == 0
        mock_radio.transmit_started = None
        mock_radio.transmit_release = None
        assert await ll.drain_tx_queue() is True
        assert mock_radio.tx_attempts == [frame_bytes, frame_bytes]
        assert mock_radio.tx_history == [frame_bytes]

    @pytest.mark.asyncio
    async def test_concurrent_public_drain_does_not_overlap_radio(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        mock_radio.transmit_started = asyncio.Event()
        mock_radio.transmit_release = asyncio.Event()
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=False,
        )

        send = asyncio.create_task(ll.send(b"one"))
        await mock_radio.transmit_started.wait()
        drain = asyncio.create_task(ll.drain_tx_queue())
        await asyncio.sleep(0)
        assert not drain.done()

        mock_radio.transmit_release.set()
        assert await send is True
        assert await drain is False
        assert mock_radio.max_active_transmits == 1

    @pytest.mark.asyncio
    async def test_send_reports_its_own_frame_failure(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        mock_radio.cad_returns = True
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=True,
        )
        ll.set_sequence(0, 0)
        assert await ll.send(b"older", priority=Priority.ROUTING) is False

        mock_radio.cad_returns = False
        mock_radio.transmit_results = [True, False]
        assert await ll.send(b"submitted", priority=Priority.BULK) is False
        queued = ll.tx_queue.peek()
        assert queued is not None
        frame_bytes, _ = queued
        assert LichenFrame.from_bytes(frame_bytes).seqnum == 1
        assert ll.tx_queue.stats.packets_transmitted == 1

        mock_radio.transmit_returns = True
        assert await ll.drain_tx_queue() is True
        assert ll.tx_queue.stats.packets_transmitted == 2

    @pytest.mark.asyncio
    async def test_packet_expiring_during_cad_is_not_transmitted(
        self, mock_radio: MockRadio, node_identity: Identity
    ) -> None:
        now = 0
        mock_radio.cad_started = asyncio.Event()
        mock_radio.cad_release = asyncio.Event()
        ll = LinkLayer(
            radio=mock_radio,
            identity=node_identity,
            peer_lookup=lambda _: None,
            cad_enabled=True,
            tx_queue=TxQueue(clock=lambda: now),
        )

        send = asyncio.create_task(ll.send(b"stale", deadline_ms=100))
        await mock_radio.cad_started.wait()
        now = 100
        mock_radio.cad_release.set()

        assert await send is False
        assert mock_radio.tx_attempts == []
        assert ll.tx_queue.stats.packets_dropped_deadline == 1
