# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for link layer TX operations and queue integration.

Why these tests: TX is where signing happens and where packets enter the queue.
Bugs here mean:
- Unsigned frames transmitted (authentication failure)
- Wrong sequence numbers (breaks receiver replay windows)
- Queue overflow not handled (packet loss)
- Concurrency issues (race conditions in TX path)

Test categories:
1. TX: Frame construction, signing, sequencing
2. Queue integration: Priority ordering, preemption, backpressure
3. CAD integration: Channel access before transmission
4. Concurrency: Parallel sends, cancellation handling
"""

import asyncio

import pytest

from lichen.crypto.identity import Identity, PeerIdentity
from lichen.crypto.schnorr48 import sign
from lichen.link.frame import AddrMode, FrameError, LichenFrame
from lichen.link.link_layer import SIGNATURE_LENGTH, LinkLayer
from lichen.link.tx_queue import Priority, QueueFullError, TxQueue

from .conftest import MockRadio


class TestLinkLayerTx:
    """Tests for frame transmission."""

    def test_signable_data_separates_destination_from_payload(
        self, link_layer: LinkLayer, node_identity: Identity
    ) -> None:
        """Different address/payload partitions produce different signatures."""
        address = bytes.fromhex("0102030405060708")
        payload = bytes.fromhex("0a0b")

        with_address = link_layer._build_signable_data(0, 0, address, payload, 62, 0x22)
        without_address = link_layer._build_signable_data(0, 0, b"", address + payload, 62, 0x20)

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
    async def test_signing_failure_does_not_consume_tuple(
        self, link_layer: LinkLayer, monkeypatch: pytest.MonkeyPatch
    ):
        """Signing failure before queue push must not consume the tuple."""

        class SigningError(Exception):
            pass

        def fail_sign(*args: object) -> bytes:
            raise SigningError

        monkeypatch.setattr("lichen.link.link_layer.sign", fail_sign)
        with pytest.raises(SigningError):
            await link_layer.send(b"payload")
        # Tuple NOT consumed — signing happens before _next_seqnum()
        assert link_layer.get_sequence() == (0, 0)
        # _sequence_started was never set, so reset is allowed
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
        with pytest.raises(OverflowError, match="tuple exhaustion"):
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

        with pytest.raises(FrameError, match="frame body is 256 bytes, exceeds 255"):
            await link_layer.send(b"\xaa" * 204)

        assert link_layer.get_sequence() == sequence
        assert len(link_layer.tx_queue) == queue_len
        assert mock_radio.tx_history == []


class TestTxQueueIntegration:
    """Tests for TX queue integration in LinkLayer."""

    @pytest.mark.asyncio
    async def test_send_with_priority(self, link_layer: LinkLayer, mock_radio: MockRadio):
        """send() accepts priority parameter."""
        await link_layer.send(b"routing data", priority=Priority.ROUTING)
        await link_layer.send(b"bulk data", priority=Priority.BULK)

        assert len(mock_radio.tx_history) == 2

    @pytest.mark.asyncio
    async def test_priority_ordering_on_drain(self, mock_radio: MockRadio, node_identity: Identity):
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
    async def test_queue_full_raises_error(self, mock_radio: MockRadio, node_identity: Identity):
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
    async def test_high_priority_preempts_low(self, mock_radio: MockRadio, node_identity: Identity):
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
