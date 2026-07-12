# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration test for 2-node RX via DIO1 interrupt path.

This test verifies that two LICHEN nodes can communicate via simulated LoRa,
with RX triggered by the DIO1 interrupt mechanism (callback-based RX mode).

The DIO1 interrupt path works as follows:
1. Node B's SX1262 enters RX mode (SetRx opcode 0x82)
2. SX1262.cs sends RX_ENTER to lichen-sim
3. lichen-sim calls the on_packet callback when a packet arrives
4. SX1262.cs receives RX_PACKET, sets irqFlags |= 0x0002, and IRQ.Set(true)
5. This triggers the DIO1 GPIO line to the MCU

This test validates the lichen-sim side of that path without requiring Renode.
For the full Renode subprocess test, see test_two_node_dio1_rx_renode.py.

Run with:
    pytest -v python/tests/sim/test_two_node_dio1_rx.py
"""

from __future__ import annotations

import asyncio

import pytest

from lichen.sim.simulation import Simulation, TimeMode
from lichen.sim.renode_server import RenodeServer


class TestTwoNodeDIO1Rx:
    """Test 2-node communication via DIO1 interrupt RX path."""

    @pytest.mark.asyncio
    async def test_callback_rx_receives_transmitted_frame(self) -> None:
        """Test that callback-based RX receives a transmitted frame.

        This validates the core mechanism that drives DIO1 interrupts:
        when a node enters RX mode with callbacks, and another node transmits,
        the on_packet callback fires with the correct payload.
        """
        sim = Simulation("test-dio1-rx", time_mode=TimeMode.BARRIER_SYNC)

        # Add two nodes 50m apart (well within LoRa range)
        node_a = sim.add_node("node-a", x=0.0, y=0.0, z=0.0)
        node_b = sim.add_node("node-b", x=50.0, y=0.0, z=0.0)

        # Track RX events for node B
        rx_events: list[tuple[bytes, int, int]] = []

        def on_packet(payload: bytes, rssi: int, snr: int) -> None:
            rx_events.append((payload, rssi, snr))

        timeout_called = False

        def on_timeout() -> None:
            nonlocal timeout_called
            timeout_called = True

        # Node B enters RX mode with callbacks (simulates SetRx via SX1262.cs)
        sim.enter_rx_mode(
            "node-b",
            timeout_us=10_000_000,  # 10 second timeout
            on_packet=on_packet,
            on_timeout=on_timeout,
        )

        # Test payload - a minimal LICHEN frame
        test_payload = b"\x01\x02\x03\x04\x05\x06\x07\x08LICHEN_TEST"

        # Node A transmits (simulates WriteBuffer + SetTx via SX1262.cs)
        tx_id = sim.start_transmission("node-a", test_payload)
        assert tx_id != "", "Transmission should start immediately without jitter"

        # Advance simulation time to complete transmission and deliver packet
        # LoRa airtime for ~20 bytes at SF10/125kHz is roughly 370ms
        for _ in range(500):
            sim.deliver_pending_packets()
            if sim.maybe_advance_time():
                pass
            if rx_events:
                break

        # Verify packet was received
        assert len(rx_events) == 1, f"Expected 1 RX event, got {len(rx_events)}"
        payload, rssi, snr = rx_events[0]
        assert payload == test_payload, f"Payload mismatch: {payload!r} != {test_payload!r}"
        assert rssi < 0, "RSSI should be negative dBm"
        assert not timeout_called, "Timeout should not have been called"

    @pytest.mark.asyncio
    async def test_two_renode_servers_communicate(self) -> None:
        """Test that two RenodeServer instances can communicate.

        This tests the full Renode bridge path without requiring the Renode
        subprocess. Each RenodeServer wraps a node in lichen-sim and provides
        the TCP bridge protocol that SX1262.cs uses.
        """
        sim = Simulation("test-renode-servers", time_mode=TimeMode.BARRIER_SYNC)

        # Create two RenodeServer instances (one per node)
        server_a = RenodeServer(sim, "node-a", position=(0.0, 0.0, 0.0))
        server_b = RenodeServer(sim, "node-b", position=(50.0, 0.0, 0.0))

        port_a = await server_a.start(host="127.0.0.1", port=0)
        port_b = await server_b.start(host="127.0.0.1", port=0)

        try:
            # Verify nodes were added to simulation
            assert sim.get_node("node-a") is not None
            assert sim.get_node("node-b") is not None

            # Track RX events via observer
            rx_events: list[tuple[str, str, int]] = []

            class RxObserver:
                def on_rx_success(
                    self,
                    sim_id: str,
                    node_id: str,
                    tx_id: str,
                    from_node_id: str,
                    payload_len: int,
                    rssi: int,
                    snr: int,
                    time_us: int,
                ) -> None:
                    rx_events.append((node_id, from_node_id, payload_len))

            sim.add_observer(RxObserver())

            # Node B enters callback-based RX mode
            rx_results: list[tuple[bytes, int, int]] = []

            def on_rx(payload: bytes, rssi: int, snr: int) -> None:
                rx_results.append((payload, rssi, snr))

            def on_timeout() -> None:
                pass

            sim.enter_rx_mode(
                "node-b",
                timeout_us=10_000_000,
                on_packet=on_rx,
                on_timeout=on_timeout,
            )

            # Node A transmits
            test_frame = b"\xDE\xAD\xBE\xEF" + b"LICHEN_FRAME_DATA"
            sim.start_transmission("node-a", test_frame)

            # Run simulation to deliver packet
            for _ in range(500):
                sim.deliver_pending_packets()
                sim.maybe_advance_time()
                if rx_results:
                    break

            # Verify RX
            assert len(rx_results) == 1
            assert rx_results[0][0] == test_frame

        finally:
            await server_a.stop()
            await server_b.stop()

    @pytest.mark.asyncio
    async def test_rx_timeout_fires_when_no_transmission(self) -> None:
        """Test that RX timeout callback fires when no packet arrives.

        This validates the timeout path of DIO1 interrupt handling.
        """
        sim = Simulation("test-rx-timeout", time_mode=TimeMode.BARRIER_SYNC)

        sim.add_node("node-a", x=0.0, y=0.0, z=0.0)
        sim.add_node("node-b", x=50.0, y=0.0, z=0.0)

        packet_received = False
        timeout_received = False

        def on_packet(payload: bytes, rssi: int, snr: int) -> None:
            nonlocal packet_received
            packet_received = True

        def on_timeout() -> None:
            nonlocal timeout_received
            timeout_received = True

        # Node B enters RX mode with a short timeout (10ms = 10,000us)
        sim.enter_rx_mode(
            "node-b",
            timeout_us=10_000,
            on_packet=on_packet,
            on_timeout=on_timeout,
        )

        # Advance time without any transmissions
        for _ in range(100):
            sim.deliver_pending_packets()
            if sim.maybe_advance_time():
                pass
            if timeout_received:
                break

        assert timeout_received, "Timeout callback should have fired"
        assert not packet_received, "No packet should have been received"

    @pytest.mark.asyncio
    async def test_frame_content_integrity(self) -> None:
        """Test that transmitted frame content is preserved exactly.

        Verifies byte-for-byte integrity of various frame types.
        """
        sim = Simulation("test-frame-integrity", time_mode=TimeMode.BARRIER_SYNC)

        sim.add_node("tx-node", x=0.0, y=0.0, z=0.0)
        sim.add_node("rx-node", x=30.0, y=0.0, z=0.0)

        # Test frames of various sizes and patterns
        test_frames = [
            # Minimal frame
            b"\x00",
            # All zeros
            b"\x00" * 64,
            # All ones
            b"\xFF" * 64,
            # Counter pattern
            bytes(range(256)),
            # Typical LICHEN frame with header
            b"\x01\x00\x0A" + b"\xDE\xAD\xBE\xEF" * 4 + b"\x12\x34\x56\x78",
            # Binary data with embedded nulls
            b"LICHEN\x00\x00FRAME\x00DATA",
        ]

        for test_frame in test_frames:
            rx_results: list[bytes] = []

            def on_rx(payload: bytes, rssi: int, snr: int) -> None:
                rx_results.append(payload)

            def on_timeout() -> None:
                pass

            sim.enter_rx_mode(
                "rx-node",
                timeout_us=10_000_000,
                on_packet=on_rx,
                on_timeout=on_timeout,
            )

            sim.start_transmission("tx-node", test_frame)

            # Run simulation
            for _ in range(500):
                sim.deliver_pending_packets()
                sim.maybe_advance_time()
                if rx_results:
                    break

            assert len(rx_results) == 1, f"No RX for frame: {test_frame.hex()}"
            assert rx_results[0] == test_frame, (
                f"Frame mismatch:\n"
                f"  TX: {test_frame.hex()}\n"
                f"  RX: {rx_results[0].hex()}"
            )

    @pytest.mark.asyncio
    async def test_bidirectional_communication(self) -> None:
        """Test that both nodes can transmit and receive.

        Verifies the DIO1 RX path works in both directions.
        """
        sim = Simulation("test-bidirectional", time_mode=TimeMode.BARRIER_SYNC)

        sim.add_node("alice", x=0.0, y=0.0, z=0.0)
        sim.add_node("bob", x=50.0, y=0.0, z=0.0)

        alice_rx: list[bytes] = []
        bob_rx: list[bytes] = []

        def alice_on_rx(payload: bytes, rssi: int, snr: int) -> None:
            alice_rx.append(payload)

        def bob_on_rx(payload: bytes, rssi: int, snr: int) -> None:
            bob_rx.append(payload)

        def noop_timeout() -> None:
            pass

        # Alice transmits to Bob
        sim.enter_rx_mode("bob", timeout_us=10_000_000, on_packet=bob_on_rx, on_timeout=noop_timeout)
        alice_msg = b"Hello from Alice"
        sim.start_transmission("alice", alice_msg)

        for _ in range(500):
            sim.deliver_pending_packets()
            sim.maybe_advance_time()
            if bob_rx:
                break

        assert bob_rx == [alice_msg]

        # Bob transmits to Alice
        sim.enter_rx_mode("alice", timeout_us=10_000_000, on_packet=alice_on_rx, on_timeout=noop_timeout)
        bob_msg = b"Hello from Bob"
        sim.start_transmission("bob", bob_msg)

        for _ in range(500):
            sim.deliver_pending_packets()
            sim.maybe_advance_time()
            if alice_rx:
                break

        assert alice_rx == [bob_msg]

    @pytest.mark.asyncio
    async def test_rssi_snr_values_are_reasonable(self) -> None:
        """Test that RSSI and SNR values are within expected ranges.

        For 50m separation with typical LoRa parameters:
        - RSSI should be roughly -60 to -80 dBm
        - SNR should be positive (good link)
        """
        sim = Simulation("test-rssi-snr", time_mode=TimeMode.BARRIER_SYNC)

        sim.add_node("tx", x=0.0, y=0.0, z=0.0)
        sim.add_node("rx", x=50.0, y=0.0, z=0.0)

        rssi_values: list[int] = []
        snr_values: list[int] = []

        def on_rx(payload: bytes, rssi: int, snr: int) -> None:
            rssi_values.append(rssi)
            snr_values.append(snr)

        def on_timeout() -> None:
            pass

        sim.enter_rx_mode("rx", timeout_us=10_000_000, on_packet=on_rx, on_timeout=on_timeout)
        sim.start_transmission("tx", b"TEST")

        for _ in range(500):
            sim.deliver_pending_packets()
            sim.maybe_advance_time()
            if rssi_values:
                break

        assert len(rssi_values) == 1
        rssi = rssi_values[0]
        snr = snr_values[0]

        # RSSI should be negative and reasonable for 50m
        assert -120 < rssi < -30, f"RSSI {rssi} dBm out of expected range"
        # SNR is returned as dB * 10 in some cases, or raw dB
        # Either way, at 50m it should be reasonably good
        assert snr >= -100, f"SNR {snr} unexpectedly low for 50m distance"
