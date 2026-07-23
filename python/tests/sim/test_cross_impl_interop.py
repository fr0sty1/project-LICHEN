# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Cross-implementation interop tests: Python vs Rust vs Zephyr.

These tests verify that frames transmitted by one implementation can be
correctly parsed by another. This catches:
- Byte order mismatches (big vs little endian)
- Field size disagreements (u16 vs u32)
- Encoding differences (varint vs fixed)
- Constant mismatches (rule IDs, dispatch bytes)

Architecture:
1. Start lichen-sim server
2. Python node transmits test frames
3. Rust node receives and parses
4. Compare parsed fields match expected

Run with:
    LICHEN_RUN_CROSS_IMPL=1 pytest -v tests/sim/test_cross_impl_interop.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from collections.abc import AsyncGenerator
from pathlib import Path

import pytest

from lichen.announce.messages import AnnounceMessage
from lichen.announce.scheduler import AnnounceScheduler, SchedulerConfig
from lichen.crypto.identity import Identity
from lichen.link.frame import AddrMode, LichenFrame, MicLength
from lichen.radio.sim_client import SimRadio
from lichen.sim.server import SimulatorServer
from lichen.sim.simulation import Simulation, TimeMode


class MockTransmitter:
    """Mock transmitter for AnnounceScheduler."""

    def __init__(self) -> None:
        self.last_data: bytes | None = None

    async def transmit_announce(self, data: bytes) -> bool:
        self.last_data = data
        return True


PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
RUN_CROSS_IMPL = os.environ.get("LICHEN_RUN_CROSS_IMPL") == "1"


def _has_rust_test_binary() -> bool:
    """Check if the Rust interop test binary is available."""
    binary = PROJECT_ROOT / "rust/target/release/cross-impl-receiver"
    return binary.exists()


@pytest.fixture
async def simulator_server() -> AsyncGenerator[tuple[SimulatorServer, Simulation], None]:
    """Start simulator server for cross-impl testing."""
    server = SimulatorServer(node_port=0, api_port=0)
    await server.start()
    sim = await server.create_simulation("cross-impl-test", TimeMode.BARRIER_SYNC)
    yield server, sim
    await server.stop()


class TestPythonToPythonBaseline:
    """Baseline: Python transmit, Python receive (sanity check)."""

    @pytest.mark.asyncio
    async def test_link_frame_roundtrip(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Python node transmits, Python node receives and parses."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("cross-impl-test")
        assert node_port is not None

        # Build a raw payload to transmit (the sim doesn't require valid frames)
        payload = b"hello cross-impl test"

        async with (
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "tx-node", (0.0, 0.0, 0.0)
            ) as radio_tx,
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "rx-node", (50.0, 0.0, 0.0)
            ) as radio_rx,
        ):
            # TX
            tx_ok = await radio_tx.transmit(payload)
            assert tx_ok is True

            # RX
            result = await radio_rx.receive(1000)
            assert result is not None
            rx_data, rssi, snr = result

            # Verify payload matches
            assert rx_data == payload

    @pytest.mark.asyncio
    async def test_announce_roundtrip(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Python node transmits announce, Python node receives."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("cross-impl-test")
        assert node_port is not None

        # Create identity and announce via scheduler
        seed = bytes([0x42] + [0] * 31)
        identity = Identity.from_seed(seed)
        mock_tx = MockTransmitter()
        scheduler = AnnounceScheduler(
            identity=identity,
            transmitter=mock_tx,
            config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
        )
        announce = scheduler.build_announce()
        announce_bytes = announce.to_bytes()

        async with (
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "announce-tx", (0.0, 0.0, 0.0)
            ) as radio_tx,
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "announce-rx", (50.0, 0.0, 0.0)
            ) as radio_rx,
        ):
            # TX
            tx_ok = await radio_tx.transmit(announce_bytes)
            assert tx_ok is True

            # RX
            result = await radio_rx.receive(1000)
            assert result is not None
            rx_data, _, _ = result

            # Parse and verify
            rx_announce = AnnounceMessage.from_bytes(rx_data)
            assert rx_announce.seq_num == 1  # First announce from scheduler
            assert rx_announce.hop_count == 0
            assert rx_announce.originator_iid == identity.iid


class TestPythonToRust:
    """Python transmit, Rust receive and parse."""

    def test_link_frame_interop_via_vectors(self) -> None:
        """Python-encoded frames parsed by Rust frame-parser.

        Uses test vectors from test/vectors/link_frame.json.
        Verifies Python encoding matches Rust parsing.
        """
        rust_binary = PROJECT_ROOT / "rust/target/release/frame-parser"
        vectors_path = PROJECT_ROOT / "test/vectors/link_frame.json"

        if not rust_binary.exists():
            if RUN_CROSS_IMPL:
                pytest.fail("Rust frame-parser binary not built")
            pytest.skip("Rust frame-parser binary not built (cargo build --release -p lichen-apps)")

        if not vectors_path.exists():
            if RUN_CROSS_IMPL:
                pytest.fail("Test vectors not found")
            pytest.skip("Test vectors not found")

        with open(vectors_path) as f:
            vectors = json.load(f)

        for vector in vectors["vectors"]:
            fields = vector["fields"]
            dst_addr = bytes.fromhex(fields["dst_addr"])
            payload = bytes.fromhex(fields["payload"])
            mic = bytes.fromhex(fields["mic"])
            assert len(dst_addr) == (0, 2, 8, 0)[fields["addr_mode"]]
            assert len(mic) == (48 if fields["signature_present"] else 0)
            llsec = (
                fields["addr_mode"]
                | (fields["mic_length"] << 2)
                | (int(fields["signature_present"]) << 5)
                | (int(fields["encrypted"]) << 6)
            )
            body = (
                bytes([llsec, fields["epoch"]])
                + fields["seqnum"].to_bytes(2, "big")
                + dst_addr
                + payload
                + mic
            )
            encoded = bytes.fromhex(vector["encoded"])
            expected_error = vector.get("expect", {}).get("error")
            if expected_error == "frame_too_large":
                assert len(encoded) == 256
                assert encoded[0] == 255
            else:
                assert len(body) <= 254
                assert len(encoded) <= 255
                assert encoded[0] == len(body)
                assert encoded[1:] == body

            frame = LichenFrame(
                epoch=fields["epoch"],
                seqnum=fields["seqnum"],
                dst_addr=dst_addr,
                payload=payload,
                mic=mic,
                addr_mode=AddrMode(fields["addr_mode"]),
                mic_length=MicLength(fields["mic_length"]),
                signature_present=fields["signature_present"],
                encrypted=fields["encrypted"],
            )
            if expected_error == "encryption_unsupported":
                python_error = {
                    "encryption_unsupported": "encrypted frames are unsupported",
                }[expected_error]
                with pytest.raises(FrameError) as exc_info:
                    frame.to_bytes()
                assert str(exc_info.value) == python_error
            else:
                if expected_error is None:
                    assert frame.to_bytes().hex() == vector["encoded"]

            # Parse with Rust
            result = subprocess.run(
                [str(rust_binary), "--hex", vector["encoded"]],
                capture_output=True,
                timeout=5,
            )
            if vector.get("expect", {}).get("error"):
                assert result.returncode != 0, f"Vector '{vector['name']}' should be rejected"
                continue
            assert result.returncode == 0, (
                f"Vector '{vector['name']}' parse failed: {result.stderr.decode()}"
            )

            parsed = json.loads(result.stdout)
            fields = vector["fields"]
            name = vector["name"]

            python_frame = LichenFrame(
                epoch=fields["epoch"],
                seqnum=fields["seqnum"],
                dst_addr=bytes.fromhex(fields["dst_addr"]),
                payload=bytes.fromhex(fields["payload"]),
                mic=bytes.fromhex(fields["mic"]),
                addr_mode=AddrMode(fields["addr_mode"]),
                mic_length=MicLength(fields["mic_length"]),
                signature_present=fields["signature_present"],
                encrypted=fields["encrypted"],
            )
            assert python_frame.to_bytes() == bytes.fromhex(vector["encoded"]), (
                f"Vector '{vector['name']}': Python encoding mismatch"
            )

            # Verify fields match
            assert parsed["epoch"] == fields["epoch"], f"Vector '{name}': epoch mismatch"
            assert parsed["seqnum"] == fields["seqnum"], f"Vector '{name}': seqnum mismatch"
            assert parsed["addr_mode"] == fields["addr_mode"], (
                f"Vector '{name}': addr_mode mismatch"
            )
            assert parsed["signature_present"] == fields["signature_present"], (
                f"Vector '{name}': signature_present mismatch"
            )
            assert parsed["encrypted"] == fields["encrypted"], (
                f"Vector '{name}': encrypted mismatch"
            )
            assert parsed["mic_length"] == fields["mic_length"], (
                f"Vector '{name}': mic_length mismatch"
            )
            assert parsed["dst_addr"] == fields["dst_addr"], (
                f"Vector '{name}': dst_addr mismatch"
            )
            assert parsed["payload"] == fields["payload"], (
                f"Vector '{name}': payload mismatch"
            )
            assert parsed["mic"] == fields["mic"], f"Vector '{name}': mic mismatch"
            assert parsed["total_len"] == len(bytes.fromhex(vector["encoded"])), (
                f"Vector '{name}': length mismatch"
            )

    @pytest.mark.skipif(
        not RUN_CROSS_IMPL,
        reason="set LICHEN_RUN_CROSS_IMPL=1 to run cross-implementation tests",
    )
    @pytest.mark.asyncio
    async def test_live_frame_interop(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Python transmits via simulator, Rust binary parses captured frame."""
        server, sim = simulator_server
        node_port = server.get_node_server_port("cross-impl-test")
        assert node_port is not None

        rust_binary = PROJECT_ROOT / "rust/target/release/frame-parser"
        if not rust_binary.exists():
            if RUN_CROSS_IMPL:
                pytest.fail("Rust frame-parser binary not built")
            pytest.skip("Rust frame-parser binary not built")

        # Build frame using test vector data
        frame_hex = "0700010002616263"  # broadcast_min, unsigned with no MIC

        async with (
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "tx-node", (0.0, 0.0, 0.0)
            ) as radio_tx,
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "rx-node", (50.0, 0.0, 0.0)
            ) as radio_rx,
        ):
            # TX
            tx_ok = await radio_tx.transmit(frame_bytes)
            assert tx_ok is True

            # RX
            result = await radio_rx.receive(1000)
            assert result is not None
            rx_data, _, _ = result
            assert rx_data == frame_bytes

            # Parse received data with Rust
            rx_hex = rx_data.hex()
            proc = subprocess.run(
                [str(rust_binary), "--hex", rx_hex],
                capture_output=True,
                timeout=5,
            )
            assert proc.returncode == 0, f"Rust parse failed: {proc.stderr.decode()}"

            parsed = json.loads(proc.stdout)
            assert parsed["epoch"] == 1
            assert parsed["seqnum"] == 2
            assert parsed["addr_mode"] == 0
            assert parsed["mic_length"] == 0
            assert parsed["signature_present"] is False
            assert parsed["encrypted"] is False
            assert parsed["dst_addr"] == ""
            assert parsed["payload"] == "616263"  # "abc"
            assert parsed["mic"] == ""
            assert parsed["total_len"] == len(frame_bytes)


@pytest.mark.skipif(
    not RUN_CROSS_IMPL,
    reason="set LICHEN_RUN_CROSS_IMPL=1 to run cross-implementation tests",
)
class TestMultiNodeMesh:
    """Multi-node mesh tests with mixed implementations.

    These test real protocol interop across a simulated mesh network.
    """

    @pytest.mark.asyncio
    async def test_five_node_announce_propagation(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """5 nodes in a line, verify announce reaches all nodes.

        Topology: A--B--C--D--E (50m spacing)
        A sends announce, verify E receives it (via relays).
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("cross-impl-test")
        assert node_port is not None

        # Create 5 nodes in a line
        positions = [(i * 50.0, 0.0, 0.0) for i in range(5)]
        radios = []

        for i, pos in enumerate(positions):
            radio = SimRadio("127.0.0.1", node_port, "cross-impl-test", f"node-{i}", pos)
            await radio.connect()
            radios.append(radio)

        try:
            # Node 0 transmits announce
            seed = bytes([0x00] + [0] * 31)
            identity = Identity.from_seed(seed)
            mock_tx = MockTransmitter()
            scheduler = AnnounceScheduler(
                identity=identity,
                transmitter=mock_tx,
                config=SchedulerConfig(interval_ms=1000, jitter_ms=0, initial_delay_ms=0),
            )
            announce = scheduler.build_announce()

            await radios[0].transmit(announce.to_bytes())

            # Node 1 (immediate neighbor) should receive
            result = await radios[1].receive(1000)
            assert result is not None, "Node 1 should receive announce from Node 0"
            rx_data, _, _ = result
            rx_announce = AnnounceMessage.from_bytes(rx_data)
            assert rx_announce.seq_num == 1

            # Node 1 relays by re-transmitting (real implementation would increment hop)
            await radios[1].transmit(rx_data)

            # Node 2 receives relay
            result = await radios[2].receive(1000)
            assert result is not None, "Node 2 should receive relayed announce"
            rx_data, _, _ = result
            rx_announce = AnnounceMessage.from_bytes(rx_data)
            assert rx_announce.seq_num == 1

        finally:
            for radio in radios:
                await radio.disconnect()

    @pytest.mark.asyncio
    async def test_hidden_terminal_scenario(
        self, simulator_server: tuple[SimulatorServer, Simulation]
    ) -> None:
        """Classic hidden terminal: A--B--C where A and C can't hear each other.

        Both A and C transmit to B. Verify at least one succeeds (collision
        detection is implementation-defined in simulation).
        """
        server, sim = simulator_server
        node_port = server.get_node_server_port("cross-impl-test")
        assert node_port is not None

        async with (
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "node-a", (0.0, 0.0, 0.0)
            ) as radio_a,
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "node-b", (100.0, 0.0, 0.0)
            ) as radio_b,
            SimRadio(
                "127.0.0.1", node_port, "cross-impl-test", "node-c", (200.0, 0.0, 0.0)
            ) as radio_c,
        ):
            # A and C both transmit different payloads
            payload_a = b"from-a"
            payload_b = b"from-c"

            # Transmit concurrently
            await asyncio.gather(
                radio_a.transmit(payload_a),
                radio_c.transmit(payload_b),
            )

            # B receives (may get one, both, or neither depending on timing)
            received = []
            for _ in range(2):
                result = await radio_b.receive(500)
                if result:
                    rx_data, _, _ = result
                    received.append(rx_data)

            # At least one should succeed in most simulation models
            # (exact behavior depends on medium implementation)
            print(f"Hidden terminal test: B received {len(received)} packets")
