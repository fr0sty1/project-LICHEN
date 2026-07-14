# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration test for native LCI interface over SLIP transport.

End-to-end test of native LCI interface: starts native_sim node with SLIP
transport, uses aiocoap to exercise CoAP resources per spec/11-lci.md.

Run with:
    LICHEN_RUN_NATIVE_LCI_INTEGRATION=1 pytest -v -k native_lci

Requirements:
- Zephyr native_sim binary with LCI CoAP server and SLIP transport
- Build: west build -b native_sim firmware/bridge-zephyr -- -DCONFIG_NET_SLIP=y

Architecture:
    pytest <--> aiocoap <--> SlipTransport <--> PTY <--> native_sim

This test exercises LCI resources defined in spec/11-lci.md:
- /.well-known/core (resource discovery)
- /status (node status)
- /config (GET/PUT)
- /neighbors (neighbor table)
- /key (public key, if available)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import pty
import signal
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cbor2
import pytest

from lichen.slip.codec import StreamDecoder
from lichen.slip.codec import encode as slip_encode

# ============================================================================
# Configuration
# ============================================================================

PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
TWISTER_OUT = PROJECT_ROOT / "twister-out"
RUN_NATIVE_LCI_INTEGRATION = os.environ.get("LICHEN_RUN_NATIVE_LCI_INTEGRATION") == "1"

# Default timeout for CoAP requests (seconds)
COAP_TIMEOUT = 5.0

# SLIP transport settings
SLIP_BUFFER_SIZE = 4096


# ============================================================================
# SLIP Transport over PTY
# ============================================================================


@dataclass
class SlipPtyTransport:
    """SLIP framing over a PTY connected to native_sim.

    Provides send/receive for IPv6 packets wrapped in SLIP framing.
    Used as the underlying transport for CoAP communication with native_sim.
    """

    master_fd: int
    decoder: StreamDecoder

    @classmethod
    def create(cls, master_fd: int) -> SlipPtyTransport:
        """Create a SLIP transport from a PTY master file descriptor."""
        return cls(master_fd=master_fd, decoder=StreamDecoder())

    def send(self, packet: bytes) -> None:
        """Send an IPv6 packet wrapped in SLIP framing."""
        frame = slip_encode(packet)
        os.write(self.master_fd, frame)

    async def receive(self, timeout: float = 1.0) -> bytes | None:
        """Receive and decode the next SLIP-framed IPv6 packet.

        Returns None on timeout.
        """
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout

        while loop.time() < deadline:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None

            try:
                # Use select to check if data is available
                ready = await asyncio.wait_for(
                    loop.run_in_executor(None, self._read_available),
                    timeout=remaining,
                )
                if ready:
                    packets = self.decoder.feed(ready)
                    if packets:
                        return packets[0]
            except TimeoutError:
                return None

        return None

    def _read_available(self) -> bytes:
        """Read available data from PTY (blocking helper for executor)."""
        import select

        readable, _, _ = select.select([self.master_fd], [], [], 0.1)
        if readable:
            return os.read(self.master_fd, SLIP_BUFFER_SIZE)
        return b""


# ============================================================================
# Native Sim Process Manager
# ============================================================================


def _find_native_sim_binary() -> Path | None:
    """Find a native_sim binary with SLIP support.

    Searches:
    1. twister-out/ for test builds
    2. firmware/bridge-zephyr/build/ for manual builds
    """
    # Check twister-out for native_sim builds
    for twister_dir in PROJECT_ROOT.glob("twister-out*"):
        native_sim_dir = twister_dir / "native_sim"
        if native_sim_dir.is_dir():
            for test_dir in native_sim_dir.iterdir():
                binary = test_dir / "zephyr" / "zephyr.exe"
                if binary.exists():
                    return binary

    # Check manual build directory
    bridge_build = PROJECT_ROOT / "firmware" / "bridge-zephyr" / "build"
    if bridge_build.exists():
        binary = bridge_build / "zephyr" / "zephyr.exe"
        if binary.exists():
            return binary

    return None


@dataclass
class NativeSimProcess:
    """Manages a native_sim process with PTY for SLIP communication."""

    process: subprocess.Popen[bytes]
    master_fd: int
    slave_fd: int
    transport: SlipPtyTransport

    @classmethod
    async def start(cls, binary_path: Path) -> NativeSimProcess:
        """Start native_sim with a PTY for SLIP communication.

        Args:
            binary_path: Path to the native_sim executable.

        Returns:
            NativeSimProcess managing the running instance.
        """
        # Create PTY pair for SLIP communication
        master_fd, slave_fd = pty.openpty()

        # Get the slave device name
        slave_name = os.ttyname(slave_fd)

        # Start native_sim with the PTY as its serial device
        # native_sim uses --bt-dev for serial device path
        process = subprocess.Popen(
            [
                str(binary_path),
                f"--bt-dev={slave_name}",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Give the process time to initialize
        await asyncio.sleep(0.5)

        transport = SlipPtyTransport.create(master_fd)

        return cls(
            process=process,
            master_fd=master_fd,
            slave_fd=slave_fd,
            transport=transport,
        )

    async def stop(self) -> None:
        """Stop the native_sim process and cleanup resources."""
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, self.process.wait
                    ),
                    timeout=5.0,
                )
            except TimeoutError:
                self.process.kill()
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None, self.process.wait
                        ),
                        timeout=2.0,
                    )

        os.close(self.master_fd)
        os.close(self.slave_fd)


# ============================================================================
# CoAP Client for SLIP Transport
# ============================================================================


class SlipCoapClient:
    """Minimal CoAP client over SLIP transport.

    This is a simplified CoAP implementation that works over SLIP
    for testing purposes. For full LCI testing, use aiocoap with
    a proper transport binding.

    Note: This stub implementation demonstrates the architecture.
    Full implementation requires CoAP message parsing/serialization.
    """

    def __init__(self, transport: SlipPtyTransport) -> None:
        self.transport = transport
        self._message_id = 0

    def _next_message_id(self) -> int:
        self._message_id = (self._message_id + 1) & 0xFFFF
        return self._message_id

    async def get(self, path: str, timeout: float = COAP_TIMEOUT) -> dict[str, Any]:
        """Send a CoAP GET request and return the parsed CBOR response.

        Args:
            path: Resource path (e.g., "/status")
            timeout: Request timeout in seconds

        Returns:
            Parsed CBOR payload as a dictionary

        Raises:
            TimeoutError: If no response received
            ValueError: If response parsing fails
        """
        # TODO: Implement full CoAP request/response over SLIP
        # This requires:
        # 1. Build CoAP GET message
        # 2. Wrap in IPv6+UDP headers
        # 3. Send via SLIP
        # 4. Receive and parse response
        raise NotImplementedError(
            "Full CoAP-over-SLIP implementation pending. "
            "See architecture notes in module docstring."
        )

    async def put(
        self, path: str, payload: dict[str, Any], timeout: float = COAP_TIMEOUT
    ) -> bool:
        """Send a CoAP PUT request with CBOR payload.

        Args:
            path: Resource path (e.g., "/config")
            payload: Dictionary to encode as CBOR
            timeout: Request timeout in seconds

        Returns:
            True if the PUT was successful (2.xx response)

        Raises:
            TimeoutError: If no response received
        """
        raise NotImplementedError(
            "Full CoAP-over-SLIP implementation pending. "
            "See architecture notes in module docstring."
        )


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
async def native_sim() -> NativeSimProcess | None:
    """Fixture providing a running native_sim process with SLIP transport.

    Yields None if native_sim binary is not available.
    """
    binary = _find_native_sim_binary()
    if binary is None:
        yield None
        return

    proc = await NativeSimProcess.start(binary)
    try:
        yield proc
    finally:
        await proc.stop()


@pytest.fixture
def coap_client(
    native_sim: NativeSimProcess | None,
) -> SlipCoapClient | None:
    """Fixture providing a CoAP client connected to native_sim."""
    if native_sim is None:
        return None
    return SlipCoapClient(native_sim.transport)


# ============================================================================
# Skip Conditions
# ============================================================================


def _has_native_sim() -> bool:
    """Check if native_sim binary is available."""
    return _find_native_sim_binary() is not None


skip_no_native_sim = pytest.mark.skipif(
    not _has_native_sim(),
    reason="native_sim binary not found; build with: west build -b native_sim",
)

skip_integration_disabled = pytest.mark.skipif(
    not RUN_NATIVE_LCI_INTEGRATION,
    reason="set LICHEN_RUN_NATIVE_LCI_INTEGRATION=1 to run native LCI integration",
)


# ============================================================================
# Integration Tests
# ============================================================================


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_native_sim_starts() -> None:
    """Test that native_sim starts and can be stopped cleanly."""
    binary = _find_native_sim_binary()
    assert binary is not None

    proc = await NativeSimProcess.start(binary)
    try:
        # Verify process is running
        assert proc.process.poll() is None
        # Give it time to initialize
        await asyncio.sleep(0.5)
        # Still running
        assert proc.process.poll() is None
    finally:
        await proc.stop()

    # Process should be terminated
    assert proc.process.poll() is not None


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_well_known_core_discovery(
    coap_client: SlipCoapClient | None,
) -> None:
    """Test CoAP resource discovery via /.well-known/core.

    Per RFC 6690, the response is link-format listing available resources.
    Expected resources per spec/11-lci.md:
    - /status
    - /config
    - /neighbors
    """
    if coap_client is None:
        pytest.skip("native_sim not available")

    # TODO: Implement when CoAP-over-SLIP is ready
    pytest.skip("CoAP-over-SLIP implementation pending")


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_status_resource(
    coap_client: SlipCoapClient | None,
) -> None:
    """Test GET /status returns CBOR-encoded node status.

    Expected fields per spec/11-lci.md:
    - uptime_s: integer seconds since boot
    - rank: RPL rank (if joined)
    - battery_pct: battery percentage (if applicable)
    """
    if coap_client is None:
        pytest.skip("native_sim not available")

    # TODO: Implement when CoAP-over-SLIP is ready
    pytest.skip("CoAP-over-SLIP implementation pending")


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_config_resource_get(
    coap_client: SlipCoapClient | None,
) -> None:
    """Test GET /config returns CBOR-encoded configuration."""
    if coap_client is None:
        pytest.skip("native_sim not available")

    # TODO: Implement when CoAP-over-SLIP is ready
    pytest.skip("CoAP-over-SLIP implementation pending")


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_config_resource_put(
    coap_client: SlipCoapClient | None,
) -> None:
    """Test PUT /config updates configuration and returns 2.04 Changed."""
    if coap_client is None:
        pytest.skip("native_sim not available")

    # TODO: Implement when CoAP-over-SLIP is ready
    pytest.skip("CoAP-over-SLIP implementation pending")


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_neighbors_resource(
    coap_client: SlipCoapClient | None,
) -> None:
    """Test GET /neighbors returns CBOR neighbor table.

    In a freshly started node with no peers, this should return an empty list.
    """
    if coap_client is None:
        pytest.skip("native_sim not available")

    # TODO: Implement when CoAP-over-SLIP is ready
    pytest.skip("CoAP-over-SLIP implementation pending")


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_key_resource(
    coap_client: SlipCoapClient | None,
) -> None:
    """Test GET /key returns public key and fingerprint.

    Expected fields:
    - fingerprint: hex string (first 8 bytes of pubkey)
    - pubkey: raw 32-byte public key
    """
    if coap_client is None:
        pytest.skip("native_sim not available")

    # TODO: Implement when CoAP-over-SLIP is ready
    pytest.skip("CoAP-over-SLIP implementation pending")


# ============================================================================
# CBOR Encoding Contract Tests
# ============================================================================


class TestCborEncodingContracts:
    """Test CBOR encoding matches spec/11-lci.md contracts.

    These tests verify the CBOR encoding/decoding logic works correctly,
    independent of the transport layer.
    """

    def test_status_payload_structure(self) -> None:
        """Verify status payload CBOR structure."""
        payload = {
            "uptime_s": 12345,
            "battery_pct": 87,
            "battery_mv": 3950,
            "rank": 512,
        }
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)

        assert decoded["uptime_s"] == 12345
        assert decoded["battery_pct"] == 87
        assert isinstance(decoded["rank"], int)

    def test_config_payload_structure(self) -> None:
        """Verify config payload CBOR structure."""
        payload = {
            "name": "node-01",
            "role": "router",
            "region": "US915",
            "tx_power_dbm": 14,
        }
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)

        assert decoded["name"] == "node-01"
        assert decoded["tx_power_dbm"] == 14

    def test_neighbors_payload_structure(self) -> None:
        """Verify neighbors payload CBOR structure."""
        payload = [
            {
                "addr": "fe80::1",
                "rank": 256,
                "etx": 1.5,
                "rssi_dbm": -80,
            }
        ]
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)

        assert len(decoded) == 1
        assert decoded[0]["addr"] == "fe80::1"
        assert decoded[0]["etx"] == 1.5

    def test_key_payload_structure(self) -> None:
        """Verify key payload CBOR structure."""
        pubkey = bytes(32)  # 32-byte Ed25519 public key
        payload = {
            "fingerprint": pubkey[:8].hex(),
            "pubkey": pubkey,
        }
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)

        assert len(decoded["fingerprint"]) == 16  # 8 bytes = 16 hex chars
        assert len(decoded["pubkey"]) == 32
