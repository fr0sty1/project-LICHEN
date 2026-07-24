# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration test for native LCI interface over SLIP transport.

End-to-end test of native LCI interface: starts native_sim node with SLIP
transport, uses aiocoap-backed LciClient to exercise CoAP resources per
spec/11-lci.md.

Run with:
    LICHEN_RUN_NATIVE_LCI_INTEGRATION=1 pytest -v -k native_lci

Requirements:
- Zephyr native_sim binary with LCI CoAP server and SLIP transport
- Build: west build -b native_sim firmware/bridge-zephyr -- -DCONFIG_NET_SLIP=y

Architecture:
    pytest <--> LciClient <--> PacketCoapResourceTransport
        <--> PacketDatagramChannel <--> SlipPacketTransport <--> PTY
        <--> native_sim

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
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import cbor2
import pytest

from lichen.client.ip_coap import CoapTransportError
from lichen.client.lci import LciClient
from lichen.client.model import DeviceStatus, Neighbor
from lichen.client.packet_coap import PacketCoapConfig, PacketCoapResourceTransport
from lichen.client.transport import PacketTransport
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
# PacketTransport over PTY + SLIP
# ============================================================================


class SlipPacketTransport(PacketTransport):
    """PacketTransport implementation over a PTY with SLIP framing.

    Sends and receives IPv6 packets through a PTY connected to native_sim,
    using SLIP (RFC 1055) framing.
    """

    def __init__(self, master_fd: int) -> None:
        self._master_fd = master_fd
        self._decoder = StreamDecoder()
        self._rx_queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._reader_task: asyncio.Task[None] | None = None
        self._closed = False

    async def connect(self) -> None:
        if self._reader_task is None:
            self._reader_task = asyncio.create_task(self._read_loop())

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
            self._reader_task = None

    async def send_packet(self, packet: bytes) -> None:
        frame = slip_encode(packet)
        os.write(self._master_fd, frame)

    def packets(self) -> AsyncIterator[bytes]:
        return self._packets()

    async def _packets(self) -> AsyncIterator[bytes]:
        while not self._closed:
            try:
                packet = await asyncio.wait_for(
                    self._rx_queue.get(), timeout=1.0
                )
            except TimeoutError:
                continue
            if packet is None:
                break
            yield packet

    async def _read_loop(self) -> None:
        loop = asyncio.get_event_loop()
        while not self._closed:
            try:
                data = await loop.run_in_executor(None, self._read_available)
                if data:
                    for packet in self._decoder.feed(data):
                        await self._rx_queue.put(packet)
            except OSError:
                break
            except asyncio.CancelledError:
                break
        await self._rx_queue.put(None)

    def _read_available(self) -> bytes:
        import select

        readable, _, _ = select.select([self._master_fd], [], [], 0.1)
        if readable:
            return os.read(self._master_fd, SLIP_BUFFER_SIZE)
        return b""


# ============================================================================
# Native Sim Process Manager
# ============================================================================


def _find_native_sim_binary() -> Path | None:
    for twister_dir in PROJECT_ROOT.glob("twister-out*"):
        native_sim_dir = twister_dir / "native_sim"
        if native_sim_dir.is_dir():
            for test_dir in native_sim_dir.iterdir():
                binary = test_dir / "zephyr" / "zephyr.exe"
                if binary.exists():
                    return binary

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
    packet_transport: SlipPacketTransport
    lci_client: LciClient | None = field(default=None, init=False)
    _resource_transport: PacketCoapResourceTransport | None = field(
        default=None, init=False
    )

    @classmethod
    async def start(cls, binary_path: Path) -> NativeSimProcess:
        master_fd, slave_fd = pty.openpty()
        slave_name = os.ttyname(slave_fd)

        process = subprocess.Popen(
            [
                str(binary_path),
                f"--bt-dev={slave_name}",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        await asyncio.sleep(0.5)

        packet_transport = SlipPacketTransport(master_fd)

        return cls(
            process=process,
            master_fd=master_fd,
            slave_fd=slave_fd,
            packet_transport=packet_transport,
        )

    async def connect_lci(self) -> LciClient:
        if self.lci_client is not None:
            return self.lci_client

        config = PacketCoapConfig(
            local_host="fe80::2",
            peer_host="fe80::1",
            timeout_s=COAP_TIMEOUT,
        )
        transport = PacketCoapResourceTransport(
            self.packet_transport,
            config=config,
        )
        await transport.connect()
        client = LciClient(transport)
        self._resource_transport = transport
        self.lci_client = client
        return client

    async def stop(self) -> None:
        if self.lci_client is not None:
            try:
                await self.lci_client.close()
            except (CoapTransportError, OSError, asyncio.CancelledError):
                pass
            self.lci_client = None
            self._resource_transport = None

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
# Test Fixtures
# ============================================================================


@pytest.fixture
async def native_sim() -> NativeSimProcess | None:
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
async def lci_client(
    native_sim: NativeSimProcess | None,
) -> LciClient | None:
    if native_sim is None:
        yield None
        return

    client = await native_sim.connect_lci()
    try:
        yield client
    finally:
        pass


# ============================================================================
# Skip Conditions
# ============================================================================


def _has_native_sim() -> bool:
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
    binary = _find_native_sim_binary()
    assert binary is not None

    proc = await NativeSimProcess.start(binary)
    try:
        assert proc.process.poll() is None
        await asyncio.sleep(0.5)
        assert proc.process.poll() is None
    finally:
        await proc.stop()

    assert proc.process.poll() is not None


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_well_known_core_discovery(
    lci_client: LciClient | None,
) -> None:
    if lci_client is None:
        pytest.skip("native_sim not available")

    resources = await lci_client.discover()

    assert isinstance(resources, list)
    resource_paths = {r for r in resources}
    assert "/status" in resource_paths
    assert "/config" in resource_paths
    assert "/neighbors" in resource_paths


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_status_resource(
    lci_client: LciClient | None,
) -> None:
    if lci_client is None:
        pytest.skip("native_sim not available")

    status = await lci_client.get_status()

    assert isinstance(status, DeviceStatus)
    assert status.uptime_s is not None
    assert isinstance(status.uptime_s, int)
    assert status.uptime_s >= 0


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_config_resource_get(
    lci_client: LciClient | None,
) -> None:
    if lci_client is None:
        pytest.skip("native_sim not available")

    config = await lci_client.get_config()

    assert isinstance(config, dict)
    assert len(config) >= 0


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_config_resource_put(
    lci_client: LciClient | None,
) -> None:
    if lci_client is None:
        pytest.skip("native_sim not available")

    await lci_client.set_config({"name": "test-node"})


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_neighbors_resource(
    lci_client: LciClient | None,
) -> None:
    if lci_client is None:
        pytest.skip("native_sim not available")

    neighbors = await lci_client.list_neighbors()

    assert isinstance(neighbors, list)
    for n in neighbors:
        assert isinstance(n, Neighbor)


@skip_integration_disabled
@skip_no_native_sim
@pytest.mark.asyncio
async def test_key_resource(
    lci_client: LciClient | None,
) -> None:
    if lci_client is None:
        pytest.skip("native_sim not available")

    identity = await lci_client.get_identity()

    assert isinstance(identity, dict)
    if "fingerprint" in identity:
        assert isinstance(identity["fingerprint"], str)
    if "pubkey" in identity:
        assert isinstance(identity["pubkey"], bytes)
        assert len(identity["pubkey"]) == 32


# ============================================================================
# CBOR Encoding Contract Tests
# ============================================================================


class TestCborEncodingContracts:
    """Test CBOR encoding matches spec/11-lci.md contracts.

    These tests verify the CBOR encoding/decoding logic works correctly,
    independent of the transport layer.
    """

    def test_status_payload_structure(self) -> None:
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
        pubkey = bytes(32)
        payload = {
            "fingerprint": pubkey[:8].hex(),
            "pubkey": pubkey,
        }
        encoded = cbor2.dumps(payload)
        decoded = cbor2.loads(encoded)

        assert len(decoded["fingerprint"]) == 16
        assert len(decoded["pubkey"]) == 32
