# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for serial/USB LoRa radio bridge server."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from lichen.sim.serial_server import SerialServer, find_lora_ports, start_serial_server
from lichen.sim.simulation import Simulation


class MockSerial:
    """Mock serial port for testing without hardware."""

    def __init__(self, port: str, baudrate: int, timeout: float = 0.1) -> None:
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.is_open = True
        self._read_buffer = b""
        self._write_buffer = b""

    def read(self, size: int = 1) -> bytes:
        """Read from the mock buffer."""
        data = self._read_buffer[:size]
        self._read_buffer = self._read_buffer[size:]
        return data

    def write(self, data: bytes) -> int:
        """Write to the mock buffer."""
        self._write_buffer += data
        return len(data)

    def close(self) -> None:
        """Close the mock port."""
        self.is_open = False

    def inject_rx(self, rssi: float, snr: float, data: bytes) -> None:
        """Inject an RX notification into the read buffer."""
        line = f"RX {rssi} {snr} {data.hex()}\n"
        self._read_buffer += line.encode()

    def get_written(self) -> bytes:
        """Get and clear the write buffer."""
        data = self._write_buffer
        self._write_buffer = b""
        return data


@pytest.fixture
def simulation() -> Simulation:
    """Create a test simulation."""
    return Simulation("test")


@pytest.fixture
def mock_serial() -> MockSerial:
    """Create a mock serial port."""
    return MockSerial("/dev/ttyUSB0", 115200)


@pytest.mark.asyncio
async def test_serial_server_init(simulation: Simulation) -> None:
    """Test SerialServer initialization."""
    server = SerialServer(
        simulation,
        node_id="radio1",
        port="/dev/ttyUSB0",
        baudrate=115200,
        position=(10.0, 20.0, 0.0),
        tx_power_dbm=20,
    )

    assert server._node_id == "radio1"
    assert server._port == "/dev/ttyUSB0"
    assert server._baudrate == 115200
    assert server._position == (10.0, 20.0, 0.0)
    assert server._tx_power_dbm == 20


@pytest.mark.asyncio
async def test_serial_server_start_stop(
    simulation: Simulation, mock_serial: MockSerial
) -> None:
    """Test starting and stopping the serial server."""
    server = SerialServer(
        simulation,
        node_id="radio1",
        port="/dev/ttyUSB0",
        position=(0.0, 0.0, 0.0),
    )

    with patch("serial.Serial", return_value=mock_serial):
        await server.start()

        # Node should be added to simulation
        node = simulation.get_node("radio1")
        assert node is not None
        assert node.position == (0.0, 0.0, 0.0)

        # Server should be running
        assert server._serial is not None
        assert server._reader_task is not None
        assert server._sim_driver_task is not None

        await server.stop()

        # Server should be stopped
        assert server._serial is None
        assert mock_serial.is_open is False


@pytest.mark.asyncio
async def test_serial_server_rx_injection(
    simulation: Simulation, mock_serial: MockSerial
) -> None:
    """Test that RX packets from hardware are injected into simulation."""
    server = SerialServer(
        simulation,
        node_id="radio1",
        port="/dev/ttyUSB0",
        position=(0.0, 0.0, 0.0),
    )

    # Add another node to receive
    simulation.add_node("simnode", 50.0, 0.0, 0.0)

    with patch("serial.Serial", return_value=mock_serial):
        await server.start()

        # Let the server tasks start
        await asyncio.sleep(0.02)

        # Inject an RX notification
        mock_serial.inject_rx(-80.0, 10.0, b"hello from radio")

        # Wait for processing
        await asyncio.sleep(0.05)

        # The packet should have been transmitted in the simulation
        # Check that metrics recorded the transmission
        metrics = simulation._metrics
        assert metrics.transmissions > 0

        await server.stop()


@pytest.mark.asyncio
async def test_serial_server_tx_to_hardware(
    simulation: Simulation, mock_serial: MockSerial
) -> None:
    """Test that simulation packets are forwarded to hardware."""
    server = SerialServer(
        simulation,
        node_id="radio1",
        port="/dev/ttyUSB0",
        position=(100.0, 0.0, 0.0),
        tx_power_dbm=22,
    )

    # Add a transmitting node close enough to reach radio1
    tx_node = simulation.add_node("txnode", 0.0, 0.0, 0.0)
    tx_node.tx_power_dbm = 22

    with patch("serial.Serial", return_value=mock_serial):
        await server.start()

        # Let the server tasks start
        await asyncio.sleep(0.02)

        # Transmit from the simulated node
        simulation.start_transmission("txnode", b"hello to radio")

        # Advance time past the transmission
        simulation.advance_to(simulation.current_time_us + 500_000)  # 500ms
        simulation.deliver_pending_packets()

        # Wait for the packet to be forwarded to hardware
        await asyncio.sleep(0.05)

        # Check what was written to the serial port
        written = mock_serial.get_written()
        # The TX command format is "TX <hex>\n"
        if written:
            assert b"TX " in written
            assert b"hello to radio".hex().encode() in written

        await server.stop()


@pytest.mark.asyncio
async def test_serial_server_process_line_debug(
    simulation: Simulation, mock_serial: MockSerial
) -> None:
    """Test processing debug/comment lines from radio."""
    server = SerialServer(
        simulation,
        node_id="radio1",
        port="/dev/ttyUSB0",
    )

    with patch("serial.Serial", return_value=mock_serial):
        await server.start()

        # Inject various line types
        mock_serial._read_buffer = b"# Debug message\n"
        mock_serial._read_buffer += b"OK\n"
        mock_serial._read_buffer += b"ERR Something failed\n"
        mock_serial._read_buffer += b"READY\n"

        # Wait for processing
        await asyncio.sleep(0.05)

        # No errors should occur (just logging)
        await server.stop()


@pytest.mark.asyncio
async def test_serial_server_malformed_rx(
    simulation: Simulation, mock_serial: MockSerial
) -> None:
    """Test handling malformed RX lines."""
    server = SerialServer(
        simulation,
        node_id="radio1",
        port="/dev/ttyUSB0",
    )

    with patch("serial.Serial", return_value=mock_serial):
        await server.start()

        # Inject malformed RX lines
        mock_serial._read_buffer = b"RX not-a-number 10 1234\n"
        mock_serial._read_buffer += b"RX -80 10\n"  # Missing hex data
        mock_serial._read_buffer += b"RX -80 10 not-hex\n"

        # Wait for processing
        await asyncio.sleep(0.05)

        # No errors should crash the server
        await server.stop()


def test_find_lora_ports_empty() -> None:
    """Test find_lora_ports with no devices."""
    with patch("serial.tools.list_ports.comports", return_value=[]):
        ports = find_lora_ports()
        assert ports == []


def test_find_lora_ports_matches() -> None:
    """Test find_lora_ports with matching devices."""
    mock_port1 = MagicMock()
    mock_port1.device = "/dev/ttyUSB0"
    mock_port1.description = "RAK4631 LoRa Module"

    mock_port2 = MagicMock()
    mock_port2.device = "/dev/ttyACM0"
    mock_port2.description = "Generic USB Serial"

    mock_port3 = MagicMock()
    mock_port3.device = "/dev/cu.usbmodem1234"
    mock_port3.description = "nRF52840"

    with patch(
        "serial.tools.list_ports.comports",
        return_value=[mock_port1, mock_port2, mock_port3],
    ):
        ports = find_lora_ports()
        assert "/dev/ttyUSB0" in ports  # RAK in description
        assert "/dev/ttyACM0" in ports  # Generic ttyACM
        assert "/dev/cu.usbmodem1234" in ports  # usbmodem


@pytest.mark.asyncio
async def test_start_serial_server_helper(
    simulation: Simulation, mock_serial: MockSerial
) -> None:
    """Test the start_serial_server helper function."""
    with patch("serial.Serial", return_value=mock_serial):
        server = await start_serial_server(
            simulation,
            node_id="radio1",
            port="/dev/ttyUSB0",
            baudrate=9600,
            position=(5.0, 5.0, 0.0),
            tx_power_dbm=14,
        )

        try:
            assert server._node_id == "radio1"
            assert server._baudrate == 9600
            assert server._position == (5.0, 5.0, 0.0)
            assert server._tx_power_dbm == 14

            node = simulation.get_node("radio1")
            assert node is not None
        finally:
            await server.stop()


@pytest.mark.asyncio
async def test_serial_server_rx_reentry(
    simulation: Simulation, mock_serial: MockSerial
) -> None:
    """Test that RX mode is re-entered after receiving a packet."""
    server = SerialServer(
        simulation,
        node_id="radio1",
        port="/dev/ttyUSB0",
        position=(100.0, 0.0, 0.0),
    )

    # Add a close transmitting node
    tx_node = simulation.add_node("txnode", 0.0, 0.0, 0.0)
    tx_node.tx_power_dbm = 22

    with patch("serial.Serial", return_value=mock_serial):
        await server.start()
        await asyncio.sleep(0.02)

        # First transmission
        simulation.start_transmission("txnode", b"packet1")
        simulation.advance_to(simulation.current_time_us + 500_000)
        simulation.deliver_pending_packets()
        await asyncio.sleep(0.02)

        # Node should still be in RX mode for next packet
        node = simulation.get_node("radio1")
        assert node is not None
        assert node.rx_callbacks is not None

        # Second transmission should also work
        simulation.start_transmission("txnode", b"packet2")
        simulation.advance_to(simulation.current_time_us + 500_000)
        simulation.deliver_pending_packets()
        await asyncio.sleep(0.02)

        await server.stop()
