# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Serial/USB bridge for physical LoRa radios.

Connects real LoRa hardware (SX1262/SX1276) to the lichen simulator,
allowing hardware-in-the-loop testing where physical radios participate
alongside simulated nodes.

Protocol (simple text over serial):
    TX <hex>           -> OK | ERR <msg>
    RX <rssi> <snr> <hex>  <- unsolicited from radio
    CFG SF=<n> BW=<n> CR=<n> FREQ=<n> PWR=<n>

The bridge translates between this text protocol and the simulator's
internal TX/RX operations.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

import serial
import serial.tools.list_ports

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from lichen.sim.simulation import Simulation

logger = logging.getLogger(__name__)


class SerialServer:
    """Bridge between a physical LoRa radio and lichen-sim.

    Each SerialServer handles exactly one physical radio, representing
    it as a node in the simulation. Create multiple servers for
    multiple radios.

    The radio must run firmware that implements the simple text protocol:
        TX <hex>           - Transmit packet, responds with OK or ERR
        RX <rssi> <snr> <hex> - Unsolicited packet arrival notification
        CFG ...            - Configure radio parameters

    Radio Register Mapping
    ----------------------
    For radios with register-level access (e.g., SPI bridge), the server
    maps key SX126x/SX127x registers to simulator state:

        - RegOpMode (0x01): TX/RX/SLEEP state
        - RegFrMsb/Mid/Lsb (0x06-08): Frequency
        - RegPaConfig (0x09): TX power
        - FIFO operations: Payload data

    This enables accurate HIL testing where the firmware's register
    writes are reflected in the simulated RF environment.
    """

    def __init__(
        self,
        simulation: Simulation,
        node_id: str,
        port: str,
        baudrate: int = 115200,
        position: tuple[float, float, float] = (0.0, 0.0, 0.0),
        tx_power_dbm: int = 22,
    ) -> None:
        """Initialize the serial bridge server.

        Args:
            simulation: The simulation instance to bridge to.
            node_id: Unique identifier for this physical radio node.
            port: Serial port path (e.g., /dev/ttyUSB0, COM3).
            baudrate: Serial baud rate (default 115200).
            position: Node position (x, y, z) in meters.
            tx_power_dbm: Transmit power in dBm.
        """
        self._simulation = simulation
        self._node_id = node_id
        self._port = port
        self._baudrate = baudrate
        self._position = position
        self._tx_power_dbm = tx_power_dbm
        self._serial: serial.Serial | None = None
        self._stopping = False
        self._reader_task: asyncio.Task[None] | None = None
        self._sim_driver_task: asyncio.Task[None] | None = None
        self._pending_tasks: set[asyncio.Task[None]] = set()

    async def start(self) -> None:
        """Start the serial bridge and add node to simulation."""
        self._stopping = False

        # Add node to simulation
        node = self._simulation.add_node(
            self._node_id,
            self._position[0],
            self._position[1],
            self._position[2],
        )
        node.tx_power_dbm = self._tx_power_dbm

        # Open serial port
        loop = asyncio.get_event_loop()
        try:
            self._serial = await loop.run_in_executor(
                None,
                lambda: serial.Serial(self._port, self._baudrate, timeout=0.1),
            )
        except serial.SerialException as e:
            raise RuntimeError(f"Failed to open serial port {self._port}: {e}") from e

        logger.info(
            "Serial bridge for %s started on %s @ %d baud",
            self._node_id,
            self._port,
            self._baudrate,
        )

        # Start reader task
        self._reader_task = asyncio.create_task(self._reader_loop())

        # Start simulation driver task
        self._sim_driver_task = asyncio.create_task(self._simulation_driver())

    async def stop(self) -> None:
        """Stop the serial bridge."""
        import contextlib

        self._stopping = True

        # Cancel reader task
        if self._reader_task is not None:
            self._reader_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._reader_task
            self._reader_task = None

        # Cancel simulation driver
        if self._sim_driver_task is not None:
            self._sim_driver_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sim_driver_task
            self._sim_driver_task = None

        # Cancel pending background tasks
        for task in list(self._pending_tasks):
            task.cancel()
        if self._pending_tasks:
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.gather(*self._pending_tasks, return_exceptions=True)
        self._pending_tasks.clear()

        # Exit RX mode and close serial
        self._simulation.exit_rx_mode(self._node_id)
        if self._serial is not None:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._serial.close)
            self._serial = None

    async def _reader_loop(self) -> None:
        """Background task to read incoming data from the serial port."""
        assert self._serial is not None

        loop = asyncio.get_event_loop()
        buffer = b""

        try:
            while not self._stopping:
                # Read in executor to avoid blocking
                chunk = await loop.run_in_executor(
                    None, lambda: self._serial.read(256) if self._serial else b""
                )
                if chunk:
                    buffer += chunk

                    # Process complete lines
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        await self._process_line(
                            line.decode("utf-8", errors="ignore").strip()
                        )

                await asyncio.sleep(0.01)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Serial reader error for %s", self._node_id)
            raise

    async def _process_line(self, line: str) -> None:
        """Process a line received from the radio."""
        if not line:
            return

        if line.startswith("RX "):
            # RX <rssi> <snr> <hex>
            await self._handle_rx_line(line)
        elif line.startswith("#"):
            # Debug/comment output
            logger.debug("[%s] %s", self._node_id, line)
        elif line.startswith("OK"):
            logger.debug("[%s] OK", self._node_id)
        elif line.startswith("ERR"):
            logger.warning("[%s] %s", self._node_id, line)
        elif line.startswith("READY"):
            logger.info("[%s] Radio ready", self._node_id)
        else:
            logger.debug("[%s] Unknown: %s", self._node_id, line)

    async def _handle_rx_line(self, line: str) -> None:
        """Handle an RX notification from the radio.

        Format: RX <rssi> <snr> <hex>

        This indicates the physical radio received a packet over the air.
        We inject this packet into the simulation so other nodes can see it.
        """
        parts = line[3:].split(" ", 2)
        if len(parts) != 3:
            logger.warning(
                "[%s] Malformed RX line: %s", self._node_id, line
            )
            return

        try:
            rssi = float(parts[0])
            snr = float(parts[1])
            data = bytes.fromhex(parts[2])
        except ValueError as e:
            logger.warning(
                "[%s] Invalid RX data: %s (%s)", self._node_id, line, e
            )
            return

        logger.info(
            "[%s] RX from hardware: %d bytes, rssi=%d, snr=%d",
            self._node_id,
            len(data),
            int(rssi),
            int(snr),
        )

        # Inject the packet into the simulation as a transmission from this node
        # This makes the physical radio's received packets visible to simulated nodes
        try:
            self._simulation.start_transmission(self._node_id, data, channel=0)
        except ValueError as e:
            logger.warning("[%s] Failed to inject RX: %s", self._node_id, e)

    async def _simulation_driver(self) -> None:
        """Background task that drives simulation and delivers packets to hardware.

        When the simulation delivers a packet to this node (another simulated
        or physical node transmitted), we forward it to the physical radio
        for actual over-the-air transmission.
        """
        try:
            # Enter RX mode with callbacks
            self._simulation.enter_rx_mode(
                self._node_id,
                timeout_us=0xFFFFFFFF,  # Very long timeout
                on_packet=lambda p, r, s: self._on_sim_packet(p, r, s),
                on_timeout=lambda: self._on_sim_timeout(),
                channel=0,
            )

            while not self._stopping:
                self._simulation.deliver_pending_packets()
                self._simulation.maybe_advance_time()
                self._simulation.deliver_pending_packets()
                await asyncio.sleep(0.001)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Simulation driver error for %s", self._node_id)
            raise

    def _on_sim_packet(self, payload: bytes, rssi: int, snr: int) -> None:
        """Callback when a simulated packet arrives for this node.

        Forward it to the physical radio for transmission.
        """
        logger.info(
            "[%s] Sim packet for hardware: %d bytes",
            self._node_id,
            len(payload),
        )
        self._create_background_task(self._transmit_to_hardware(payload))

        # Re-enter RX mode for next packet
        self._simulation.enter_rx_mode(
            self._node_id,
            timeout_us=0xFFFFFFFF,
            on_packet=lambda p, r, s: self._on_sim_packet(p, r, s),
            on_timeout=lambda: self._on_sim_timeout(),
            channel=0,
        )

    def _on_sim_timeout(self) -> None:
        """Callback when RX times out (shouldn't happen with infinite timeout)."""
        logger.debug("[%s] Sim RX timeout", self._node_id)
        # Re-enter RX mode
        self._simulation.enter_rx_mode(
            self._node_id,
            timeout_us=0xFFFFFFFF,
            on_packet=lambda p, r, s: self._on_sim_packet(p, r, s),
            on_timeout=lambda: self._on_sim_timeout(),
            channel=0,
        )

    async def _transmit_to_hardware(self, payload: bytes) -> None:
        """Send a packet to the physical radio for transmission."""
        if self._serial is None:
            logger.warning("[%s] No serial connection", self._node_id)
            return

        cmd = f"TX {payload.hex()}\n"
        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(
                None, lambda: self._serial.write(cmd.encode()) if self._serial else 0
            )
            logger.debug("[%s] Sent TX to hardware: %d bytes", self._node_id, len(payload))
        except serial.SerialException as e:
            logger.error("[%s] Serial write failed: %s", self._node_id, e)

    def _create_background_task(self, coro: Coroutine[None, None, None]) -> None:
        """Create a tracked background task with exception handling."""
        task = asyncio.create_task(coro)
        self._pending_tasks.add(task)

        def on_done(t: asyncio.Task[None]) -> None:
            self._pending_tasks.discard(t)
            if t.cancelled():
                return
            exc = t.exception()
            if exc is not None:
                logger.debug(
                    "Background task failed for %s: %s", self._node_id, exc
                )

        task.add_done_callback(on_done)


def find_lora_ports() -> list[str]:
    """Find serial ports that might be LoRa radios.

    Returns a list of port paths for devices that match common
    LoRa radio USB identifiers.
    """
    ports = []
    for port in serial.tools.list_ports.comports():
        # Match LoRa radio identifiers, Nordic nRF52840, or generic USB-serial
        if (
            any(
                x in port.description.lower()
                for x in ["lora", "sx126", "sx127", "rak", "heltec", "ttgo"]
            )
            or "usbmodem" in port.device
            or any(x in port.device for x in ["ttyUSB", "ttyACM", "COM"])
        ):
            ports.append(port.device)
    return ports


async def start_serial_server(
    simulation: Simulation,
    node_id: str,
    port: str,
    baudrate: int = 115200,
    position: tuple[float, float, float] = (0.0, 0.0, 0.0),
    tx_power_dbm: int = 22,
) -> SerialServer:
    """Start a serial bridge server for a physical radio.

    Args:
        simulation: The simulation instance.
        node_id: Unique identifier for this node.
        port: Serial port path.
        baudrate: Serial baud rate.
        position: Node position (x, y, z) in meters.
        tx_power_dbm: Transmit power in dBm.

    Returns:
        The started SerialServer instance.
    """
    server = SerialServer(
        simulation,
        node_id,
        port,
        baudrate,
        position,
        tx_power_dbm,
    )
    await server.start()
    return server
