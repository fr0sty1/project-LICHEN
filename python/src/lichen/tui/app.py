# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""TUI application for a simulated LICHEN node.

Provides an interactive terminal interface for controlling a node
connected to the LICHEN simulator. Features:

- Connection management to simulator server
- Transmit packets with hex or text payload
- Receive packets with configurable timeout
- View simulation time and connection status
- Event log showing all TX/RX activity

Defensive design:
- All network errors caught and displayed
- Graceful disconnect on exit
- Input validation before transmission
- Safe cancellation of pending receives
"""

from __future__ import annotations

import asyncio
import binascii
import contextlib
from datetime import datetime
from typing import Any, ClassVar

from rich.markup import escape
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Static,
)

from lichen.radio.sim_client import SimRadio, SimRadioError


def format_time_us(time_us: int) -> str:
    """Format microseconds as human-readable time.

    Args:
        time_us: Time in microseconds.

    Returns:
        Formatted string like "1.234s" or "123.456ms", or "--" for negative values.
    """
    if time_us < 0:
        return "--"
    if time_us >= 1_000_000:
        return f"{time_us / 1_000_000:.3f}s"
    elif time_us >= 1_000:
        return f"{time_us / 1_000:.3f}ms"
    else:
        return f"{time_us}us"


def format_payload(data: bytes) -> str:
    """Format payload for display, showing hex and printable text.

    Uses UTF-8 decode and accepts printable chars plus common whitespace
    (\n, \r, \t) to avoid misclassifying text payloads with control chars.

    Args:
        data: Raw bytes to format.

    Returns:
        String like "48656c6c6f (Hello)" or just hex if not printable.
    """
    hex_str = data.hex()
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\n\r\t" for c in text):
            return f"{hex_str} ({text})"
    except (UnicodeDecodeError, ValueError):
        pass
    return hex_str


class ConnectionStatus(Static):
    """Widget showing connection status."""

    DEFAULT_CSS = """
    ConnectionStatus {
        width: 100%;
        height: 3;
        padding: 1;
        background: $surface;
        border: solid $primary;
    }
    ConnectionStatus.connected {
        border: solid $success;
    }
    ConnectionStatus.disconnected {
        border: solid $error;
    }
    """

    def __init__(self) -> None:
        super().__init__("Status: Disconnected")
        self.add_class("disconnected")

    @staticmethod
    def _sanitize(text: str) -> str:
        from rich.markup import escape
        return escape(text)

    def set_connected(self, host: str, port: int, sim_id: str, node_id: str) -> None:
        """Update to show connected state."""
        self.update(f"Connected: {self._sanitize(node_id)}@{self._sanitize(sim_id)} via {self._sanitize(host)}:{port}")
        self.remove_class("disconnected")
        self.add_class("connected")

    def set_disconnected(self, reason: str = "") -> None:
        """Update to show disconnected state."""
        msg = "Status: Disconnected"
        if reason:
            msg = f"Status: Disconnected ({reason})"
        self.update(msg)
        self.remove_class("connected")
        self.add_class("disconnected")


class SimTimeDisplay(Static):
    """Widget showing current simulation time."""

    DEFAULT_CSS = """
    SimTimeDisplay {
        width: 100%;
        height: 3;
        padding: 1;
        background: $surface;
    }
    """

    def __init__(self) -> None:
        super().__init__("Sim Time: --")

    def set_time(self, time_us: int) -> None:
        """Update the displayed time."""
        self.update(f"Sim Time: {format_time_us(time_us)}")


class SimNodeApp(App[None]):
    """TUI application for a simulated LICHEN node.

    Connects to a simulator server and provides an interactive interface
    for transmitting and receiving packets.
    """

    TITLE = "LICHEN Simulated Node"
    CSS = """
    Screen {
        layout: vertical;
    }

    #main-container {
        height: 1fr;
    }

    #left-panel {
        width: 40;
        height: 100%;
        padding: 1;
    }

    #right-panel {
        width: 1fr;
        height: 100%;
        padding: 1;
    }

    #event-log {
        height: 1fr;
        border: solid $primary;
    }

    #controls {
        height: auto;
        padding: 1;
    }

    .control-row {
        height: 3;
        margin-bottom: 1;
    }

    .control-label {
        width: 10;
    }

    .control-input {
        width: 1fr;
    }

    Button {
        margin: 1;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "quit", "Quit"),
        Binding("c", "connect", "Connect"),
        Binding("d", "disconnect", "Disconnect"),
        Binding("t", "focus_tx", "Transmit"),
        Binding("r", "receive", "Receive"),
    ]

    def __init__(
        self,
        host: str = "localhost",
        port: int = 4444,
        sim_id: str = "default",
        node_id: str = "tui-node",
        position: tuple[float, float, float] = (0.0, 0.0, 0.0),
    ) -> None:
        """Initialize the TUI application.

        Args:
            host: Simulator server hostname.
            port: Simulator server TCP port.
            sim_id: Simulation to join.
            node_id: Unique node identifier.
            position: Node position (x, y, z) in meters.
        """
        super().__init__()
        self._host = host
        self._port = port
        self._sim_id = sim_id
        self._node_id = node_id
        self._position = position
        self._radio: SimRadio | None = None
        self._receive_task: asyncio.Task[Any] | None = None

    def compose(self) -> ComposeResult:
        """Build the UI layout."""
        yield Header()

        with Horizontal(id="main-container"):
            with Vertical(id="left-panel"):
                yield ConnectionStatus()
                yield SimTimeDisplay()

                with Container(id="controls"):
                    yield Label("Transmit (hex or text):")
                    yield Input(placeholder="hello or 48656c6c6f", id="tx-input")
                    yield Button("Send", id="btn-send", variant="primary")

                    yield Label("Receive timeout (ms):")
                    yield Input(placeholder="5000", id="rx-timeout", value="5000")
                    yield Button("Start Receive", id="btn-receive", variant="success")

            with Vertical(id="right-panel"):
                yield RichLog(id="event-log", highlight=True, markup=True)

        yield Footer()

    def on_mount(self) -> None:
        """Called when app is mounted - auto-connect."""
        self._log_event("info", f"Starting TUI for node {self._node_id}")
        self._log_event("info", f"Target: {self._host}:{self._port}, sim: {self._sim_id}")
        self._log_event("info", "Press 'c' to connect, 'q' to quit")

    async def on_unmount(self) -> None:
        """Called on shutdown - cleanup."""
        if self._receive_task is not None:
            receive_task = self._receive_task
            self._receive_task = None
            receive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, asyncio.InvalidStateError):
                await receive_task
        # Radio cleanup happens in action_quit

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "btn-send":
            self._do_transmit()
        elif event.button.id == "btn-receive":
            self._do_receive()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in input fields."""
        if event.input.id == "tx-input":
            self._do_transmit()
        elif event.input.id == "rx-timeout":
            self._do_receive()

    async def action_quit(self) -> None:
        if self._receive_task is not None:
            receive_task = self._receive_task
            self._receive_task = None
            receive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, asyncio.InvalidStateError):
                await receive_task
        if self._radio is not None:
            with contextlib.suppress(Exception):
                await self._radio.close()
            self._radio = None
        self.exit()

    def action_connect(self) -> None:
        """Connect to the simulator."""
        if self._radio is not None:
            self._log_event("warn", "Already connected")
            return
        self._connect_to_sim()

    def action_disconnect(self) -> None:
        """Disconnect from the simulator."""
        self._disconnect()

    def action_focus_tx(self) -> None:
        """Focus the transmit input."""
        tx_input = self.query_one("#tx-input", Input)
        tx_input.focus()

    def action_receive(self) -> None:
        """Start a receive operation."""
        self._do_receive()

    def _log_event(self, level: str, message: str) -> None:
        """Log an event to the event log widget.

        Args:
            level: Log level (info, warn, error, tx, rx).
            message: Message to log.
        """
        log = self.query_one("#event-log", RichLog)
        timestamp = datetime.now().strftime("%H:%M:%S")

        colors = {
            "info": "cyan",
            "warn": "yellow",
            "error": "red",
            "tx": "green",
            "rx": "blue",
        }
        color = colors.get(level, "white")

        log.write(f"[{color}][{timestamp}] {escape(message)}[/{color}]")

    @work(exclusive=True, group="connect")
    async def _connect_to_sim(self) -> None:
        """Connect to the simulator server (async worker)."""
        self._log_event("info", f"Connecting to {self._host}:{self._port}...")

        try:
            self._radio = SimRadio(
                host=self._host,
                port=self._port,
                sim_id=self._sim_id,
                node_id=self._node_id,
                position=self._position,
            )
            await self._radio.connect()

            status = self.query_one(ConnectionStatus)
            status.set_connected(self._host, self._port, self._sim_id, self._node_id)

            self._log_event("info", "Connected successfully")

            await self._update_sim_time()

        except SimRadioError as e:
            self._log_event("error", f"Connection failed: {e}")
            if self._radio is not None:
                with contextlib.suppress(Exception):
                    await self._radio.close()
            self._radio = None
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            if isinstance(e, (SystemExit, KeyboardInterrupt, GeneratorExit)):
                raise
            self._log_event("error", f"Unexpected error: {e}")
            if self._radio is not None:
                with contextlib.suppress(Exception):
                    await self._radio.close()
            self._radio = None

    @work(exclusive=True, group="connect")
    async def _disconnect(self) -> None:
        """Disconnect from the simulator (async worker)."""
        if self._radio is None:
            self._log_event("warn", "Not connected")
            return

        if self._receive_task is not None:
            self._receive_task.cancel()
            self._receive_task = None

        try:
            await self._radio.close()
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            if isinstance(e, (SystemExit, KeyboardInterrupt, GeneratorExit)):
                raise
            self._log_event("error", f"Error during disconnect: {e}")
        finally:
            self._radio = None
            status = self.query_one(ConnectionStatus)
            status.set_disconnected()
            self._log_event("info", "Disconnected")

    def _do_transmit(self) -> None:
        """Start a transmit operation."""
        if self._radio is None:
            self._log_event("error", "Not connected - press 'c' to connect first")
            return

        tx_input = self.query_one("#tx-input", Input)
        payload_str = tx_input.value.strip()

        if not payload_str:
            self._log_event("warn", "No payload to transmit")
            return

        # Try to parse as hex first, fall back to text
        try:
            payload = binascii.unhexlify(payload_str)
        except (binascii.Error, ValueError):
            payload = payload_str.encode("utf-8")

        self._transmit(payload)
        tx_input.value = ""

    @work(exclusive=True, group="tx")
    async def _transmit(self, payload: bytes) -> None:
        """Transmit a payload (async worker).

        Args:
            payload: Raw bytes to transmit.
        """
        if self._radio is None:
            return

        self._log_event("tx", f"TX: {format_payload(payload)} ({len(payload)} bytes)")

        try:
            success = await self._radio.transmit(payload)
            if success:
                self._log_event("tx", "TX complete")
            else:
                self._log_event("error", "TX failed (channel busy or other error)")

            await self._update_sim_time()

        except SimRadioError as e:
            self._log_event("error", f"TX error: {e}")
            await self._handle_connection_lost()

    def _do_receive(self) -> None:
        """Start a receive operation."""
        if self._radio is None:
            self._log_event("error", "Not connected - press 'c' to connect first")
            return

        timeout_input = self.query_one("#rx-timeout", Input)
        try:
            timeout_ms = int(timeout_input.value.strip())
            if timeout_ms <= 0:
                raise ValueError("Timeout must be positive")
        except ValueError as e:
            self._log_event("error", f"Invalid timeout: {e}")
            return

        self._receive(timeout_ms)

    @work(exclusive=True, group="rx")
    async def _receive(self, timeout_ms: int) -> None:
        """Receive a packet (async worker).

        Args:
            timeout_ms: Receive timeout in milliseconds.
        """
        if self._radio is None:
            return

        self._log_event("rx", f"RX: Listening for {timeout_ms}ms...")

        try:
            result = await self._radio.receive(timeout_ms)

            if result is None:
                self._log_event("rx", "RX: Timeout (no packet received)")
            else:
                payload, rssi, snr = result
                self._log_event(
                    "rx",
                    f"RX: {format_payload(payload)} ({len(payload)} bytes, "
                    f"RSSI={rssi}dBm, SNR={snr}dB)"
                )

            await self._update_sim_time()

        except SimRadioError as e:
            self._log_event("error", f"RX error: {e}")
            await self._handle_connection_lost()

    async def _update_sim_time(self) -> None:
        """Update the simulation time display."""
        if self._radio is None:
            return

        try:
            time_us = await self._radio.get_time()
            time_display = self.query_one(SimTimeDisplay)
            time_display.set_time(time_us)
        except SimRadioError:
            pass  # Ignore time fetch errors

    async def _handle_connection_lost(self) -> None:
        """Handle connection loss."""
        self._radio = None
        status = self.query_one(ConnectionStatus)
        status.set_disconnected("connection lost")
        self._log_event("error", "Connection lost")


def main() -> None:
    """Run the TUI application."""
    import argparse

    parser = argparse.ArgumentParser(
        description="LICHEN Simulated Node TUI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Simulator server hostname",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4444,
        help="Simulator server TCP port",
    )
    parser.add_argument(
        "--sim",
        dest="sim_id",
        default="default",
        help="Simulation ID to join",
    )
    parser.add_argument(
        "--node",
        dest="node_id",
        default="tui-node",
        help="Node ID for this client",
    )
    parser.add_argument(
        "--position",
        type=str,
        default="0,0,0",
        help="Node position as x,y,z in meters",
    )

    args = parser.parse_args()

    # Parse position
    try:
        x, y, z = (float(v.strip()) for v in args.position.split(","))
        position = (x, y, z)
    except ValueError:
        parser.error(f"Invalid position format: {args.position}")

    app = SimNodeApp(
        host=args.host,
        port=args.port,
        sim_id=args.sim_id,
        node_id=args.node_id,
        position=position,
    )
    app.run()


if __name__ == "__main__":
    main()
