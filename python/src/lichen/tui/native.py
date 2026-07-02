# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI shell and shared widgets."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.widgets import Static


class LinkMode(StrEnum):
    """Local client transport mode labels."""

    DEMO = "DEMO"
    BLE = "BLE"
    IP = "IP"


class UiState(StrEnum):
    """Compact connection/data state labels for the shell."""

    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    SYNCED = "SYNCED"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class ShellStatus:
    """Top-bar state rendered on every native TUI screen."""

    context: str = "Dashboard"
    mode: LinkMode = LinkMode.DEMO
    state: UiState = UiState.DISCONNECTED
    device: str = "--"
    battery: str = "--"
    time: str = "none"
    unread: int = 0
    target: str = "--"


@dataclass(frozen=True)
class MessagePreview:
    """One compact chat/message list row."""

    target: str
    preview: str
    age: str = "--"
    state: str = "--"
    unread: bool = False


@dataclass(frozen=True)
class ConfigRow:
    """One config editor row."""

    name: str
    value: str
    status: str = "read-only"


@dataclass(frozen=True)
class LogRow:
    """One device log row."""

    level: str
    module: str
    message: str


@dataclass(frozen=True)
class DiagnosticRow:
    """One diagnostics panel row."""

    name: str
    value: str


def clip(value: str, width: int) -> str:
    """Clip text to a fixed terminal width using ASCII ellipsis."""
    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return f"{value[: width - 3]}..."


def status_line(status: ShellStatus, width: int = 80) -> str:
    """Render the one-line LilyGO-style status bar."""
    base = (
        f"LICHEN {status.context} | {status.mode} {status.state} | "
        f"{status.device} | BAT {status.battery} | TIME {status.time} | "
        f"UNREAD {status.unread} | TARGET {status.target}"
    )
    return clip(base, width)


def message_line(row: MessagePreview, width: int = 80) -> str:
    """Render a stable message list row."""
    marker = "*" if row.unread else " "
    return clip(f"{marker} {row.target:<12} {row.age:>5} {row.state:<8} {row.preview}", width)


def field_line(name: str, value: str, status: str = "", width: int = 80) -> str:
    """Render a label/value/status row."""
    suffix = f" [{status}]" if status else ""
    return clip(f"{name:<18} {value}{suffix}", width)


class NativeStatusBar(Static):
    """One-line global status bar."""

    DEFAULT_CSS = """
    NativeStatusBar {
        height: 1;
        dock: top;
        background: $boost;
        color: $text;
    }
    """

    def __init__(self, status: ShellStatus | None = None, *, width: int = 80) -> None:
        self.status = status or ShellStatus()
        self.line_width = width
        super().__init__(
            status_line(self.status, self.line_width),
            id="native-status",
            markup=False,
        )

    def set_status(self, status: ShellStatus) -> None:
        """Update the rendered status."""
        self.status = status
        self.update(status_line(status, self.line_width))

    def set_width(self, width: int) -> None:
        """Update the status line width for the current terminal size."""
        self.line_width = max(24, width)
        self.update(status_line(self.status, self.line_width))


class CommandBar(Static):
    """One-line context command footer."""

    DEFAULT_CSS = """
    CommandBar {
        height: 1;
        dock: bottom;
        background: $panel;
        color: $text-muted;
    }
    """

    def __init__(self, commands: tuple[str, ...] = ()) -> None:
        self.commands = commands or ("Tab tabs", "[/] tabs", "1-7 jump", "? help", "q quit")
        super().__init__(self.render_commands(), id="command-bar", markup=False)

    def render_commands(self) -> str:
        """Return the compact command line."""
        return "  ".join(self.commands)


class ModeNav(Static):
    """Top-level mode navigation."""

    MODES: ClassVar[tuple[str, ...]] = (
        "Dashboard",
        "Chats",
        "Nodes",
        "Mesh",
        "Config",
        "Logs",
        "Diag",
    )

    DEFAULT_CSS = """
    ModeNav {
        height: 1;
        background: $surface;
        color: $accent;
    }
    """

    def __init__(self, active: str = "Dashboard", *, width: int = 80) -> None:
        self.active = active
        self.line_width = width
        super().__init__(self.render_modes(), id="mode-nav", markup=False)

    def render_modes(self) -> str:
        """Return bracketed tab labels with the active mode marked."""
        return clip(
            " ".join(f"[{mode}]" if mode == self.active else mode for mode in self.MODES),
            self.line_width,
        )

    def set_active(self, active: str) -> None:
        """Update the active tab label."""
        self.active = active
        self.update(self.render_modes())

    def set_width(self, width: int) -> None:
        """Update the nav width for the current terminal size."""
        self.line_width = max(24, width)
        self.update(self.render_modes())


class MessageList(Static):
    """Compact message preview list."""

    DEFAULT_CSS = """
    MessageList {
        height: auto;
        min-height: 6;
    }
    """

    def __init__(self, rows: tuple[MessagePreview, ...] = (), *, width: int = 76) -> None:
        self.rows = rows
        self.line_width = width
        super().__init__(self.render_rows(), id="message-list", markup=False)

    def render_rows(self) -> str:
        """Return a deterministic message list render."""
        rows = self.rows or (
            MessagePreview("broadcast", "No messages yet", state="empty"),
            MessagePreview("target", "Choose a target to compose", state="idle"),
        )
        return "\n".join(message_line(row, self.line_width) for row in rows)


class ConfigTable(Static):
    """Config row summary widget."""

    def __init__(self, rows: tuple[ConfigRow, ...] = (), *, width: int = 76) -> None:
        self.line_width = width
        self.rows = rows or (
            ConfigRow("name", "--", "unsupported"),
            ConfigRow("role", "--", "unsupported"),
            ConfigRow("freq_mhz", "--", "unsupported"),
            ConfigRow("bw_khz", "--", "unsupported"),
            ConfigRow("sf", "--", "unsupported"),
            ConfigRow("cr", "--", "unsupported"),
            ConfigRow("tx_power_dbm", "--", "unsupported"),
            ConfigRow("sync_word", "--", "read-only"),
        )
        super().__init__(self.render_rows(), id="config-table", markup=False)

    def render_rows(self) -> str:
        """Return config rows."""
        return "\n".join(
            field_line(row.name, row.value, row.status, self.line_width) for row in self.rows
        )


class LogPanel(Static):
    """Log stream summary widget."""

    def __init__(self, rows: tuple[LogRow, ...] = (), *, width: int = 76) -> None:
        self.line_width = width
        self.rows = rows or (LogRow("info", "tui", "log stream inactive"),)
        super().__init__(self.render_rows(), id="log-panel", markup=False)

    def render_rows(self) -> str:
        """Return log rows."""
        return "\n".join(
            clip(f"{row.level:<5} {row.module:<10} {row.message}", self.line_width)
            for row in self.rows
        )


class DiagnosticsPanel(Static):
    """Diagnostics summary widget."""

    def __init__(self, rows: tuple[DiagnosticRow, ...] = (), *, width: int = 76) -> None:
        self.line_width = width
        self.rows = rows or (
            DiagnosticRow("transport", "disconnected"),
            DiagnosticRow("capabilities", "not discovered"),
            DiagnosticRow("last_error", "--"),
        )
        super().__init__(self.render_rows(), id="diagnostics-panel", markup=False)

    def render_rows(self) -> str:
        """Return diagnostics rows."""
        return "\n".join(
            field_line(row.name, row.value, width=self.line_width) for row in self.rows
        )


class ActivePane(Static):
    """Single active screen pane for all top-level modes."""

    DEFAULT_CSS = """
    ActivePane {
        height: 1fr;
        padding: 0 1;
    }
    """

    def __init__(self, mode: str = "Dashboard", *, width: int = 76) -> None:
        self.mode = mode
        self.line_width = width
        super().__init__(self.render_mode(), id="active-pane", markup=False)

    def set_mode(self, mode: str) -> None:
        """Switch the visible screen."""
        self.mode = mode
        self.update(self.render_mode())

    def set_width(self, width: int) -> None:
        """Update row width for the current terminal size."""
        self.line_width = max(20, width)
        self.update(self.render_mode())

    def render_mode(self) -> str:
        """Return deterministic text for the active screen."""
        match self.mode:
            case "Dashboard":
                return "\n".join(
                    (
                        "DASHBOARD",
                        field_line("connection", "disconnected", width=self.line_width),
                        field_line("device", "--", width=self.line_width),
                        field_line("battery", "--", width=self.line_width),
                        field_line("radio", "rx 0 tx 0 err 0", width=self.line_width),
                        field_line("mesh", "neighbors 0 routes 0", width=self.line_width),
                    )
                )
            case "Chats":
                return "\n".join(
                    (
                        "CHATS",
                        MessageList(width=self.line_width).render_rows(),
                        "COMPOSE  target --  disabled",
                    )
                )
            case "Nodes":
                return "\n".join(
                    (
                        "NODES",
                        field_line("node", "--", "empty", width=self.line_width),
                        field_line("last_heard", "--", width=self.line_width),
                        field_line("rssi_snr", "--", width=self.line_width),
                        field_line("route", "--", width=self.line_width),
                    )
                )
            case "Mesh":
                return "\n".join(
                    (
                        "MESH",
                        field_line("destination", "--", "empty", width=self.line_width),
                        field_line("next_hop", "--", width=self.line_width),
                        field_line("hops", "--", width=self.line_width),
                        field_line("expires", "--", width=self.line_width),
                    )
                )
            case "Config":
                return "\n".join(("CONFIG", ConfigTable(width=self.line_width).render_rows()))
            case "Logs":
                return "\n".join(("LOGS", LogPanel(width=self.line_width).render_rows()))
            case "Diag":
                return "\n".join(
                    ("DIAGNOSTICS", DiagnosticsPanel(width=self.line_width).render_rows())
                )
            case "Quit":
                return "\n".join(("QUIT?", "Press y to quit or Esc/n to cancel."))
            case "Open":
                return "\n".join(("OPEN", "Select a concrete row in child flow screens."))
            case "Filter":
                return "\n".join(("FILTER", "Filter prompt is reserved for data-backed screens."))
            case _:
                return "\n".join(
                    ("HELP", "? help", "Tab or ] next", "Shift+Tab or [ previous", "1-7 jump")
                )


class NativeClientApp(App[None]):
    """Native LCI TUI shell with stable dashboard widgets."""

    TITLE = "LICHEN Native Client"
    CSS = """
    Screen {
        layout: vertical;
    }

    #native-body {
        height: 1fr;
        layout: vertical;
    }

    .section-title {
        height: 1;
        color: $accent;
        text-style: bold;
    }
    """

    BINDINGS: ClassVar[list[Binding | tuple[str, str] | tuple[str, str, str]]] = [
        Binding("q", "confirm_quit", "Quit"),
        Binding("y", "accept_prompt", "Yes", show=False),
        Binding("n", "cancel_prompt", "No", show=False),
        Binding("escape", "cancel_prompt", "Cancel"),
        Binding("enter", "open", "Open"),
        Binding("slash", "filter", "Filter"),
        Binding("tab", "next_mode", "Next", priority=True),
        Binding("shift+tab", "prev_mode", "Prev", priority=True),
        Binding("right_square_bracket", "next_mode", "Next", priority=True),
        Binding("left_square_bracket", "prev_mode", "Prev", priority=True),
        Binding("question_mark", "help", "Help", priority=True),
        Binding("ctrl+l", "refresh", "Refresh", priority=True),
        Binding("r", "refresh", "Refresh", priority=True),
        Binding("1", "jump_mode(0)", "Dashboard"),
        Binding("2", "jump_mode(1)", "Chats"),
        Binding("3", "jump_mode(2)", "Nodes"),
        Binding("4", "jump_mode(3)", "Mesh"),
        Binding("5", "jump_mode(4)", "Config"),
        Binding("6", "jump_mode(5)", "Logs"),
        Binding("7", "jump_mode(6)", "Diag"),
    ]

    def __init__(self, status: ShellStatus | None = None) -> None:
        super().__init__()
        self.status = status or ShellStatus()
        self.mode_index = (
            ModeNav.MODES.index(self.status.context)
            if self.status.context in ModeNav.MODES
            else 0
        )
        self.prompt_mode: str | None = None

    def compose(self) -> ComposeResult:
        """Build the native client frame."""
        yield NativeStatusBar(self.status)
        yield ModeNav(self.status.context)
        with Container(id="native-body"):
            yield ActivePane(self.status.context)
        yield CommandBar()

    def on_mount(self) -> None:
        """Size initial fixed-width text renderers to the terminal."""
        self._resize_widgets()

    async def _on_resize(self, event: events.Resize) -> None:
        """Refresh fixed-width text when the terminal changes size."""
        await super()._on_resize(event)
        self._resize_widgets()

    def action_next_mode(self) -> None:
        """Move to the next top-level mode."""
        self._set_mode((self.mode_index + 1) % len(ModeNav.MODES))

    def action_prev_mode(self) -> None:
        """Move to the previous top-level mode."""
        self._set_mode((self.mode_index - 1) % len(ModeNav.MODES))

    def action_refresh(self) -> None:
        """Refresh placeholder action for keyboard-only operation."""
        pane = self.query_one("#active-pane", ActivePane)
        pane.update(f"{pane.render_mode()}\nrefresh requested")

    def action_open(self) -> None:
        """Show an open placeholder for keyboard-only row activation."""
        self.prompt_mode = "Open"
        self.query_one("#active-pane", ActivePane).set_mode("Open")

    def action_filter(self) -> None:
        """Show a filter placeholder for keyboard-only operation."""
        self.prompt_mode = "Filter"
        self.query_one("#active-pane", ActivePane).set_mode("Filter")

    def action_help(self) -> None:
        """Show keyboard help without changing the active tab."""
        self.prompt_mode = "Help"
        self.query_one("#active-pane", ActivePane).set_mode("Help")

    def action_confirm_quit(self) -> None:
        """Ask for confirmation before leaving the shell."""
        self.prompt_mode = "Quit"
        self.query_one("#active-pane", ActivePane).set_mode("Quit")

    def action_accept_prompt(self) -> None:
        """Accept the active confirmation prompt."""
        if self.prompt_mode == "Quit":
            self.exit()

    def action_cancel_prompt(self) -> None:
        """Dismiss a prompt and restore the active mode."""
        if self.prompt_mode is None:
            return
        self.prompt_mode = None
        self.query_one("#active-pane", ActivePane).set_mode(self.status.context)

    def action_jump_mode(self, index: int) -> None:
        """Jump directly to a numbered top-level mode."""
        self._set_mode(index)

    def _set_mode(self, index: int) -> None:
        self.prompt_mode = None
        self.mode_index = index
        mode = ModeNav.MODES[index]
        self.status = ShellStatus(
            context=mode,
            mode=self.status.mode,
            state=self.status.state,
            device=self.status.device,
            battery=self.status.battery,
            time=self.status.time,
            unread=self.status.unread,
            target=self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)
        self.query_one("#mode-nav", ModeNav).set_active(mode)
        self.query_one("#active-pane", ActivePane).set_mode(mode)

    def _resize_widgets(self) -> None:
        width = max(24, self.size.width)
        self.query_one("#native-status", NativeStatusBar).set_width(width)
        self.query_one("#mode-nav", ModeNav).set_width(width)
        self.query_one("#active-pane", ActivePane).set_width(max(20, width - 2))


def main() -> None:
    """Run the native client shell."""
    NativeClientApp().run()
