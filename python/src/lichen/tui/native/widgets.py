# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI widgets."""

from __future__ import annotations

from typing import ClassVar

from textual.widgets import Static

from .formatting import (
    clip,
    config_rows,
    diagnostics_rows,
    field_line,
    mesh_neighbor_rows,
    mesh_route_rows,
    message_line,
    radio_rows,
    rf_health_rows,
    status_line,
    status_rows,
)
from .models import (
    ConfigRow,
    ConfigState,
    DashboardState,
    DiagnosticRow,
    DiagnosticsState,
    LogRow,
    LogsState,
    MeshState,
    MessagePreview,
    MessagingState,
    RadioTuiState,
    RFHealthState,
    ShellStatus,
)


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
        self.commands = commands or (
            "Tab tabs",
            "1-7 jump",
            "c compose",
            "r refresh",
            "o observe",
            "l link",
            "? help",
            "q quit",
        )
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
        "RF",
        "Config",
        "Logs",
        "Diag",
        "Radio",
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


class MessagingPanel:
    """Pure renderer for the Chats flow."""

    def __init__(self, state: MessagingState | None = None, *, width: int = 76) -> None:
        self.state = state or MessagingState()
        self.line_width = width

    def render(self) -> str:
        """Return the full chats view."""

        rows = [
            "CHATS",
            self._summary_line(),
            self._message_rows(),
            self._detail_lines(),
            self._compose_line(),
        ]
        if self.state.last_send is not None:
            rows.append(self._delivery_line(self.state.last_send))
        if self.state.error:
            rows.append(field_line("error", self.state.error, "recoverable", self.line_width))
        return "\n".join(row for row in rows if row)

    def _summary_line(self) -> str:
        if self.state.loading:
            return field_line("inbox", "loading", width=self.line_width)
        return field_line("inbox", f"{len(self.state.messages)} message(s)", width=self.line_width)

    def _message_rows(self) -> str:
        from .formatting import message_preview

        if not self.state.messages:
            return MessageList(width=self.line_width).render_rows()
        previews = tuple(
            message_preview(record, unread=index == self.state.selected)
            for index, record in enumerate(self.state.messages)
        )
        return MessageList(previews, width=self.line_width).render_rows()

    def _detail_lines(self) -> str:
        if not self.state.messages:
            return field_line("thread", "empty", width=self.line_width)
        selected = self.state.messages[min(self.state.selected, len(self.state.messages) - 1)]
        source = selected.sender or selected.recipient or "--"
        timestamp = str(selected.received or selected.timestamp or "--")
        body = selected.body or ""
        return "\n".join(
            (
                field_line("thread", source, width=self.line_width),
                field_line("time", timestamp, width=self.line_width),
                field_line("body", body, width=self.line_width),
            )
        )

    def _compose_line(self) -> str:
        target = self.state.draft_target or "--"
        body = self.state.draft_body or "--"
        return clip(f"COMPOSE  target {target}  body {body}", self.line_width)

    def _delivery_line(self, result: SendResult) -> str:
        detail = result.detail or result.coap_code or "/".join(result.location_path) or "--"
        return field_line("delivery", result.state.value, detail, self.line_width)


# Import SendResult for type hint
from lichen.client import SendResult  # noqa: E402


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

    def __init__(
        self,
        mode: str = "Dashboard",
        *,
        width: int = 76,
        messaging: MessagingState | None = None,
        dashboard: DashboardState | None = None,
        mesh: MeshState | None = None,
        config_state: ConfigState | None = None,
        logs: LogsState | None = None,
        diagnostics: DiagnosticsState | None = None,
        radio_tui: RadioTuiState | None = None,
        rf_health: RFHealthState | None = None,
        connection_error: str | None = None,
    ) -> None:
        self.mode = mode
        self.line_width = width
        self.messaging = messaging or MessagingState()
        self.dashboard = dashboard or DashboardState()
        self.mesh = mesh or MeshState()
        self.config_state = config_state or ConfigState()
        self.logs = logs or LogsState()
        self.diagnostics = diagnostics or DiagnosticsState()
        self.radio_tui = radio_tui or RadioTuiState()
        self.rf_health = rf_health or RFHealthState()
        self.connection_error = connection_error
        super().__init__(self.render_mode(), id="active-pane", markup=False)

    def set_mode(self, mode: str) -> None:
        """Switch the visible screen."""
        self.mode = mode
        self.update(self.render_mode())

    def set_width(self, width: int) -> None:
        """Update row width for the current terminal size."""
        self.line_width = max(20, width)
        self.update(self.render_mode())

    def set_messaging(self, state: MessagingState) -> None:
        """Update messaging state and rerender when Chats is visible."""
        self.messaging = state
        if self.mode == "Chats":
            self.update(self.render_mode())

    def set_dashboard(self, state: DashboardState) -> None:
        """Update dashboard state and rerender when Dashboard is visible."""
        self.dashboard = state
        if self.mode == "Dashboard":
            self.update(self.render_mode())

    def set_mesh(self, state: MeshState) -> None:
        """Update mesh state and rerender when Nodes or Mesh is visible."""
        self.mesh = state
        if self.mode in {"Nodes", "Mesh"}:
            self.update(self.render_mode())

    def set_config_state(self, state: ConfigState) -> None:
        """Update config state and rerender when Config is visible."""
        self.config_state = state
        if self.mode == "Config":
            self.update(self.render_mode())

    def set_logs(self, state: LogsState) -> None:
        """Update log state and rerender when Logs is visible."""
        self.logs = state
        if self.mode == "Logs":
            self.update(self.render_mode())

    def set_diagnostics(self, state: DiagnosticsState) -> None:
        """Update diagnostics state and rerender when Diag is visible."""
        self.diagnostics = state
        if self.mode == "Diag":
            self.update(self.render_mode())

    def set_radio(self, state: RadioTuiState) -> None:
        """Update radio state and rerender when Radio is visible."""
        self.radio_tui = state
        if self.mode == "Radio":
            self.update(self.render_mode())

    def set_rf_health(self, state: RFHealthState) -> None:
        """Update RF health state and rerender when RF is visible."""
        self.rf_health = state
        if self.mode == "RF":
            self.update(self.render_mode())

    def set_connection_error(self, detail: str) -> None:
        """Render a connection picker error."""
        self.connection_error = detail
        self.mode = "ConnectError"
        self.update(self.render_mode())

    def render_mode(self) -> str:
        """Return deterministic text for the active screen."""
        match self.mode:
            case "Dashboard":
                return "\n".join(("DASHBOARD", *status_rows(self.dashboard, self.line_width)))
            case "Chats":
                return MessagingPanel(self.messaging, width=self.line_width).render()
            case "Nodes":
                return "\n".join(("NODES", *mesh_neighbor_rows(self.mesh, self.line_width)))
            case "Mesh":
                return "\n".join(("MESH", *mesh_route_rows(self.mesh, self.line_width)))
            case "Config":
                return "\n".join(
                    (
                        "CONFIG",
                        ConfigTable(
                            config_rows(self.config_state, self.line_width),
                            width=self.line_width,
                        ).render_rows(),
                    )
                )
            case "Logs":
                return "\n".join(
                    (
                        "LOGS",
                        LogPanel(self.logs.rows, width=self.line_width).render_rows()
                        if self.logs.error is None
                        else field_line(
                            "log_error",
                            self.logs.error,
                            "recoverable",
                            self.line_width,
                        ),
                    )
                )
            case "Diag":
                return "\n".join(
                    (
                        "DIAGNOSTICS",
                        DiagnosticsPanel(
                            diagnostics_rows(self.diagnostics, self.line_width),
                            width=self.line_width,
                        ).render_rows(),
                    )
                )
            case "RF":
                return "\n".join(("RF HEALTH", *rf_health_rows(self.rf_health, self.line_width)))
            case "Radio":
                return "\n".join(("RADIO", *radio_rows(self.radio_tui, self.line_width)))
            case "Quit":
                return "\n".join(("QUIT?", "Press y to quit or Esc/n to cancel."))
            case "Connect":
                return "\n".join(
                    (
                        "CONNECTION",
                        field_line("1", "Demo", "local", self.line_width),
                        field_line("2", "BLE", "packet", self.line_width),
                        field_line("3", "IP/CoAP", "network", self.line_width),
                    )
                )
            case "ConnectError":
                return "\n".join(
                    (
                        "CONNECTION",
                        field_line(
                            "error",
                            self.connection_error or "transport unavailable",
                            "recoverable",
                            self.line_width,
                        ),
                    )
                )
            case "Open":
                return "\n".join(("OPEN", "Select a concrete row in child flow screens."))
            case "Filter":
                return "\n".join(("FILTER", "Filter prompt is reserved for data-backed screens."))
            case _:
                return "\n".join(
                    ("HELP", "? help", "Tab or ] next", "Shift+Tab or [ previous", "1-8 jump")
                )
