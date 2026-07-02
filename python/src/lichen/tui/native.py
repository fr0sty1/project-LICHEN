# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI shell and shared widgets."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, ClassVar, Protocol

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.css.query import NoMatches
from textual.widgets import Input, Static

from lichen.client import (
    AiocoapResourceTransport,
    BlePacketTransport,
    Capabilities,
    CoapResult,
    ConfigSnapshot,
    DeliveryState,
    DeviceStatus,
    Identity,
    IpCoapConfig,
    LciClient,
    MessageDraft,
    MessageRecord,
    Neighbor,
    PacketCoapConfig,
    PacketCoapResourceTransport,
    RadioConfig,
    ResourceSubscription,
    Route,
    SendResult,
)


class MessageSubscriptionLike(Protocol):
    """Subset of a typed inbox Observe subscription used by the TUI."""

    def messages(self) -> AsyncIterator[list[MessageRecord]]:
        """Yield normalized inbox snapshots."""

    async def close(self) -> None:
        """Cancel the Observe relationship."""


class MessagingClient(Protocol):
    """Subset of the shared LCI client needed by the messaging screen."""

    async def inbox(self, path: str = "/msg/inbox") -> list[MessageRecord]:
        """Return normalized inbox records."""

    async def observe_inbox(self, path: str = "/msg/inbox") -> MessageSubscriptionLike:
        """Start a normalized inbox Observe subscription."""

    async def send_message(self, draft: MessageDraft, path: str = "/msg/inbox") -> SendResult:
        """Send a normalized message draft."""

    async def discover(self) -> Capabilities:
        """Discover advertised LCI resources."""

    async def get_status(self) -> DeviceStatus:
        """Return normalized device status."""

    async def get_config(self) -> ConfigSnapshot:
        """Return normalized device config."""

    async def get_radio_config(self) -> RadioConfig:
        """Return normalized radio config."""

    async def get_identity(self) -> Identity:
        """Return normalized identity."""

    async def list_neighbors(self) -> list[Neighbor]:
        """Return normalized mesh neighbors."""

    async def list_routes(self) -> list[Route]:
        """Return normalized mesh routes."""

    async def set_config(self, values: Mapping[str, Any]) -> CoapResult:
        """Write node config values."""

    async def set_radio_config(self, values: Mapping[str, Any]) -> CoapResult:
        """Write radio config values."""

    async def subscribe_logs(self, path: str = "/logs") -> ResourceSubscription:
        """Subscribe to log notifications."""

    async def get_diagnostics(self, path: str = "/diag") -> Any:
        """Return raw diagnostics payload."""


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
class MessagingState:
    """State rendered by the Chats screen."""

    messages: tuple[MessageRecord, ...] = ()
    selected: int = 0
    unread_count: int = 0
    draft_target: str = ""
    draft_body: str = ""
    last_send: SendResult | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class DashboardState:
    """State rendered by the Dashboard screen."""

    status: DeviceStatus | None = None
    config: ConfigSnapshot | None = None
    identity: Identity | None = None
    capabilities: Capabilities | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class MeshState:
    """State rendered by the Nodes and Mesh screens."""

    neighbors: tuple[Neighbor, ...] = ()
    routes: tuple[Route, ...] = ()
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class ConfigState:
    """State rendered by the Config screen."""

    config: ConfigSnapshot | None = None
    radio: RadioConfig | None = None
    identity: Identity | None = None
    pending_path: str | None = None
    pending_field: str | None = None
    pending_value: str | int | float | None = None
    last_write: str | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class LogsState:
    """State rendered by the Logs screen."""

    rows: tuple[LogRow, ...] = ()
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class DiagnosticsState:
    """State rendered by the Diagnostics screen."""

    rows: tuple[DiagnosticRow, ...] = ()
    error: str | None = None
    loading: bool = False


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


def message_preview(record: MessageRecord, *, unread: bool = False) -> MessagePreview:
    """Convert a normalized LCI message record into a compact terminal row."""
    target = record.sender or record.recipient or "--"
    age = str(record.received or record.timestamp or "--")
    state = "inbox" if record.sender else "sent"
    return MessagePreview(
        target=target,
        preview=record.body or "",
        age=age,
        state=state,
        unread=unread,
    )


def outbound_record(draft: MessageDraft, result: SendResult) -> MessageRecord:
    """Create a local optimistic message record after a send attempt."""
    return MessageRecord(
        raw={
            "to": draft.to,
            "body": draft.body,
            "state": result.state.value,
            "coap_code": result.coap_code,
        },
        recipient=draft.to,
        body=draft.body,
        received="local",
    )


SENSITIVE_FIELD_PARTS = (
    "key",
    "payload",
    "psk",
    "raw",
    "secret",
    "seed",
    "token",
    "password",
)
RADIO_CONFIG_FIELDS = frozenset({"freq_mhz", "bw_khz", "sf", "cr", "tx_power_dbm"})
NODE_CONFIG_FIELDS = frozenset({"name", "role"})


def safe_display_value(name: str, value: object | None) -> str:
    """Return a bounded display value with key-like fields redacted."""
    if (
        any(part in name.lower() for part in SENSITIVE_FIELD_PARTS)
        and "fingerprint" not in name.lower()
    ):
        return "<redacted>"
    if value is None:
        return "--"
    if isinstance(value, bytes | bytearray | memoryview):
        return f"<{len(value)} bytes redacted>"
    if isinstance(value, dict):
        parts = [
            f"{key}={safe_display_value(str(key), item)}"
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        ]
        return ", ".join(parts) or "--"
    if isinstance(value, list | tuple):
        return ", ".join(safe_display_value(name, item) for item in value) or "--"
    return str(value)


def status_rows(state: DashboardState, width: int = 76) -> tuple[str, ...]:
    """Render dashboard rows from normalized shared-client status models."""
    if state.loading:
        return (field_line("status", "loading", width=width),)
    if state.error is not None:
        return (field_line("status_error", state.error, "recoverable", width),)
    status = state.status
    config = state.config
    identity = state.identity
    capabilities = state.capabilities
    radio = status.radio if status is not None else None
    dodag = status.dodag if status is not None else None
    return (
        field_line("connection", "synced" if status is not None else "unsupported", width=width),
        field_line(
            "device",
            safe_display_value("name", config.name if config else None),
            width=width,
        ),
        field_line(
            "role",
            safe_display_value("role", config.role if config else None),
            width=width,
        ),
        field_line(
            "battery",
            _battery_text(status.battery_pct, status.battery_mv) if status else "--",
            width=width,
        ),
        field_line(
            "uptime_s",
            safe_display_value("uptime_s", status.uptime_s if status else None),
            width=width,
        ),
        field_line(
            "mem_free_kb",
            safe_display_value("mem_free_kb", status.mem_free_kb if status else None),
            width=width,
        ),
        field_line("radio", safe_display_value("radio", radio), width=width),
        field_line("dodag", safe_display_value("dodag", dodag), width=width),
        field_line(
            "resources",
            str(len(capabilities.resources)) if capabilities is not None else "--",
            width=width,
        ),
        field_line(
            "observable",
            str(len(capabilities.observable)) if capabilities is not None else "--",
            width=width,
        ),
        field_line(
            "eui64",
            safe_display_value("eui64", identity.eui64 if identity else None),
            width=width,
        ),
        field_line(
            "pubkey_fpr",
            safe_display_value(
                "pubkey_fingerprint",
                identity.pubkey_fingerprint if identity else None,
            ),
            width=width,
        ),
    )


def mesh_neighbor_rows(state: MeshState, width: int = 76) -> tuple[str, ...]:
    """Render node/neighbor rows."""
    if state.loading:
        return (field_line("neighbors", "loading", width=width),)
    if state.error is not None:
        return (field_line("mesh_error", state.error, "recoverable", width),)
    if not state.neighbors:
        return (field_line("node", "--", "empty", width),)
    rows = []
    for neighbor in state.neighbors:
        rows.append(
            field_line(
                neighbor.addr or neighbor.iid or "node",
                f"rssi {safe_display_value('rssi', neighbor.rssi_dbm)} "
                f"snr {safe_display_value('snr', neighbor.snr_db)} "
                f"etx {safe_display_value('etx', neighbor.etx)} "
                f"trust {safe_display_value('trust', neighbor.trust)}",
                width=width,
            )
        )
    return tuple(rows)


def mesh_route_rows(state: MeshState, width: int = 76) -> tuple[str, ...]:
    """Render route rows."""
    if state.loading:
        return (field_line("routes", "loading", width=width),)
    if state.error is not None:
        return (field_line("mesh_error", state.error, "recoverable", width),)
    if not state.routes:
        return (field_line("destination", "--", "empty", width),)
    return tuple(
        field_line(
            route.prefix or "route",
            f"via {safe_display_value('via', route.via)} "
            f"metric {safe_display_value('metric', route.metric)} "
            f"lifetime {safe_display_value('lifetime_s', route.lifetime_s)}",
            width=width,
        )
        for route in state.routes
    )


def config_rows(state: ConfigState, width: int = 76) -> tuple[ConfigRow, ...]:
    """Render config rows without exposing key material."""
    if state.loading:
        return (ConfigRow("config", "loading", "pending"),)
    if state.error is not None:
        return (ConfigRow("config_error", state.error, "recoverable"),)
    rows = [
        ConfigRow(
            "name",
            safe_display_value("name", state.config.name if state.config else None),
            "mutable",
        ),
        ConfigRow(
            "role",
            safe_display_value("role", state.config.role if state.config else None),
            "mutable",
        ),
        ConfigRow(
            "freq_mhz",
            safe_display_value("freq_mhz", state.radio.freq_mhz if state.radio else None),
            "mutable",
        ),
        ConfigRow(
            "bw_khz",
            safe_display_value("bw_khz", state.radio.bw_khz if state.radio else None),
            "mutable",
        ),
        ConfigRow(
            "sf",
            safe_display_value("sf", state.radio.sf if state.radio else None),
            "mutable",
        ),
        ConfigRow(
            "cr",
            safe_display_value("cr", state.radio.cr if state.radio else None),
            "mutable",
        ),
        ConfigRow(
            "tx_power_dbm",
            safe_display_value("tx_power_dbm", state.radio.tx_power_dbm if state.radio else None),
            "mutable",
        ),
        ConfigRow(
            "sync_word",
            safe_display_value("sync_word", state.radio.sync_word if state.radio else None),
            "read-only",
        ),
        ConfigRow(
            "eui64",
            safe_display_value("eui64", state.identity.eui64 if state.identity else None),
            "read-only",
        ),
        ConfigRow(
            "pubkey_fpr",
            safe_display_value(
                "pubkey_fingerprint",
                state.identity.pubkey_fingerprint if state.identity else None,
            ),
            "read-only",
        ),
    ]
    if state.pending_field is not None:
        pending_value = safe_display_value(state.pending_field, state.pending_value)
        rows.append(
            ConfigRow(
                "pending",
                f"{state.pending_field}={pending_value}",
                "confirm",
            )
        )
    if state.last_write is not None:
        rows.append(ConfigRow("last_write", state.last_write, "ok"))
    return tuple(rows)


def diagnostics_rows(state: DiagnosticsState, width: int = 76) -> tuple[DiagnosticRow, ...]:
    """Render diagnostics rows with key-like fields redacted."""
    if state.loading:
        return (DiagnosticRow("diagnostics", "loading"),)
    if state.error is not None:
        return (DiagnosticRow("diag_error", state.error),)
    if not state.rows:
        return (
            DiagnosticRow("transport", "disconnected"),
            DiagnosticRow("capabilities", "not discovered"),
            DiagnosticRow("last_error", "--"),
        )
    return state.rows


def flatten_diagnostics(
    payload: Any,
    *,
    prefix: str = "",
    depth: int = 0,
) -> tuple[DiagnosticRow, ...]:
    """Flatten decoded diagnostics payloads into deterministic redacted rows."""
    if depth > 3:
        return (DiagnosticRow(prefix or "value", safe_display_value(prefix, payload)),)
    if isinstance(payload, Mapping):
        rows: list[DiagnosticRow] = []
        for key, value in sorted(payload.items(), key=lambda pair: str(pair[0])):
            name = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(flatten_diagnostics(value, prefix=name, depth=depth + 1))
        return tuple(rows) or (DiagnosticRow(prefix or "value", "--"),)
    if isinstance(payload, list | tuple):
        if all(not isinstance(item, Mapping | list | tuple) for item in payload):
            return (DiagnosticRow(prefix or "value", safe_display_value(prefix, payload)),)
        rows = []
        for index, value in enumerate(payload):
            name = f"{prefix}.{index}" if prefix else str(index)
            rows.extend(flatten_diagnostics(value, prefix=name, depth=depth + 1))
        return tuple(rows) or (DiagnosticRow(prefix or "value", "--"),)
    return (DiagnosticRow(prefix or "value", safe_display_value(prefix, payload)),)


def log_rows_from_payload(payload: Any) -> tuple[LogRow, ...]:
    """Normalize common decoded log notification payload shapes."""
    records: Any
    if isinstance(payload, Mapping):
        records = payload.get("records", payload.get("logs", payload.get("log", payload)))
    else:
        records = payload
    if isinstance(records, str):
        return (LogRow("info", "device", records),)
    if isinstance(records, Mapping):
        return (_log_row_from_map(records),)
    if isinstance(records, list | tuple):
        rows = []
        for item in records:
            if isinstance(item, Mapping):
                rows.append(_log_row_from_map(item))
            else:
                rows.append(LogRow("info", "device", safe_display_value("log", item)))
        return tuple(rows)
    return (LogRow("info", "device", safe_display_value("log", records)),)


def _log_row_from_map(item: Mapping[str, Any]) -> LogRow:
    level = safe_display_value("level", item.get("level", item.get("severity", "info")))
    module = safe_display_value("module", item.get("module", item.get("source", "device")))
    message = safe_display_value("message", item.get("message", item.get("msg", item)))
    return LogRow(level=level, module=module, message=message)


def parse_config_value(field: str, value: str) -> str | int | float:
    """Parse config input strings into simple typed values."""
    if field in {"bw_khz", "sf", "tx_power_dbm"}:
        return int(value)
    if field == "freq_mhz":
        return float(value)
    return value


def _battery_text(pct: int | None, mv: int | None) -> str:
    parts = []
    if pct is not None:
        parts.append(f"{pct}%")
    if mv is not None:
        parts.append(f"{mv}mV")
    return " ".join(parts) or "--"


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
    ) -> None:
        self.mode = mode
        self.line_width = width
        self.messaging = messaging or MessagingState()
        self.dashboard = dashboard or DashboardState()
        self.mesh = mesh or MeshState()
        self.config_state = config_state or ConfigState()
        self.logs = logs or LogsState()
        self.diagnostics = diagnostics or DiagnosticsState()
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
        Binding("c", "focus_compose", "Compose"),
        Binding("o", "observe_messages", "Observe", priority=True),
        Binding("1", "jump_mode(0)", "Dashboard"),
        Binding("2", "jump_mode(1)", "Chats"),
        Binding("3", "jump_mode(2)", "Nodes"),
        Binding("4", "jump_mode(3)", "Mesh"),
        Binding("5", "jump_mode(4)", "Config"),
        Binding("6", "jump_mode(5)", "Logs"),
        Binding("7", "jump_mode(6)", "Diag"),
    ]

    def __init__(
        self,
        status: ShellStatus | None = None,
        *,
        client: MessagingClient | None = None,
        inbox_path: str = "/msg/inbox",
        send_path: str = "/msg/inbox",
    ) -> None:
        super().__init__()
        self.status = status or ShellStatus()
        self.client = client
        self.inbox_path = inbox_path
        self.send_path = send_path
        self.messaging = MessagingState()
        self.dashboard = DashboardState()
        self.mesh = MeshState()
        self.config_state = ConfigState()
        self.logs = LogsState()
        self.diagnostics = DiagnosticsState()
        self._observe_task: asyncio.Task[None] | None = None
        self._log_task: asyncio.Task[None] | None = None
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
            yield ActivePane(
                self.status.context,
                messaging=self.messaging,
                dashboard=self.dashboard,
                mesh=self.mesh,
                config_state=self.config_state,
                logs=self.logs,
                diagnostics=self.diagnostics,
            )
            yield Input(placeholder="message target", id="message-target", disabled=True)
            yield Input(placeholder="message body", id="message-body", disabled=True)
        yield CommandBar()

    async def on_mount(self) -> None:
        """Size initial fixed-width text renderers to the terminal."""
        self._resize_widgets()
        self._update_compose_inputs()
        connect = getattr(self.client, "connect", None)
        if connect is None:
            return
        self.status = ShellStatus(
            context=self.status.context,
            mode=self.status.mode,
            state=UiState.CONNECTING,
            device=self.status.device,
            battery=self.status.battery,
            time=self.status.time,
            unread=self.status.unread,
            target=self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)
        try:
            await connect()
        except Exception as exc:
            self._set_messaging(self._messaging_error(str(exc)))
            return
        self.status = ShellStatus(
            context=self.status.context,
            mode=self.status.mode,
            state=UiState.SYNCED,
            device=self.status.device,
            battery=self.status.battery,
            time=self.status.time,
            unread=self.status.unread,
            target=self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)

    async def on_unmount(self) -> None:
        """Close an owned client transport when the app exits."""
        if self._observe_task is not None:
            self._observe_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._observe_task
        if self._log_task is not None:
            self._log_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._log_task
        disconnect = getattr(self.client, "disconnect", None)
        if disconnect is not None:
            await disconnect()

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

    async def action_refresh(self) -> None:
        """Refresh the active data-backed screen."""
        match self.status.context:
            case "Dashboard":
                await self.refresh_dashboard()
            case "Chats":
                await self.refresh_messages()
            case "Nodes" | "Mesh":
                await self.refresh_mesh()
            case "Config":
                await self.refresh_config()
            case "Logs":
                await self.start_observing_logs()
            case "Diag":
                await self.refresh_diagnostics()
            case _:
                pane = self.query_one("#active-pane", ActivePane)
                pane.update(f"{pane.render_mode()}\nrefresh requested")

    async def action_open(self) -> None:
        """Show an open placeholder for keyboard-only row activation."""
        if self.prompt_mode == "ConfigConfirm":
            await self.confirm_config_write()
            return
        if self.status.context == "Config" and self.config_state.error is not None:
            return
        if self.status.context == "Config" and self.config_state.pending_field is not None:
            self.prompt_mode = "ConfigConfirm"
            self._disable_text_inputs()
            self.query_one("#active-pane", ActivePane).set_config_state(
                ConfigState(
                    config=self.config_state.config,
                    radio=self.config_state.radio,
                    identity=self.config_state.identity,
                    pending_path=self.config_state.pending_path,
                    pending_field=self.config_state.pending_field,
                    pending_value=self.config_state.pending_value,
                    last_write=self.config_state.last_write,
                    error=self.config_state.error,
                )
            )
            return
        if self.status.context == "Chats" and self.messaging.draft_body:
            self._sync_compose_from_inputs()
            await self.send_draft()
            return
        if self.status.context == "Chats" and self.select_current_contact():
            return
        self.prompt_mode = "Open"
        self.query_one("#active-pane", ActivePane).set_mode("Open")

    def action_focus_compose(self) -> None:
        """Focus the chat target input for keyboard compose."""
        if self.status.context != "Chats":
            self._set_mode(ModeNav.MODES.index("Chats"))
        self._restore_message_inputs(disabled=False)
        target = self.query_one("#message-target", Input)
        self.query_one("#message-body", Input).disabled = False
        target.disabled = False
        target.focus()

    async def action_observe_messages(self) -> None:
        """Start the active screen's Observe flow."""
        if self.status.context == "Logs":
            await self.start_observing_logs()
            return
        if self.status.context != "Chats":
            self._set_mode(ModeNav.MODES.index("Chats"))
        await self.start_observing_messages()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Advance chat compose fields and send from the body field."""
        if self.prompt_mode == "ConfigEdit":
            if event.input.id == "message-target":
                self.query_one("#message-body", Input).focus()
                return
            if event.input.id == "message-body":
                field = self.query_one("#message-target", Input).value.strip()
                value = self.query_one("#message-body", Input).value.strip()
                if field and value:
                    try:
                        parsed_value = parse_config_value(field, value)
                    except ValueError as exc:
                        self._set_config_error(f"invalid {field}: {exc}")
                        return
                    self.stage_config_change(field, parsed_value)
                    self.prompt_mode = None
                    self._restore_message_inputs(disabled=True)
                return
        if event.input.id == "message-target":
            self.query_one("#message-body", Input).focus()
            return
        if event.input.id == "message-body":
            self._sync_compose_from_inputs()
            await self.send_draft()

    def action_filter(self) -> None:
        """Show a filter placeholder for keyboard-only operation."""
        if self.status.context == "Config":
            self.prompt_mode = "ConfigEdit"
            target = self.query_one("#message-target", Input)
            body = self.query_one("#message-body", Input)
            target.disabled = False
            body.disabled = False
            target.placeholder = "config field"
            body.placeholder = "config value"
            target.value = ""
            body.value = ""
            target.focus()
            return
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

    async def action_accept_prompt(self) -> None:
        """Accept the active confirmation prompt."""
        if self.prompt_mode == "Quit":
            self.exit()
        elif self.prompt_mode == "ConfigConfirm":
            await self.confirm_config_write()

    def action_cancel_prompt(self) -> None:
        """Dismiss a prompt and restore the active mode."""
        if self.prompt_mode is None:
            return
        self.prompt_mode = None
        if self.status.context == "Config":
            self._restore_message_inputs(disabled=True)
            self._set_config_state(
                ConfigState(
                    config=self.config_state.config,
                    radio=self.config_state.radio,
                    identity=self.config_state.identity,
                    last_write=self.config_state.last_write,
                )
            )
        self.query_one("#active-pane", ActivePane).set_mode(self.status.context)

    def action_jump_mode(self, index: int) -> None:
        """Jump directly to a numbered top-level mode."""
        self._set_mode(index)

    def _set_mode(self, index: int) -> None:
        previous_mode = self.status.context
        next_mode = ModeNav.MODES[index]
        if self.prompt_mode == "ConfigEdit":
            self._restore_message_inputs(disabled=True)
        elif previous_mode == "Chats" and next_mode != "Chats":
            self._sync_compose_from_inputs_if_available()
            self._restore_message_inputs(disabled=True)
        self.prompt_mode = None
        self.mode_index = index
        self.status = ShellStatus(
            context=next_mode,
            mode=self.status.mode,
            state=self.status.state,
            device=self.status.device,
            battery=self.status.battery,
            time=self.status.time,
            unread=self.status.unread,
            target=self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)
        self.query_one("#mode-nav", ModeNav).set_active(next_mode)
        self.query_one("#active-pane", ActivePane).set_mode(next_mode)

    async def refresh_dashboard(self) -> None:
        """Refresh status, config, identity, and capability summary."""
        if self.client is None:
            self._set_dashboard_error("status transport unavailable")
            return
        self._set_dashboard_state(DashboardState(loading=True))
        try:
            status, config, identity, capabilities = await asyncio.gather(
                self.client.get_status(),
                self.client.get_config(),
                self.client.get_identity(),
                self.client.discover(),
            )
        except Exception as exc:
            self._set_dashboard_error(str(exc))
            return
        self._set_dashboard_state(
            DashboardState(
                status=status,
                config=config,
                identity=identity,
                capabilities=capabilities,
            ),
            recover_error=True,
        )
        self._update_shell_from_status(status=status, config=config)

    async def refresh_mesh(self) -> None:
        """Refresh mesh neighbor and route state."""
        if self.client is None:
            self._set_mesh_error("mesh transport unavailable")
            return
        self._set_mesh_state(MeshState(loading=True))
        try:
            neighbors, routes = await asyncio.gather(
                self.client.list_neighbors(),
                self.client.list_routes(),
            )
        except Exception as exc:
            self._set_mesh_error(str(exc))
            return
        self._set_mesh_state(
            MeshState(neighbors=tuple(neighbors), routes=tuple(routes)),
            recover_error=True,
        )

    async def refresh_config(self) -> None:
        """Refresh editable config and read-only identity rows."""
        if self.client is None:
            self._set_config_error("config transport unavailable")
            return
        self._set_config_state(ConfigState(loading=True))
        try:
            config, radio, identity = await asyncio.gather(
                self.client.get_config(),
                self.client.get_radio_config(),
                self.client.get_identity(),
            )
        except Exception as exc:
            self._set_config_error(str(exc))
            return
        self._set_config_state(
            ConfigState(config=config, radio=radio, identity=identity),
            recover_error=True,
        )

    def stage_config_change(
        self,
        field: str,
        value: str | int | float,
        *,
        path: str | None = None,
    ) -> None:
        """Stage one config write; caller must confirm before transport write."""
        config_path = path or ("/config/radio" if field in RADIO_CONFIG_FIELDS else "/config")
        allowed_fields = (
            RADIO_CONFIG_FIELDS if config_path == "/config/radio" else NODE_CONFIG_FIELDS
        )
        if field not in allowed_fields:
            self._set_config_error(f"{field} is read-only or unsupported")
            return
        self._set_config_state(
            ConfigState(
                config=self.config_state.config,
                radio=self.config_state.radio,
                identity=self.config_state.identity,
                pending_path=config_path,
                pending_field=field,
                pending_value=value,
                last_write=self.config_state.last_write,
            )
        )

    async def confirm_config_write(self) -> None:
        """Write a staged config change only after explicit confirmation."""
        if self.client is None:
            self._set_config_error("config transport unavailable")
            return
        if self.config_state.pending_field is None or self.config_state.pending_path is None:
            self._set_config_error("no pending config change")
            return
        field = self.config_state.pending_field
        value = self.config_state.pending_value
        path = self.config_state.pending_path
        self.prompt_mode = None
        try:
            if path == "/config/radio":
                result = await self.client.set_radio_config({field: value})
            elif path == "/config":
                result = await self.client.set_config({field: value})
            else:
                self._set_config_error(f"{path} writes are unsupported")
                return
        except Exception as exc:
            self._set_config_error(f"{path} write failed: {exc}")
            return
        if not result.is_success:
            self._set_config_error(f"{path} write unsupported or rejected: {result.code}")
            self._restore_message_inputs(disabled=True)
            return
        self._set_config_state(
            ConfigState(
                config=self.config_state.config,
                radio=self.config_state.radio,
                identity=self.config_state.identity,
                last_write=f"{field} -> {result.code}",
            ),
            recover_error=True,
        )
        self._restore_message_inputs(disabled=True)

    async def refresh_diagnostics(self) -> None:
        """Fetch and flatten diagnostics with redaction."""
        if self.client is None:
            self._set_diagnostics_error("diagnostics transport unavailable")
            return
        self._set_diagnostics_state(DiagnosticsState(loading=True))
        try:
            payload = await self.client.get_diagnostics()
        except Exception as exc:
            self._set_diagnostics_error(str(exc))
            return
        self._set_diagnostics_state(
            DiagnosticsState(rows=flatten_diagnostics(payload)),
            recover_error=True,
        )

    async def start_observing_logs(self) -> None:
        """Start a live log Observe task if one is not already running."""
        if self.client is None:
            self._set_logs_error("log transport unavailable")
            return
        if self._log_task is not None and not self._log_task.done():
            return
        self._set_logs_state(LogsState(rows=self.logs.rows, loading=True))
        self._log_task = asyncio.create_task(self._logs_loop())

    async def _logs_loop(self) -> None:
        """Apply log Observe notifications until the subscription ends."""
        try:
            if self.client is None:
                self._set_logs_error("log transport unavailable")
                return
            subscription = await self.client.subscribe_logs()
            try:
                async for result in subscription.results():
                    if not result.is_success:
                        self._set_logs_error(f"/logs observe failed: {result.code}")
                        return
                    self._set_logs_state(
                        LogsState(rows=log_rows_from_payload(result.payload)),
                        recover_error=True,
                    )
            finally:
                await subscription.close()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._set_logs_error(str(exc))

    def set_compose(self, target: str, body: str) -> None:
        """Set the current compose draft."""
        self._set_messaging(
            MessagingState(
                messages=self.messaging.messages,
                selected=self.messaging.selected,
                unread_count=self.messaging.unread_count,
                draft_target=target,
                draft_body=body,
                last_send=self.messaging.last_send,
                error=self.messaging.error,
            )
        )
        self._update_compose_inputs()

    def select_current_contact(self) -> bool:
        """Use the selected message source or recipient as the compose target."""
        if not self.messaging.messages:
            return False
        selected = self.messaging.messages[
            min(self.messaging.selected, len(self.messaging.messages) - 1)
        ]
        target = selected.sender or selected.recipient
        if not target:
            return False
        self.set_compose(target, self.messaging.draft_body)
        return True

    async def refresh_messages(self) -> None:
        """Fetch inbox messages through the shared client model."""
        if self.client is None:
            self._set_messaging(self._messaging_error("messaging transport unavailable"))
            return
        self._sync_compose_from_inputs_if_available()
        self._set_messaging(
            MessagingState(
                messages=self.messaging.messages,
                selected=self.messaging.selected,
                unread_count=self.messaging.unread_count,
                draft_target=self.messaging.draft_target,
                draft_body=self.messaging.draft_body,
                last_send=self.messaging.last_send,
                loading=True,
            )
        )
        try:
            messages = tuple(await self.client.inbox(self.inbox_path))
        except Exception as exc:
            self._set_messaging(self._messaging_error(str(exc)))
            return
        self._set_messaging(
            MessagingState(
                messages=messages,
                selected=0,
                unread_count=len(messages),
                draft_target=self.messaging.draft_target,
                draft_body=self.messaging.draft_body,
                last_send=self.messaging.last_send,
            ),
            recover_error=True,
        )

    async def send_draft(self) -> None:
        """Send the current compose draft through the shared client model."""
        draft = MessageDraft(to=self.messaging.draft_target, body=self.messaging.draft_body)
        if not draft.body.strip():
            self._set_messaging(self._messaging_error("message body is required"))
            return
        if self.client is None:
            self._set_messaging(self._messaging_error("messaging transport unavailable"))
            return
        try:
            result = await self.client.send_message(draft, self.send_path)
        except Exception as exc:
            self._set_messaging(self._messaging_error(str(exc)))
            return
        messages = self.messaging.messages
        if result.state == DeliveryState.ACCEPTED:
            messages = messages + (outbound_record(draft, result),)
        error = None
        if result.state != DeliveryState.ACCEPTED:
            error = result.detail or result.coap_code or result.state.value
        self._set_messaging(
            MessagingState(
                messages=messages,
                selected=max(0, len(messages) - 1),
                unread_count=self.messaging.unread_count,
                draft_target=draft.to,
                draft_body="" if result.state == DeliveryState.ACCEPTED else draft.body,
                last_send=result,
                error=error,
            ),
            recover_error=result.state == DeliveryState.ACCEPTED,
        )

    async def start_observing_messages(self) -> None:
        """Start a live inbox Observe task if one is not already running."""
        if self.client is None:
            self._set_messaging(self._messaging_error("messaging transport unavailable"))
            return
        if self._observe_task is not None and not self._observe_task.done():
            return
        self._sync_compose_from_inputs_if_available()
        self._observe_task = asyncio.create_task(self._observe_messages_loop())

    async def _observe_messages_loop(self) -> None:
        """Apply Observe snapshots until the subscription ends or is cancelled."""
        try:
            if self.client is None:
                self._set_messaging(self._messaging_error("messaging transport unavailable"))
                return
            subscription = await self.client.observe_inbox(self.inbox_path)
            try:
                async for messages in subscription.messages():
                    self._sync_compose_from_inputs_if_available()
                    self.apply_inbound_messages(tuple(messages))
            finally:
                await subscription.close()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._set_messaging(self._messaging_error(str(exc)))

    def apply_inbound_messages(self, messages: tuple[MessageRecord, ...]) -> None:
        """Apply an inbound inbox update from an Observe notification."""
        self._set_messaging(
            MessagingState(
                messages=messages,
                selected=0,
                unread_count=len(messages),
                draft_target=self.messaging.draft_target,
                draft_body=self.messaging.draft_body,
                last_send=self.messaging.last_send,
            ),
            recover_error=True,
        )

    def _messaging_error(self, detail: str) -> MessagingState:
        return MessagingState(
            messages=self.messaging.messages,
            selected=self.messaging.selected,
            unread_count=self.messaging.unread_count,
            draft_target=self.messaging.draft_target,
            draft_body=self.messaging.draft_body,
            last_send=SendResult(state=DeliveryState.TRANSPORT_ERROR, detail=detail),
            error=detail,
        )

    def _set_messaging(self, state: MessagingState, *, recover_error: bool = False) -> None:
        self.messaging = state
        if state.error is not None:
            ui_state = UiState.ERROR
        elif self.status.state == UiState.ERROR and recover_error:
            ui_state = UiState.SYNCED
        else:
            ui_state = self.status.state
        self.status = ShellStatus(
            context=self.status.context,
            mode=self.status.mode,
            state=ui_state,
            device=self.status.device,
            battery=self.status.battery,
            time=self.status.time,
            unread=state.unread_count,
            target=state.draft_target or self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)
        self.query_one("#active-pane", ActivePane).set_messaging(state)
        self._update_compose_inputs()

    def _set_dashboard_state(
        self,
        state: DashboardState,
        *,
        recover_error: bool = False,
    ) -> None:
        self.dashboard = state
        self._set_screen_status(error=state.error, recover_error=recover_error)
        self.query_one("#active-pane", ActivePane).set_dashboard(state)

    def _set_dashboard_error(self, detail: str) -> None:
        self._set_dashboard_state(
            DashboardState(
                status=self.dashboard.status,
                config=self.dashboard.config,
                identity=self.dashboard.identity,
                capabilities=self.dashboard.capabilities,
                error=detail,
            )
        )

    def _set_mesh_state(self, state: MeshState, *, recover_error: bool = False) -> None:
        self.mesh = state
        self._set_screen_status(error=state.error, recover_error=recover_error)
        self.query_one("#active-pane", ActivePane).set_mesh(state)

    def _set_mesh_error(self, detail: str) -> None:
        self._set_mesh_state(
            MeshState(
                neighbors=self.mesh.neighbors,
                routes=self.mesh.routes,
                error=detail,
            )
        )

    def _set_config_state(
        self,
        state: ConfigState,
        *,
        recover_error: bool = False,
    ) -> None:
        self.config_state = state
        self._set_screen_status(error=state.error, recover_error=recover_error)
        self.query_one("#active-pane", ActivePane).set_config_state(state)

    def _set_config_error(self, detail: str) -> None:
        self._set_config_state(
            ConfigState(
                config=self.config_state.config,
                radio=self.config_state.radio,
                identity=self.config_state.identity,
                last_write=self.config_state.last_write,
                error=detail,
            )
        )

    def _set_logs_state(self, state: LogsState, *, recover_error: bool = False) -> None:
        self.logs = state
        self._set_screen_status(error=state.error, recover_error=recover_error)
        self.query_one("#active-pane", ActivePane).set_logs(state)

    def _set_logs_error(self, detail: str) -> None:
        self._set_logs_state(LogsState(rows=self.logs.rows, error=detail))

    def _set_diagnostics_state(
        self,
        state: DiagnosticsState,
        *,
        recover_error: bool = False,
    ) -> None:
        self.diagnostics = state
        self._set_screen_status(error=state.error, recover_error=recover_error)
        self.query_one("#active-pane", ActivePane).set_diagnostics(state)

    def _set_diagnostics_error(self, detail: str) -> None:
        self._set_diagnostics_state(
            DiagnosticsState(rows=self.diagnostics.rows, error=detail)
        )

    def _set_screen_status(self, *, error: str | None, recover_error: bool = False) -> None:
        if error is not None:
            ui_state = UiState.ERROR
        elif self.status.state == UiState.ERROR and recover_error:
            ui_state = UiState.SYNCED
        else:
            ui_state = self.status.state
        self.status = ShellStatus(
            context=self.status.context,
            mode=self.status.mode,
            state=ui_state,
            device=self.status.device,
            battery=self.status.battery,
            time=self.status.time,
            unread=self.status.unread,
            target=self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)

    def _update_shell_from_status(
        self,
        *,
        status: DeviceStatus,
        config: ConfigSnapshot,
    ) -> None:
        self.status = ShellStatus(
            context=self.status.context,
            mode=self.status.mode,
            state=self.status.state,
            device=config.name or self.status.device,
            battery=_battery_text(status.battery_pct, None)
            if status.battery_pct is not None
            else self.status.battery,
            time=self.status.time,
            unread=self.status.unread,
            target=self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)

    def _sync_compose_from_inputs(self) -> None:
        target = self.query_one("#message-target", Input).value
        body = self.query_one("#message-body", Input).value
        self.messaging = MessagingState(
            messages=self.messaging.messages,
            selected=self.messaging.selected,
            unread_count=self.messaging.unread_count,
            draft_target=target,
            draft_body=body,
            last_send=self.messaging.last_send,
            error=self.messaging.error,
            loading=self.messaging.loading,
        )

    def _sync_compose_from_inputs_if_available(self) -> None:
        try:
            self._sync_compose_from_inputs()
        except NoMatches:
            return

    def _update_compose_inputs(self) -> None:
        try:
            target = self.query_one("#message-target", Input)
            body = self.query_one("#message-body", Input)
        except NoMatches:
            return
        target.value = self.messaging.draft_target
        body.value = self.messaging.draft_body

    def _disable_text_inputs(self) -> None:
        try:
            self.query_one("#message-target", Input).disabled = True
            self.query_one("#message-body", Input).disabled = True
        except NoMatches:
            return
        self.set_focus(None)

    def _restore_message_inputs(self, *, disabled: bool) -> None:
        try:
            target = self.query_one("#message-target", Input)
            body = self.query_one("#message-body", Input)
        except NoMatches:
            return
        target.placeholder = "message target"
        body.placeholder = "message body"
        target.value = self.messaging.draft_target
        body.value = self.messaging.draft_body
        target.disabled = disabled
        body.disabled = disabled
        if disabled:
            self.set_focus(None)

    def _resize_widgets(self) -> None:
        width = max(24, self.size.width)
        self.query_one("#native-status", NativeStatusBar).set_width(width)
        self.query_one("#mode-nav", ModeNav).set_width(width)
        self.query_one("#active-pane", ActivePane).set_width(max(20, width - 2))


def build_messaging_client(
    base_uri: str | None,
    *,
    ble_address: str | None = None,
    ble_local_host: str = "fe80::2",
    ble_node_host: str = "fe80::1",
) -> MessagingClient | None:
    """Build a messaging client for IP/CoAP or BLE packet-backed LCI."""
    if ble_address is not None:
        packet_transport = BlePacketTransport(ble_address)
        transport = PacketCoapResourceTransport(
            packet_transport,
            config=PacketCoapConfig(local_host=ble_local_host, peer_host=ble_node_host),
        )
        return LciClient(transport)
    if base_uri is None:
        return None
    transport = AiocoapResourceTransport(config=IpCoapConfig(base_uri=base_uri))
    return LciClient(transport)


def main(argv: Sequence[str] | None = None) -> None:
    """Run the native client shell."""
    parser = argparse.ArgumentParser(description="Run the LICHEN native LCI TUI")
    parser.add_argument(
        "--coap-base-uri",
        help="Base IP/CoAP URI for a local LCI endpoint, for example coap://[fe80::1]",
    )
    parser.add_argument("--ble-address", help="BLE address for a SLIP/IPv6 LCI endpoint")
    parser.add_argument("--ble-local-host", default="fe80::2")
    parser.add_argument("--ble-node-host", default="fe80::1")
    parser.add_argument("--inbox-path", default="/msg/inbox")
    parser.add_argument("--send-path", default="/msg/inbox")
    args = parser.parse_args(argv)
    client = build_messaging_client(
        args.coap_base_uri,
        ble_address=args.ble_address,
        ble_local_host=args.ble_local_host,
        ble_node_host=args.ble_node_host,
    )
    mode = LinkMode.DEMO
    if args.ble_address is not None:
        mode = LinkMode.BLE
    elif client is not None:
        mode = LinkMode.IP
    status = ShellStatus(
        mode=mode,
        state=UiState.SYNCED if client is not None else UiState.DISCONNECTED,
    )
    NativeClientApp(
        status,
        client=client,
        inbox_path=args.inbox_path,
        send_path=args.send_path,
    ).run()
