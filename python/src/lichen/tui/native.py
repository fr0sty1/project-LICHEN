# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI shell and shared widgets."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
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
    LocalRFStats,
    MessageDraft,
    MessageRecord,
    Neighbor,
    PacketCoapConfig,
    PacketCoapResourceTransport,
    RadioConfig,
    RawDiagnosticResult,
    RawDiagnosticState,
    RawRxEvent,
    RawRxStatus,
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


class RawRxSubscriptionLike(Protocol):
    """Subset of a typed raw RX Observe subscription used by the TUI."""

    def events(self) -> AsyncIterator[RawRxEvent]:
        """Yield normalized raw RX diagnostic events."""

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

    async def get_raw_rx_status(self, path: str = "/diag/raw/rx") -> RawRxStatus:
        """Return optional raw RX diagnostics state."""

    async def arm_raw_rx(
        self,
        *,
        ttl_s: int,
        include_payload: bool = False,
        enabled: bool = True,
        path: str = "/diag/raw/rx",
    ) -> RawDiagnosticResult:
        """Arm optional raw RX diagnostics for a finite TTL."""

    async def send_raw_tx(
        self,
        frame: bytes | bytearray | memoryview,
        *,
        wait: bool = True,
        path: str = "/diag/raw/tx",
    ) -> RawDiagnosticResult:
        """Transmit one optional raw diagnostic frame."""

    async def observe_raw_rx_events(
        self,
        path: str = "/diag/raw/rx/events",
    ) -> RawRxSubscriptionLike:
        """Observe optional raw RX diagnostic events."""


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


ConnectionClientFactory = Callable[[LinkMode], MessagingClient | None]


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
    raw_rx_status: RawRxStatus | None = None
    raw_events: tuple[RawRxEvent, ...] = ()
    raw_available: bool | None = None
    admin_enabled: bool = False
    last_raw_action: RawDiagnosticResult | None = None
    error: str | None = None
    loading: bool = False


@dataclass(frozen=True)
class RadioTuiState:
    """State rendered by the Radio screen.

    Shows duty cycle usage and TX queue status for RF observability.
    """

    # Duty cycle state
    duty_cycle_usage_percent: float = 0.0
    duty_cycle_remaining_ms: int = 0
    duty_cycle_time_until_refill_ms: int = 0
    duty_cycle_limit_percent: float = 1.0

    # TX queue state
    tx_queue_depth_by_priority: tuple[tuple[int, int], ...] = ()
    tx_queue_total_bytes: int = 0
    tx_queue_drain_time_ms: int = 0
    tx_queue_oldest_age_ms: int = 0

    error: str | None = None
    loading: bool = False

    @property
    def duty_cycle_usage_ratio(self) -> float:
        """Return usage as a ratio from 0.0 to 1.0+."""
        return self.duty_cycle_usage_percent / 100.0

    @property
    def is_over_limit(self) -> bool:
        """Return True if duty cycle limit has been exceeded."""
        return self.duty_cycle_usage_percent > 100.0

    @property
    def tx_queue_total_depth(self) -> int:
        """Return total packets across all priority levels."""
        return sum(depth for _, depth in self.tx_queue_depth_by_priority)


@dataclass(frozen=True)
class RFHealthState:
    """State rendered by the RF Health screen (5g8t.6).

    Shows neighbor RF metrics (success rate, duty cycle observed, cheater flags)
    and local RF stats (noise floor, channel busy, RX errors).
    """

    # Neighbors with RF health metrics
    neighbors: tuple[Neighbor, ...] = ()

    # Local RF stats
    local_rf: LocalRFStats | None = None

    error: str | None = None
    loading: bool = False

    @property
    def cheater_count(self) -> int:
        """Return count of neighbors flagged as cheaters."""
        return sum(1 for n in self.neighbors if n.is_cheater is True)

    @property
    def has_rf_data(self) -> bool:
        """Return True if any RF health data is available."""
        return bool(self.neighbors) or self.local_rf is not None


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
    if width == 1:
        return "."
    if width == 2:
        return ".."
    if width == 3:
        return "..."
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
MAX_DIAG_ROWS = 100


def safe_display_value(name: str, value: object | None) -> str:
    """Return a bounded display value with key-like fields redacted."""
    if _is_sensitive_display_name(name):
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


def safe_float(value: object | None) -> float | None:
    """Safely convert to float or None on parse failure."""
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError, OverflowError):
        return None


def safe_int(value: object | None) -> int:
    """Safely convert to int, defaulting to 0 on parse failure."""
    if value is None:
        return 0
    try:
        return int(float(value))
    except (ValueError, TypeError, OverflowError):
        return 0


def _is_sensitive_display_name(name: str) -> bool:
    lowered = name.lower()
    leaf = lowered.rsplit(".", maxsplit=1)[-1]
    if leaf == "frame":
        return True
    return (
        any(part in lowered for part in SENSITIVE_FIELD_PARTS)
        and "fingerprint" not in lowered
    )


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
    has_raw_context = (
        state.raw_available is not None
        or state.raw_rx_status is not None
        or bool(state.raw_events)
        or state.last_raw_action is not None
    )
    if not state.rows and not has_raw_context:
        return (
            DiagnosticRow("transport", "disconnected"),
            DiagnosticRow("capabilities", "not discovered"),
            DiagnosticRow("last_error", "--"),
        )
    rows = list(state.rows)
    if state.raw_available is not None:
        rows.append(
            DiagnosticRow("raw.admin", "enabled" if state.admin_enabled else "required")
        )
        rows.append(
            DiagnosticRow("raw.resources", "available" if state.raw_available else "unsupported")
        )
    if state.raw_rx_status is not None:
        status = state.raw_rx_status
        rows.extend(
            (
                DiagnosticRow("raw.rx.state", status.state.value),
                DiagnosticRow("raw.rx.enabled", safe_display_value("enabled", status.enabled)),
                DiagnosticRow(
                    "raw.rx.remaining_s",
                    safe_display_value("remaining_s", status.remaining_s),
                ),
                DiagnosticRow(
                    "raw.rx.max_ttl_s",
                    safe_display_value("max_ttl_s", status.max_ttl_s),
                ),
            )
        )
        if status.coap_code is not None:
            rows.append(DiagnosticRow("raw.rx.coap", status.coap_code))
        if status.detail is not None:
            rows.append(DiagnosticRow("raw.rx.detail", safe_display_value("detail", status.detail)))
    if state.last_raw_action is not None:
        action = state.last_raw_action
        rows.append(DiagnosticRow("raw.action.state", action.state.value))
        if action.coap_code is not None:
            rows.append(DiagnosticRow("raw.action.coap", action.coap_code))
        if action.detail is not None:
            rows.append(
                DiagnosticRow("raw.action.detail", safe_display_value("detail", action.detail))
            )
    for index, event in enumerate(state.raw_events[-3:]):
        prefix = f"raw.rx.event.{index}"
        rows.append(DiagnosticRow(f"{prefix}.state", event.state.value))
        if event.frame is not None:
            rows.append(DiagnosticRow(f"{prefix}.frame", safe_display_value("frame", event.frame)))
        if event.rssi_dbm is not None:
            rows.append(
                DiagnosticRow(f"{prefix}.rssi_dbm", safe_display_value("rssi", event.rssi_dbm))
            )
        if event.snr_db is not None:
            rows.append(DiagnosticRow(f"{prefix}.snr_db", safe_display_value("snr", event.snr_db)))
        if event.detail is not None:
            rows.append(
                DiagnosticRow(f"{prefix}.detail", safe_display_value("detail", event.detail))
            )
    return tuple(rows)


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
            if len(rows) > MAX_DIAG_ROWS:
                rows = rows[:MAX_DIAG_ROWS] + [DiagnosticRow("...", "truncated")]
                break
        return tuple(rows) or (DiagnosticRow(prefix or "value", "--"),)
    if isinstance(payload, list | tuple):
        if all(not isinstance(item, Mapping | list | tuple) for item in payload):
            return (DiagnosticRow(prefix or "value", safe_display_value(prefix, payload)),)
        rows = []
        for index, value in enumerate(payload):
            name = f"{prefix}.{index}" if prefix else str(index)
            rows.extend(flatten_diagnostics(value, prefix=name, depth=depth + 1))
            if len(rows) > MAX_DIAG_ROWS:
                rows = rows[:MAX_DIAG_ROWS] + [DiagnosticRow("...", "truncated")]
                break
        return tuple(rows) or (DiagnosticRow(prefix or "value", "--"),)
    return (DiagnosticRow(prefix or "value", safe_display_value(prefix, payload)),)


def raw_diagnostics_available(payload: Any) -> bool:
    """Return true when `/diag` advertises admin-only raw diagnostics resources."""
    if not isinstance(payload, Mapping):
        return False
    raw = payload.get("raw")
    if not isinstance(raw, Mapping):
        return False
    if raw.get("available") is False:
        return False
    return any(raw.get(key) for key in ("rx", "rx_events", "tx"))


def duty_cycle_bar(usage_percent: float, width: int = 20) -> str:
    """Render a text-based progress bar for duty cycle usage.

    Args:
        usage_percent: Current duty cycle usage as percentage (0-100+).
        width: Width of the bar in characters.

    Returns:
        ASCII bar like "[=========>          ] 45.2%"

    """
    width = max(1, width)
    ratio = min(usage_percent / 100.0, 1.0)
    filled = int(ratio * width)
    empty = width - filled

    # Use different indicators for normal vs over-limit
    if usage_percent > 100.0:
        bar_char = "!"
        indicator = "X"
    elif usage_percent > 80.0:
        bar_char = "#"
        indicator = ">"
    else:
        bar_char = "="
        indicator = ">"

    bar = (bar_char * (filled - 1) + indicator + " " * empty) if filled > 0 else (" " * width)

    return f"[{bar}] {usage_percent:5.1f}%"


def format_duration_ms(ms: int) -> str:
    """Format milliseconds as human-readable duration.

    Args:
        ms: Duration in milliseconds.

    Returns:
        Formatted string like "1.2s", "45ms", "2m30s", "1h15m".
    """
    if ms < 0:
        return "--"
    if ms == 0:
        return "0ms"
    if ms < 1000:
        return f"{ms}ms"
    seconds = ms // 1000
    if seconds < 60:
        return f"{seconds}.{(ms % 1000) // 100}s"
    minutes = seconds // 60
    if minutes < 60:
        remaining_s = seconds % 60
        if remaining_s:
            return f"{minutes}m{remaining_s}s"
        return f"{minutes}m"
    hours = minutes // 60
    remaining_m = minutes % 60
    if remaining_m:
        return f"{hours}h{remaining_m}m"
    return f"{hours}h"


def radio_rows(state: RadioTuiState, width: int = 76) -> tuple[str, ...]:
    """Render radio observability rows for duty cycle and TX queue state."""
    if state.loading:
        return (field_line("radio", "loading", width=width),)
    if state.error is not None:
        return (field_line("radio_error", state.error, "recoverable", width),)

    rows: list[str] = []

    # Duty cycle section
    rows.append(field_line("duty_cycle", "--- Duty Cycle ---", width=width))
    rows.append(
        field_line(
            "usage",
            duty_cycle_bar(state.duty_cycle_usage_percent, width=min(20, width - 30)),
            "OVER LIMIT" if state.is_over_limit else "",
            width,
        )
    )
    rows.append(
        field_line(
            "remaining",
            format_duration_ms(state.duty_cycle_remaining_ms),
            f"of {state.duty_cycle_limit_percent:.1f}% limit",
            width,
        )
    )
    rows.append(
        field_line(
            "refill_in",
            format_duration_ms(state.duty_cycle_time_until_refill_ms),
            "until budget starts refilling",
            width,
        )
    )

    # TX queue section
    rows.append(field_line("tx_queue", "--- TX Queue ---", width=width))
    rows.append(
        field_line(
            "depth",
            str(state.tx_queue_total_depth),
            f"packets ({state.tx_queue_total_bytes} bytes)",
            width,
        )
    )

    # Show depth by priority if available
    priority_labels = {
        0: "P0 (urgent)",
        1: "P1 (high)",
        2: "P2 (normal)",
        3: "P3 (low)",
    }
    if state.tx_queue_depth_by_priority:
        for priority, depth in state.tx_queue_depth_by_priority:
            priority_label = priority_labels.get(priority, f"P{priority}")
            rows.append(field_line(f"  {priority_label}", str(depth), "packets", width))

    rows.append(
        field_line(
            "drain_time",
            format_duration_ms(state.tx_queue_drain_time_ms),
            "estimated at current budget",
            width,
        )
    )
    rows.append(
        field_line(
            "oldest_age",
            format_duration_ms(state.tx_queue_oldest_age_ms),
            "oldest queued packet",
            width,
        )
    )

    return tuple(rows)


def rf_health_rows(state: RFHealthState, width: int = 76) -> tuple[str, ...]:
    """Render RF health rows for neighbor metrics and local RF stats (5g8t.6).

    Shows:
    - Neighbor table with callsign, RSSI, SNR, last heard, success rate, duty observed
    - Cheater flags for neighbors exceeding expected duty cycle
    - Local RF stats: noise floor, channel busy, RX errors
    """
    if state.loading:
        return (field_line("rf_health", "loading", width=width),)
    if state.error is not None:
        return (field_line("rf_error", state.error, "recoverable", width),)

    rows: list[str] = []

    # Local RF stats section
    rows.append(field_line("local_rf", "--- Local RF Stats ---", width=width))
    if state.local_rf is not None:
        rf = state.local_rf
        rows.append(
            field_line(
                "noise_floor",
                f"{rf.noise_floor_dbm:.1f} dBm" if rf.noise_floor_dbm is not None else "--",
                width=width,
            )
        )
        rows.append(
            field_line(
                "channel_busy",
                f"{rf.channel_busy_pct:.1f}%" if rf.channel_busy_pct is not None else "--",
                width=width,
            )
        )
        error_rate = rf.rx_error_rate_pct
        rows.append(
            field_line(
                "rx_errors",
                f"{error_rate:.1f}% ({rf.rx_crc_errors} CRC, {rf.rx_timeout_errors} timeout, "
                f"{rf.rx_header_errors} header)"
                if error_rate is not None
                else f"CRC {rf.rx_crc_errors}, timeout {rf.rx_timeout_errors}, "
                f"header {rf.rx_header_errors}",
                f"of {rf.rx_total} total" if rf.rx_total > 0 else "",
                width,
            )
        )
    else:
        rows.append(field_line("local_rf", "--", "no data", width))

    # Neighbor RF section
    rows.append(field_line("neighbors_rf", "--- Neighbor RF Health ---", width=width))

    if state.neighbors and state.cheater_count > 0:
        rows.append(
            field_line(
                "CHEATERS",
                f"{state.cheater_count} neighbor(s) exceeding duty cycle",
                "WARNING",
                width,
            )
        )

    if not state.neighbors:
        rows.append(field_line("neighbor", "--", "no neighbors", width))
    else:
        for neighbor in state.neighbors:
            # Build neighbor identifier (callsign/addr/iid)
            ident = neighbor.addr or neighbor.iid or "unknown"

            # Build RF metrics string
            parts = []
            if neighbor.rssi_dbm is not None:
                parts.append(f"RSSI {neighbor.rssi_dbm:.0f}")
            if neighbor.snr_db is not None:
                parts.append(f"SNR {neighbor.snr_db:.1f}")
            if neighbor.last_seen_s is not None:
                parts.append(f"seen {neighbor.last_seen_s}s")
            if neighbor.success_rate_pct is not None:
                parts.append(f"succ {neighbor.success_rate_pct:.0f}%")
            if neighbor.duty_observed_pct is not None:
                parts.append(f"duty {neighbor.duty_observed_pct:.2f}%")

            metrics = " ".join(parts) if parts else "--"

            # Flag cheaters
            status = ""
            if neighbor.is_cheater is True:
                status = "CHEATER"
            elif neighbor.trust is not None:
                status = neighbor.trust

            rows.append(field_line(ident, metrics, status, width))

    return tuple(rows)


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
    message = safe_display_value("message", item.get("message", item.get("msg", "--")))
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
        Binding("l", "connect_picker", "Link"),
        Binding("tab", "next_mode", "Next", priority=True),
        Binding("shift+tab", "prev_mode", "Prev", priority=True),
        Binding("right_square_bracket", "next_mode", "Next", priority=True),
        Binding("left_square_bracket", "prev_mode", "Prev", priority=True),
        Binding("question_mark", "help", "Help", priority=True),
        Binding("ctrl+l", "refresh", "Refresh", priority=True),
        Binding("r", "refresh", "Refresh", priority=True),
        Binding("c", "focus_compose", "Compose"),
        Binding("o", "observe_messages", "Observe", priority=True),
        Binding("a", "enable_raw_diagnostics_admin", "Admin", priority=True),
        Binding("u", "arm_raw_rx_diagnostics", "Arm RX", priority=True),
        Binding("x", "send_raw_diagnostic_frame", "Raw TX", priority=True),
        Binding("1", "jump_mode(0)", "Dashboard"),
        Binding("2", "jump_mode(1)", "Chats"),
        Binding("3", "jump_mode(2)", "Nodes"),
        Binding("4", "jump_mode(3)", "Mesh"),
        Binding("5", "jump_mode(4)", "RF"),
        Binding("6", "jump_mode(5)", "Config"),
        Binding("7", "jump_mode(6)", "Logs"),
        Binding("8", "jump_mode(7)", "Diag"),
        Binding("9", "jump_mode(8)", "Radio"),
    ]

    def __init__(
        self,
        status: ShellStatus | None = None,
        *,
        client: MessagingClient | None = None,
        connection_factory: ConnectionClientFactory | None = None,
        inbox_path: str = "/msg/inbox",
        send_path: str = "/msg/inbox",
    ) -> None:
        super().__init__()
        self.status = status or ShellStatus()
        self.client = client
        self.connection_factory = connection_factory
        self.inbox_path = inbox_path
        self.send_path = send_path
        self.messaging = MessagingState()
        self.dashboard = DashboardState()
        self.mesh = MeshState()
        self.config_state = ConfigState()
        self.logs = LogsState()
        self.diagnostics = DiagnosticsState()
        self.radio_tui = RadioTuiState()
        self.rf_health = RFHealthState()
        self._observe_task: asyncio.Task[None] | None = None
        self._log_task: asyncio.Task[None] | None = None
        self._raw_rx_task: asyncio.Task[None] | None = None
        self.raw_diagnostics_admin_enabled = False
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
                radio_tui=self.radio_tui,
                rf_health=self.rf_health,
            )
            yield Input(placeholder="message target", id="message-target", disabled=True)
            yield Input(placeholder="message body", id="message-body", disabled=True)
        yield CommandBar()

    async def on_mount(self) -> None:
        """Size initial fixed-width text renderers to the terminal."""
        self._resize_widgets()
        self._update_compose_inputs()
        await self._connect_current_client()

    async def _connect_current_client(self) -> None:
        """Connect the current client if it exposes a connect hook."""
        if self.client is None:
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
        error = await self._connect_client(self.client)
        if error is not None:
            self._set_messaging(self._messaging_error(error))
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

    async def _connect_client(self, client: MessagingClient) -> str | None:
        """Connect a candidate client and return a displayable error on failure."""
        connect = getattr(client, "connect", None)
        if connect is None:
            return None
        try:
            await connect()
        except Exception as exc:
            return str(exc)
        return None

    async def _disconnect_current_client(self) -> None:
        """Disconnect the current client if it exposes a disconnect hook."""
        if self.client is not None:
            await self._disconnect_client(self.client)

    async def _disconnect_client(self, client: MessagingClient) -> None:
        """Disconnect a client if it exposes a disconnect hook."""
        disconnect = getattr(client, "disconnect", None)
        if disconnect is not None:
            await disconnect()

    async def _cancel_live_tasks(self) -> None:
        """Cancel active Observe/log tasks before switching transports."""
        if self._observe_task is not None:
            observe_task = self._observe_task
            self._observe_task = None
            observe_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await observe_task
        if self._log_task is not None:
            log_task = self._log_task
            self._log_task = None
            log_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await log_task
        if self._raw_rx_task is not None:
            raw_rx_task = self._raw_rx_task
            self._raw_rx_task = None
            raw_rx_task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await raw_rx_task

    async def on_unmount(self) -> None:
        """Close an owned client transport when the app exits."""
        with suppress(Exception):
            await self._cancel_live_tasks()
        with suppress(Exception):
            await self._disconnect_current_client()

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
            case "RF":
                await self.refresh_rf_health()
            case "Radio":
                await self.refresh_radio()
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
        if self.status.context == "Diag":
            await self.start_observing_raw_rx()
            return
        if self.status.context != "Chats":
            self._set_mode(ModeNav.MODES.index("Chats"))
        await self.start_observing_messages()

    async def action_enable_raw_diagnostics_admin(self) -> None:
        """Enable admin-gated raw diagnostics on the Diag screen."""
        if self.status.context != "Diag":
            self._set_mode(ModeNav.MODES.index("Diag"))
        self.enable_raw_diagnostics_admin()
        await self.refresh_diagnostics()

    async def action_arm_raw_rx_diagnostics(self) -> None:
        """Arm raw RX diagnostics from the Diag screen."""
        if self.status.context != "Diag":
            self._set_mode(ModeNav.MODES.index("Diag"))
        await self.arm_raw_rx_diagnostics(ttl_s=60)

    async def action_send_raw_diagnostic_frame(self) -> None:
        """Send a bounded raw diagnostics test frame from the Diag screen."""
        if self.status.context != "Diag":
            self._set_mode(ModeNav.MODES.index("Diag"))
        await self.send_raw_diagnostic_frame(b"\xc1\x02\x03\x04")

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

    def action_connect_picker(self) -> None:
        """Open the local transport picker."""
        self.prompt_mode = "Connect"
        self._disable_text_inputs()
        self.query_one("#active-pane", ActivePane).set_mode("Connect")

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

    async def action_jump_mode(self, index: int) -> None:
        """Jump directly to a numbered top-level mode."""
        if self.prompt_mode == "Connect":
            await self.select_connection(index)
            return
        self._set_mode(index)

    async def select_connection(self, index: int) -> None:
        """Select Demo, BLE, or IP/CoAP from the connection picker."""
        mode_by_index = {0: LinkMode.DEMO, 1: LinkMode.BLE, 2: LinkMode.IP}
        mode = mode_by_index.get(index)
        if mode is None:
            return
        next_client = None if mode is LinkMode.DEMO else self._build_connection_client(mode)
        if mode is not LinkMode.DEMO and next_client is None:
            detail = f"{mode.value} transport unavailable"
            self.prompt_mode = None
            self.status = ShellStatus(
                context=self.status.context,
                mode=self.status.mode,
                state=UiState.ERROR,
                device=self.status.device,
                battery=self.status.battery,
                time=self.status.time,
                unread=self.status.unread,
                target=self.status.target,
            )
            self.query_one("#native-status", NativeStatusBar).set_status(self.status)
            self.query_one("#active-pane", ActivePane).set_connection_error(detail)
            return
        candidate_ready = False
        if next_client is not None and next_client is not self.client:
            error = await self._connect_client(next_client)
            if error is not None:
                with suppress(Exception):
                    await self._disconnect_client(next_client)
                detail = f"{mode.value} connection failed: {error}"
                self.prompt_mode = None
                self.status = ShellStatus(
                    context=self.status.context,
                    mode=self.status.mode,
                    state=UiState.ERROR,
                    device=self.status.device,
                    battery=self.status.battery,
                    time=self.status.time,
                    unread=self.status.unread,
                    target=self.status.target,
                )
                self.query_one("#native-status", NativeStatusBar).set_status(self.status)
                self.query_one("#active-pane", ActivePane).set_connection_error(detail)
                return
            candidate_ready = True
        if next_client is self.client:
            self.prompt_mode = None
            self.status = ShellStatus(
                context=self.status.context,
                mode=mode,
                state=self.status.state,
                device=self.status.device,
                battery=self.status.battery,
                time=self.status.time,
                unread=self.status.unread,
                target=self.status.target,
            )
            self.query_one("#native-status", NativeStatusBar).set_status(self.status)
            self.query_one("#active-pane", ActivePane).set_mode(self.status.context)
            return
        try:
            await self._disconnect_current_client()
        except Exception as exc:
            if next_client is not None and candidate_ready:
                with suppress(Exception):
                    await self._disconnect_client(next_client)
            detail = f"{mode.value} switch failed: {exc}"
            self.prompt_mode = None
            self.status = ShellStatus(
                context=self.status.context,
                mode=self.status.mode,
                state=UiState.ERROR,
                device=self.status.device,
                battery=self.status.battery,
                time=self.status.time,
                unread=self.status.unread,
                target=self.status.target,
            )
            self.query_one("#native-status", NativeStatusBar).set_status(self.status)
            self.query_one("#active-pane", ActivePane).set_connection_error(detail)
            return
        await self._cancel_live_tasks()
        self.client = next_client
        self.prompt_mode = None
        self.status = ShellStatus(
            context=self.status.context,
            mode=mode,
            state=UiState.SYNCED
            if next_client is not None and candidate_ready
            else UiState.DISCONNECTED,
            device="--",
            battery="--",
            time=self.status.time,
            unread=self.status.unread,
            target=self.status.target,
        )
        self.query_one("#native-status", NativeStatusBar).set_status(self.status)
        self.query_one("#active-pane", ActivePane).set_mode(self.status.context)

    def _build_connection_client(self, mode: LinkMode) -> MessagingClient | None:
        if self.connection_factory is None:
            return self.client if self.status.mode == mode else None
        return self.connection_factory(mode)

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
            raw_available = raw_diagnostics_available(payload)
            raw_rx_status = (
                await self.client.get_raw_rx_status()
                if raw_available and self.raw_diagnostics_admin_enabled
                else None
            )
        except Exception as exc:
            self._set_diagnostics_error(str(exc))
            return
        self._set_diagnostics_state(
            DiagnosticsState(
                rows=flatten_diagnostics(payload),
                raw_rx_status=raw_rx_status,
                raw_events=self.diagnostics.raw_events,
                raw_available=raw_available,
                admin_enabled=self.raw_diagnostics_admin_enabled,
                last_raw_action=self.diagnostics.last_raw_action,
            ),
            recover_error=True,
        )

    async def refresh_radio(self) -> None:
        """Refresh duty cycle and TX queue status for the Radio tab.

        Note: In simulator mode, this fetches from the node server's duty
        cycle tracker. In demo mode, shows placeholder data.
        """
        # Demo mode: show placeholder data since no real node is connected
        if self.client is None:
            self._set_radio_state(
                RadioTuiState(
                    duty_cycle_usage_percent=0.0,
                    duty_cycle_remaining_ms=36000,  # 36s = 1% of 1 hour
                    duty_cycle_time_until_refill_ms=0,
                    duty_cycle_limit_percent=1.0,
                    tx_queue_depth_by_priority=(),
                    tx_queue_total_bytes=0,
                    tx_queue_drain_time_ms=0,
                    tx_queue_oldest_age_ms=0,
                ),
                recover_error=True,
            )
            return

        self._set_radio_state(RadioTuiState(loading=True))

        # Fetch radio status from the device if available
        # For now, show demo data - real implementation would query
        # /status/radio or similar endpoint with duty cycle and queue info
        try:
            status = await self.client.get_status()
            radio_info = status.radio or {}

            # Extract duty cycle info from radio status if available
            duty_usage = float(radio_info.get("duty_cycle_usage_pct", 0.0))
            duty_remaining = int(radio_info.get("duty_cycle_remaining_ms", 36000))
            duty_refill = int(radio_info.get("duty_cycle_refill_ms", 0))

            # Extract TX queue info if available
            queue_info = radio_info.get("tx_queue", {})
            depth_by_priority = tuple(
                (int(k), int(v))
                for k, v in sorted(queue_info.get("depth_by_priority", {}).items())
            )
            total_bytes = int(queue_info.get("total_bytes", 0))
            drain_time = int(queue_info.get("drain_time_ms", 0))
            oldest_age = int(queue_info.get("oldest_age_ms", 0))

            self._set_radio_state(
                RadioTuiState(
                    duty_cycle_usage_percent=duty_usage,
                    duty_cycle_remaining_ms=duty_remaining,
                    duty_cycle_time_until_refill_ms=duty_refill,
                    duty_cycle_limit_percent=1.0,
                    tx_queue_depth_by_priority=depth_by_priority,
                    tx_queue_total_bytes=total_bytes,
                    tx_queue_drain_time_ms=drain_time,
                    tx_queue_oldest_age_ms=oldest_age,
                ),
                recover_error=True,
            )
        except Exception as exc:
            self._set_radio_error(str(exc))

    async def refresh_rf_health(self) -> None:
        """Refresh RF health neighbor metrics and local RF stats (5g8t.6).

        Fetches neighbor list with RF health extensions (success rate, observed
        duty cycle, cheater flags) and local RF stats (noise floor, channel
        busy, RX errors).
        """
        # Demo mode: show placeholder data
        if self.client is None:
            self._set_rf_health_state(
                RFHealthState(
                    neighbors=(),
                    local_rf=LocalRFStats(),
                    error="RF transport unavailable (demo mode)",
                ),
                recover_error=True,
            )
            return

        self._set_rf_health_state(RFHealthState(loading=True))

        try:
            # Fetch neighbors with RF health extensions
            neighbors = await self.client.list_neighbors()

            # Fetch status for local RF stats (if available)
            status = await self.client.get_status()
            radio_info = status.radio or {}

            # Extract local RF stats from radio info if available
            rf_info = radio_info.get("rf_health", radio_info.get("local_rf", {}))
            local_rf = LocalRFStats(
                noise_floor_dbm=safe_float(rf_info.get("noise_floor_dbm")),
                channel_busy_pct=safe_float(rf_info.get("channel_busy_pct")),
                rx_crc_errors=safe_int(rf_info.get("rx_crc_errors")),
                rx_timeout_errors=safe_int(rf_info.get("rx_timeout_errors")),
                rx_header_errors=safe_int(rf_info.get("rx_header_errors")),
                rx_total=safe_int(rf_info.get("rx_total")),
            )

            self._set_rf_health_state(
                RFHealthState(
                    neighbors=tuple(neighbors),
                    local_rf=local_rf,
                ),
                recover_error=True,
            )
        except Exception as exc:
            self._set_rf_health_error(str(exc))

    def enable_raw_diagnostics_admin(self, *, enabled: bool = True) -> None:
        """Toggle explicit admin authorization for raw diagnostics UI flows."""
        self.raw_diagnostics_admin_enabled = enabled
        self._set_diagnostics_state(
            DiagnosticsState(
                rows=self.diagnostics.rows,
                raw_rx_status=self.diagnostics.raw_rx_status if enabled else None,
                raw_events=self.diagnostics.raw_events if enabled else (),
                raw_available=self.diagnostics.raw_available,
                admin_enabled=enabled,
                last_raw_action=self.diagnostics.last_raw_action if enabled else None,
            )
        )

    async def arm_raw_rx_diagnostics(
        self,
        *,
        ttl_s: int,
        include_payload: bool = False,
    ) -> None:
        """Arm raw RX diagnostics only after explicit admin enablement."""
        if self.client is None:
            self._set_diagnostics_error("diagnostics transport unavailable")
            return
        if not self.raw_diagnostics_admin_enabled:
            self._set_diagnostics_error("raw diagnostics admin authorization required")
            return
        try:
            result = await self.client.arm_raw_rx(ttl_s=ttl_s, include_payload=include_payload)
            status = await self.client.get_raw_rx_status()
        except Exception as exc:
            self._set_diagnostics_error(str(exc))
            return
        self._set_diagnostics_state(
            DiagnosticsState(
                rows=self.diagnostics.rows,
                raw_rx_status=status,
                raw_events=self.diagnostics.raw_events,
                raw_available=result.state is not RawDiagnosticState.UNSUPPORTED
                and status.state is not RawDiagnosticState.UNSUPPORTED,
                admin_enabled=True,
                last_raw_action=result,
            ),
            recover_error=True,
        )

    async def send_raw_diagnostic_frame(
        self,
        frame: bytes | bytearray | memoryview,
        *,
        wait: bool = True,
    ) -> None:
        """Post one raw diagnostic TX frame only after explicit admin enablement."""
        if self.client is None:
            self._set_diagnostics_error("diagnostics transport unavailable")
            return
        if not self.raw_diagnostics_admin_enabled:
            self._set_diagnostics_error("raw diagnostics admin authorization required")
            return
        try:
            result = await self.client.send_raw_tx(frame, wait=wait)
        except Exception as exc:
            self._set_diagnostics_error(str(exc))
            return
        self._set_diagnostics_state(
            DiagnosticsState(
                rows=self.diagnostics.rows,
                raw_rx_status=self.diagnostics.raw_rx_status,
                raw_events=self.diagnostics.raw_events,
                raw_available=result.state is not RawDiagnosticState.UNSUPPORTED,
                admin_enabled=True,
                last_raw_action=result,
            ),
            recover_error=True,
        )

    async def start_observing_raw_rx(self) -> None:
        """Start raw RX Observe only after explicit admin enablement."""
        if self.client is None:
            self._set_diagnostics_error("diagnostics transport unavailable")
            return
        if not self.raw_diagnostics_admin_enabled:
            self._set_diagnostics_error("raw diagnostics admin authorization required")
            return
        if self._raw_rx_task is not None and not self._raw_rx_task.done():
            return
        self._raw_rx_task = asyncio.create_task(self._raw_rx_loop())

    async def _raw_rx_loop(self) -> None:
        """Apply raw RX Observe notifications until the subscription ends."""
        try:
            if self.client is None:
                self._set_diagnostics_error("diagnostics transport unavailable")
                return
            subscription = await self.client.observe_raw_rx_events()
            try:
                async for event in subscription.events():
                    # Trim raw_events to prevent unbounded memory growth (only last 3 displayed)
                    raw_events = (self.diagnostics.raw_events + (event,))[-10:]
                    self._set_diagnostics_state(
                        DiagnosticsState(
                            rows=self.diagnostics.rows,
                            raw_rx_status=self.diagnostics.raw_rx_status,
                            raw_events=raw_events,
                            raw_available=event.state is not RawDiagnosticState.UNSUPPORTED,
                            admin_enabled=True,
                            last_raw_action=self.diagnostics.last_raw_action,
                        ),
                        recover_error=True,
                    )
            finally:
                with suppress(Exception):
                    await subscription.close()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self._set_diagnostics_error(str(exc))
        finally:
            self._raw_rx_task = None

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
                with suppress(Exception):
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
                with suppress(Exception):
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
            DiagnosticsState(
                rows=self.diagnostics.rows,
                raw_rx_status=self.diagnostics.raw_rx_status,
                raw_events=self.diagnostics.raw_events,
                raw_available=self.diagnostics.raw_available,
                admin_enabled=self.raw_diagnostics_admin_enabled,
                last_raw_action=self.diagnostics.last_raw_action,
                error=detail,
            )
        )

    def _set_radio_state(
        self,
        state: RadioTuiState,
        *,
        recover_error: bool = False,
    ) -> None:
        self.radio_tui = state
        self._set_screen_status(error=state.error, recover_error=recover_error)
        self.query_one("#active-pane", ActivePane).set_radio(state)

    def _set_radio_error(self, detail: str) -> None:
        self._set_radio_state(
            RadioTuiState(
                duty_cycle_usage_percent=self.radio_tui.duty_cycle_usage_percent,
                duty_cycle_remaining_ms=self.radio_tui.duty_cycle_remaining_ms,
                duty_cycle_time_until_refill_ms=self.radio_tui.duty_cycle_time_until_refill_ms,
                duty_cycle_limit_percent=self.radio_tui.duty_cycle_limit_percent,
                tx_queue_depth_by_priority=self.radio_tui.tx_queue_depth_by_priority,
                tx_queue_total_bytes=self.radio_tui.tx_queue_total_bytes,
                tx_queue_drain_time_ms=self.radio_tui.tx_queue_drain_time_ms,
                tx_queue_oldest_age_ms=self.radio_tui.tx_queue_oldest_age_ms,
                error=detail,
            )
        )

    def _set_rf_health_state(
        self,
        state: RFHealthState,
        *,
        recover_error: bool = False,
    ) -> None:
        self.rf_health = state
        self._set_screen_status(error=state.error, recover_error=recover_error)
        self.query_one("#active-pane", ActivePane).set_rf_health(state)

    def _set_rf_health_error(self, detail: str) -> None:
        self._set_rf_health_state(
            RFHealthState(
                neighbors=self.rf_health.neighbors,
                local_rf=self.rf_health.local_rf,
                error=detail,
            )
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


def build_connection_factory(
    *,
    coap_base_uri: str | None = None,
    ble_address: str | None = None,
    ble_local_host: str = "fe80::2",
    ble_node_host: str = "fe80::1",
) -> ConnectionClientFactory:
    """Return a picker factory for Demo, BLE, and IP/CoAP modes."""

    def factory(mode: LinkMode) -> MessagingClient | None:
        if mode is LinkMode.DEMO:
            return None
        if mode is LinkMode.BLE:
            if ble_address is None:
                return None
            return build_messaging_client(
                None,
                ble_address=ble_address,
                ble_local_host=ble_local_host,
                ble_node_host=ble_node_host,
            )
        if mode is LinkMode.IP and coap_base_uri is not None:
            return build_messaging_client(coap_base_uri)
        return None

    return factory


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
    connection_factory = build_connection_factory(
        coap_base_uri=args.coap_base_uri,
        ble_address=args.ble_address,
        ble_local_host=args.ble_local_host,
        ble_node_host=args.ble_node_host,
    )
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
        connection_factory=connection_factory,
        inbox_path=args.inbox_path,
        send_path=args.send_path,
    ).run()
