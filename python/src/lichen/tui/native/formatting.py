# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI formatting functions."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from lichen.client import (
    MessageDraft,
    MessageRecord,
    SendResult,
)

from .models import (
    ConfigRow,
    ConfigState,
    DashboardState,
    DiagnosticRow,
    DiagnosticsState,
    LogRow,
    MeshState,
    MessagePreview,
    RadioTuiState,
    RFHealthState,
    ShellStatus,
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
    ts = record.received or record.timestamp
    if isinstance(ts, datetime):
        age = ts.strftime("%H:%M")
    elif isinstance(ts, int | float):
        age = datetime.fromtimestamp(ts).strftime("%H:%M")
    elif isinstance(ts, str):
        try:
            age = datetime.fromisoformat(ts).strftime("%H:%M")
        except (ValueError, TypeError):
            age = ts
    else:
        age = "--"
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


def safe_int(value: object | None, default: int = 0) -> int:
    """Safely convert to int, returning default on parse failure."""
    if value is None:
        return default
    try:
        return int(float(value))
    except (ValueError, TypeError, OverflowError):
        return default


def _is_sensitive_display_name(name: str) -> bool:
    lowered = name.lower()
    leaf = lowered.rsplit(".", maxsplit=1)[-1]
    if leaf == "frame":
        return True
    return any(part in lowered for part in SENSITIVE_FIELD_PARTS) and "fingerprint" not in lowered


def _battery_text(pct: int | None, mv: int | None) -> str:
    parts = []
    if pct is not None:
        parts.append(f"{pct}%")
    if mv is not None:
        parts.append(f"{mv}mV")
    return " ".join(parts) or "--"


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
        rows.append(DiagnosticRow("raw.admin", "enabled" if state.admin_enabled else "required"))
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
