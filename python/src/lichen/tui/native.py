# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI shell and shared widgets."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import AsyncIterator, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar, Protocol

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.css.query import NoMatches
from textual.widgets import Input, Static

from lichen.client import (
    AiocoapResourceTransport,
    DeliveryState,
    IpCoapConfig,
    LciClient,
    MessageDraft,
    MessageRecord,
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

    async def send_message(self, draft: MessageDraft, path: str = "/msg") -> SendResult:
        """Send a normalized message draft."""


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
    ) -> None:
        self.mode = mode
        self.line_width = width
        self.messaging = messaging or MessagingState()
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
                return MessagingPanel(self.messaging, width=self.line_width).render()
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
        send_path: str = "/msg",
    ) -> None:
        super().__init__()
        self.status = status or ShellStatus()
        self.client = client
        self.inbox_path = inbox_path
        self.send_path = send_path
        self.messaging = MessagingState()
        self._observe_task: asyncio.Task[None] | None = None
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
            yield ActivePane(self.status.context, messaging=self.messaging)
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
        """Refresh placeholder action for keyboard-only operation."""
        if self.status.context == "Chats":
            await self.refresh_messages()
            return
        pane = self.query_one("#active-pane", ActivePane)
        pane.update(f"{pane.render_mode()}\nrefresh requested")

    async def action_open(self) -> None:
        """Show an open placeholder for keyboard-only row activation."""
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
        target = self.query_one("#message-target", Input)
        self.query_one("#message-body", Input).disabled = False
        target.disabled = False
        target.focus()

    async def action_observe_messages(self) -> None:
        """Apply one inbox Observe notification through the shared client model."""
        if self.status.context != "Chats":
            self._set_mode(ModeNav.MODES.index("Chats"))
        await self.start_observing_messages()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Advance chat compose fields and send from the body field."""
        if event.input.id == "message-target":
            self.query_one("#message-body", Input).focus()
            return
        if event.input.id == "message-body":
            self._sync_compose_from_inputs()
            await self.send_draft()

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

    def _resize_widgets(self) -> None:
        width = max(24, self.size.width)
        self.query_one("#native-status", NativeStatusBar).set_width(width)
        self.query_one("#mode-nav", ModeNav).set_width(width)
        self.query_one("#active-pane", ActivePane).set_width(max(20, width - 2))


def build_messaging_client(base_uri: str | None) -> MessagingClient | None:
    """Build an IP/CoAP-backed messaging client when a base URI is supplied."""
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
    parser.add_argument("--inbox-path", default="/msg/inbox")
    parser.add_argument("--send-path", default="/msg")
    args = parser.parse_args(argv)
    client = build_messaging_client(args.coap_base_uri)
    status = ShellStatus(
        mode=LinkMode.IP if client is not None else LinkMode.DEMO,
        state=UiState.SYNCED if client is not None else UiState.DISCONNECTED,
    )
    NativeClientApp(
        status,
        client=client,
        inbox_path=args.inbox_path,
        send_path=args.send_path,
    ).run()
