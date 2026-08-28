# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Native LICHEN client TUI application."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import ClassVar

from textual import events
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container
from textual.css.query import NoMatches
from textual.widgets import Input

from lichen.client import (
    DeliveryState,
    LocalRFStats,
    MessageDraft,
    MessageRecord,
    RawDiagnosticState,
    SendResult,
)

from .formatting import (
    NODE_CONFIG_FIELDS,
    RADIO_CONFIG_FIELDS,
    flatten_diagnostics,
    log_rows_from_payload,
    outbound_record,
    parse_config_value,
    raw_diagnostics_available,
    safe_float,
    safe_int,
)
from .models import (
    ConfigState,
    ConnectionClientFactory,
    DashboardState,
    DiagnosticsState,
    LinkMode,
    LogsState,
    MeshState,
    MessagingClient,
    MessagingState,
    RadioTuiState,
    RFHealthState,
    ShellStatus,
    UiState,
)
from .widgets import (
    ActivePane,
    CommandBar,
    ModeNav,
    NativeStatusBar,
)


def _battery_text(pct: int | None, mv: int | None) -> str:
    parts = []
    if pct is not None:
        parts.append(f"{pct}%")
    if mv is not None:
        parts.append(f"{mv}mV")
    return " ".join(parts) or "--"


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
        self._connection_lock = asyncio.Lock()
        self._observe_task: asyncio.Task[None] | None = None
        self._log_task: asyncio.Task[None] | None = None
        self._raw_rx_task: asyncio.Task[None] | None = None
        self.raw_diagnostics_admin_enabled = False
        self.mode_index = (
            ModeNav.MODES.index(self.status.context) if self.status.context in ModeNav.MODES else 0
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
        async with self._connection_lock:
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
            self.client = next_client
            await self._cancel_live_tasks()
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

            duty_usage = safe_float(radio_info.get("duty_cycle_usage_pct")) or 0.0
            duty_remaining = safe_int(radio_info.get("duty_cycle_remaining_ms"), 36000)
            duty_refill = safe_int(radio_info.get("duty_cycle_refill_ms"))

            queue_info = radio_info.get("tx_queue", {})
            depth_by_priority = tuple(
                (safe_int(k) or 0, safe_int(v) or 0)
                for k, v in sorted(queue_info.get("depth_by_priority", {}).items())
            )
            total_bytes = safe_int(queue_info.get("total_bytes"))
            drain_time = safe_int(queue_info.get("drain_time_ms"))
            oldest_age = safe_int(queue_info.get("oldest_age_ms"))

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
            rf_raw = radio_info.get("rf_health", radio_info.get("local_rf", {}))
            rf_info = rf_raw if isinstance(rf_raw, dict) else {}
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


# Import types for type hints
from lichen.client import ConfigSnapshot, DeviceStatus  # noqa: E402
