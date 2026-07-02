# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for native TUI shell widgets."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping

import pytest
from textual.widgets import Input

from lichen.client import (
    Capabilities,
    CoapResult,
    ConfigSnapshot,
    DeliveryState,
    DeviceStatus,
    Identity,
    LciClient,
    MessageDraft,
    MessageRecord,
    Neighbor,
    RadioConfig,
    Route,
    SendResult,
)
from lichen.tui.native import (
    ActivePane,
    CommandBar,
    ConfigRow,
    ConfigTable,
    DiagnosticRow,
    DiagnosticsPanel,
    LinkMode,
    LogPanel,
    LogRow,
    MessageList,
    MessagePreview,
    MessagingPanel,
    MessagingState,
    ModeNav,
    NativeClientApp,
    NativeStatusBar,
    ShellStatus,
    UiState,
    build_messaging_client,
    clip,
    field_line,
    main,
    message_line,
    status_line,
)


class FakeMessageSubscription:
    def __init__(self, snapshots: list[list[MessageRecord]]) -> None:
        self.snapshots = snapshots
        self.closed = False

    def messages(self) -> AsyncIterator[list[MessageRecord]]:
        return self._messages()

    async def close(self) -> None:
        self.closed = True

    async def _messages(self) -> AsyncIterator[list[MessageRecord]]:
        for snapshot in self.snapshots:
            yield snapshot


class FakeMessagingClient:
    def __init__(
        self,
        *,
        inbox: list[MessageRecord] | None = None,
        observe: list[list[MessageRecord]] | None = None,
        result: SendResult | None = None,
        inbox_error: Exception | None = None,
        observe_error: Exception | None = None,
        send_error: Exception | None = None,
        status_error: Exception | None = None,
        config_write_result: CoapResult | None = None,
    ) -> None:
        self.inbox_rows = inbox or []
        self.observe_rows = observe or []
        self.result = result or SendResult(state=DeliveryState.ACCEPTED, coap_code="2.04")
        self.inbox_error = inbox_error
        self.observe_error = observe_error
        self.send_error = send_error
        self.status_error = status_error
        self.config_write_result = config_write_result or CoapResult(code="2.04")
        self.inbox_calls: list[str] = []
        self.observe_calls: list[str] = []
        self.send_calls: list[tuple[MessageDraft, str]] = []
        self.status_calls = 0
        self.config_calls = 0
        self.radio_calls = 0
        self.identity_calls = 0
        self.discover_calls = 0
        self.neighbor_calls = 0
        self.route_calls = 0
        self.config_writes: list[dict[str, object]] = []
        self.radio_writes: list[dict[str, object]] = []
        self.log_calls: list[str] = []
        self.diagnostics_calls: list[str] = []
        self.subscription: FakeMessageSubscription | None = None
        self.log_subscription = FakeResourceSubscription(
            [
                CoapResult(
                    code="2.05",
                    payload={
                        "records": [
                            {"level": "warn", "module": "coap", "message": "timeout"}
                        ]
                    },
                )
            ]
        )

    async def inbox(self, path: str = "/msg/inbox") -> list[MessageRecord]:
        self.inbox_calls.append(path)
        if self.inbox_error is not None:
            raise self.inbox_error
        return self.inbox_rows

    async def observe_inbox(self, path: str = "/msg/inbox") -> FakeMessageSubscription:
        self.observe_calls.append(path)
        if self.observe_error is not None:
            raise self.observe_error
        self.subscription = FakeMessageSubscription(self.observe_rows)
        return self.subscription

    async def send_message(self, draft: MessageDraft, path: str = "/msg") -> SendResult:
        self.send_calls.append((draft, path))
        if self.send_error is not None:
            raise self.send_error
        return self.result

    async def discover(self) -> Capabilities:
        self.discover_calls += 1
        if self.status_error is not None:
            raise self.status_error
        return Capabilities(
            resources=frozenset({"/status", "/config", "/logs"}),
            observable=frozenset({"/logs"}),
        )

    async def get_status(self) -> DeviceStatus:
        self.status_calls += 1
        if self.status_error is not None:
            raise self.status_error
        return DeviceStatus(
            raw={},
            uptime_s=42,
            battery_pct=87,
            battery_mv=3950,
            mem_free_kb=128,
            dodag={"joined": True},
            radio={"rx_packets": 3, "tx_packets": 2},
        )

    async def get_config(self) -> ConfigSnapshot:
        self.config_calls += 1
        return ConfigSnapshot(raw={}, name="node-a", role="router", radio_path="/config/radio")

    async def get_radio_config(self) -> RadioConfig:
        self.radio_calls += 1
        return RadioConfig(
            raw={},
            freq_mhz=906.875,
            bw_khz=125,
            sf=10,
            cr="4/5",
            tx_power_dbm=17,
            sync_word="0x34",
        )

    async def get_identity(self) -> Identity:
        self.identity_calls += 1
        return Identity(
            raw={"private_key": "DO_NOT_PRINT"},
            eui64="0x0011223344556677",
            pubkey="PUBLIC_KEY_SHOULD_NOT_RENDER",
            pubkey_fingerprint="SHA256:abc",
            addrs={"link_local": "fe80::1"},
        )

    async def list_neighbors(self) -> list[Neighbor]:
        self.neighbor_calls += 1
        return [
            Neighbor(
                raw={},
                addr="fe80::2",
                rssi_dbm=-80,
                snr_db=7.5,
                etx=1.2,
                trust="tofu",
                last_seen_s=30,
            )
        ]

    async def list_routes(self) -> list[Route]:
        self.route_calls += 1
        return [Route(raw={}, prefix="fd00::/64", via="fe80::2", metric=512, lifetime_s=1800)]

    async def set_config(self, values: Mapping[str, object]) -> CoapResult:
        self.config_writes.append(dict(values))
        return self.config_write_result

    async def set_radio_config(self, values: Mapping[str, object]) -> CoapResult:
        self.radio_writes.append(dict(values))
        return self.config_write_result

    async def subscribe_logs(self, path: str = "/logs") -> FakeResourceSubscription:
        self.log_calls.append(path)
        return self.log_subscription

    async def get_diagnostics(self, path: str = "/diag") -> object:
        self.diagnostics_calls.append(path)
        return {
            "ok": True,
            "nested": {"queue": 3},
            "private_key": "DO_NOT_PRINT",
            "raw_payload": "DO_NOT_PRINT_RAW",
            "blob": b"DO_NOT_PRINT_BYTES",
            "tokens": ["DO_NOT_PRINT"],
        }


class FakeResourceTransport:
    def __init__(self) -> None:
        self.connected = False
        self.closed = False
        self.requests: list[tuple[str, str]] = []

    async def connect(self) -> None:
        self.connected = True

    async def close(self) -> None:
        self.closed = True

    async def request(
        self,
        method: str,
        path: str,
        *,
        payload: bytes = b"",
        content_format: int | None = None,
        observe: bool = False,
    ) -> CoapResult:
        self.requests.append((method, path))
        return CoapResult(
            code="2.05",
            payload=[
                {
                    "from": "fd00::1",
                    "to": "fd00::2",
                    "body": "from ip transport",
                    "received": "2026-07-02T04:00:00Z",
                }
            ],
        )

    async def observe(self, path: str, *, method: str = "GET") -> FakeResourceSubscription:
        return FakeResourceSubscription()


class FakeResourceSubscription:
    def __init__(self, results: list[CoapResult] | None = None) -> None:
        self._result_rows = results or [
            CoapResult(
                code="2.05",
                payload=[
                    {
                        "from": "fd00::1",
                        "to": "fd00::2",
                        "body": "observed from transport",
                        "received": "2026-07-02T04:00:00Z",
                    }
                ],
            )
        ]
        self.closed = False

    def results(self) -> AsyncIterator[CoapResult]:
        return self._results()

    async def close(self) -> None:
        self.closed = True

    async def _results(self) -> AsyncIterator[CoapResult]:
        for result in self._result_rows:
            yield result


def message_record(
    body: str,
    *,
    sender: str | None = "fd00::1",
    recipient: str | None = "fd00::2",
    received: str = "2026-07-02T04:00:00Z",
) -> MessageRecord:
    return MessageRecord(
        raw={"from": sender, "to": recipient, "body": body, "received": received},
        sender=sender,
        recipient=recipient,
        body=body,
        received=received,
    )


def test_clip_uses_stable_ascii_ellipsis() -> None:
    assert clip("abcdef", 4) == "a..."
    assert clip("abcdef", 2) == "ab"


def test_status_line_contains_text_indicators() -> None:
    line = status_line(
        ShellStatus(
            context="Chats",
            mode=LinkMode.BLE,
            state=UiState.SYNCED,
            device="node-a",
            battery="87%",
            time="fix",
            unread=3,
            target="fd00::2",
        ),
        width=120,
    )

    assert "BLE SYNCED" in line
    assert "BAT 87%" in line
    assert "TIME fix" in line
    assert "UNREAD 3" in line


def test_message_and_field_rows_are_bounded() -> None:
    message = message_line(
        MessagePreview("fd00::2", "hello from the mesh", age="1m", state="sent", unread=True),
        width=42,
    )
    field = field_line("freq_mhz", "915.0", "pending", width=42)

    assert len(message) <= 42
    assert message.startswith("* fd00::2")
    assert len(field) <= 42
    assert "freq_mhz" in field
    assert "[pending]" in field


def test_core_widgets_record_expected_terminal_text() -> None:
    status = NativeStatusBar(ShellStatus(mode=LinkMode.IP, state=UiState.DEGRADED))
    messages = MessageList((MessagePreview("broadcast", "ready", state="observed"),))
    config = ConfigTable((ConfigRow("name", "lichen-01", "changed"),))
    logs = LogPanel((LogRow("warn", "coap", "timeout"),))
    diag = DiagnosticsPanel((DiagnosticRow("transport", "ip/coap"),))

    assert "IP DEGRADED" in status_line(status.status)
    assert "broadcast" in messages.render_rows()
    assert "lichen-01" in config.render_rows()
    assert "timeout" in logs.render_rows()
    assert "ip/coap" in diag.render_rows()


def test_messaging_panel_renders_empty_inbox_and_compose_state() -> None:
    panel = MessagingPanel(
        MessagingState(draft_target="fd00::2", draft_body="status?"),
        width=80,
    )
    rendered = panel.render()

    assert "0 message(s)" in rendered
    assert "No messages yet" in rendered
    assert "COMPOSE  target fd00::2  body status?" in rendered


def test_active_pane_covers_expected_modes() -> None:
    pane = ActivePane()

    pane.set_mode("Dashboard")
    assert "DASHBOARD" in pane.render_mode()
    assert "unsupported" in pane.render_mode()

    pane.set_mode("Chats")
    assert "COMPOSE" in pane.render_mode()

    pane.set_mode("Nodes")
    assert "empty" in pane.render_mode()

    pane.set_mode("Mesh")
    assert "destination" in pane.render_mode()

    pane.set_mode("Config")
    assert "sync_word" in pane.render_mode()

    pane.set_mode("Logs")
    assert "log stream inactive" in pane.render_mode()

    pane.set_mode("Diag")
    assert "capabilities" in pane.render_mode()

    pane.set_mode("Help")
    assert "Shift+Tab or [ previous" in pane.render_mode()

    pane.set_mode("Quit")
    assert "Press y to quit" in pane.render_mode()


async def test_message_refresh_renders_inbound_messages() -> None:
    client = FakeMessagingClient(inbox=[message_record("hello from mesh")])
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        pane = app.query_one("#active-pane", ActivePane)
        status = app.query_one("#native-status", NativeStatusBar).status

    assert client.inbox_calls == ["/msg/inbox"]
    assert "hello from mesh" in pane.render_mode()
    assert "* fd00::1" in pane.render_mode()
    assert status.unread == 1


async def test_message_send_success_updates_chat_and_status() -> None:
    client = FakeMessagingClient(
        result=SendResult(
            state=DeliveryState.ACCEPTED,
            coap_code="2.04",
            location_path=("msg", "42"),
        )
    )
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.set_compose("fd00::2", "ping")
        await pilot.press("enter")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert [(call[0].to, call[0].body, call[1]) for call in client.send_calls] == [
        ("fd00::2", "ping", "/msg")
    ]
    assert "ping" in rendered
    assert "delivery" in rendered
    assert "accepted [2.04]" in rendered
    assert app.messaging.draft_body == ""
    assert status.target == "fd00::2"
    assert status.unread == 0


async def test_message_send_from_compose_inputs() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("c")
        app.query_one("#message-target", Input).value = "fd00::2"
        body = app.query_one("#message-body", Input)
        body.value = "from keyboard"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()

    assert [(call[0].to, call[0].body, call[1]) for call in client.send_calls] == [
        ("fd00::2", "from keyboard", "/msg")
    ]
    assert app.messaging.draft_body == ""


async def test_message_send_failure_marks_failed_and_preserves_draft() -> None:
    client = FakeMessagingClient(
        result=SendResult(
            state=DeliveryState.REJECTED,
            coap_code="4.00",
            detail="bad target",
        )
    )
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.set_compose("fd00::bad", "ping")
        await pilot.press("enter")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert len(client.send_calls) == 1
    assert "delivery" in rendered
    assert "rejected [bad target]" in rendered
    assert "error" in rendered
    assert "bad target [recoverable]" in rendered
    assert app.messaging.draft_body == "ping"
    assert status.state == UiState.ERROR


async def test_message_rejection_without_detail_is_error_and_recovery_clears_status() -> None:
    client = FakeMessagingClient(
        result=SendResult(state=DeliveryState.REJECTED, coap_code="4.04")
    )
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.set_compose("fd00::bad", "ping")
        await pilot.press("enter")
        await pilot.pause()
        rejected_render = app.query_one("#active-pane", ActivePane).render_mode()
        rejected_status = app.query_one("#native-status", NativeStatusBar).status

        client.result = SendResult(state=DeliveryState.ACCEPTED, coap_code="2.04")
        app.set_compose("fd00::2", "ping")
        edited_status = app.query_one("#native-status", NativeStatusBar).status
        await pilot.press("enter")
        await pilot.pause()
        recovered_status = app.query_one("#native-status", NativeStatusBar).status

    assert "rejected [4.04]" in rejected_render
    assert "4.04 [recoverable]" in rejected_render
    assert rejected_status.state == UiState.ERROR
    assert edited_status.state == UiState.ERROR
    assert recovered_status.state == UiState.SYNCED


async def test_message_send_transport_exception_is_recoverable() -> None:
    client = FakeMessagingClient(send_error=RuntimeError("link down"))
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.set_compose("fd00::2", "ping")
        await pilot.press("enter")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert len(client.send_calls) == 1
    assert "transport_error [link down]" in rendered
    assert status.state == UiState.ERROR


async def test_empty_message_does_not_send() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.set_compose("fd00::2", "   ")
        await pilot.press("enter")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.send_calls == []
    assert "message body is required" in rendered


async def test_apply_inbound_message_increments_unread_without_transport() -> None:
    app = NativeClientApp(ShellStatus(context="Chats", state=UiState.SYNCED))

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.apply_inbound_messages((message_record("observed update"),))
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert "observed update" in rendered
    assert "* fd00::1" in rendered
    assert status.unread == 1


async def test_refresh_preserves_live_compose_input_values() -> None:
    client = FakeMessagingClient(inbox=[message_record("hello")])
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("c")
        app.query_one("#message-target", Input).value = "fd00::draft"
        app.query_one("#message-body", Input).value = "unsent body"
        await app.refresh_messages()
        await pilot.pause()
        target_value = app.query_one("#message-target", Input).value
        body_value = app.query_one("#message-body", Input).value

    assert app.messaging.draft_target == "fd00::draft"
    assert app.messaging.draft_body == "unsent body"
    assert target_value == "fd00::draft"
    assert body_value == "unsent body"


async def test_observe_messages_applies_live_notifications_and_closes_subscription() -> None:
    client = FakeMessagingClient(
        observe=[
            [message_record("first observed")],
            [message_record("second observed", sender="fd00::3")],
        ]
    )
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("o")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert client.observe_calls == ["/msg/inbox"]
    assert client.subscription is not None
    assert client.subscription.closed is True
    assert "second observed" in rendered
    assert "fd00::3" in rendered
    assert status.unread == 1


async def test_observe_preserves_live_compose_input_values() -> None:
    client = FakeMessagingClient(observe=[[message_record("observed")]])
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("c")
        app.query_one("#message-target", Input).value = "fd00::draft"
        app.query_one("#message-body", Input).value = "unsent body"
        await app.start_observing_messages()
        await pilot.pause()

    assert app.messaging.draft_target == "fd00::draft"
    assert app.messaging.draft_body == "unsent body"


async def test_open_selects_current_message_contact_for_compose() -> None:
    client = FakeMessagingClient(inbox=[message_record("reply target")])
    app = NativeClientApp(
        ShellStatus(context="Chats", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        target_value = app.query_one("#message-target", Input).value

    assert app.messaging.draft_target == "fd00::1"
    assert target_value == "fd00::1"


def test_build_messaging_client_uses_ip_coap_when_uri_is_supplied() -> None:
    assert build_messaging_client(None) is None
    assert build_messaging_client("coap://[fe80::1]") is not None


async def test_lci_client_app_connects_and_refreshes_ip_transport() -> None:
    transport = FakeResourceTransport()
    client = LciClient(transport)
    app = NativeClientApp(
        ShellStatus(context="Chats", mode=LinkMode.IP, state=UiState.DISCONNECTED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert transport.connected is True
    assert transport.closed is True
    assert transport.requests == [("GET", "/msg/inbox")]
    assert "from ip transport" in rendered


async def test_status_refresh_populates_dashboard_and_status_bar() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(
        ShellStatus(context="Dashboard", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert client.status_calls == 1
    assert client.config_calls == 1
    assert client.identity_calls == 1
    assert client.discover_calls == 1
    assert "node-a" in rendered
    assert "87% 3950mV" in rendered
    assert "uptime_s" in rendered
    assert "128" in rendered
    assert "resources" in rendered
    assert "SHA256:abc" in rendered
    assert "PUBLIC_KEY_SHOULD_NOT_RENDER" not in rendered
    assert status.device == "node-a"
    assert status.battery == "87%"


async def test_mesh_refresh_renders_neighbors_and_routes() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Mesh", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        mesh_rendered = app.query_one("#active-pane", ActivePane).render_mode()
        await pilot.press("3")
        await pilot.pause()
        node_rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.neighbor_calls == 1
    assert client.route_calls == 1
    assert "fd00::/64" in mesh_rendered
    assert "via fe80::2" in mesh_rendered
    assert "metric 512" in mesh_rendered
    assert "fe80::2" in node_rendered
    assert "rssi -80" in node_rendered
    assert "snr 7.5" in node_rendered
    assert "etx 1.2" in node_rendered
    assert "trust tofu" in node_rendered


async def test_config_refresh_renders_safe_rows_and_redacts_key_material() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Config", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert "node-a" in rendered
    assert "router" in rendered
    assert "906.875" in rendered
    assert "sf" in rendered
    assert "0x34" in rendered
    assert "SHA256:abc" in rendered
    assert "PUBLIC_KEY_SHOULD_NOT_RENDER" not in rendered
    assert "DO_NOT_PRINT" not in rendered


async def test_config_write_requires_confirmation() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Config", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.refresh_config()
        await pilot.press("/")
        app.query_one("#message-target", Input).value = "name"
        body = app.query_one("#message-body", Input)
        body.value = "new-name"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        confirming = app.query_one("#active-pane", ActivePane).render_mode()
        await pilot.press("escape")
        await pilot.pause()
        await pilot.press("/")
        app.query_one("#message-target", Input).value = "name"
        body = app.query_one("#message-body", Input)
        body.value = "new-name"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.press("y")
        await pilot.pause()
        written = app.query_one("#active-pane", ActivePane).render_mode()

    assert "pending" in confirming
    assert client.config_writes == [{"name": "new-name"}]
    assert client.radio_writes == []
    assert "last_write" in written
    assert "name -> 2.04" in written


async def test_unsupported_config_write_is_actionable_error() -> None:
    client = FakeMessagingClient(config_write_result=CoapResult(code="4.05"))
    app = NativeClientApp(ShellStatus(context="Config", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.refresh_config()
        await pilot.press("/")
        app.query_one("#message-target", Input).value = "sf"
        body = app.query_one("#message-body", Input)
        body.value = "10"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.press("y")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert client.radio_writes == [{"sf": 10}]
    assert "/config/radio" in rendered
    assert "unsupported or rejected" in rendered
    assert status.state == UiState.ERROR


async def test_invalid_config_numeric_input_is_recoverable_error() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Config", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.refresh_config()
        await pilot.press("/")
        app.query_one("#message-target", Input).value = "sf"
        body = app.query_one("#message-body", Input)
        body.value = "bad"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert client.radio_writes == []
    assert "invalid sf" in rendered
    assert status.state == UiState.ERROR


async def test_read_only_config_field_is_not_written() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Config", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.refresh_config()
        await pilot.press("/")
        app.query_one("#message-target", Input).value = "private_key"
        body = app.query_one("#message-body", Input)
        body.value = "DO_NOT_WRITE"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert client.config_writes == []
    assert client.radio_writes == []
    assert "private_key is read-only or unsupported" in rendered
    assert "DO_NOT_WRITE" not in rendered
    assert status.state == UiState.ERROR


async def test_rejected_config_edit_clears_prior_pending_write() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Config", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.refresh_config()
        app.stage_config_change("name", "new-name")
        await pilot.press("/")
        app.query_one("#message-target", Input).value = "private_key"
        body = app.query_one("#message-body", Input)
        body.value = "DO_NOT_WRITE"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.press("y")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.config_writes == []
    assert client.radio_writes == []
    assert "private_key is read-only or unsupported" in rendered
    assert "pending" not in rendered


async def test_config_editor_values_do_not_leak_into_chat_compose() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Config", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.refresh_config()
        await pilot.press("/")
        app.query_one("#message-target", Input).value = "name"
        body = app.query_one("#message-body", Input)
        body.value = "new-name"
        body.focus()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("2")
        await pilot.press("r")
        await pilot.pause()
        await pilot.press("c")
        await pilot.pause()
        target_value = app.query_one("#message-target", Input).value
        body_value = app.query_one("#message-body", Input).value

    assert app.messaging.draft_target == ""
    assert app.messaging.draft_body == ""
    assert target_value == ""
    assert body_value == ""


async def test_logs_observe_applies_notifications_and_closes_subscription() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Logs", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("o")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.log_calls == ["/logs"]
    assert client.log_subscription.closed is True
    assert "warn" in rendered
    assert "coap" in rendered
    assert "timeout" in rendered


async def test_diagnostics_refresh_flattens_and_redacts_payloads() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.diagnostics_calls == ["/diag"]
    assert "ok" in rendered
    assert "nested.queue" in rendered
    assert "private_key" in rendered
    assert "<redacted>" in rendered
    assert "DO_NOT_PRINT" not in rendered
    assert "DO_NOT_PRINT_RAW" not in rendered
    assert "DO_NOT_PRINT_BYTES" not in rendered


async def test_non_chat_refresh_error_recovers_on_success() -> None:
    client = FakeMessagingClient(status_error=RuntimeError("status down"))
    app = NativeClientApp(
        ShellStatus(context="Dashboard", state=UiState.SYNCED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        failed = app.query_one("#active-pane", ActivePane).render_mode()
        failed_status = app.query_one("#native-status", NativeStatusBar).status
        client.status_error = None
        await pilot.press("r")
        await pilot.pause()
        recovered = app.query_one("#active-pane", ActivePane).render_mode()
        recovered_status = app.query_one("#native-status", NativeStatusBar).status

    assert "status down" in failed
    assert failed_status.state == UiState.ERROR
    assert "node-a" in recovered
    assert recovered_status.state == UiState.SYNCED


def test_main_wires_ip_coap_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, NativeClientApp] = {}

    def fake_run(self: NativeClientApp) -> None:
        captured["app"] = self

    monkeypatch.setattr(NativeClientApp, "run", fake_run)

    main(
        [
            "--coap-base-uri",
            "coap://[fe80::1]",
            "--inbox-path",
            "/custom/inbox",
            "--send-path",
            "/custom/send",
        ]
    )

    app = captured["app"]
    assert app.client is not None
    assert app.inbox_path == "/custom/inbox"
    assert app.send_path == "/custom/send"
    assert app.status.mode == LinkMode.IP


async def test_native_client_app_renders_at_common_size() -> None:
    app = NativeClientApp(ShellStatus(state=UiState.SYNCED, mode=LinkMode.IP, device="node-a"))

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.device == "node-a"
        assert "DASHBOARD" in app.query_one("#active-pane", ActivePane).render_mode()
        assert "Tab tabs" in app.query_one("#command-bar", CommandBar).render_commands()
        assert "1-7 jump" in app.query_one("#command-bar", CommandBar).render_commands()
        assert "[Dashboard]" in app.query_one("#mode-nav", ModeNav).render_modes()
        dashboard_svg = app.export_screenshot()

        await pilot.press("tab")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Chats"
        assert "CHATS" in app.query_one("#active-pane", ActivePane).render_mode()
        assert "[Chats]" in app.query_one("#mode-nav", ModeNav).render_modes()

        await pilot.press("shift+tab")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Dashboard"

        await pilot.press("5")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Config"
        assert "sync_word" in app.query_one("#active-pane", ActivePane).render_mode()
        config_svg = app.export_screenshot()

        await pilot.press("]")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Logs"

        await pilot.press("[")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Config"

        await pilot.press("enter")
        await pilot.pause()
        assert "OPEN" in app.query_one("#active-pane", ActivePane).render_mode()

        await pilot.press("escape")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Config"
        assert "CONFIG" in app.query_one("#active-pane", ActivePane).render_mode()

        await pilot.press("/")
        await pilot.pause()
        assert app.prompt_mode == "ConfigEdit"

        await pilot.press("escape")
        await pilot.pause()
        assert "CONFIG" in app.query_one("#active-pane", ActivePane).render_mode()

        await pilot.press("q")
        await pilot.pause()
        assert "QUIT?" in app.query_one("#active-pane", ActivePane).render_mode()

        await pilot.press("escape")
        await pilot.pause()
        assert "CONFIG" in app.query_one("#active-pane", ActivePane).render_mode()

        await pilot.press("1")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Dashboard"

        await pilot.press("ctrl+l")
        await pilot.pause()
        assert app.query_one("#native-status", NativeStatusBar).status.context == "Dashboard"

        await pilot.press("?")
        await pilot.pause()
        assert "HELP" in app.query_one("#active-pane", ActivePane).render_mode()

        help_svg = app.export_screenshot()
        await pilot.resize_terminal(100, 30)
        await pilot.pause()
        assert app.size.width == 100
        await pilot.resize_terminal(60, 20)
        await pilot.pause()
        assert app.size.width == 60
        assert app.query_one("#native-status", NativeStatusBar).line_width == 60
        assert app.query_one("#active-pane", ActivePane).line_width == 58
        assert all(
            len(line) <= 58
            for line in app.query_one("#active-pane", ActivePane).render_mode().splitlines()
        )

    assert "node-a" in dashboard_svg
    assert "[Dashboard]" in dashboard_svg
    assert "[read-only]" in config_svg
    assert "Tab" in help_svg
    assert "tabs" in help_svg
