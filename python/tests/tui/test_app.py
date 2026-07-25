# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for native TUI application (NativeClientApp)."""

from __future__ import annotations

import asyncio

import pytest
from textual.widgets import Input

from lichen.client import (
    CoapResult,
    DeliveryState,
    LciClient,
    RawDiagnosticResult,
    RawDiagnosticState,
    RawRxEvent,
    RawRxStatus,
    SendResult,
)
from lichen.tui.native import (
    ActivePane,
    CommandBar,
    LinkMode,
    ModeNav,
    NativeClientApp,
    NativeStatusBar,
    ShellStatus,
    UiState,
)

from .conftest import (
    FakeMessagingClient,
    FakeResourceTransport,
    message_record,
)


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
        ("fd00::2", "ping", "/msg/inbox")
    ]
    assert client.send_calls[0][0].ack is False
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
        ("fd00::2", "from keyboard", "/msg/inbox")
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
    client = FakeMessagingClient(result=SendResult(state=DeliveryState.REJECTED, coap_code="4.04"))
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


async def test_lci_client_app_connects_and_refreshes_ip_transport() -> None:
    transport = FakeResourceTransport()
    client = LciClient(transport)
    app = NativeClientApp(
        ShellStatus(context="Chats", mode=LinkMode.IP, state=UiState.DISCONNECTED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.refresh_messages()
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert transport.connected is True
    assert transport.closed is True
    assert transport.requests == [("GET", "/msg/inbox")]
    assert "from ip transport" in rendered


async def test_tui_messaging_flow_uses_same_lci_client_interface_for_ble_transport() -> None:
    transport = FakeResourceTransport()
    client = LciClient(transport)
    app = NativeClientApp(
        ShellStatus(context="Chats", mode=LinkMode.BLE, state=UiState.DISCONNECTED),
        client=client,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert transport.connected is True
    assert transport.closed is True
    assert transport.requests == [("GET", "/msg/inbox")]
    assert status.mode == LinkMode.BLE
    assert "from ip transport" in rendered


async def test_connection_picker_selects_ble_client_from_factory() -> None:
    initial = FakeMessagingClient()
    ble_client = FakeMessagingClient(inbox=[message_record("ble inbox")])
    clients = {LinkMode.BLE: ble_client}

    app = NativeClientApp(
        ShellStatus(context="Chats", mode=LinkMode.DEMO, state=UiState.DISCONNECTED),
        client=initial,
        connection_factory=lambda mode: clients.get(mode),
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()
        picker = app.query_one("#active-pane", ActivePane).render_mode()
        await pilot.press("2")
        await pilot.press("r")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert "CONNECTION" in picker
    assert "BLE" in picker
    assert initial.disconnect_calls == 1
    assert ble_client.connect_calls == 1
    assert ble_client.inbox_calls == ["/msg/inbox"]
    assert status.mode == LinkMode.BLE
    assert status.state == UiState.SYNCED
    assert "ble inbox" in rendered


async def test_connection_picker_unavailable_choice_preserves_current_client() -> None:
    current = FakeMessagingClient(inbox=[message_record("current inbox")])
    app = NativeClientApp(
        ShellStatus(context="Dashboard", mode=LinkMode.IP, state=UiState.SYNCED),
        client=current,
        connection_factory=lambda _mode: None,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status
        disconnect_calls = current.disconnect_calls

    assert app.client is current
    assert app.prompt_mode is None
    assert disconnect_calls == 0
    assert status.mode == LinkMode.IP
    assert status.state == UiState.ERROR
    assert "CONNECTION" in rendered
    assert "BLE transport unavailable" in rendered


async def test_connection_picker_failed_connect_preserves_current_client() -> None:
    current = FakeMessagingClient(inbox=[message_record("current inbox")])
    failing_ble = FakeMessagingClient(connect_error=RuntimeError("adapter offline"))
    app = NativeClientApp(
        ShellStatus(context="Dashboard", mode=LinkMode.IP, state=UiState.SYNCED),
        client=current,
        connection_factory=lambda mode: failing_ble if mode is LinkMode.BLE else None,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status
        disconnect_calls = current.disconnect_calls

    assert app.client is current
    assert app.prompt_mode is None
    assert failing_ble.connect_calls == 1
    assert failing_ble.disconnect_calls == 1
    assert disconnect_calls == 0
    assert status.mode == LinkMode.IP
    assert status.state == UiState.ERROR
    assert "CONNECTION" in rendered
    assert "BLE connection failed: adapter offline" in rendered


async def test_connection_picker_failed_connect_ignores_candidate_cleanup_error() -> None:
    current = FakeMessagingClient()
    failing_ble = FakeMessagingClient(
        connect_error=RuntimeError("adapter offline"),
        disconnect_error=RuntimeError("close failed"),
    )
    app = NativeClientApp(
        ShellStatus(context="Dashboard", mode=LinkMode.IP, state=UiState.SYNCED),
        client=current,
        connection_factory=lambda mode: failing_ble if mode is LinkMode.BLE else None,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status
        disconnect_calls = current.disconnect_calls

    assert app.client is current
    assert app.prompt_mode is None
    assert disconnect_calls == 0
    assert failing_ble.connect_calls == 1
    assert failing_ble.disconnect_calls == 1
    assert status.mode == LinkMode.IP
    assert status.state == UiState.ERROR
    assert "BLE connection failed: adapter offline" in rendered


async def test_connection_picker_old_disconnect_failure_cleans_staged_client() -> None:
    current = FakeMessagingClient(
        observe=[[message_record("old observed")]],
        keep_observe_open=True,
        disconnect_error=RuntimeError("old close failed"),
    )
    staged_ble = FakeMessagingClient()
    app = NativeClientApp(
        ShellStatus(context="Chats", mode=LinkMode.IP, state=UiState.SYNCED),
        client=current,
        connection_factory=lambda mode: staged_ble if mode is LinkMode.BLE else None,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("o")
        await pilot.pause()
        assert app._observe_task is not None
        observe_task = app._observe_task
        await pilot.press("l")
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status
        current_disconnect_calls = current.disconnect_calls
        subscription_open = current.subscription is not None and not current.subscription.closed
        observe_task_retained = app._observe_task is observe_task and not observe_task.done()

    assert app.client is current
    assert app.prompt_mode is None
    assert current_disconnect_calls == 1
    assert subscription_open is True
    assert observe_task_retained is True
    assert staged_ble.connect_calls == 1
    assert staged_ble.disconnect_calls == 1
    assert status.mode == LinkMode.IP
    assert status.state == UiState.ERROR
    assert "BLE switch failed: old close failed" in rendered


async def test_connection_picker_cancels_live_observe_before_switching() -> None:
    old_client = FakeMessagingClient(
        observe=[[message_record("old observed")]],
        keep_observe_open=True,
    )
    new_client = FakeMessagingClient(inbox=[message_record("new inbox")])
    app = NativeClientApp(
        ShellStatus(context="Chats", mode=LinkMode.IP, state=UiState.SYNCED),
        client=old_client,
        connection_factory=lambda mode: new_client if mode is LinkMode.BLE else None,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("o")
        await pilot.pause()
        assert app._observe_task is not None
        assert not app._observe_task.done()
        await pilot.press("l")
        await pilot.pause()
        await pilot.press("2")
        await pilot.pause()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert old_client.subscription is not None
    assert old_client.subscription.closed is True
    assert old_client.disconnect_calls == 1
    assert new_client.connect_calls == 1
    assert status.mode == LinkMode.BLE
    assert status.state == UiState.SYNCED


async def test_unmount_disconnects_client_after_task_cleanup_failure() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(
        ShellStatus(context="Dashboard", mode=LinkMode.IP, state=UiState.SYNCED),
        client=client,
    )
    log_cancelled = asyncio.Event()

    async def fail_on_cancel() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            raise RuntimeError("observe cleanup failed")

    async def log_on_cancel() -> None:
        try:
            await asyncio.Event().wait()
        finally:
            log_cancelled.set()

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app._observe_task = asyncio.create_task(fail_on_cancel())
        app._log_task = asyncio.create_task(log_on_cancel())

    assert client.disconnect_calls == 1
    assert app._observe_task is None
    assert app._log_task is None
    assert log_cancelled.is_set()


async def test_connection_picker_selects_demo_and_disconnects_transport() -> None:
    current = FakeMessagingClient()
    app = NativeClientApp(
        ShellStatus(context="Dashboard", mode=LinkMode.IP, state=UiState.SYNCED),
        client=current,
    )

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("l")
        await pilot.pause()
        await pilot.press("1")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()
        status = app.query_one("#native-status", NativeStatusBar).status

    assert current.disconnect_calls == 1
    assert app.client is None
    assert status.mode == LinkMode.DEMO
    assert status.state == UiState.DISCONNECTED
    assert "DASHBOARD" in rendered


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


async def test_rf_health_refresh_renders_neighbors_and_local_stats() -> None:
    """Test RF health tab renders neighbor RF metrics and local stats (5g8t.6)."""
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="RF", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("r")
        await pilot.pause()
        rf_rendered = app.query_one("#active-pane", ActivePane).render_mode()

    # Tab header and sections present
    assert "RF HEALTH" in rf_rendered
    assert "Local RF Stats" in rf_rendered
    assert "Neighbor RF Health" in rf_rendered

    # Neighbor info rendered with RF metrics
    assert "fe80::2" in rf_rendered
    assert "RSSI -80" in rf_rendered
    assert "SNR 7.5" in rf_rendered
    assert "seen 30s" in rf_rendered
    # Note: success_rate and duty_observed are None in fake client

    # Neighbors call made
    assert client.neighbor_calls == 1


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
    assert client.raw_rx_calls == []
    assert "ok" in rendered
    assert "nested.queue" in rendered
    assert "raw.admin" in rendered
    assert "required" in rendered
    assert "private_key" in rendered
    assert "<redacted>" in rendered
    assert "frame" in rendered
    assert "c1020304" not in rendered
    assert "DO_NOT_PRINT" not in rendered
    assert "DO_NOT_PRINT_RAW" not in rendered
    assert "DO_NOT_PRINT_BYTES" not in rendered


async def test_diagnostics_admin_enable_unlocks_raw_status_refresh() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.enable_raw_diagnostics_admin()
        await app.refresh_diagnostics()
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.diagnostics_calls == ["/diag"]
    assert client.raw_rx_calls == ["/diag/raw/rx"]
    assert "raw.admin" in rendered
    assert "enabled" in rendered
    assert "raw.rx.state" in rendered
    assert "raw.rx.enabled" in rendered
    assert "True" in rendered


async def test_raw_diagnostics_flows_require_admin_before_transport_calls() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await app.arm_raw_rx_diagnostics(ttl_s=60, include_payload=True)
        await app.send_raw_diagnostic_frame(b"\xc1\x02")
        await app.start_observing_raw_rx()
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.raw_rx_arm_calls == []
    assert client.raw_tx_calls == []
    assert client.raw_observe_calls == []
    assert "raw diagnostics admin authorization required" in rendered


async def test_raw_diagnostics_admin_flows_arm_observe_and_tx_with_redaction() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.enable_raw_diagnostics_admin()
        await app.arm_raw_rx_diagnostics(ttl_s=60, include_payload=True)
        await app.start_observing_raw_rx()
        await pilot.pause()
        await app.send_raw_diagnostic_frame(b"\xc1\x02\x03\x04", wait=True)
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.raw_rx_arm_calls == [(60, True, True, "/diag/raw/rx")]
    assert client.raw_rx_calls == ["/diag/raw/rx"]
    assert client.raw_observe_calls == ["/diag/raw/rx/events"]
    assert client.raw_subscription.closed is True
    assert client.raw_tx_calls == [(b"\xc1\x02\x03\x04", True, "/diag/raw/tx")]
    assert "raw.action.state" in rendered
    assert "raw.rx.event.0.frame" in rendered
    assert "<redacted>" in rendered
    assert "c1020304" not in rendered


async def test_raw_diagnostics_key_actions_reach_admin_arm_observe_and_tx() -> None:
    client = FakeMessagingClient()
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("a")
        await pilot.pause()
        await pilot.press("u")
        await pilot.press("o")
        await pilot.pause()
        await pilot.press("x")
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.diagnostics_calls == ["/diag"]
    assert client.raw_rx_calls == ["/diag/raw/rx", "/diag/raw/rx"]
    assert client.raw_rx_arm_calls == [(60, False, True, "/diag/raw/rx")]
    assert client.raw_observe_calls == ["/diag/raw/rx/events"]
    assert client.raw_tx_calls == [(b"\xc1\x02\x03\x04", True, "/diag/raw/tx")]
    assert "raw.admin" in rendered
    assert "enabled" in rendered
    assert "raw.action.state" in rendered
    assert "raw.rx.event.0.frame" in rendered
    assert "c1020304" not in rendered


async def test_raw_diagnostics_unsupported_arm_and_tx_mark_resources_unsupported() -> None:
    client = FakeMessagingClient(
        raw_arm_result=RawDiagnosticResult(
            state=RawDiagnosticState.UNSUPPORTED,
            coap_code="5.01",
            detail="raw arm unsupported",
        ),
        raw_tx_result=RawDiagnosticResult(
            state=RawDiagnosticState.UNSUPPORTED,
            coap_code="4.04",
            detail="raw tx unsupported",
        ),
    )
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.enable_raw_diagnostics_admin()
        await app.arm_raw_rx_diagnostics(ttl_s=60)
        arm_rendered = app.query_one("#active-pane", ActivePane).render_mode()
        await app.send_raw_diagnostic_frame(b"\xc1")
        tx_rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert "raw.resources" in arm_rendered
    assert "unsupported" in arm_rendered
    assert "raw arm unsupported" in arm_rendered
    assert "raw.resources" in tx_rendered
    assert "unsupported" in tx_rendered
    assert "raw tx unsupported" in tx_rendered


async def test_raw_diagnostics_unsupported_observe_marks_resources_unsupported() -> None:
    client = FakeMessagingClient(
        raw_events=[
            RawRxEvent(
                state=RawDiagnosticState.UNSUPPORTED,
                coap_code="5.01",
                detail="raw observe unsupported",
            )
        ]
    )
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.enable_raw_diagnostics_admin()
        await app.start_observing_raw_rx()
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.raw_observe_calls == ["/diag/raw/rx/events"]
    assert "raw.resources" in rendered
    assert "unsupported" in rendered
    assert "raw observe unsupported" in rendered


async def test_diagnostics_refresh_skips_raw_status_when_not_advertised() -> None:
    client = FakeMessagingClient(raw_available=False)
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.enable_raw_diagnostics_admin()
        await app.refresh_diagnostics()
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.diagnostics_calls == ["/diag"]
    assert client.raw_rx_calls == []
    assert "raw.resources" in rendered
    assert "unsupported" in rendered
    assert "raw.rx.state" not in rendered


async def test_diagnostics_refresh_renders_raw_unsupported_state() -> None:
    client = FakeMessagingClient(
        raw_rx_status=RawRxStatus(
            state=RawDiagnosticState.UNSUPPORTED,
            coap_code="5.01",
            detail="raw diagnostics unavailable",
        )
    )
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.enable_raw_diagnostics_admin()
        await app.refresh_diagnostics()
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert client.raw_rx_calls == ["/diag/raw/rx"]
    assert "raw.rx.state" in rendered
    assert "unsupported" in rendered
    assert "5.01" in rendered
    assert "raw diagnostics unavailable" in rendered


async def test_diagnostics_refresh_renders_raw_error_state() -> None:
    client = FakeMessagingClient(
        raw_rx_status=RawRxStatus(
            state=RawDiagnosticState.ERROR,
            coap_code="4.01",
            detail="admin required",
        )
    )
    app = NativeClientApp(ShellStatus(context="Diag", state=UiState.SYNCED), client=client)

    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        app.enable_raw_diagnostics_admin()
        await app.refresh_diagnostics()
        await pilot.pause()
        rendered = app.query_one("#active-pane", ActivePane).render_mode()

    assert "raw.rx.state" in rendered
    assert "error" in rendered
    assert "4.01" in rendered
    assert "admin required" in rendered


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

        await pilot.press("6")
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


async def test_native_client_terminal_snapshots_cover_core_screens() -> None:
    client = FakeMessagingClient(inbox=[message_record("snapshot inbox")])
    app = NativeClientApp(
        ShellStatus(context="Dashboard", mode=LinkMode.IP, state=UiState.SYNCED),
        client=client,
    )
    snapshots: dict[str, str] = {}

    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        snapshots["connection"] = app.export_screenshot()

        await pilot.press("l")
        await pilot.pause()
        snapshots["connection_picker"] = app.export_screenshot()
        await pilot.press("escape")
        await pilot.pause()

        await pilot.press("r")
        await pilot.pause()
        snapshots["status"] = app.export_screenshot()

        await pilot.press("2")
        await pilot.press("r")
        await pilot.pause()
        snapshots["inbox"] = app.export_screenshot()

        await pilot.press("c")
        app.query_one("#message-target", Input).value = "fd00::2"
        app.query_one("#message-body", Input).value = "snapshot compose"
        snapshots["compose"] = app.export_screenshot()

        await pilot.press("tab")
        await pilot.press("r")
        await pilot.pause()
        snapshots["nodes"] = app.export_screenshot()

        await pilot.press("4")
        await pilot.pause()
        snapshots["mesh"] = app.export_screenshot()

        await pilot.press("5")
        await pilot.press("r")
        await pilot.pause()
        snapshots["rf_health"] = app.export_screenshot()

        await pilot.press("6")
        await pilot.press("r")
        await pilot.pause()
        snapshots["config"] = app.export_screenshot()

        await pilot.press("7")
        await pilot.press("o")
        await pilot.pause()
        snapshots["logs"] = app.export_screenshot()

        await pilot.press("8")
        await pilot.press("r")
        await pilot.pause()
        snapshots["diagnostics"] = app.export_screenshot()

    assert "IP" in snapshots["connection"]
    assert "SYNCED" in snapshots["connection"]
    assert "CONNECTION" in snapshots["connection_picker"]
    assert "IP/CoAP" in snapshots["connection_picker"]
    assert "node-a" in snapshots["status"]
    assert "snapshot" in snapshots["inbox"]
    assert "inbox" in snapshots["inbox"]
    assert "snapshot" in snapshots["compose"]
    assert "compose" in snapshots["compose"]
    assert "fe80::2" in snapshots["nodes"]
    assert "fd00::/64" in snapshots["mesh"]
    # RF tab shows local RF stats and neighbors
    assert "local_rf" in snapshots["rf_health"] or "RF" in snapshots["rf_health"]
    assert "sync_word" in snapshots["config"]
    assert "timeout" in snapshots["logs"]
    assert "nested.queue" in snapshots["diagnostics"]
    assert "DO_NOT_PRINT" not in "".join(snapshots.values())
