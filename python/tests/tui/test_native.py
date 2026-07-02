# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for native TUI shell widgets."""

from __future__ import annotations

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
    ModeNav,
    NativeClientApp,
    NativeStatusBar,
    ShellStatus,
    UiState,
    clip,
    field_line,
    message_line,
    status_line,
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


def test_active_pane_covers_expected_modes() -> None:
    pane = ActivePane()

    pane.set_mode("Dashboard")
    assert "DASHBOARD" in pane.render_mode()
    assert "neighbors 0 routes 0" in pane.render_mode()

    pane.set_mode("Chats")
    assert "COMPOSE" in pane.render_mode()

    pane.set_mode("Nodes")
    assert "last_heard" in pane.render_mode()

    pane.set_mode("Mesh")
    assert "next_hop" in pane.render_mode()

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
        assert "FILTER" in app.query_one("#active-pane", ActivePane).render_mode()

        await pilot.press("n")
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
