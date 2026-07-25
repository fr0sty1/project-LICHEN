# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for native TUI widget classes."""

from __future__ import annotations

from lichen.tui.native import (
    ActivePane,
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
    NativeStatusBar,
    ShellStatus,
    UiState,
    status_line,
)


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
