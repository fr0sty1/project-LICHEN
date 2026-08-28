# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Integration tests for native TUI module public API.

Component tests are split into:
- test_formatting.py - formatting functions (clip, status_line, message_line, etc.)
- test_widgets.py - widget classes (NativeStatusBar, MessagingPanel, ActivePane, etc.)
- test_app.py - NativeClientApp and its behavior
- test_client.py - client factories and main entry point
"""

from __future__ import annotations


def test_native_module_exports_public_api() -> None:
    """Verify the native module re-exports its public API correctly."""
    from lichen.tui.native import (
        # widgets
        ActivePane,
        CommandBar,
        # models
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
        ModeNav,
        # app
        NativeClientApp,
        NativeStatusBar,
        ShellStatus,
        UiState,
        # client
        build_connection_factory,
        build_messaging_client,
        # formatting
        clip,
        field_line,
        main,
        message_line,
        status_line,
    )

    # Verify key exports are callable/instantiable
    assert callable(clip)
    assert callable(status_line)
    assert callable(message_line)
    assert callable(field_line)
    assert callable(build_messaging_client)
    assert callable(build_connection_factory)
    assert callable(main)

    # Verify enums have expected members
    assert LinkMode.IP
    assert LinkMode.BLE
    assert LinkMode.DEMO
    assert UiState.SYNCED
    assert UiState.ERROR
    assert UiState.DISCONNECTED

    # Verify dataclasses/namedtuples are instantiable
    status = ShellStatus()
    assert status.context == "Dashboard"
    assert status.state == UiState.DISCONNECTED

    preview = MessagePreview("target", "body")
    assert preview.target == "target"

    row = ConfigRow("name", "value", "status")
    assert row.name == "name"

    log = LogRow("info", "module", "message")
    assert log.level == "info"

    diag = DiagnosticRow("name", "value")
    assert diag.name == "name"

    # Verify widget classes exist and are classes
    assert isinstance(NativeClientApp, type)
    assert isinstance(NativeStatusBar, type)
    assert isinstance(CommandBar, type)
    assert isinstance(ModeNav, type)
    assert isinstance(ActivePane, type)
    assert isinstance(MessageList, type)
    assert isinstance(MessagingPanel, type)
    assert isinstance(ConfigTable, type)
    assert isinstance(LogPanel, type)
    assert isinstance(DiagnosticsPanel, type)
