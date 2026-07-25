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
        # app
        NativeClientApp,
        # client
        build_connection_factory,
        build_messaging_client,
        main,
        # formatting
        clip,
        field_line,
        message_line,
        status_line,
        # models
        ConfigRow,
        DiagnosticRow,
        LinkMode,
        LogRow,
        MessagePreview,
        MessagingState,
        ShellStatus,
        UiState,
        # widgets
        ActivePane,
        CommandBar,
        ConfigTable,
        DiagnosticsPanel,
        LogPanel,
        MessageList,
        MessagingPanel,
        ModeNav,
        NativeStatusBar,
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

    # Verify widget classes exist
    assert NativeClientApp
    assert NativeStatusBar
    assert CommandBar
    assert ModeNav
    assert ActivePane
    assert MessageList
    assert MessagingPanel
    assert ConfigTable
    assert LogPanel
    assert DiagnosticsPanel
