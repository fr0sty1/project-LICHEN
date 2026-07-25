# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for native TUI formatting functions."""

from __future__ import annotations

from lichen.tui.native import (
    LinkMode,
    MessagePreview,
    ShellStatus,
    UiState,
    clip,
    field_line,
    message_line,
    status_line,
)


def test_clip_uses_stable_ascii_ellipsis() -> None:
    assert clip("abcdef", 4) == "a..."
    assert clip("abcdef", 3) == "..."
    assert clip("abcdef", 2) == ".."
    assert clip("abcdef", 1) == "."
    assert clip("abcdef", 0) == ""
    assert clip("ab", 5) == "ab"


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
