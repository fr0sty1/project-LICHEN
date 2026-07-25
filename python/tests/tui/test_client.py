# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for native TUI client factories and entry point."""

from __future__ import annotations

import pytest

from lichen.tui.native import (
    LinkMode,
    NativeClientApp,
    build_messaging_client,
    main,
)


def test_build_messaging_client_uses_ip_coap_when_uri_is_supplied() -> None:
    assert build_messaging_client(None) is None
    assert build_messaging_client("coap://[fe80::1]") is not None
    assert build_messaging_client(None, ble_address="AA:BB") is not None


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
    assert app.connection_factory is not None
    assert app.connection_factory(LinkMode.IP) is not None
    assert app.inbox_path == "/custom/inbox"
    assert app.send_path == "/custom/send"
    assert app.status.mode == LinkMode.IP


def test_main_wires_ble_packet_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, NativeClientApp] = {}

    def fake_run(self: NativeClientApp) -> None:
        captured["app"] = self

    monkeypatch.setattr(NativeClientApp, "run", fake_run)

    main(
        [
            "--ble-address",
            "AA:BB",
            "--ble-local-host",
            "fe80::22",
            "--ble-node-host",
            "fe80::11",
        ]
    )

    app = captured["app"]
    assert app.client is not None
    assert app.connection_factory is not None
    assert app.connection_factory(LinkMode.BLE) is not None
    assert app.status.mode == LinkMode.BLE
