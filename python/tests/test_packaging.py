# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Packaging metadata checks for Python developer entry points."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from lichen.tui import native

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def pyproject() -> dict[str, object]:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def test_console_scripts_include_native_client_entry_points() -> None:
    project = pyproject()["project"]
    assert isinstance(project, dict)
    scripts = project["scripts"]
    assert isinstance(scripts, dict)

    assert scripts["lichen-tui"] == "lichen.tui.app:main"
    assert scripts["lichen-native-tui"] == "lichen.tui.native:main"
    assert scripts["lichen-native-client"] == "lichen.tui.native:main"


def test_native_client_dependency_extras_are_declared() -> None:
    project = pyproject()["project"]
    assert isinstance(project, dict)
    optional = project["optional-dependencies"]
    assert isinstance(optional, dict)

    assert "ble" in optional
    assert "coap" in optional
    assert "native-client" in optional
    assert "bleak>=0.21" in optional["ble"]
    assert "aiocoap>=0.4.7" in optional["coap"]
    assert "textual>=0.80.0" in optional["native-client"]


def test_native_client_help_smoke(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        native.main(["--help"])

    assert exc_info.value.code == 0
    assert "Run the LICHEN native LCI TUI" in capsys.readouterr().out
