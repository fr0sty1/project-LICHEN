# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Packaging metadata checks for Python developer entry points."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from lichen.tui import native

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def pyproject() -> dict[str, object]:
    with (PROJECT_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _requirements(values: object) -> dict[str, Requirement]:
    assert isinstance(values, list)
    requirements = [Requirement(value) for value in values]
    return {requirement.name: requirement for requirement in requirements}


def _assert_specifier(requirement: Requirement, expected: str) -> None:
    assert str(requirement.specifier) == expected


def test_console_scripts_include_native_client_entry_points() -> None:
    project = pyproject()["project"]
    assert isinstance(project, dict)
    scripts = project["scripts"]
    assert isinstance(scripts, dict)

    assert scripts["lichen-tui"] == "lichen.tui.app:main"
    assert scripts["lichen-native-tui"] == "lichen.tui.native:main"
    assert scripts["lichen-native-client"] == "lichen.tui.native:main"
    assert scripts["lichen-dashboard"] == "lichen.dashboard.app:main"


def test_native_client_dependency_extras_are_declared() -> None:
    project = pyproject()["project"]
    assert isinstance(project, dict)
    optional = project["optional-dependencies"]
    assert isinstance(optional, dict)

    assert "ble" in optional
    assert "coap" in optional
    assert "native-client" in optional
    assert "bleak>=0.21" in optional["ble"]

    coap = _requirements(optional["coap"])
    native_client = _requirements(optional["native-client"])
    _assert_specifier(coap["aiocoap"], "==0.4.17")
    _assert_specifier(native_client["aiocoap"], "==0.4.17")
    _assert_specifier(native_client["cbor2"], "<6.2,>=6.1.2")
    _assert_specifier(native_client["textual"], "<8.3,>=8.2.7")
    _assert_specifier(native_client["rich"], "<15.1,>=15.0.0")


def test_runtime_dependency_ranges_are_bounded_to_tested_majors() -> None:
    project = pyproject()["project"]
    assert isinstance(project, dict)
    requirements = _requirements(project["dependencies"])

    expected = {
        "aiocoap": "==0.4.17",
        "anyio": "<4.15,>=4.14.1",
        "starlette": "<1.4,>=1.3.1",
        "uvicorn": "<0.50,>=0.49",
        "textual": "<8.3,>=8.2.7",
        "rich": "<15.1,>=15.0.0",
        "cbor2": "<6.2,>=6.1.2",
    }
    for name, specifier in expected.items():
        _assert_specifier(requirements[name], specifier)


def test_dev_dependency_ranges_are_bounded_to_tested_majors() -> None:
    project = pyproject()["project"]
    assert isinstance(project, dict)
    optional = project["optional-dependencies"]
    assert isinstance(optional, dict)
    dev = _requirements(optional["dev"])

    expected = {
        "pytest": "<10,>=9.1",
        "pytest-asyncio": "<2,>=1.4",
        "pytest-timeout": "<3,>=2.4",
        "httpx": "<0.29,>=0.28",
        "jsonschema": "<5,>=4.26",
        "ruff": "<0.16,>=0.15",
        "mypy": "<3,>=2.1",
    }
    for name, specifier in expected.items():
        _assert_specifier(dev[name], specifier)


def test_lock_metadata_matches_key_pyproject_ranges() -> None:
    project = pyproject()["project"]
    assert isinstance(project, dict)
    lock = tomllib.loads((PROJECT_ROOT / "uv.lock").read_text(encoding="utf-8"))
    package = next(pkg for pkg in lock["package"] if pkg["name"] == "lichen")
    locked = _requirements([
        item["name"] + item.get("specifier", "")
        for item in package["metadata"]["requires-dist"]
        if "marker" not in item
    ])
    pyproject_requirements = _requirements(project["dependencies"])

    for name in ("aiocoap", "starlette", "textual", "rich", "uvicorn", "cbor2"):
        assert str(locked[name].specifier) == str(pyproject_requirements[name].specifier)


def test_native_client_help_smoke(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        native.main(["--help"])

    assert exc_info.value.code == 0
    assert "Run the LICHEN native LCI TUI" in capsys.readouterr().out
