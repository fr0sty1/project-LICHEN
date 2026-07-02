# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PINNED_PORTNUMS = ROOT / "rust" / "lichen-meshtastic" / "proto" / "meshtastic" / "portnums.proto"
ZEPHYR_ADAPTER_TEST = ROOT / "lichen" / "tests" / "meshtastic_adapter" / "src" / "main.c"
ZEPHYR_ADAPTER = ROOT / "lichen" / "subsys" / "lichen" / "meshtastic" / "adapter.c"
TEXT_MESSAGE_APP_PORTNUM = 1
ADMIN_APP_PORTNUM = 6


def _parse_proto_portnums() -> dict[str, int]:
    text = PINNED_PORTNUMS.read_text(encoding="utf-8")
    return {
        name: int(value)
        for name, value in re.findall(r"^\s*([A-Z0-9_]+)\s*=\s*(\d+);", text, re.MULTILINE)
    }


def _parse_zephyr_unsupported_portnums() -> set[int]:
    text = ZEPHYR_ADAPTER_TEST.read_text(encoding="utf-8")
    match = re.search(
        r"static const uint32_t unsupported_portnums\[\]\s*=\s*\{(?P<body>.*?)\};",
        text,
        re.DOTALL,
    )
    assert match is not None
    return {int(value) for value in re.findall(r"\b(\d+)U\b", match.group("body"))}


def _parse_adapter_portnum_defines() -> dict[str, int]:
    text = ZEPHYR_ADAPTER.read_text(encoding="utf-8")
    return {
        name: int(value)
        for name, value in re.findall(
            r"^\s*#define\s+MESHTASTIC_PORTNUM_([A-Z0-9_]+)\s+(\d+)U",
            text,
            re.MULTILINE,
        )
    }


def _parse_adapter_catalog_portnums() -> set[int]:
    text = ZEPHYR_ADAPTER.read_text(encoding="utf-8")
    match = re.search(
        r"unsupported_operations\[\]\s*=\s*\{(?P<body>.*?)\n\};",
        text,
        re.DOTALL,
    )
    assert match is not None
    defines = _parse_adapter_portnum_defines()
    names = re.findall(r"\.portnum\s*=\s*MESHTASTIC_PORTNUM_([A-Z0-9_]+)", match.group("body"))
    return {defines[name] for name in names}


def test_zephyr_unsupported_portnums_match_pinned_meshtastic_proto() -> None:
    portnums = _parse_proto_portnums()
    catalog_expected = {value for value in portnums.values() if value != TEXT_MESSAGE_APP_PORTNUM}
    runtime_unsupported_expected = catalog_expected - {ADMIN_APP_PORTNUM}

    assert portnums["TEXT_MESSAGE_APP"] == TEXT_MESSAGE_APP_PORTNUM
    assert portnums["ADMIN_APP"] == ADMIN_APP_PORTNUM
    assert _parse_zephyr_unsupported_portnums() == runtime_unsupported_expected
    assert _parse_adapter_catalog_portnums() == catalog_expected
