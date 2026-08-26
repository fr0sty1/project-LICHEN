# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Spec 07 UDP port table. Literals below are copied from spec/07-transport-app.md."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test" / "vectors"

# spec/07-transport-app.md section 9.1 / 10 (independent of lichen.constants).
SPEC_PORTS: dict[int, str] = {
    5681: "compact_cot",
    5682: "senml",
    5683: "coap",
    5684: "reserved_dtls",
    5685: "cayenne_lpp",
    5686: "aprs_is",
    5687: "nmea",
    10883: "mqtt_sn",
}


def _load(name: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads((VECTORS / name).read_text(encoding="utf-8")))


def test_port_dispatch_vectors_match_spec_table() -> None:
    document = _load("port_dispatch.json")
    seen: set[str] = set()
    for case in document["vectors"]:
        port = case["port"]
        app = case["app"]
        if app == "unknown":
            assert port not in SPEC_PORTS
        else:
            assert SPEC_PORTS[port] == app, case["name"]
            seen.add(app)
    assert seen == set(SPEC_PORTS.values())
