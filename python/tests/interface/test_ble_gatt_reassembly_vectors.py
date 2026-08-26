# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests for BLE GATT frame reassembly vectors.

Drives ``test/vectors/ble_gatt_reassembly.json`` through the two Python GATT
services:

- KISS-over-BLE (:class:`lichen.interface.kiss.gatt.KissGattService`) --
  stream reassembly of FEND-delimited frames across MTU-bounded writes.
- Meshtastic-compatible GATT
  (:class:`lichen.interface.meshtastic.gatt.MeshtasticGattService`) --
  reassembly of 4-byte length-prefixed messages across chunked writes.

Every byte sequence in the JSON is hand-derived from framing rules (KISS
delimiter/escape semantics, protobuf wire format) and is independent of the
implementation under test. Where a case declares both a ``stream`` and literal
``write`` steps, their concatenation is asserted equal first so a transcription
error in the vector document itself fails loudly before any SUT runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from lichen.interface.kiss import KissHandler
from lichen.interface.kiss.gatt import KissGattService
from lichen.interface.meshtastic.gatt import (
    GattError,
    MeshtasticGattService,
    parse_ble_message,
)
from lichen.interface.meshtastic.proto import FromRadio

VECTORS_DIR = Path(__file__).resolve().parents[3] / "test" / "vectors"
DOCUMENT = json.loads((VECTORS_DIR / "ble_gatt_reassembly.json").read_text())


def _cases(family: str) -> list[tuple[str, dict]]:
    assert DOCUMENT["format_version"] == 2
    return [(v["name"], v) for v in DOCUMENT["vectors"] if v.get("family") == family]


def _expand(spec: str | dict) -> bytes:
    """Expand a hex string or {byte, count} repeat spec into bytes."""
    if isinstance(spec, str):
        return bytes.fromhex(spec)
    return bytes.fromhex(spec["byte"]) * spec["count"]


def _literal_write_bytes(case: dict) -> bytes:
    return b"".join(_expand(step["data"]) for step in case["steps"] if step["op"] == "write")


# ---------------------------------------------------------------------------
# KISS-over-BLE GATT
# ---------------------------------------------------------------------------


def _run_kiss_case(service: KissGattService, case: dict) -> None:
    mtu_default = DOCUMENT["constants"]["kiss_default_mtu"]
    for step in case["steps"]:
        op = step["op"]
        if op == "connect":
            service.on_connect(mtu=step.get("mtu", mtu_default))
        elif op == "disconnect":
            service.on_disconnect()
        elif op == "write":
            service.on_tx_write(_expand(step["data"]))
        elif op == "write_repeat":
            blob = _expand(step["repeat"])
            size = step["chunk_size"]
            for i in range(0, len(blob), size):
                service.on_tx_write(blob[i : i + size])
        elif op == "write_envelope":
            payload = _expand(step["payload_repeat"])
            frame = b"\xc0\x00" + payload + b"\xc0"
            size = step["chunk_size"]
            for i in range(0, len(frame), size):
                service.on_tx_write(frame[i : i + size])
        else:  # pragma: no cover - vector authoring guard
            raise AssertionError(f"unknown step op {op!r} in {case['name']}")


@pytest.mark.parametrize(
    "name,case",
    _cases("kiss_gatt"),
    ids=[name for name, _ in _cases("kiss_gatt")],
)
def test_kiss_gatt_reassembly_vectors(name: str, case: dict) -> None:
    if "stream" in case and any(s["op"] == "write" for s in case["steps"]):
        assert _literal_write_bytes(case) == bytes.fromhex(case["stream"]), name

    # KissHandler dispatches DATA frames to on_tx_frame(port, data); the command
    # nibble is decoded internally, so vectors must stay on command 0 (DATA).
    for frame in case["expected"]["frames"]:
        assert frame["command"] == 0, f"{name}: non-DATA frame needs a config-surface vector"

    handler = KissHandler()
    received: list[tuple[int, bytes]] = []
    handler.on_tx_frame = lambda port, data: received.append((port, data))

    service = KissGattService(handler=handler)
    _run_kiss_case(service, case)

    expected_frames = []
    for frame in case["expected"]["frames"]:
        data = (
            _expand(frame["data_repeat"])
            if "data_repeat" in frame
            else bytes.fromhex(frame["data"])
        )
        expected_frames.append((frame["port"], data))

    assert received == expected_frames


# ---------------------------------------------------------------------------
# Meshtastic-compatible GATT
# ---------------------------------------------------------------------------


def _to_radio_outcome(msg: Any) -> dict | None:
    if msg is None:
        return None
    return {
        "packet": None if msg.packet is None else "present",
        "want_config_id": msg.want_config_id,
        "disconnect": bool(msg.disconnect),
        "heartbeat": msg.heartbeat.hex() if msg.heartbeat is not None else None,
        "xmodem_packet": msg.xmodem_packet.hex() if msg.xmodem_packet is not None else None,
    }


def _meshtastic_step_cases() -> list[tuple[str, dict]]:
    return [(name, case) for name, case in _cases("meshtastic_gatt") if "steps" in case]


@pytest.mark.parametrize(
    "name,case",
    _meshtastic_step_cases(),
    ids=[name for name, _ in _meshtastic_step_cases()],
)
def test_meshtastic_gatt_reassembly_vectors(name: str, case: dict) -> None:
    service = MeshtasticGattService()
    outcomes: list[dict | None] = []

    for step in case["steps"]:
        op = step["op"]
        if op == "connect":
            service.on_connect(mtu=step.get("mtu", service.mtu))
        elif op == "disconnect":
            service.on_disconnect()
        elif op == "write":
            outcomes.append(_to_radio_outcome(service.write_to_radio(_expand(step["data"]))))
        else:  # pragma: no cover - vector authoring guard
            raise AssertionError(f"unknown step op {op!r} in {case['name']}")

    assert outcomes == case["expected"]["outcomes"]


def test_meshtastic_gatt_oversized_outbound_vector() -> None:
    case = next(
        v for v in DOCUMENT["vectors"] if v["name"] == "meshtastic_outbound_oversized_rejected"
    )
    spec = case["message"]["fields"]["node_info_repeat"]
    node_info = _expand(spec)

    # Independent size cross-check of the vector's hand-computed serialization:
    # tag 0x22 (1 B) + varint(len) (2 B) + payload.
    assert len(node_info) == 600
    assert case["message"]["serialized_size"] == 603

    service = MeshtasticGattService()
    service.on_connect()
    with pytest.raises(GattError, match=case["expected"]["error_contains"]):
        service.queue_from_radio(FromRadio(node_info=node_info))
    assert service.pending_count == 0


# ---------------------------------------------------------------------------
# Wire-format helper vectors (parse_ble_message)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,case",
    _cases("meshtastic_wire_helper"),
    ids=[name for name, _ in _cases("meshtastic_wire_helper")],
)
def test_meshtastic_parse_ble_message_vectors(name: str, case: dict) -> None:
    data = bytes.fromhex(case["input"])
    if "payload" in case["expected"]:
        payload, consumed = parse_ble_message(data)
        assert payload == bytes.fromhex(case["expected"]["payload"])
        assert consumed == case["expected"]["consumed"]
    else:
        with pytest.raises(GattError, match=case["expected"]["error_contains"]):
            parse_ble_message(data)
