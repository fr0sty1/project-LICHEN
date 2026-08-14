# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""CBOR validation and decoding utilities for CoAP resources."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import cbor2

# Conservative mutation limits keep hostile CBOR work bounded for LoRa/CoAP
# nodes while remaining well above every currently defined endpoint payload.
_CBOR_MAX_ENCODED_BYTES = 4096
_CBOR_MAX_DEPTH = 16
_CBOR_MAX_MAP_ENTRIES = 64
_CBOR_MAX_ARRAY_ENTRIES = 256
_CBOR_MAX_ITEMS = 1024


@dataclass
class _CborScanBudget:
    items: int = 0


def _cbor_argument(payload: bytes, offset: int, additional: int) -> tuple[int, int]:
    if additional < 24:
        return additional, offset
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    width = widths.get(additional)
    if width is None or offset + width > len(payload):
        raise ValueError("invalid or truncated CBOR argument")
    return int.from_bytes(payload[offset : offset + width], "big"), offset + width


def _same_cbor_key(left: object, right: object, left_raw: bytes, right_raw: bytes) -> bool:
    if left_raw == right_raw:
        return True
    if type(left) is not type(right):
        return False
    try:
        return bool(left == right)
    except Exception:
        return False


def _scan_cbor_item(
    payload: bytes,
    offset: int,
    *,
    depth: int = 0,
    budget: _CborScanBudget | None = None,
) -> int:
    """Return the end of one RFC 8949 item while rejecting duplicate map keys."""
    if depth > _CBOR_MAX_DEPTH:
        raise ValueError("CBOR nesting depth exceeds mutation limit")
    if budget is None:
        budget = _CborScanBudget()
    budget.items += 1
    if budget.items > _CBOR_MAX_ITEMS:
        raise ValueError("CBOR item count exceeds mutation limit")
    if offset >= len(payload):
        raise ValueError("truncated CBOR item")
    initial = payload[offset]
    if initial == 0xFF:
        raise ValueError("unexpected CBOR break")
    offset += 1
    major = initial >> 5
    additional = initial & 0x1F
    indefinite = additional == 31

    if major in (0, 1, 7):
        if indefinite:
            raise ValueError("invalid indefinite scalar")
        _argument, offset = _cbor_argument(payload, offset, additional)
        return offset

    if major in (2, 3):
        if not indefinite:
            length, offset = _cbor_argument(payload, offset, additional)
            end = offset + length
            if end > len(payload):
                raise ValueError("truncated CBOR string")
            return end
        while True:
            if offset >= len(payload):
                raise ValueError("unterminated indefinite CBOR string")
            if payload[offset] == 0xFF:
                return offset + 1
            chunk = payload[offset]
            if chunk >> 5 != major or chunk & 0x1F == 31:
                raise ValueError("invalid indefinite CBOR string chunk")
            offset = _scan_cbor_item(
                payload, offset, depth=depth + 1, budget=budget
            )

    if major == 4:
        if indefinite:
            count = 0
            while True:
                if offset >= len(payload):
                    raise ValueError("unterminated indefinite CBOR array")
                if payload[offset] == 0xFF:
                    return offset + 1
                count += 1
                if count > _CBOR_MAX_ARRAY_ENTRIES:
                    raise ValueError("CBOR array exceeds mutation limit")
                offset = _scan_cbor_item(
                    payload, offset, depth=depth + 1, budget=budget
                )
        length, offset = _cbor_argument(payload, offset, additional)
        if length > _CBOR_MAX_ARRAY_ENTRIES:
            raise ValueError("CBOR array exceeds mutation limit")
        for _ in range(length):
            offset = _scan_cbor_item(
                payload, offset, depth=depth + 1, budget=budget
            )
        return offset

    if major == 5:
        map_length: int | None = None
        if not indefinite:
            map_length, offset = _cbor_argument(payload, offset, additional)
            if map_length > _CBOR_MAX_MAP_ENTRIES:
                raise ValueError("CBOR map exceeds mutation limit")
        keys: list[tuple[object, bytes]] = []
        count = 0
        while map_length is None or count < map_length:
            if offset >= len(payload):
                raise ValueError("unterminated CBOR map")
            if map_length is None and payload[offset] == 0xFF:
                return offset + 1
            count += 1
            if count > _CBOR_MAX_MAP_ENTRIES:
                raise ValueError("CBOR map exceeds mutation limit")
            key_start = offset
            offset = _scan_cbor_item(
                payload, offset, depth=depth + 1, budget=budget
            )
            key_raw = payload[key_start:offset]
            try:
                key = cbor2.loads(key_raw)
            except OverflowError as exc:
                raise ValueError("CBOR map key outside representable range") from exc
            if any(_same_cbor_key(key, old, key_raw, old_raw) for old, old_raw in keys):
                raise ValueError("duplicate CBOR map key")
            keys.append((key, key_raw))
            offset = _scan_cbor_item(
                payload, offset, depth=depth + 1, budget=budget
            )
        return offset

    if major == 6:
        # Mutation schemas contain no tagged values. Reject tags before cbor2
        # can materialize shared/cyclic objects (RFC 8746 tags 28 and 29) or
        # schema-external Python semantic types.
        raise ValueError("CBOR tags are not allowed in mutation payloads")

    raise ValueError("invalid CBOR major type")


def _decode_single_cbor(payload: bytes) -> Any:
    """Decode one RFC 8949 item, rejecting trailing items and duplicate keys."""
    if len(payload) > _CBOR_MAX_ENCODED_BYTES:
        raise ValueError("CBOR payload exceeds mutation byte limit")
    end = _scan_cbor_item(payload, 0)
    if end != len(payload):
        raise ValueError("trailing data after CBOR item")
    try:
        return cbor2.loads(payload)
    except OverflowError as exc:
        raise ValueError("CBOR payload contains integer outside representable range") from exc
