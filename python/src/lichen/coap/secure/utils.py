# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Endpoint helpers for OSCORE context stores."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..transport import parse_channel_endpoint
from .types import PeerContext


def validate_endpoint_key(endpoint: str) -> str:
    """Validate and canonicalize a DatagramChannel endpoint key."""
    if not endpoint:
        raise ValueError("endpoint key must not be empty")
    if len(endpoint) > 4096:
        raise ValueError("endpoint key is too long")
    if any(ord(character) < 32 or ord(character) == 127 for character in endpoint):
        raise ValueError("endpoint key must not contain control characters")
    try:
        endpoint.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("endpoint key must be valid UTF-8") from error
    return parse_channel_endpoint(endpoint).authority


def normalize_host(host: str) -> str:
    """Compatibility alias for canonical endpoint handling."""
    return validate_endpoint_key(host)


def _encode_nonnegative_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("integer must be non-negative")
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


@dataclass
class _HostRecord:
    peer_pubkey: bytes
    context: PeerContext | None = None
    generation: int = 0


def _host_records_semantically_equal(left: _HostRecord, right: _HostRecord) -> bool:
    if left.peer_pubkey != right.peer_pubkey or left.generation != right.generation:
        return False
    if left.context is None or right.context is None:
        return left.context is right.context
    return (
        left.context.peer_pubkey == right.context.peer_pubkey
        and left.context.generation == right.context.generation
        and left.context.oscore.export_parameters()
        == right.context.oscore.export_parameters()
        and left.context.oscore.sender_sequence_number
        == right.context.oscore.sender_sequence_number
        and left.context.oscore.export_replay_window()
        == right.context.oscore.export_replay_window()
    )


def _sqlite_host_values_semantically_equal(
    left: tuple[Any, ...], right: tuple[Any, ...]
) -> bool:
    """Compare persisted host rows by reconstructed security meaning."""
    if len(left) != 12 or len(right) != 12:
        return False
    blob_indexes = {0, 1, 2, 3, 4, 8, 9, 10}
    if len(left) != len(right):
        return False
    for index, (left_value, right_value) in enumerate(zip(left, right, strict=True)):
        if index == 5:
            if left_value is None or right_value is None:
                if left_value is not right_value:
                    return False
            elif json.loads(str(left_value)) != json.loads(str(right_value)):
                return False
        elif index in blob_indexes:
            if left_value is None or right_value is None:
                if left_value is not right_value:
                    return False
            elif bytes(left_value) != bytes(right_value):
                return False
        elif left_value != right_value:
            return False
    return True
