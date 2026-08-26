# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Conformance tests for the fixed-width LICHEN SCHC Rule ID profile."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lichen.schc.codec import SchcError
from lichen.schc.context import NoMatchingRuleError, SchcContext
from lichen.schc.headers import decode_rule255, decompress_packet
from lichen.schc.rules import Rule

VECTORS_DIR = Path(__file__).parents[3] / "test" / "vectors"


def _vectors(name: str) -> list[dict[str, object]]:
    document = json.loads((VECTORS_DIR / name).read_text())
    vectors = document["vectors"]
    assert isinstance(vectors, list)
    return vectors


def test_shared_compression_vectors_use_one_octet_rule_ids() -> None:
    """Every Version 3 packet starts with its complete Rule ID octet."""
    seen: set[int] = set()
    for vector in _vectors("schc_compression.json"):
        if "compressed" not in vector or "rule_id" not in vector:
            continue
        compressed = bytes.fromhex(str(vector["compressed"]))
        rule_id = vector["rule_id"]
        assert type(rule_id) is int
        assert compressed[:1] == bytes((rule_id,)), vector["name"]
        seen.add(rule_id)

    assert seen == set(range(8)) | {255}


def test_shared_adaptation_vectors_use_one_octet_control_and_fallback_ids() -> None:
    seen: set[int] = set()
    for vector in _vectors("schc_adaptation.json"):
        category = vector.get("category")
        wire_hex = vector.get("wire")
        rule_id = vector.get("rule_id")
        if category == "uncompressed":
            wire_hex = vector["compressed"]
            rule_id = 255
        if not isinstance(wire_hex, str) or not wire_hex or not isinstance(rule_id, int):
            continue
        wire = bytes.fromhex(wire_hex)
        assert wire[:1] == bytes((rule_id,)), vector["name"]
        seen.add(rule_id)

    assert {0x78, 0x79, 0xFF} <= seen


@pytest.mark.parametrize("legacy_prefix", [b"\x80\x00", b"\x81\x00", b"\xfe\x7f"])
def test_legacy_variable_length_prefixes_are_rejected(legacy_prefix: bytes) -> None:
    """High-bit prefixes are reserved octets, never varint continuation bytes."""
    with pytest.raises(NoMatchingRuleError, match=rf"unknown rule ID {legacy_prefix[0]}"):
        SchcContext().decompress(legacy_prefix)
    with pytest.raises(ValueError, match=rf"no profile for rule ID {legacy_prefix[0]}"):
        decompress_packet(legacy_prefix)


@pytest.mark.parametrize("rule_id", range(0x80, 0xFF))
def test_reserved_rule_ids_cannot_be_constructed_as_compression_rules(rule_id: int) -> None:
    with pytest.raises(ValueError, match="rule_id must be 0-127 or 255"):
        Rule(rule_id, ())


def test_empty_input_is_a_truncated_rule_id() -> None:
    with pytest.raises(NoMatchingRuleError, match="empty SCHC packet"):
        SchcContext().decompress(b"")
    with pytest.raises(ValueError, match="empty SCHC packet"):
        decompress_packet(b"")


def test_rule255_is_a_literal_octet_followed_by_a_complete_ipv6_packet() -> None:
    vector = next(
        item for item in _vectors("schc_adaptation.json") if item["name"] == "rule255_minimal_ipv6"
    )
    compressed = bytes.fromhex(str(vector["compressed"]))
    packet = bytes.fromhex(str(vector["packet"]))

    assert compressed == b"\xff" + packet
    assert decode_rule255(compressed) == packet
    with pytest.raises(SchcError, match="IPv6 packet length"):
        decode_rule255(b"\xff")
    with pytest.raises(SchcError, match="IPv6 packet length"):
        decode_rule255(b"\xff\x00")
