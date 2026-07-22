# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SCHC rule context and selection (RFC 8724 section 7)."""

from __future__ import annotations

import pytest

from lichen.schc.context import NoMatchingRuleError, SchcContext, rule_matches
from lichen.schc.rules import (
    CDA,
    MO,
    FieldDescriptor,
    Rule,
)

# A small two-rule context with disjoint EQUAL matches for deterministic tests.
RULE_A = Rule(
    rule_id=10,
    fields=(
        FieldDescriptor("F.kind", 8, MO.EQUAL, CDA.NOT_SENT, target_value=1),
        FieldDescriptor("F.val", 8, MO.IGNORE, CDA.VALUE_SENT),
    ),
)
RULE_B = Rule(
    rule_id=11,
    fields=(
        FieldDescriptor("F.kind", 8, MO.EQUAL, CDA.NOT_SENT, target_value=2),
        FieldDescriptor("F.val", 8, MO.IGNORE, CDA.VALUE_SENT),
    ),
)


def _ctx() -> SchcContext:
    return SchcContext({RULE_A.rule_id: RULE_A, RULE_B.rule_id: RULE_B})


def test_rule_matches_equal_and_ignore() -> None:
    assert rule_matches(RULE_A, {"F.kind": 1, "F.val": 99}) is True
    assert rule_matches(RULE_A, {"F.kind": 2, "F.val": 99}) is False  # EQUAL fails


def test_rule_matches_requires_value_sent_field() -> None:
    # F.val is value-sent: it must be present to compress.
    assert rule_matches(RULE_A, {"F.kind": 1}) is False


def test_rule_matches_msb() -> None:
    rule = Rule(
        rule_id=12,
        fields=(
            FieldDescriptor("P", 16, MO.MSB, CDA.LSB, target_value=5683, mo_arg=12),
        ),
    )
    assert rule_matches(rule, {"P": 5683}) is True
    assert rule_matches(rule, {"P": 5680}) is True  # same top 12 bits
    assert rule_matches(rule, {"P": 1234}) is False


def test_select_rule_picks_matching() -> None:
    ctx = _ctx()
    assert ctx.select_rule({"F.kind": 1, "F.val": 7}).rule_id == 10
    assert ctx.select_rule({"F.kind": 2, "F.val": 7}).rule_id == 11
    assert ctx.select_rule({"F.kind": 9, "F.val": 7}) is None


def test_select_rule_is_deterministic_by_ascending_id() -> None:
    # Two rules both match (ignore-only); the lower ID wins.
    r_lo = Rule(5, (FieldDescriptor("X", 8, MO.IGNORE, CDA.VALUE_SENT),))
    r_hi = Rule(6, (FieldDescriptor("X", 8, MO.IGNORE, CDA.VALUE_SENT),))
    ctx = SchcContext({6: r_hi, 5: r_lo})
    assert ctx.select_rule({"X": 1}).rule_id == 5


def test_compress_decompress_round_trip_via_context() -> None:
    ctx = _ctx()
    packet = ctx.compress({"F.kind": 2, "F.val": 200})
    assert packet[0] == 11  # selected RULE_B
    rule_id, fields = ctx.decompress(packet)
    assert rule_id == 11
    assert fields["F.kind"] == 2  # reconstructed from target value (not-sent)
    assert fields["F.val"] == 200


def test_compress_raises_when_no_rule_matches() -> None:
    with pytest.raises(NoMatchingRuleError):
        _ctx().compress({"F.kind": 99, "F.val": 1})


def test_decompress_unknown_rule_id() -> None:
    with pytest.raises(NoMatchingRuleError):
        _ctx().decompress(bytes([200]))


def test_default_context_has_registry_rules() -> None:
    ctx = SchcContext()
    assert len(ctx) >= 3
    # The ICMPv6 Echo header building block (id 66) is present and selectable
    # for an ICMPv6-only field set (rule 2 is the whole-packet variant).
    assert ctx.get(66) is not None
    fields = {
        "ICMPv6.type": 128,
        "ICMPv6.code": 0,
        "ICMPv6.checksum": 0,
        "ICMPv6.identifier": 0xABCD,
        "ICMPv6.sequence": 7,
    }
    rule = ctx.select_rule(fields)
    assert rule is not None and rule.rule_id == 66


def test_icmpv6_echo_round_trip() -> None:
    ctx = SchcContext()
    fields = {
        "ICMPv6.type": 129,
        "ICMPv6.code": 0,
        "ICMPv6.checksum": 0x1234,
        "ICMPv6.identifier": 0xBEEF,
        "ICMPv6.sequence": 42,
    }
    packet = ctx.compress(fields)
    assert packet[0] == 66
    assert len(packet) == 1 + 5
    rule_id, out = ctx.decompress(packet)
    assert out["ICMPv6.type"] == 129
    assert out["ICMPv6.code"] == 0
    assert out["ICMPv6.checksum"] is None
    assert out["ICMPv6.identifier"] == 0xBEEF
    assert out["ICMPv6.sequence"] == 42
