# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Tests for SCHC rule context and selection (RFC 8724 section 7)."""

from __future__ import annotations

import pytest

from lichen.schc import (
    CDA,
    MO,
    RULE_SET_VERSION,
    SCHC_RULE_VERSION_TYPE,
    FieldDescriptor,
    NoMatchingRuleError,
    Rule,
    SchcContext,
    SchcRuleVersionOption,
    VersionMismatchError,
    check_version_compatibility,
    create_rule_version_option,
    rule_matches,
    versions_compatible,
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


def test_rule_matches_ignores_extra_fields() -> None:
    # Extra fields in the input are ignored — the rule only checks declared fields.
    assert rule_matches(RULE_A, {"F.kind": 1, "F.val": 2, "F.extra": 3}) is True


def test_rule_matches_msb() -> None:
    rule = Rule(
        rule_id=12,
        fields=(FieldDescriptor("P", 16, MO.MSB, CDA.LSB, target_value=5683, mo_arg=12),),
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


def test_context_uses_dict_keys_not_rule_id() -> None:
    # Context stores rules under their dict keys, even if they mismatch rule_id.
    rule = Rule(5, ())
    ctx = SchcContext({6: rule})
    assert ctx.get(6) is rule  # stored under dict key
    assert ctx.get(5) is None  # rule_id is ignored for lookup


def test_context_accepts_non_integer_keys() -> None:
    # Type hints enforce int keys, but no runtime validation.
    # String keys work but are non-standard usage.
    ctx = SchcContext({5: Rule(5, ()), "6": Rule(6, ())})  # type: ignore[dict-item]
    assert ctx.get(5) is not None
    assert ctx.get("6") is not None  # type: ignore[arg-type]


def test_context_accepts_non_rule_value_at_construction() -> None:
    # Type hints enforce Rule values, but no runtime validation at construction.
    # Operations on non-Rule values will fail later when accessed.
    ctx = SchcContext({5: object()})  # type: ignore[dict-item]
    # Context was created (no immediate error)
    assert ctx.get(5) is not None


@pytest.mark.parametrize("value", [-1, 256, True, 1.0])
def test_select_rule_rejects_invalid_field_values(value: object) -> None:
    rule = Rule(5, (FieldDescriptor("X", 8, MO.IGNORE, CDA.VALUE_SENT),))
    assert SchcContext({5: rule}).select_rule({"X": value}) is None  # type: ignore[dict-item]


@pytest.mark.parametrize("value", [0, 255])
def test_select_rule_accepts_field_width_boundaries(value: int) -> None:
    rule = Rule(5, (FieldDescriptor("X", 8, MO.IGNORE, CDA.VALUE_SENT),))
    assert SchcContext({5: rule}).select_rule({"X": value}) is rule


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


# --- Rule Set Versioning (spec section 5.7) ---


def test_rule_set_version_constant_is_2() -> None:
    """Spec section 5.7: version 2 is current RFC 8724 profile."""
    assert RULE_SET_VERSION == 2


def test_default_context_has_current_version() -> None:
    """Default context uses RULE_SET_VERSION."""
    ctx = SchcContext()
    assert ctx.version == RULE_SET_VERSION
    assert ctx.version == 2


def test_context_accepts_custom_version() -> None:
    """Context can be constructed with a specific version."""
    ctx = SchcContext(version=3)
    assert ctx.version == 3


def test_context_version_zero_reserved() -> None:
    """Version 0 is reserved but can still be set (for testing/edge cases)."""
    ctx = SchcContext(version=0)
    assert ctx.version == 0


def test_context_rejects_invalid_version() -> None:
    """Context rejects version outside 0-255 (spec section 5.7: 8-bit unsigned)."""
    with pytest.raises(ValueError, match="version must be 0-255"):
        SchcContext(version=-1)
    with pytest.raises(ValueError, match="version must be 0-255"):
        SchcContext(version=256)


def test_context_rejects_non_integer_version() -> None:
    """Context rejects non-integer version values."""
    with pytest.raises(ValueError, match="version must be 0-255"):
        SchcContext(version=2.0)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="version must be 0-255"):
        SchcContext(version="2")  # type: ignore[arg-type]


# --- SchcRuleVersionOption (spec section 5.7 DIO option) ---


def test_rule_version_option_type_constant() -> None:
    """SCHC_RULE_VERSION_TYPE is 0x13 (LICHEN extension)."""
    assert SCHC_RULE_VERSION_TYPE == 0x13


def test_rule_version_option_serialization() -> None:
    """Option serializes to 3-byte TLV format."""
    opt = SchcRuleVersionOption(version=2)
    data = opt.to_bytes()
    assert data == bytes([0x13, 0x01, 0x02])


def test_rule_version_option_deserialization() -> None:
    """Option deserializes from 3-byte TLV format."""
    data = bytes([0x13, 0x01, 0x02])
    opt = SchcRuleVersionOption.from_bytes(data)
    assert opt.version == 2


def test_rule_version_option_round_trip() -> None:
    """Serialize/deserialize round trip preserves version."""
    for version in [0, 1, 2, 3, 127, 255]:
        opt = SchcRuleVersionOption(version=version)
        parsed = SchcRuleVersionOption.from_bytes(opt.to_bytes())
        assert parsed.version == version


def test_rule_version_option_current() -> None:
    """current() factory uses RULE_SET_VERSION."""
    opt = SchcRuleVersionOption.current()
    assert opt.version == RULE_SET_VERSION
    assert opt.version == 2


def test_rule_version_option_rejects_invalid_version() -> None:
    """Option rejects version outside 0-255."""
    with pytest.raises(ValueError, match="version must be 0-255"):
        SchcRuleVersionOption(version=-1)
    with pytest.raises(ValueError, match="version must be 0-255"):
        SchcRuleVersionOption(version=256)


def test_rule_version_option_from_bytes_rejects_short() -> None:
    """from_bytes rejects data shorter than 3 bytes."""
    with pytest.raises(ValueError, match="too short"):
        SchcRuleVersionOption.from_bytes(bytes([0x13, 0x01]))


def test_rule_version_option_from_bytes_rejects_wrong_type() -> None:
    """from_bytes rejects wrong option type."""
    with pytest.raises(ValueError, match="wrong option type"):
        SchcRuleVersionOption.from_bytes(bytes([0x12, 0x01, 0x02]))


def test_rule_version_option_from_bytes_rejects_wrong_length() -> None:
    """from_bytes rejects unexpected length field."""
    with pytest.raises(ValueError, match="unexpected length"):
        SchcRuleVersionOption.from_bytes(bytes([0x13, 0x02, 0x02, 0x00]))


# --- Version Compatibility (spec section 5.7) ---


def test_versions_compatible_same() -> None:
    """Same versions are compatible."""
    assert versions_compatible(2, 2) is True
    assert versions_compatible(0, 0) is True
    assert versions_compatible(3, 3) is True


def test_versions_compatible_different() -> None:
    """Different versions are incompatible."""
    assert versions_compatible(1, 2) is False
    assert versions_compatible(2, 1) is False
    assert versions_compatible(2, 3) is False


def test_check_version_compatibility_returns_true() -> None:
    """check_version_compatibility returns True for matching versions."""
    assert check_version_compatibility(2, 2) is True


def test_check_version_compatibility_raises_on_mismatch() -> None:
    """check_version_compatibility raises VersionMismatchError by default."""
    with pytest.raises(VersionMismatchError) as exc_info:
        check_version_compatibility(2, 1)
    assert exc_info.value.local == 2
    assert exc_info.value.remote == 1
    assert "local=2" in str(exc_info.value)
    assert "remote=1" in str(exc_info.value)


def test_check_version_compatibility_no_raise() -> None:
    """check_version_compatibility returns False when raise_on_mismatch=False."""
    assert check_version_compatibility(2, 1, raise_on_mismatch=False) is False


def test_create_rule_version_option_default() -> None:
    """create_rule_version_option uses current version by default."""
    opt = create_rule_version_option()
    assert opt.version == RULE_SET_VERSION


def test_create_rule_version_option_custom() -> None:
    """create_rule_version_option accepts custom version."""
    opt = create_rule_version_option(version=3)
    assert opt.version == 3
