"""SCHC rule context and selection (RFC 8724 section 7).

A :class:`SchcContext` holds the active rule set and selects a matching rule for
a set of field values: the first rule (by ascending rule ID) whose every
descriptor is satisfied — EQUAL/MSB constraints hold and all fields needed for
the residue are present. If no compression rule matches, selection falls back to
the uncompressed rule (ID 255).

This is the piece the compressor/decompressor build on: given parsed header
fields, pick a rule, then call :func:`lichen.schc.codec.compress`.
"""

from __future__ import annotations

from lichen.schc.codec import compress, decompress
from lichen.schc.rules import (
    CDA,
    MO,
    RULE_ID_UNCOMPRESSED,
    RULES,
    Rule,
)


def rule_matches(rule: Rule, fields: dict[str, int]) -> bool:
    """Whether ``fields`` satisfy every descriptor of ``rule``."""
    for fd in rule.fields:
        value = fields.get(fd.field_id)
        needs_value = fd.mo in (MO.EQUAL, MO.MSB, MO.MATCH_MAPPING) or fd.cda in (
            CDA.VALUE_SENT,
            CDA.LSB,
            CDA.MAPPING_SENT,
        )
        if value is None:
            if needs_value:
                return False
            continue
        if fd.mo == MO.EQUAL and value != fd.target_value:
            return False
        if fd.mo == MO.MSB:
            if fd.mo_arg is None:
                return False
            shift = fd.length_bits - fd.mo_arg
            if (value >> shift) != (fd.target_value >> shift):
                return False
        if fd.mo == MO.MATCH_MAPPING and (
            fd.mapping is None or value not in fd.mapping
        ):
            return False
    return True


class SchcContext:
    """An ordered set of SCHC rules with pattern-based selection."""

    def __init__(self, rules: dict[int, Rule] | None = None) -> None:
        source = RULES if rules is None else rules
        # Keep rules ordered by ascending rule ID for deterministic selection.
        self._rules: dict[int, Rule] = dict(sorted(source.items()))

    def get(self, rule_id: int) -> Rule | None:
        """Look up a rule by ID."""
        return self._rules.get(rule_id)

    def select_rule(self, fields: dict[str, int]) -> Rule | None:
        """The first matching compression rule, or None if none matches."""
        for rule in self._rules.values():
            if rule.rule_id == RULE_ID_UNCOMPRESSED:
                continue
            if rule_matches(rule, fields):
                return rule
        return None

    def compress(self, fields: dict[str, int]) -> bytes:
        """Select a matching rule and compress; raises if none matches."""
        rule = self.select_rule(fields)
        if rule is None:
            raise NoMatchingRuleError("no SCHC rule matches the given fields")
        return compress(rule, fields)

    def decompress(self, data: bytes) -> tuple[int, dict[str, int | None]]:
        """Decompress using the rule named by the packet's leading Rule ID."""
        if not data:
            raise NoMatchingRuleError("empty SCHC packet")
        rule = self._rules.get(data[0])
        if rule is None:
            raise NoMatchingRuleError(f"unknown rule ID {data[0]}")
        return decompress(data, rule)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)


class NoMatchingRuleError(Exception):
    """Raised when no rule in the context matches and there is no fallback."""
