# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
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

from lichen.schc.codec import SchcError, compress, decompress
from lichen.schc.rules import (
    GLOBAL_OSCORE_RULE,
    LINK_LOCAL_OSCORE_RULE,
    MO,
    RULE_ID_UNCOMPRESSED,
    RULE_SET_VERSION,
    RULES,
    Rule,
    SchcRuleVersionOption,
)


def rule_matches(rule: Rule, fields: dict[str, int]) -> bool:
    for fd in rule.fields:
        value = fields.get(fd.field_id)
        if value is None:
            if fd.requires_value():
                return False
            continue
        if type(value) is not int or not 0 <= value < (1 << fd.length_bits):
            return False
        if fd.mo == MO.EQUAL and value != fd.target_value:
            return False
        if fd.mo == MO.MSB:
            if fd.mo_arg is None or fd.mo_arg > fd.length_bits:
                return False
            shift = fd.length_bits - fd.mo_arg
            if (value >> shift) != (fd.target_value >> shift):
                return False
        if fd.mo == MO.MATCH_MAPPING and (fd.mapping is None or value not in fd.mapping):
            return False
    return True


class SchcContext:
    def __init__(
        self,
        rules: dict[int, Rule] | None = None,
        version: int | None = None,
    ) -> None:
        source = RULES if rules is None else rules
        _oscore_ids = {LINK_LOCAL_OSCORE_RULE.rule_id, GLOBAL_OSCORE_RULE.rule_id}

        def _rule_sort_key(item: tuple[int, Rule]) -> tuple[int, int]:
            rid = item[0]
            return (0 if rid in _oscore_ids else 1, rid)

        self._rules: dict[int, Rule] = dict(sorted(source.items(), key=_rule_sort_key))
        resolved = version if version is not None else RULE_SET_VERSION
        if type(resolved) is not int or not 0 <= resolved <= 255:
            raise ValueError(f"version must be 0-255, got {resolved}")
        self._version = resolved

    @property
    def version(self) -> int:
        """Rule set version (8-bit, per spec section 5.7).

        Version 0 is reserved for uncompressed fallback. Version 1 was legacy
        experimental. Version 2 is the current RFC 8724 fragmentation profile.
        """
        return self._version

    def get(self, rule_id: int) -> Rule | None:
        return self._rules.get(rule_id)

    def select_rule(self, fields: dict[str, int]) -> Rule | None:
        for rule in self._rules.values():
            if rule.rule_id == RULE_ID_UNCOMPRESSED:
                continue
            if rule_matches(rule, fields):
                return rule
        return None

    def compress(self, fields: dict[str, int]) -> bytes:
        rule = self.select_rule(fields)
        if rule is None:
            raise NoMatchingRuleError("no SCHC rule matches the given fields")
        return compress(rule, fields)

    def decompress(self, data: bytes) -> tuple[int, dict[str, int | None]]:
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


class NoMatchingRuleError(SchcError):
    pass


class VersionMismatchError(SchcError):
    """Raised when SCHC rule set versions are incompatible."""

    def __init__(self, local: int, remote: int) -> None:
        self.local = local
        self.remote = remote
        super().__init__(f"rule set version mismatch: local={local}, remote={remote}")


def versions_compatible(local: int, remote: int) -> bool:
    """Check whether two rule set versions are compatible.

    Per spec section 5.7, versions must match exactly for full interoperability.
    Rule 255 (uncompressed fallback) is always supported regardless of version
    for unfragmented packets, but this function checks compression compatibility.

    Args:
        local: The local node's rule set version.
        remote: The remote node's advertised rule set version.

    Returns:
        True if the versions are compatible for full SCHC operation.
    """
    return local == remote


def check_version_compatibility(
    local: int,
    remote: int,
    *,
    raise_on_mismatch: bool = True,
) -> bool:
    """Check and optionally enforce rule set version compatibility.

    Args:
        local: The local node's rule set version.
        remote: The remote node's advertised rule set version (e.g., from DIO).
        raise_on_mismatch: If True, raise VersionMismatchError on mismatch.

    Returns:
        True if versions are compatible.

    Raises:
        VersionMismatchError: If versions mismatch and raise_on_mismatch is True.
    """
    if versions_compatible(local, remote):
        return True
    if raise_on_mismatch:
        raise VersionMismatchError(local, remote)
    return False


def create_rule_version_option(version: int | None = None) -> SchcRuleVersionOption:
    """Create a SCHC Rule Version Option for DIO messages.

    Args:
        version: Rule set version to advertise. Defaults to RULE_SET_VERSION.

    Returns:
        Option ready to be serialized and included in a DIO message.
    """
    return SchcRuleVersionOption(version=version if version is not None else RULE_SET_VERSION)
