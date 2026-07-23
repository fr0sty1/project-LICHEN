# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
from __future__ import annotations

from lichen.schc.rules import CDA, MO, RULES, FieldDescriptor, Rule


class SchcError(Exception):
    pass


def residue_bit_length(rule: Rule) -> int:
    total = 0
    for fd in rule.fields:
        if fd.cda == CDA.VALUE_SENT:
            total += fd.length_bits
        elif fd.cda == CDA.LSB:
            total += fd.lsb_bits()
        elif fd.cda == CDA.MAPPING_SENT:
            total += fd.mapping_bits()
    return total


def residue_byte_length(rule: Rule) -> int:
    return (residue_bit_length(rule) + 7) // 8


class BitWriter:
    def __init__(self) -> None:
        self._acc = 0
        self._nbits = 0

    def write(self, value: int, nbits: int) -> None:
        if nbits < 0:
            raise ValueError(f"nbits must be non-negative, got {nbits}")
        if value < 0 or value >= (1 << nbits):
            raise ValueError(f"value {value} does not fit in {nbits} bits")
        self._acc = (self._acc << nbits) | value
        self._nbits += nbits

    @property
    def bit_length(self) -> int:
        return self._nbits

    def to_bytes(self) -> bytes:
        if self._nbits == 0:
            return b""
        if self._nbits > 65536:  # prevent excessive memory use on malformed input
            raise OverflowError(f"excessive bit count: {self._nbits}")
        pad = (-self._nbits) % 8
        total = self._nbits + pad
        return (self._acc << pad).to_bytes(total // 8, "big")


class BitReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, nbits: int) -> int:
        if nbits < 0:
            raise ValueError(f"nbits must be non-negative, got {nbits}")
        if self._pos + nbits > len(self._data) * 8:
            raise SchcError("residue underrun: not enough bits to read")
        value = 0
        for _ in range(nbits):
            byte = self._data[self._pos // 8]
            bit = (byte >> (7 - (self._pos % 8))) & 1
            value = (value << 1) | bit
            self._pos += 1
        return value


def _check_msb(fd: FieldDescriptor, value: int) -> None:
    if fd.mo_arg is None:
        raise SchcError(f"{fd.field_id}: MSB requires mo_arg")
    if fd.mo_arg > fd.length_bits:
        raise SchcError(
            f"{fd.field_id}: mo_arg ({fd.mo_arg}) exceeds length_bits ({fd.length_bits})"
        )
    shift = fd.length_bits - fd.mo_arg
    if (value >> shift) != (fd.target_value >> shift):
        raise SchcError(
            f"{fd.field_id}: MSB({fd.mo_arg}) mismatch — value {value} not "
            f"compatible with target {fd.target_value}"
        )


def compress(rule: Rule, fields: dict[str, int]) -> bytes:
    writer = BitWriter()
    for fd in rule.fields:
        value = fields.get(fd.field_id)
        if value is None:
            if fd.requires_value():
                raise SchcError(f"{fd.field_id}: missing required field value")
            continue
        if fd.mo == MO.EQUAL and value != fd.target_value:
            raise SchcError(f"{fd.field_id}: EQUAL mismatch — {value} != {fd.target_value}")
        if fd.mo == MO.MSB:
            _check_msb(fd, value)
        if fd.mo == MO.MATCH_MAPPING and (fd.mapping is None or value not in fd.mapping):
            raise SchcError(f"{fd.field_id}: value {value} not in mapping")
        if fd.cda == CDA.VALUE_SENT:
            if value < 0 or value >= (1 << fd.length_bits):
                raise SchcError(
                    f"{fd.field_id}: value {value} does not fit in {fd.length_bits} bits"
                )
            writer.write(value, fd.length_bits)
        elif fd.cda == CDA.LSB:
            k = fd.lsb_bits()
            writer.write(value & ((1 << k) - 1), k)
        elif fd.cda == CDA.MAPPING_SENT:
            if fd.mapping is None or value not in fd.mapping:
                raise SchcError(f"{fd.field_id}: value {value} not in mapping")
            writer.write(fd.mapping.index(value), fd.mapping_bits())
    return bytes([rule.rule_id]) + writer.to_bytes()


def decompress(data: bytes, rule: Rule | None = None) -> tuple[int, dict[str, int | None]]:
    if not data:
        raise SchcError("empty SCHC packet")
    rule_id = data[0]
    if rule is None:
        rule = RULES.get(rule_id)
        if rule is None:
            raise SchcError(f"unknown rule ID {rule_id}")
    elif rule.rule_id != rule_id:
        raise SchcError(f"rule ID mismatch: packet has {rule_id}, rule is {rule.rule_id}")
    reader = BitReader(data[1:])
    out: dict[str, int | None] = {}
    for fd in rule.fields:
        if fd.cda == CDA.NOT_SENT:
            out[fd.field_id] = fd.target_value
        elif fd.cda == CDA.COMPUTE:
            out[fd.field_id] = None
        elif fd.cda == CDA.VALUE_SENT:
            out[fd.field_id] = reader.read(fd.length_bits)
        elif fd.cda == CDA.LSB:
            k = fd.lsb_bits()
            lsb = reader.read(k)
            msb = (fd.target_value >> k) << k
            out[fd.field_id] = msb | lsb
        elif fd.cda == CDA.MAPPING_SENT:
            if fd.mapping is None:
                raise SchcError(f"{fd.field_id}: MAPPING_SENT requires a mapping")
            index = reader.read(fd.mapping_bits())
            if index >= len(fd.mapping):
                raise SchcError(f"{fd.field_id}: mapping index {index} out of range")
            out[fd.field_id] = fd.mapping[index]
    return rule_id, out
