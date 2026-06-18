"""SCHC compression/decompression engine (RFC 8724).

Given a :class:`~lichen.schc.rules.Rule` and a mapping of field values, the
compressor emits a one-byte Rule ID followed by a bit-packed *residue* holding
only the information that cannot be reconstructed from the rule. The
decompressor reverses the process, looking the rule up by its leading Rule ID.

Bits are packed most-significant-first (network bit order). The residue is
padded to a byte boundary with zero bits, per RFC 8724.
"""

from __future__ import annotations

from lichen.schc.rules import CDA, MO, RULES, FieldDescriptor, Rule


class SchcError(Exception):
    """Raised when compression or decompression fails."""


def residue_bit_length(rule: Rule) -> int:
    """Total residue bits a rule emits (sum over fields by their CDA).

    Lets callers find where a byte-aligned residue ends and a variable tail
    (e.g. a CoAP token/options/payload) begins.
    """
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
    """Byte length of a rule's residue, padded to a byte boundary."""
    return (residue_bit_length(rule) + 7) // 8


class BitWriter:
    """Accumulates bits most-significant-first and emits padded bytes."""

    def __init__(self) -> None:
        self._acc = 0
        self._nbits = 0

    def write(self, value: int, nbits: int) -> None:
        """Append the low `nbits` of `value` (which must fit in `nbits`)."""
        if nbits < 0:
            raise ValueError(f"nbits must be non-negative, got {nbits}")
        if value < 0 or value >= (1 << nbits):
            raise ValueError(f"value {value} does not fit in {nbits} bits")
        self._acc = (self._acc << nbits) | value
        self._nbits += nbits

    @property
    def bit_length(self) -> int:
        """Number of bits written so far (before padding)."""
        return self._nbits

    def to_bytes(self) -> bytes:
        """Return the written bits, zero-padded up to a byte boundary."""
        if self._nbits == 0:
            return b""
        pad = (-self._nbits) % 8
        total = self._nbits + pad
        return (self._acc << pad).to_bytes(total // 8, "big")


class BitReader:
    """Reads bits most-significant-first from a byte string."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def read(self, nbits: int) -> int:
        """Read `nbits` bits and return them as an integer."""
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
    """Verify the top `mo_arg` bits of value match the target value's."""
    if fd.mo_arg is None:
        raise ValueError(f"{fd.field_id}: MSB requires mo_arg")
    shift = fd.length_bits - fd.mo_arg
    if (value >> shift) != (fd.target_value >> shift):
        raise SchcError(
            f"{fd.field_id}: MSB({fd.mo_arg}) mismatch — value {value} not "
            f"compatible with target {fd.target_value}"
        )


def compress(rule: Rule, fields: dict[str, int]) -> bytes:
    """Compress a set of field values under a rule.

    Args:
        rule: The rule to apply (assumed already selected as matching).
        fields: Field values keyed by ``FieldDescriptor.field_id``. Fields whose
            CDA is COMPUTE, or whose MO is IGNORE with a NOT_SENT action, may be
            omitted.

    Returns:
        One Rule-ID byte followed by the byte-aligned residue.

    Raises:
        SchcError: If an EQUAL/MSB match fails or a required field is missing.
    """
    writer = BitWriter()

    for fd in rule.fields:
        value = fields.get(fd.field_id)
        needs_value = fd.mo in (MO.EQUAL, MO.MSB, MO.MATCH_MAPPING) or fd.cda in (
            CDA.VALUE_SENT,
            CDA.LSB,
            CDA.MAPPING_SENT,
        )
        if value is None:
            if needs_value:
                raise SchcError(f"{fd.field_id}: missing required field value")
            continue

        # Matching operator.
        if fd.mo == MO.EQUAL and value != fd.target_value:
            raise SchcError(
                f"{fd.field_id}: EQUAL mismatch — {value} != {fd.target_value}"
            )
        if fd.mo == MO.MSB:
            _check_msb(fd, value)
        if fd.mo == MO.MATCH_MAPPING and (
            fd.mapping is None or value not in fd.mapping
        ):
            raise SchcError(f"{fd.field_id}: value {value} not in mapping")

        # Compression action.
        if fd.cda == CDA.VALUE_SENT:
            if value < 0 or value >= (1 << fd.length_bits):
                raise SchcError(
                    f"{fd.field_id}: value {value} does not fit in "
                    f"{fd.length_bits} bits"
                )
            writer.write(value, fd.length_bits)
        elif fd.cda == CDA.LSB:
            k = fd.lsb_bits()
            writer.write(value & ((1 << k) - 1), k)
        elif fd.cda == CDA.MAPPING_SENT:
            if fd.mapping is None or value not in fd.mapping:
                raise SchcError(f"{fd.field_id}: value {value} not in mapping")
            writer.write(fd.mapping.index(value), fd.mapping_bits())
        # NOT_SENT and COMPUTE contribute nothing to the residue.

    return bytes([rule.rule_id]) + writer.to_bytes()


def decompress(data: bytes, rule: Rule | None = None) -> tuple[int, dict[str, int | None]]:
    """Decompress a SCHC packet back into field values.

    Args:
        data: One Rule-ID byte followed by the residue.
        rule: The rule to use. If omitted, it is looked up from the global
            registry by the leading Rule ID.

    Returns:
        A tuple ``(rule_id, fields)``. COMPUTE fields are returned as ``None``
        because they must be recomputed by an upper layer.

    Raises:
        SchcError: If data is empty, the rule is unknown, or the residue is
            truncated.
    """
    if not data:
        raise SchcError("empty SCHC packet")

    rule_id = data[0]
    if rule is None:
        rule = RULES.get(rule_id)
        if rule is None:
            raise SchcError(f"unknown rule ID {rule_id}")
    elif rule.rule_id != rule_id:
        raise SchcError(
            f"rule ID mismatch: packet has {rule_id}, rule is {rule.rule_id}"
        )

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
