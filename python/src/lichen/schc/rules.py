"""SCHC rule definitions for LICHEN (RFC 8724).

A SCHC *rule* describes, field by field, how a header is compressed. Each field
carries a Matching Operator (MO) that decides whether the rule applies to a
given value, and a Compression/Decompression Action (CDA) that decides what (if
anything) is placed in the compression residue.

This module implements the rule *model* and a small registry of rules drawn
from the LICHEN specification (spec/03-adaptation.md and spec/appendix-schc.md).
The compression engine lives in :mod:`lichen.schc.codec`.

Scope: fixed-bit-length fields with the operators the LICHEN rules use
(EQUAL / IGNORE / MSB and NOT_SENT / VALUE_SENT / LSB / COMPUTE). Variable-length
fields (e.g. a CoAP token) and fragmentation (RFC 8724 section 8) are not
handled here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MO(Enum):
    """Matching Operator — decides whether a rule applies to a field value."""

    EQUAL = "equal"  # value must equal the target value
    IGNORE = "ignore"  # always matches
    MSB = "msb"  # the top `mo_arg` bits must equal the target value's top bits
    MATCH_MAPPING = "match-mapping"  # value must be one of `mapping`


class CDA(Enum):
    """Compression/Decompression Action — what goes in the residue."""

    NOT_SENT = "not-sent"  # nothing sent; reconstructed from the target value
    VALUE_SENT = "value-sent"  # the whole field is sent in the residue
    LSB = "lsb"  # only the least-significant (length - MSB) bits are sent
    COMPUTE = "compute"  # nothing sent; recomputed by an upper layer
    MAPPING_SENT = "mapping-sent"  # the index of the value within `mapping`


@dataclass(frozen=True)
class FieldDescriptor:
    """One field's compression behaviour within a rule.

    Attributes:
        field_id: Stable identifier for the field (e.g. "CoAP.MID").
        length_bits: Field width in bits.
        mo: Matching Operator.
        cda: Compression/Decompression Action.
        target_value: Target value used by EQUAL / MSB matching and NOT_SENT
            reconstruction.
        mo_arg: For MSB, the number of most-significant bits to match. Also
            determines the LSB residue width (length_bits - mo_arg).
        mapping: For MATCH_MAPPING / MAPPING_SENT, the ordered list of allowed
            values; the residue carries the index into this list.
    """

    field_id: str
    length_bits: int
    mo: MO
    cda: CDA
    target_value: int = 0
    mo_arg: int | None = None
    mapping: tuple[int, ...] | None = None

    def lsb_bits(self) -> int:
        """Number of residue bits for an LSB action (length_bits - MSB length)."""
        if self.mo_arg is None:
            raise ValueError(f"{self.field_id}: LSB requires mo_arg (MSB length)")
        return self.length_bits - self.mo_arg

    def mapping_bits(self) -> int:
        """Number of residue bits for a MAPPING_SENT index (ceil(log2(n)))."""
        if not self.mapping:
            raise ValueError(f"{self.field_id}: mapping action requires a mapping")
        return (len(self.mapping) - 1).bit_length()


@dataclass(frozen=True)
class Rule:
    """A SCHC rule: an ordered set of field descriptors keyed by a rule ID.

    Rule IDs 0-127 are compression rules; 255 is the uncompressed fallback
    (spec section 5.5). The rule ID is encoded as a single leading byte.
    """

    rule_id: int
    fields: tuple[FieldDescriptor, ...]


# Rule ID reserved for the uncompressed fallback (spec sections 5.5 / 5.7).
RULE_ID_UNCOMPRESSED = 255


# CoAP header compression (spec appendix A.2), fixed part (no variable token).
# Version is a constant; the rest are carried verbatim in the residue.
# IDs 64+ are used for these standalone building-block rules to avoid colliding
# with the spec's reserved top-level rules 0-4 (which additionally require IPv6
# header parsing that is not yet implemented).
COAP_RULE = Rule(
    rule_id=64,
    fields=(
        FieldDescriptor("CoAP.Version", 2, MO.EQUAL, CDA.NOT_SENT, target_value=1),
        FieldDescriptor("CoAP.Type", 2, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("CoAP.TKL", 4, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("CoAP.Code", 8, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("CoAP.MID", 16, MO.IGNORE, CDA.VALUE_SENT),
    ),
)


# UDP port compression (spec section 5.5): well-known CoAP port 5683 with
# MSB(12)/LSB(4), so only the low nibble of each port travels in the residue.
UDP_PORT_RULE = Rule(
    rule_id=65,
    fields=(
        FieldDescriptor(
            "UDP.SrcPort", 16, MO.MSB, CDA.LSB, target_value=5683, mo_arg=12
        ),
        FieldDescriptor(
            "UDP.DstPort", 16, MO.MSB, CDA.LSB, target_value=5683, mo_arg=12
        ),
    ),
)


# ICMPv6 Echo Request/Reply (spec appendix A.1 rule 2). Type distinguishes
# request (128) from reply (129) so it is carried; code is always 0; the
# checksum is recomputed over the pseudo-header on decompression.
ICMPV6_ECHO_RULE = Rule(
    rule_id=2,
    fields=(
        FieldDescriptor("ICMPv6.Type", 8, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("ICMPv6.Code", 8, MO.EQUAL, CDA.NOT_SENT, target_value=0),
        FieldDescriptor("ICMPv6.Checksum", 16, MO.IGNORE, CDA.COMPUTE),
        FieldDescriptor("ICMPv6.Identifier", 16, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("ICMPv6.Sequence", 16, MO.IGNORE, CDA.VALUE_SENT),
    ),
)


# ---------------------------------------------------------------------------
# Whole-packet rules (spec appendix A.1), built from shared field helpers.
#
# Constant IPv6/transport fields are elided. Link-local addresses match the
# fe80::/64 prefix via MSB(64) so only the 64-bit IID travels; global addresses
# are carried in full (prefix-context elision and full L2-derived IID elision
# are future optimizations that need the link layer). Lengths and checksums are
# recomputed on decompression. Variable trailers (CoAP token/options/payload,
# RPL options) travel verbatim after the residue, handled by schc/headers.py.
# ---------------------------------------------------------------------------

_LINK_LOCAL_PREFIX_TV = 0xFE80 << 112  # fe80::/64 as a 128-bit target value


def _addr_field(field_id: str, *, link_local: bool) -> FieldDescriptor:
    if link_local:
        return FieldDescriptor(
            field_id, 128, MO.MSB, CDA.LSB,
            target_value=_LINK_LOCAL_PREFIX_TV, mo_arg=64,
        )
    return FieldDescriptor(field_id, 128, MO.IGNORE, CDA.VALUE_SENT)


def _ipv6_header_fields(
    next_header: int, *, link_local: bool
) -> tuple[FieldDescriptor, ...]:
    return (
        FieldDescriptor("IPv6.version", 4, MO.EQUAL, CDA.NOT_SENT, target_value=6),
        FieldDescriptor("IPv6.traffic_class", 8, MO.EQUAL, CDA.NOT_SENT),
        FieldDescriptor("IPv6.flow_label", 20, MO.EQUAL, CDA.NOT_SENT),
        FieldDescriptor("IPv6.payload_length", 16, MO.IGNORE, CDA.COMPUTE),
        FieldDescriptor(
            "IPv6.next_header", 8, MO.EQUAL, CDA.NOT_SENT, target_value=next_header
        ),
        FieldDescriptor("IPv6.hop_limit", 8, MO.IGNORE, CDA.VALUE_SENT),
        _addr_field("IPv6.src", link_local=link_local),
        _addr_field("IPv6.dst", link_local=link_local),
    )


def _udp_fields() -> tuple[FieldDescriptor, ...]:
    return (
        FieldDescriptor("UDP.src_port", 16, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("UDP.dst_port", 16, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("UDP.length", 16, MO.IGNORE, CDA.COMPUTE),
        FieldDescriptor("UDP.checksum", 16, MO.IGNORE, CDA.COMPUTE),
    )


def _coap_fields() -> tuple[FieldDescriptor, ...]:
    return (
        FieldDescriptor("CoAP.version", 2, MO.EQUAL, CDA.NOT_SENT, target_value=1),
        FieldDescriptor("CoAP.type", 2, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("CoAP.tkl", 4, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("CoAP.code", 8, MO.IGNORE, CDA.VALUE_SENT),
        FieldDescriptor("CoAP.mid", 16, MO.IGNORE, CDA.VALUE_SENT),
    )


def _icmpv6_rpl_fields(code: int) -> tuple[FieldDescriptor, ...]:
    # ICMPv6 type 155 (RPL); code selects the message; checksum recomputed.
    return (
        FieldDescriptor("ICMPv6.type", 8, MO.EQUAL, CDA.NOT_SENT, target_value=155),
        FieldDescriptor("ICMPv6.code", 8, MO.EQUAL, CDA.NOT_SENT, target_value=code),
        FieldDescriptor("ICMPv6.checksum", 16, MO.IGNORE, CDA.COMPUTE),
    )


# Rule 0 / 1: link-local / global IPv6 + UDP + CoAP.
LINK_LOCAL_COAP_RULE = Rule(
    rule_id=0,
    fields=_ipv6_header_fields(17, link_local=True) + _udp_fields() + _coap_fields(),
)
GLOBAL_COAP_RULE = Rule(
    rule_id=1,
    fields=_ipv6_header_fields(17, link_local=False) + _udp_fields() + _coap_fields(),
)

# Rule 3: RPL DIO base object (RFC 6550 6.3) over link-local ICMPv6.
_DIO_BASE_FIELDS = (
    FieldDescriptor("RPL.instance", 8, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.version", 8, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.rank", 16, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.gmop", 8, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.dtsn", 8, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.flags", 8, MO.EQUAL, CDA.NOT_SENT),
    FieldDescriptor("RPL.reserved", 8, MO.EQUAL, CDA.NOT_SENT),
    FieldDescriptor("RPL.dodagid", 128, MO.IGNORE, CDA.VALUE_SENT),
)
RPL_DIO_RULE = Rule(
    rule_id=3,
    fields=_ipv6_header_fields(58, link_local=True) + _icmpv6_rpl_fields(1)
    + _DIO_BASE_FIELDS,
)

# Rule 4: RPL DAO base object (RFC 6550 6.4) with DODAGID (D flag set), the
# common non-storing case. DAOs without a DODAGID fall back to uncompressed.
_DAO_BASE_FIELDS = (
    FieldDescriptor("RPL.instance", 8, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.kd_flags", 8, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.reserved", 8, MO.EQUAL, CDA.NOT_SENT),
    FieldDescriptor("RPL.seq", 8, MO.IGNORE, CDA.VALUE_SENT),
    FieldDescriptor("RPL.dodagid", 128, MO.IGNORE, CDA.VALUE_SENT),
)
RPL_DAO_RULE = Rule(
    rule_id=4,
    fields=_ipv6_header_fields(58, link_local=True) + _icmpv6_rpl_fields(2)
    + _DAO_BASE_FIELDS,
)


# Registry keyed by rule ID.
RULES: dict[int, Rule] = {
    LINK_LOCAL_COAP_RULE.rule_id: LINK_LOCAL_COAP_RULE,
    GLOBAL_COAP_RULE.rule_id: GLOBAL_COAP_RULE,
    RPL_DIO_RULE.rule_id: RPL_DIO_RULE,
    RPL_DAO_RULE.rule_id: RPL_DAO_RULE,
    ICMPV6_ECHO_RULE.rule_id: ICMPV6_ECHO_RULE,
    COAP_RULE.rule_id: COAP_RULE,
    UDP_PORT_RULE.rule_id: UDP_PORT_RULE,
}
