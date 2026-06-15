"""SCHC (RFC 8724) header compression for LICHEN.

Public API:
    - Rule model: ``Rule``, ``FieldDescriptor``, ``MO``, ``CDA``
    - Rule registry: ``RULES``, ``COAP_RULE``, ``UDP_PORT_RULE``
    - Engine: ``compress``, ``decompress``, ``SchcError``
"""

from lichen.schc.codec import BitReader, BitWriter, SchcError, compress, decompress
from lichen.schc.context import NoMatchingRuleError, SchcContext, rule_matches
from lichen.schc.rules import (
    CDA,
    COAP_RULE,
    ICMPV6_ECHO_RULE,
    MO,
    RULE_ID_UNCOMPRESSED,
    RULES,
    UDP_PORT_RULE,
    FieldDescriptor,
    Rule,
)

__all__ = [
    "BitReader",
    "BitWriter",
    "CDA",
    "COAP_RULE",
    "FieldDescriptor",
    "ICMPV6_ECHO_RULE",
    "MO",
    "NoMatchingRuleError",
    "RULES",
    "RULE_ID_UNCOMPRESSED",
    "Rule",
    "SchcContext",
    "SchcError",
    "UDP_PORT_RULE",
    "compress",
    "decompress",
    "rule_matches",
]
