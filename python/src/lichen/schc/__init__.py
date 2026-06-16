"""SCHC (RFC 8724) header compression for LICHEN.

Public API:
    - Rule model: ``Rule``, ``FieldDescriptor``, ``MO``, ``CDA``
    - Rule registry: ``RULES``, ``COAP_RULE``, ``UDP_PORT_RULE``
    - Engine: ``compress``, ``decompress``, ``SchcError``
"""

from lichen.schc.codec import BitReader, BitWriter, SchcError, compress, decompress
from lichen.schc.context import NoMatchingRuleError, SchcContext, rule_matches
from lichen.schc.fragment import (
    ALL_1,
    DEFAULT_WINDOW_SIZE,
    MIC_LENGTH,
    Ack,
    Fragment,
    FragmentError,
    FragmentSender,
    compute_mic,
)
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
    "ALL_1",
    "BitReader",
    "BitWriter",
    "CDA",
    "COAP_RULE",
    "DEFAULT_WINDOW_SIZE",
    "MIC_LENGTH",
    "Ack",
    "FieldDescriptor",
    "Fragment",
    "FragmentError",
    "FragmentSender",
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
    "compute_mic",
    "decompress",
    "rule_matches",
]
